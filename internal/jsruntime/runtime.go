// Package jsruntime runs source-only JavaScript in fresh, resource-bounded Wasm instances.
package jsruntime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	quickjs "github.com/aperturerobotics/go-quickjs-wasi-reactor"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

// ABI binds reviewed integrations to the engine and host protocol.
const ABI = "quickjs-ng-0.15.1/wazero-1.12.0/json-v1"
const MaxSource = 256 << 10
const MaxInput = 64 << 10
const MaxOutput = 256 << 10

var identifier = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*$`)
var slots = make(chan struct{}, 2)

// Engine owns only trusted compiled code. Guest state is never pooled.
type Engine struct {
	runtime  wazero.Runtime
	compiled wazero.CompiledModule
}

// New compiles the pinned engine; no integration source is compiled here.
func New(ctx context.Context) (*Engine, error) {
	r := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().WithMemoryLimitPages(1024).WithCloseOnContextDone(true))
	if _, err := wasi_snapshot_preview1.Instantiate(ctx, r); err != nil {
		r.Close(ctx)
		return nil, err
	}
	compiled, err := r.CompileModule(ctx, quickjs.QuickJSWASM)
	if err != nil {
		r.Close(ctx)
		return nil, err
	}
	return &Engine{r, compiled}, nil
}

// Close releases the trusted compilation and all instances. Stop callers first.
func (e *Engine) Close(ctx context.Context) error { return e.runtime.Close(ctx) }

// Exchange performs one bounded host request while no guest code is running.
type Exchange func(context.Context, json.RawMessage) (json.RawMessage, error)

// Run invokes an exported handler(args, ctx), with only ctx.http.request available.
// Each guest turn is cancellable, including parsing, native builtins and promise jobs.
func (e *Engine) Run(ctx context.Context, source, handler string, args json.RawMessage, exchange Exchange) (json.RawMessage, error) {
	if len(source) > MaxSource || len(args) > MaxInput || !json.Valid(args) || !identifier.MatchString(handler) {
		return nil, errors.New("invalid JavaScript invocation")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	select {
	case slots <- struct{}{}:
		defer func() { <-slots }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	// No files, environment, arguments, clocks, randomness, sockets or standard streams.
	mod, err := e.runtime.InstantiateModule(ctx, e.compiled, wazero.NewModuleConfig().WithName("").WithStartFunctions("_initialize"))
	if err != nil {
		return nil, err
	}
	defer mod.Close(context.Background()) // Discard memory directly; do not run guest destructors.
	g := guest{mod: mod, remaining: 5 * time.Second}
	var output json.RawMessage
	encodedInput, _ := json.Marshal(string(args))
	err = g.turn(ctx, func(ctx context.Context) error {
		rt, err := g.call(ctx, "JS_NewRuntime")
		if err != nil || rt == 0 {
			return errors.New("create JavaScript runtime")
		}
		g.runtime = rt
		if _, err = g.call(ctx, "JS_SetMemoryLimit", rt, 32<<20); err != nil {
			return err
		}
		js, err := g.call(ctx, "JS_NewContext", rt)
		if err != nil || js == 0 {
			return errors.New("create JavaScript context")
		}
		g.js = js
		if _, err = g.eval(ctx, bootstrap, 0); err != nil {
			return err
		}
		_, err = g.eval(ctx, source+"\n;__begin(() => "+handler+"(JSON.parse("+string(encodedInput)+"), __ctx));", 1)
		return err
	})
	if err != nil {
		return nil, err
	}
	for {
		var envelope struct {
			Kind  string          `json:"kind"`
			Value json.RawMessage `json:"value"`
		}
		err = g.turn(ctx, func(ctx context.Context) error {
			for {
				// JS_ExecutePendingJob needs a JSContext** for exception reporting.
				pending, err := g.call(ctx, "JS_IsJobPending", g.runtime)
				if err != nil {
					return err
				}
				if pending == 0 {
					break
				}
				p, err := g.call(ctx, "malloc", 4)
				if err != nil || p == 0 {
					return errors.New("allocate job pointer")
				}
				n, err := g.call(ctx, "JS_ExecutePendingJob", g.runtime, p)
				_, freeErr := g.call(ctx, "free", p)
				if err != nil {
					return err
				}
				if freeErr != nil {
					return freeErr
				}
				if int32(n) < 0 {
					return errors.New("JavaScript promise job failed")
				}
			}
			value, err := g.eval(ctx, "__step()", 0)
			if err != nil {
				return err
			}
			raw, err := g.stringValue(ctx, value, MaxOutput+MaxInput+128)
			if err != nil {
				return err
			}
			return json.Unmarshal(raw, &envelope)
		})
		if err != nil {
			return nil, err
		}
		switch envelope.Kind {
		case "result":
			output = envelope.Value
			if len(output) > MaxOutput {
				return nil, errors.New("JavaScript output exceeds limit")
			}
			return output, nil
		case "request":
			if len(envelope.Value) > MaxInput || exchange == nil {
				return nil, errors.New("HTTP capability unavailable or request too large")
			}
			response, err := exchange(ctx, envelope.Value)
			if err != nil {
				return nil, err
			}
			if len(response) > 2<<20 || !json.Valid(response) {
				return nil, errors.New("invalid host response")
			}
			encodedResponse, _ := json.Marshal(string(response))
			err = g.turn(ctx, func(ctx context.Context) error {
				_, err := g.eval(ctx, "__resume(JSON.parse("+string(encodedResponse)+"))", 0)
				return err
			})
			if err != nil {
				return nil, err
			}
		default:
			return nil, errors.New("JavaScript handler failed or did not settle")
		}
	}
}

type guest struct {
	mod       api.Module
	js        uint64
	remaining time.Duration
	runtime   uint64
}

func (g *guest) turn(ctx context.Context, fn func(context.Context) error) error {
	if g.remaining <= 0 {
		return errors.New("JavaScript execution budget exhausted")
	}
	d := min(g.remaining, time.Second)
	turn, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	start := time.Now()
	err := fn(turn)
	g.remaining -= time.Since(start)
	if err != nil {
		return err
	}
	return turn.Err()
}
func (g *guest) call(ctx context.Context, name string, args ...uint64) (uint64, error) {
	f := g.mod.ExportedFunction(name)
	if f == nil {
		return 0, fmt.Errorf("missing engine export %s", name)
	}
	v, err := f.Call(ctx, args...)
	if err != nil {
		return 0, err
	}
	if len(v) == 0 {
		return 0, nil
	}
	return v[0], nil
}
func (g *guest) eval(ctx context.Context, source string, flag uint64) (uint64, error) {
	const filename = "integration.js\x00"
	p, err := g.call(ctx, "malloc", uint64(len(source)+1+len(filename)))
	if err != nil || p == 0 {
		return 0, errors.New("allocate source")
	}
	if !g.mod.Memory().Write(uint32(p), append([]byte(source), 0)) {
		return 0, errors.New("source outside guest memory")
	}
	defer g.call(ctx, "free", p)
	file := p + uint64(len(source)) + 1
	if !g.mod.Memory().Write(uint32(file), []byte(filename)) {
		return 0, errors.New("filename outside guest memory")
	}
	v, err := g.call(ctx, "JS_Eval", g.js, p, uint64(len(source)), file, flag)
	if err != nil {
		return 0, err
	}
	if int32(v>>32) == 6 {
		return 0, errors.New("JavaScript exception")
	}
	return v, nil
}
func (g *guest) stringValue(ctx context.Context, value uint64, limit uint32) ([]byte, error) {
	defer g.call(ctx, "JS_FreeValue", g.js, value)
	p, err := g.call(ctx, "malloc", 4)
	if err != nil || p == 0 {
		return nil, errors.New("allocate result pointer")
	}
	defer g.call(ctx, "free", p)
	str, err := g.call(ctx, "JS_ToCStringLen2", g.js, p, value, 0)
	if err != nil || str == 0 {
		return nil, errors.New("serialize result")
	}
	defer g.call(ctx, "JS_FreeCString", g.js, str)
	n, ok := g.mod.Memory().ReadUint32Le(uint32(p))
	if !ok || n > limit {
		return nil, errors.New("JavaScript result exceeds limit")
	}
	data, ok := g.mod.Memory().Read(uint32(str), n)
	if !ok {
		return nil, errors.New("result outside guest memory")
	}
	return append([]byte(nil), data...), nil
}

const bootstrap = `(() => {
 const stringify = JSON.stringify.bind(JSON);
 let request, resolve, result, state = 'waiting';
 const ctx = Object.freeze({http: Object.freeze({request(value) {
   if (request !== undefined || resolve) throw new Error('Only sequential HTTP is supported');
   request = stringify(value);
   return new Promise(r => { resolve = r; });
 }})});
 Object.defineProperties(globalThis, {
  __ctx: {value: ctx},
  __begin: {value: fn => { Promise.resolve().then(fn).then(value => {
    result = stringify(value); state = result === undefined ? 'error' : 'result';
   }, () => { state = 'error'; }); }},
  __step: {value: () => {
    if (state === 'result') return '{"kind":"result","value":' + result + '}';
    if (request !== undefined) { const r = request; request = undefined; return '{"kind":"request","value":' + r + '}'; }
    return stringify({kind: state});
  }},
  __resume: {value: value => { const r = resolve; resolve = undefined; r(value); }}
 });
})();`
