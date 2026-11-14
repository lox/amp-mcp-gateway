package jsruntime

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestIsolation(t *testing.T) {
	e, err := New(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close(context.Background())
	for _, tt := range []struct {
		name, source string
		fail         bool
	}{
		{"compute", `export function run(a) { return {sum:a.x+a.y}; }`, false},
		{"JSON data", `export function run(a) { if (!Object.hasOwn(a,'__proto__') || Object.getPrototypeOf(a)!==Object.prototype) throw Error('not JSON data'); return true; }`, false},
		{"globals", `export function run() { return [typeof process, typeof require, typeof fetch, typeof std, typeof os]; }`, false},
		{"loop", `export function run() { while(true) {} }`, true},
		{"promise loop", `export async function run() { while(true) await Promise.resolve(); }`, true},
		{"memory", `export function run() { return new ArrayBuffer(100*1024*1024); }`, true},
		{"serialization", `export function run() { return 'x'.repeat(300000); }`, true},
		{"regex", `export function run() { return /(a+)+$/.test('a'.repeat(100)+'!'); }`, true},
		{"module", `import * as std from 'qjs:std'; export function run() {return std.getenv('HOME');}`, true},
		{"fresh", `export function run() { return typeof globalThis.stolen; }`, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			start := time.Now()
			got, err := e.Run(t.Context(), tt.source, "run", json.RawMessage(`{"x":7,"y":12,"__proto__":{"admin":true}}`), nil)
			t.Logf("elapsed=%s output=%s error=%v", time.Since(start), got, err)
			if tt.fail != (err != nil) {
				t.Fatalf("failure=%v, got %s, %v", tt.fail, got, err)
			}
			if tt.name == "compute" && string(got) != `{"sum":19}` {
				t.Fatalf("got %s", got)
			}
			if tt.name == "globals" && string(got) != `["undefined","undefined","undefined","undefined","undefined"]` {
				t.Fatalf("got %s", got)
			}
			if tt.name == "fresh" && string(got) != `"undefined"` {
				t.Fatalf("got %s", got)
			}
			if time.Since(start) > 3*time.Second {
				t.Fatal("cancellation too slow")
			}
		})
	}
}

func TestSequentialHTTP(t *testing.T) {
	e, err := New(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close(context.Background())
	calls := 0
	got, err := e.Run(t.Context(), `export async function run(a,ctx) { globalThis.stolen='secret'; const a1=await ctx.http.request({path:'/first'}); if(!Object.hasOwn(a1,'__proto__') || Object.getPrototypeOf(a1)!==Object.prototype) throw Error('not JSON data'); const a2=await ctx.http.request({path:'/second'}); return a1.n*10+a2.n; }`, "run", json.RawMessage(`{}`), func(_ context.Context, request json.RawMessage) (json.RawMessage, error) {
		calls++
		if !strings.Contains(string(request), []string{"first", "second"}[calls-1]) {
			t.Errorf("request %s", request)
		}
		return json.RawMessage([]string{`{"n":3,"__proto__":{"admin":true}}`, `{"n":7}`}[calls-1]), nil
	})
	if err != nil || string(got) != "37" || calls != 2 {
		t.Fatalf("got %s calls=%d err=%v", got, calls, err)
	}
	got, err = e.Run(t.Context(), `export function run(){return typeof globalThis.stolen}`, "run", json.RawMessage(`{}`), nil)
	if err != nil || string(got) != `"undefined"` {
		t.Fatalf("cross invocation state: %s %v", got, err)
	}
}
