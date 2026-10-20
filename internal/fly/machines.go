package fly

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"ampcode.com/lox/amp-mcp-gateway/internal/sandbox"
)

// SandboxTimeout includes Machine boot and result collection, not just guest execution.
const SandboxTimeout = sandbox.ExecutionTimeout + time.Minute

// Sandbox defines a public GitHub stdio server hosted in an idle-expiring Machine.
// The app must be dedicated to this installation on its own custom private network.
type Sandbox struct {
	App, Image, TokenEnv, Region string
	MemoryMB                     int `json:",omitempty"`
	sandbox.Server
}

var appName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
var githubPath = regexp.MustCompile(`^/[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$`)
var pinnedImage = regexp.MustCompile(`^[^\s@]+@sha256:[a-f0-9]{64}$`)

// Validate checks configuration without contacting Fly or running untrusted code.
func (s Sandbox) Validate() error {
	u, err := url.Parse(s.Repository)
	if err != nil || u.Scheme != "https" || u.Host != "github.com" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !githubPath.MatchString(u.Path) {
		return errors.New("sandbox Repository must be a public https://github.com/owner/repository URL")
	}
	if !pinnedImage.MatchString(s.Image) {
		return errors.New("sandbox Image must be pinned with @sha256:<64 lowercase hex characters>")
	}
	if !appName.MatchString(s.App) || s.App == os.Getenv("FLY_APP_NAME") || s.TokenEnv == "" || strings.TrimSpace(s.RunCmd) == "" || strings.HasPrefix(s.Revision, "-") {
		return errors.New("sandbox requires a separate Fly App, TokenEnv and RunCmd, and a revision without a leading dash")
	}
	if s.MemoryMB != 0 && (s.MemoryMB < 256 || s.MemoryMB > 2048 || s.MemoryMB%256 != 0) {
		return errors.New("sandbox MemoryMB must be a multiple of 256 between 256 and 2048")
	}
	return nil
}

// Runner owns one connection's Machine. Never share it between accounts or definitions.
// Requests are serialized; an idle or failed Machine is replaced on a later request.
type Runner struct {
	config       Sandbox
	gate         chan struct{}
	machine      string
	lastDispatch time.Time
}

// NewRunner creates a lazy runner without provisioning any infrastructure.
func NewRunner(config Sandbox) *Runner {
	return &Runner{config: config, gate: make(chan struct{}, 1)}
}

// Run reuses a warm stdio server. Creation and request submission are never retried.
func (r *Runner) Run(ctx context.Context, request sandbox.Request) (sandbox.Response, error) {
	// Leave headroom for the readiness endpoint's 30-second server-side wait.
	return r.run(ctx, "https://api.machines.dev/v1", &http.Client{Timeout: 40 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, request)
}

func (r *Runner) run(ctx context.Context, endpoint string, client *http.Client, request sandbox.Request) (response sandbox.Response, err error) {
	ctx, cancel := context.WithTimeout(ctx, SandboxTimeout)
	defer cancel()
	select {
	case r.gate <- struct{}{}:
		defer func() { <-r.gate }()
	case <-ctx.Done():
		return sandbox.Response{}, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return sandbox.Response{}, err
	}
	s := r.config
	token := os.Getenv(s.TokenEnv)
	if token == "" {
		return sandbox.Response{}, errors.New("sandbox Fly token is unavailable")
	}
	requestTimeout := errors.New("Fly API returned HTTP 408")
	notFound := errors.New("Fly Machine not found")
	api := func(ctx context.Context, method, path string, input, output any) error {
		var body io.Reader
		if input != nil {
			raw, err := json.Marshal(input)
			if err != nil {
				return errors.New("encode sandbox request")
			}
			body = bytes.NewReader(raw)
		}
		r, err := http.NewRequestWithContext(ctx, method, endpoint+"/apps/"+s.App+path, body)
		if err != nil {
			return errors.New("create Fly API request")
		}
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", "application/json")
		res, err := client.Do(r)
		if err != nil {
			// Do not expose response bodies, tokens, subprocess output or arguments.
			return errors.New("Fly API request failed; execution may have occurred")
		}
		defer res.Body.Close()
		if res.StatusCode == http.StatusRequestTimeout {
			return requestTimeout
		}
		if res.StatusCode == http.StatusNotFound {
			return notFound
		}
		if res.StatusCode < 200 || res.StatusCode >= 300 {
			return fmt.Errorf("Fly API returned HTTP %d", res.StatusCode)
		}
		if output == nil {
			return nil
		}
		raw, err := io.ReadAll(io.LimitReader(res.Body, 8*sandbox.ResultLimit+1))
		if err != nil || len(raw) > 8*sandbox.ResultLimit || json.Unmarshal(raw, output) != nil {
			return errors.New("invalid or oversized Fly API response")
		}
		return nil
	}
	// A failed or ambiguous request poisons this instance. Never replay it on a
	// fresh Machine; the next explicit request may create another instance.
	defer func() {
		if err == nil || r.machine == "" {
			return
		}
		cleanup, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if cleanupErr := api(cleanup, "DELETE", "/machines/"+r.machine+"?force=true", nil, nil); cleanupErr != nil {
			slog.Warn("sandbox Machine cleanup failed; inspect the runner app", "app", s.App, "machine", r.machine)
		}
		r.machine = ""
	}()
	var app struct{ Network string }
	if err := api(ctx, "GET", "", nil, &app); err != nil {
		return sandbox.Response{}, err
	}
	if app.Network == "" || app.Network == "default" {
		return sandbox.Response{}, errors.New("sandbox app must use a dedicated custom private network, not the default network")
	}
	request.ID = strings.ToLower(rand.Text())
	raw, err := json.Marshal(request)
	if err != nil || len(raw) > sandbox.RequestLimit {
		return sandbox.Response{}, errors.New("invalid or oversized sandbox request")
	}
	if r.machine != "" {
		var machine struct{ State string }
		err := api(ctx, "GET", "/machines/"+r.machine, nil, &machine)
		if errors.Is(err, notFound) {
			r.machine = ""
		} else if err != nil {
			return sandbox.Response{}, err
		} else if machine.State != "started" || time.Since(r.lastDispatch) >= sandbox.IdleTimeout-time.Minute {
			// Retire conservatively before the guest's idle deadline to avoid
			// submitting into an instance that is already exiting.
			if err := api(ctx, "DELETE", "/machines/"+r.machine+"?force=true", nil, nil); err != nil {
				return sandbox.Response{}, err
			}
			r.machine = ""
		}
	}
	if r.machine == "" {
		definition, err := json.Marshal(s.Server)
		if err != nil {
			return sandbox.Response{}, errors.New("encode sandbox definition")
		}
		memory := s.MemoryMB
		if memory == 0 {
			memory = 512
		}
		create := map[string]any{
			"name": "mcp-" + strings.ToLower(rand.Text()), "region": s.Region,
			"config": map[string]any{
				"image": s.Image, "auto_destroy": true,
				"restart":   map[string]any{"policy": "no"},
				"guest":     map[string]any{"cpu_kind": "shared", "cpus": 1, "memory_mb": memory},
				"processes": []any{map[string]any{"exec": []string{"/usr/local/bin/mcp-sandbox"}, "ignore_app_secrets": true}},
				"files":     []any{map[string]any{"guest_path": sandbox.ConfigPath, "raw_value": base64.StdEncoding.EncodeToString(definition)}},
			},
		}
		var machine struct{ ID string }
		if err := api(ctx, "POST", "/machines", create, &machine); err != nil {
			return sandbox.Response{}, err
		}
		if machine.ID == "" || strings.Trim(machine.ID, "0123456789abcdef") != "" {
			return sandbox.Response{}, errors.New("Fly returned an invalid Machine ID")
		}
		r.machine = machine.ID
		path := "/machines/" + machine.ID
		for {
			err := api(ctx, "GET", path+"/wait?state=started&timeout=30", nil, nil)
			if err == nil {
				break
			}
			// Only a read-only readiness timeout can repeat, for the same Machine.
			// Creation and execution remain outside this loop and are never retried.
			if !errors.Is(err, requestTimeout) {
				return sandbox.Response{}, err
			}
			select {
			case <-ctx.Done():
				return sandbox.Response{}, ctx.Err()
			case <-time.After(250 * time.Millisecond):
			}
		}
	}
	path := "/machines/" + r.machine
	// The payload is base64, never shell source. Publish atomically in the
	// root-only mailbox, exactly once; subsequent exec calls only read results.
	r.lastDispatch = time.Now()
	var submitted struct {
		ExitCode int `json:"exit_code"`
	}
	if err := api(ctx, "POST", path+"/exec", map[string]any{
		"command": []string{"/bin/sh", "-c", "umask 077; printf '%s' '" + base64.StdEncoding.EncodeToString(raw) + "' | base64 -d > " + sandbox.RequestPath + ".tmp && mv " + sandbox.RequestPath + ".tmp " + sandbox.RequestPath}, "timeout": 5,
	}, &submitted); err != nil {
		return sandbox.Response{}, err
	}
	if submitted.ExitCode != 0 {
		return sandbox.Response{}, errors.New("sandbox request submission failed")
	}
	for {
		var result struct {
			ExitCode int    `json:"exit_code"`
			Stdout   string `json:"stdout"`
		}
		if err := api(ctx, "POST", path+"/exec", map[string]any{
			"command": []string{"/bin/sh", "-c", "test -f " + sandbox.ResultPath + " && cat " + sandbox.ResultPath}, "timeout": 5,
		}, &result); err != nil {
			return sandbox.Response{}, err
		}
		if result.ExitCode == 0 {
			var response sandbox.Response
			if len(result.Stdout) > sandbox.ResultLimit || json.Unmarshal([]byte(result.Stdout), &response) != nil {
				return sandbox.Response{}, errors.New("invalid or oversized sandbox result")
			}
			if response.ID != request.ID {
				// A previous response can remain until the new request completes.
			} else if response.Error != "" {
				return sandbox.Response{}, errors.New("sandbox could not install, initialize or execute the MCP server")
			} else if request.Tool != "" && response.Result == nil {
				return sandbox.Response{}, errors.New("sandbox returned no tool result")
			} else {
				return response, nil
			}
		}
		if result.ExitCode != 0 && result.ExitCode != 1 {
			return sandbox.Response{}, errors.New("sandbox result collection failed")
		}
		select {
		case <-ctx.Done():
			return sandbox.Response{}, ctx.Err()
		case <-time.After(time.Second):
		}
	}
}
