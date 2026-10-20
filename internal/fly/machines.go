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

// Sandbox runs a public GitHub stdio server in a fresh Fly Machine per request.
// The app must be dedicated to this installation on its own custom private network.
type Sandbox struct {
	App, Image, TokenEnv, Region string
	MemoryMB                     int `json:",omitempty"`
	sandbox.Server
}

var appName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
var githubPath = regexp.MustCompile(`^/[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$`)

// Validate checks configuration without contacting Fly or running untrusted code.
func (s Sandbox) Validate() error {
	u, err := url.Parse(s.Repository)
	if err != nil || u.Scheme != "https" || u.Host != "github.com" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !githubPath.MatchString(u.Path) {
		return errors.New("sandbox Repository must be a public https://github.com/owner/repository URL")
	}
	if !appName.MatchString(s.App) || s.App == os.Getenv("FLY_APP_NAME") || s.Image == "" || s.TokenEnv == "" || strings.TrimSpace(s.RunCmd) == "" || strings.HasPrefix(s.Revision, "-") {
		return errors.New("sandbox requires a separate Fly App, Image, TokenEnv and RunCmd, and a revision without a leading dash")
	}
	if s.MemoryMB != 0 && (s.MemoryMB < 256 || s.MemoryMB > 2048 || s.MemoryMB%256 != 0) {
		return errors.New("sandbox MemoryMB must be a multiple of 256 between 256 and 2048")
	}
	return nil
}

// Run starts exactly one Machine and collects its root-owned result using read-only
// exec requests. Machine creation and MCP execution are never retried.
func (s Sandbox) Run(ctx context.Context, request sandbox.Request) (sandbox.Response, error) {
	// Leave headroom for the readiness endpoint's 30-second server-side wait.
	return s.run(ctx, "https://api.machines.dev/v1", &http.Client{Timeout: 40 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, request)
}

func (s Sandbox) run(ctx context.Context, endpoint string, client *http.Client, request sandbox.Request) (sandbox.Response, error) {
	ctx, cancel := context.WithTimeout(ctx, SandboxTimeout)
	defer cancel()
	token := os.Getenv(s.TokenEnv)
	if token == "" {
		return sandbox.Response{}, errors.New("sandbox Fly token is unavailable")
	}
	requestTimeout := errors.New("Fly API returned HTTP 408")
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
	var app struct{ Network string }
	if err := api(ctx, "GET", "", nil, &app); err != nil {
		return sandbox.Response{}, err
	}
	if app.Network == "" || app.Network == "default" {
		return sandbox.Response{}, errors.New("sandbox app must use a dedicated custom private network, not the default network")
	}
	request.Server = s.Server
	raw, err := json.Marshal(request)
	if err != nil || len(raw) > sandbox.ResultLimit {
		return sandbox.Response{}, errors.New("invalid or oversized sandbox request")
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
			"files":     []any{map[string]any{"guest_path": sandbox.RequestPath, "raw_value": base64.StdEncoding.EncodeToString(raw)}},
		},
	}
	var machine struct{ ID string }
	if err := api(ctx, "POST", "/machines", create, &machine); err != nil {
		return sandbox.Response{}, err
	}
	if machine.ID == "" || strings.Trim(machine.ID, "0123456789abcdef") != "" {
		return sandbox.Response{}, errors.New("Fly returned an invalid Machine ID")
	}
	path := "/machines/" + machine.ID
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := api(cleanup, "DELETE", path+"?force=true", nil, nil); err != nil {
			// Preserve a known tool outcome even when cleanup fails. The root
			// supervisor exits after five minutes and auto_destroy is enabled.
			slog.Warn("sandbox Machine cleanup failed; inspect the runner app", "app", s.App, "machine", machine.ID)
		}
	}()
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
			if response.Error != "" {
				return sandbox.Response{}, errors.New("sandbox could not install, initialize or execute the MCP server")
			}
			if request.Tool != "" && response.Result == nil {
				return sandbox.Response{}, errors.New("sandbox returned no tool result")
			}
			return response, nil
		}
		if result.ExitCode != 1 {
			return sandbox.Response{}, errors.New("sandbox result collection failed")
		}
		select {
		case <-ctx.Done():
			return sandbox.Response{}, ctx.Err()
		case <-time.After(time.Second):
		}
	}
}
