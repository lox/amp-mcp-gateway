package fly

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"ampcode.com/lox/amp-mcp-gateway/internal/sandbox"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestSandbox(t *testing.T) {
	for _, mode := range []string{"discover", "call", "tool-error", "pending", "cold-start", "boot-cancel", "boot-deadline", "boot-failed", "default-network", "create-ambiguous", "create-timeout", "exec-ambiguous", "exec-timeout", "cancel", "cleanup-failure", "runner-error", "oversized"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("SANDBOX_FLY_TOKEN", "management-secret-canary")
			s := Sandbox{App: "sandbox-test", Image: "runner@sha256:" + strings.Repeat("a1", 32), TokenEnv: "SANDBOX_FLY_TOKEN", Region: "syd", Server: sandbox.Server{Repository: "https://github.com/example/server", InstallCmd: "npm ci", RunCmd: "node index.js"}}
			req := sandbox.Request{}
			if mode != "discover" && mode != "pending" {
				req.Tool, req.Arguments = "sum", map[string]any{"a": 19, "b": -7}
			}
			created, waited, submitted, collected, destroyed := 0, 0, 0, 0, 0
			var guestRequest sandbox.Request
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if mode == "boot-deadline" {
				var deadlineCancel context.CancelFunc
				ctx, deadlineCancel = context.WithTimeout(ctx, 100*time.Millisecond)
				defer deadlineCancel()
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer management-secret-canary" {
					t.Error("missing management authentication")
				}
				switch r.Method + " " + r.URL.Path {
				case "GET /apps/sandbox-test":
					network := "isolated-installation"
					if mode == "default-network" {
						network = "default"
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"network": network})
				case "POST /apps/sandbox-test/machines":
					created++
					var create struct {
						Region string
						Config struct {
							Image       string
							AutoDestroy bool `json:"auto_destroy"`
							Restart     struct{ Policy string }
							Guest       struct {
								CPUs     int
								MemoryMB int `json:"memory_mb"`
							}
							Processes []struct {
								Exec             []string
								IgnoreAppSecrets bool `json:"ignore_app_secrets"`
							}
							Files []struct {
								GuestPath string `json:"guest_path"`
								RawValue  string `json:"raw_value"`
							}
							Env, Services, Mounts any
						}
					}
					if err := json.NewDecoder(r.Body).Decode(&create); err != nil {
						t.Error(err)
					}
					c := create.Config
					if create.Region != "syd" || c.Image != s.Image || !c.AutoDestroy || c.Restart.Policy != "no" || c.Guest.CPUs != 1 || c.Guest.MemoryMB != 512 || len(c.Processes) != 1 || !c.Processes[0].IgnoreAppSecrets || c.Processes[0].Exec[0] != "/usr/local/bin/mcp-sandbox" || c.Env != nil || c.Services != nil || c.Mounts != nil {
						t.Errorf("unsafe Machine configuration: %+v", create)
					}
					if len(c.Files) != 1 || c.Files[0].GuestPath != sandbox.ConfigPath {
						t.Error("missing guest definition")
						http.Error(w, "invalid request", 400)
						return
					}
					data, err := base64.StdEncoding.DecodeString(c.Files[0].RawValue)
					var guest sandbox.Server
					if err != nil || json.Unmarshal(data, &guest) != nil || guest != s.Server || strings.Contains(string(data), "management-secret-canary") {
						t.Errorf("incorrect or secret-bearing guest definition: %s", data)
					}
					if mode == "create-ambiguous" {
						http.Error(w, "management-secret-canary", 502)
						return
					}
					if mode == "create-timeout" {
						http.Error(w, "management-secret-canary", http.StatusRequestTimeout)
						return
					}
					fmt.Fprint(w, `{"id":"abc123"}`)
				case "GET /apps/sandbox-test/machines/abc123/wait":
					waited++
					if mode == "cold-start" && waited < 3 || mode == "boot-cancel" && waited == 1 || mode == "boot-deadline" {
						http.Error(w, "management-secret-canary", http.StatusRequestTimeout)
						return
					}
					if mode == "boot-cancel" {
						cancel()
						<-r.Context().Done()
						return
					}
					if mode == "boot-failed" {
						http.Error(w, "management-secret-canary", http.StatusForbidden)
						return
					}
					fmt.Fprint(w, `{}`)
				case "POST /apps/sandbox-test/machines/abc123/exec":
					var read struct{ Command []string }
					if json.NewDecoder(r.Body).Decode(&read) != nil || len(read.Command) != 3 {
						t.Error("invalid exec command")
						return
					}
					if encoded, ok := strings.CutPrefix(read.Command[2], "umask 077; printf '%s' '"); ok {
						submitted++
						encoded, _, _ = strings.Cut(encoded, "'")
						raw, err := base64.StdEncoding.DecodeString(encoded)
						if err != nil || json.Unmarshal(raw, &guestRequest) != nil || guestRequest.ID == "" || guestRequest.Tool != req.Tool || strings.Contains(string(raw), "management-secret-canary") {
							t.Error("invalid submitted request")
						}
						if req.Tool != "" && (guestRequest.Arguments["a"] != float64(19) || guestRequest.Arguments["b"] != float64(-7)) {
							t.Errorf("lost tool arguments: %+v", guestRequest.Arguments)
						}
						if mode == "exec-ambiguous" || mode == "exec-timeout" {
							status := 502
							if mode == "exec-timeout" {
								status = http.StatusRequestTimeout
							}
							http.Error(w, "management-secret-canary", status)
							return
						}
						fmt.Fprint(w, `{"exit_code":0}`)
						return
					}
					collected++
					if read.Command[2] != "test -f "+sandbox.ResultPath+" && cat "+sandbox.ResultPath {
						t.Error("polling must only read results")
					}
					if mode == "cancel" {
						cancel()
						<-r.Context().Done()
						return
					}
					if mode == "pending" && collected == 1 {
						fmt.Fprint(w, `{"exit_code":1}`)
						return
					}
					response := sandbox.Response{ID: guestRequest.ID, Tools: []*mcp.Tool{{Name: "sum", InputSchema: map[string]any{"type": "object"}}}}
					if req.Tool != "" {
						response = sandbox.Response{ID: guestRequest.ID, Result: &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "12"}}, IsError: mode == "tool-error"}}
					}
					if mode == "runner-error" || mode == "cleanup-failure" {
						response = sandbox.Response{ID: guestRequest.ID, Error: "management-secret-canary"}
					}
					out, _ := json.Marshal(response)
					if mode == "oversized" {
						out = []byte(strings.Repeat("x", sandbox.ResultLimit+1))
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"exit_code": 0, "stdout": string(out)})
				case "DELETE /apps/sandbox-test/machines/abc123":
					destroyed++
					if r.URL.Query().Get("force") != "true" || r.Context().Err() != nil {
						t.Error("cleanup must force destruction with an independent context")
					}
					if mode == "cleanup-failure" {
						http.Error(w, "management-secret-canary", 503)
					}
				default:
					t.Errorf("unexpected API request: %s %s", r.Method, r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			response, err := NewRunner(s).run(ctx, server.URL, server.Client(), req)
			wantError := mode == "default-network" || mode == "create-ambiguous" || mode == "create-timeout" || mode == "exec-ambiguous" || mode == "exec-timeout" || mode == "cancel" || mode == "boot-cancel" || mode == "boot-deadline" || mode == "boot-failed" || mode == "runner-error" || mode == "cleanup-failure" || mode == "oversized"
			if (err != nil) != wantError {
				t.Fatalf("error=%v, wantError=%t", err, wantError)
			}
			if err != nil && strings.Contains(err.Error(), "canary") {
				t.Fatal("error leaked provider text")
			}
			if !wantError {
				if req.Tool == "" && (len(response.Tools) != 1 || response.Tools[0].Name != "sum") {
					t.Fatal("discovery result lost")
				}
				if req.Tool != "" && (response.Result == nil || response.Result.Content[0].(*mcp.TextContent).Text != "12" || response.Result.IsError != (mode == "tool-error")) {
					t.Fatal("tool result lost")
				}
			}
			if mode == "default-network" {
				if created != 0 {
					t.Fatal("created Machine on the default network")
				}
			} else if created != 1 {
				t.Fatalf("created %d Machines; must never retry creation", created)
			}
			wantDestroyed := 0
			if wantError && mode != "default-network" && mode != "create-ambiguous" && mode != "create-timeout" {
				wantDestroyed = 1
			}
			if destroyed != wantDestroyed {
				t.Fatalf("destroyed %d Machines, want %d", destroyed, wantDestroyed)
			}
			if (mode == "exec-ambiguous" || mode == "exec-timeout") && (submitted != 1 || collected != 0) {
				t.Fatal("retried ambiguous execution")
			}
			if mode == "cold-start" && (waited != 3 || collected != 1) {
				t.Fatalf("cold start must wait for the same Machine then collect once: waited=%d collected=%d", waited, collected)
			}
			if mode == "boot-cancel" && (waited != 2 || collected != 0) || mode == "boot-failed" && (waited != 1 || collected != 0) {
				t.Fatalf("boot failure must stop waiting without collecting: waited=%d collected=%d", waited, collected)
			}
			if mode == "boot-deadline" && (!errors.Is(err, context.DeadlineExceeded) || collected != 0) {
				t.Fatalf("readiness waits exceeded caller deadline: err=%v collected=%d", err, collected)
			}
		})
	}
}

func TestRunnerReuseAndRecovery(t *testing.T) {
	t.Setenv("SANDBOX_FLY_TOKEN", "fake-management-token")
	s := Sandbox{App: "sandbox-test", Image: "runner@sha256:" + strings.Repeat("a1", 32), TokenEnv: "SANDBOX_FLY_TOKEN", Server: sandbox.Server{Repository: "https://github.com/example/server", RunCmd: "node index.js"}}
	var mu sync.Mutex
	created, submissions, destroyed := 0, 0, 0
	var result, previous sandbox.Response
	expired, ambiguous, stale := false, false, false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/wait"):
			fmt.Fprint(w, `{}`)
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/machines/"):
			if expired {
				expired = false
				http.NotFound(w, r)
			} else {
				fmt.Fprint(w, `{"state":"started"}`)
			}
		case r.Method == "GET":
			fmt.Fprint(w, `{"network":"isolated"}`)
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/machines"):
			created++
			fmt.Fprintf(w, `{"id":"%x"}`, created)
		case r.Method == "DELETE":
			destroyed++
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/exec"):
			var exec struct{ Command []string }
			if json.NewDecoder(r.Body).Decode(&exec) != nil || len(exec.Command) != 3 {
				t.Error("invalid exec")
				return
			}
			if encoded, ok := strings.CutPrefix(exec.Command[2], "umask 077; printf '%s' '"); ok {
				submissions++
				encoded, _, _ = strings.Cut(encoded, "'")
				raw, err := base64.StdEncoding.DecodeString(encoded)
				var req sandbox.Request
				if err != nil || json.Unmarshal(raw, &req) != nil || req.ID == result.ID {
					t.Error("request ID or payload was reused")
				}
				previous, result = result, sandbox.Response{ID: req.ID, Result: &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: req.Arguments["text"].(string)}}}}
				if ambiguous {
					ambiguous = false
					http.Error(w, "lost submission acknowledgement", 502)
					return
				}
				fmt.Fprint(w, `{"exit_code":0}`)
			} else {
				response := result
				if stale {
					response, stale = previous, false
				}
				raw, _ := json.Marshal(response)
				_ = json.NewEncoder(w).Encode(map[string]any{"exit_code": 0, "stdout": string(raw)})
			}
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()
	runner := NewRunner(s)
	call := func(runner *Runner, text string, wantError bool) {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		defer cancel()
		response, err := runner.run(ctx, server.URL, server.Client(), sandbox.Request{Tool: "echo", Arguments: map[string]any{"text": text}})
		if (err != nil) != wantError || err == nil && (response.Result == nil || response.Result.Content[0].(*mcp.TextContent).Text != text) {
			t.Errorf("call %q: response=%+v error=%v", text, response, err)
		}
	}
	var calls sync.WaitGroup
	for _, text := range []string{"first", "second 'quoted'\n; $(false)"} {
		calls.Go(func() { call(runner, text, false) })
	}
	calls.Wait()
	if created != 1 || submissions != 2 || destroyed != 0 {
		t.Fatalf("concurrent calls did not share one serialized Machine: %d %d %d", created, submissions, destroyed)
	}
	stale = true
	call(runner, "third", false)
	if created != 1 || submissions != 3 {
		t.Fatal("stale result caused recreation or resubmission")
	}
	expired = true
	call(runner, "after idle", false)
	if created != 2 {
		t.Fatal("expired Machine was not replaced")
	}
	ambiguous = true
	call(runner, "ambiguous write", true)
	if created != 2 || submissions != 5 || destroyed != 1 {
		t.Fatal("ambiguous write was retried or Machine was retained")
	}
	call(runner, "new explicit call", false)
	if created != 3 {
		t.Fatal("failed Machine was reused")
	}
	call(NewRunner(s), "another owner/connection", false)
	if created != 4 {
		t.Fatal("separate runners shared a Machine")
	}
}

func TestSandboxConfiguration(t *testing.T) {
	t.Setenv("FLY_APP_NAME", "gateway")
	t.Setenv("FLY_SANDBOX_TOKEN", "")
	valid := Sandbox{App: "separate", Image: "runner@sha256:" + strings.Repeat("a1", 32), TokenEnv: "FLY_SANDBOX_TOKEN", Server: sandbox.Server{Repository: "https://github.com/example/server", RunCmd: "node index.js"}}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, edit := range []func(*Sandbox){
		func(s *Sandbox) { s.App = "gateway" },
		func(s *Sandbox) { s.App = "../other" },
		func(s *Sandbox) { s.Repository = "https://token@github.com/example/server" },
		func(s *Sandbox) { s.Repository = "https://github.com/example/server?token=secret" },
		func(s *Sandbox) { s.Repository = "http://github.com/example/server" },
		func(s *Sandbox) { s.Repository = "https://attacker.example/server" },
		func(s *Sandbox) { s.Revision = "--help" },
		func(s *Sandbox) { s.MemoryMB = 4096 },
		func(s *Sandbox) { s.Image = "runner:latest" },
		func(s *Sandbox) { s.Image = "runner" },
		func(s *Sandbox) { s.Image = "runner@sha256:" + strings.Repeat("a", 63) },
		func(s *Sandbox) { s.Image = "runner@sha256:" + strings.Repeat("g", 64) },
		func(s *Sandbox) { s.Image = "@sha256:" + strings.Repeat("a", 64) },
	} {
		s := valid
		edit(&s)
		if s.Validate() == nil {
			t.Fatalf("accepted invalid configuration: %+v", s)
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if _, err := NewRunner(valid).Run(ctx, sandbox.Request{}); err == nil {
		t.Fatal("accepted missing Fly token")
	}
}
