package fly

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ampcode.com/lox/amp-mcp-gateway/internal/sandbox"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestSandbox(t *testing.T) {
	for _, mode := range []string{"discover", "call", "tool-error", "pending", "default-network", "create-ambiguous", "exec-ambiguous", "cancel", "cleanup-failure", "runner-error", "oversized"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("SANDBOX_FLY_TOKEN", "management-secret-canary")
			s := Sandbox{App: "sandbox-test", Image: "runner@sha256:fixture", TokenEnv: "SANDBOX_FLY_TOKEN", Region: "syd", Server: sandbox.Server{Repository: "https://github.com/example/server", InstallCmd: "npm ci", RunCmd: "node index.js"}}
			req := sandbox.Request{}
			if mode != "discover" && mode != "pending" {
				req.Tool, req.Arguments = "sum", map[string]any{"a": 19, "b": -7}
			}
			created, collected, destroyed := 0, 0, 0
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
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
					if len(c.Files) != 1 || c.Files[0].GuestPath != sandbox.RequestPath {
						t.Error("missing guest request")
						http.Error(w, "invalid request", 400)
						return
					}
					data, err := base64.StdEncoding.DecodeString(c.Files[0].RawValue)
					var guest sandbox.Request
					if err != nil || json.Unmarshal(data, &guest) != nil || guest.Server != s.Server || guest.Tool != req.Tool || strings.Contains(string(data), "management-secret-canary") {
						t.Errorf("incorrect or secret-bearing guest request: %s", data)
					}
					if req.Tool != "" && (guest.Arguments["a"] != float64(19) || guest.Arguments["b"] != float64(-7)) {
						t.Errorf("lost tool arguments: %+v", guest.Arguments)
					}
					if mode == "create-ambiguous" {
						http.Error(w, "management-secret-canary", 502)
						return
					}
					fmt.Fprint(w, `{"id":"abc123"}`)
				case "GET /apps/sandbox-test/machines/abc123/wait":
					fmt.Fprint(w, `{}`)
				case "POST /apps/sandbox-test/machines/abc123/exec":
					collected++
					var read struct{ Command []string }
					if json.NewDecoder(r.Body).Decode(&read) != nil || len(read.Command) != 3 || read.Command[2] != "test -f "+sandbox.ResultPath+" && cat "+sandbox.ResultPath {
						t.Error("exec must only read the result, never re-execute the tool")
					}
					if mode == "exec-ambiguous" {
						http.Error(w, "management-secret-canary", 502)
						return
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
					response := sandbox.Response{Tools: []*mcp.Tool{{Name: "sum", InputSchema: map[string]any{"type": "object"}}}}
					if req.Tool != "" {
						response = sandbox.Response{Result: &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "12"}}, IsError: mode == "tool-error"}}
					}
					if mode == "runner-error" {
						response = sandbox.Response{Error: "management-secret-canary"}
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
			response, err := s.run(ctx, server.URL, server.Client(), req)
			wantError := mode == "default-network" || mode == "create-ambiguous" || mode == "exec-ambiguous" || mode == "cancel" || mode == "runner-error" || mode == "oversized"
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
			if mode != "default-network" && mode != "create-ambiguous" && destroyed != 1 {
				t.Fatalf("destroyed %d Machines, want 1", destroyed)
			}
			if mode == "exec-ambiguous" && collected != 1 {
				t.Fatal("retried ambiguous execution")
			}
		})
	}
}

func TestSandboxConfiguration(t *testing.T) {
	t.Setenv("FLY_APP_NAME", "gateway")
	t.Setenv("FLY_SANDBOX_TOKEN", "")
	valid := Sandbox{App: "separate", Image: "runner", TokenEnv: "FLY_SANDBOX_TOKEN", Server: sandbox.Server{Repository: "https://github.com/example/server", RunCmd: "node index.js"}}
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
	} {
		s := valid
		edit(&s)
		if s.Validate() == nil {
			t.Fatalf("accepted invalid configuration: %+v", s)
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if _, err := valid.Run(ctx, sandbox.Request{}); err == nil {
		t.Fatal("accepted missing Fly token")
	}
}
