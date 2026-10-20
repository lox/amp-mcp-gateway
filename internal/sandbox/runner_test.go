package sandbox

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// This is a real stdio SDK server, executed from a freshly cloned repository.
func TestSandboxChild(t *testing.T) {
	if len(os.Args) < 5 || os.Args[2] != "sandbox-child" {
		return
	}
	mode := os.Args[3]
	parent, _ := strconv.Atoi(os.Args[4])
	if os.Getuid() != 1000 || os.Getgid() != 1000 || len(mustGroups()) != 0 || os.Getenv("SANDBOX_SECRET") != "" || syscall.Kill(parent, 0) != syscall.EPERM {
		os.Exit(20)
	}
	for _, key := range []string{"HOME", "TMPDIR"} {
		if err := os.WriteFile(filepath.Join(os.Getenv(key), "writable"), []byte("ok"), 0600); err != nil {
			os.Exit(21)
		}
	}
	if _, err := os.Stat("installed"); err != nil {
		os.Exit(22)
	}
	if mode == "protected" {
		for _, path := range []string{RequestPath, ResultPath} {
			if os.WriteFile(path, []byte("tampered"), 0600) == nil || os.Remove(path) == nil {
				os.Exit(26)
			}
		}
	}
	server := mcp.NewServer(&mcp.Implementation{Name: "fixture", Version: "1"}, nil)
	calls, pages := 0, 0
	server.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			switch method {
			case "tools/list":
				pages++
				n, description, cursor := 1, "", ""
				switch mode {
				case "500":
					n = 500
				case "501":
					n = 501
				case "big":
					description = strings.Repeat("x", 2<<20)
				case "cycle":
					cursor = "same"
				case "pages":
					cursor = strconv.Itoa(pages)
				case "cursor-size":
					cursor = strings.Repeat("x", 2<<20)
				case "paged":
					if pages == 1 {
						cursor = "opaque雪"
					} else if req.GetParams().(*mcp.ListToolsParams).Cursor != "opaque雪" {
						os.Exit(23)
					}
				}
				tools := make([]*mcp.Tool, n)
				for i := range tools {
					tools[i] = &mcp.Tool{Name: fmt.Sprintf("tool%d", i), Description: description, InputSchema: map[string]any{"type": "object"}}
				}
				return &mcp.ListToolsResult{Tools: tools, NextCursor: cursor}, nil
			case "tools/call":
				calls++
				if calls != 1 || pages != 0 {
					os.Exit(24)
				}
				if mode == "error" {
					return nil, fmt.Errorf("SANDBOX_SECRET arbitrary provider error")
				}
				text := "once"
				if mode == "result-big" {
					text = strings.Repeat("x", ResultLimit)
				}
				return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, nil
			}
			return next(ctx, method, req)
		}
	})
	_ = server.Run(context.Background(), &mcp.StdioTransport{})
	os.Exit(0)
}

func mustGroups() []int {
	groups, err := os.Getgroups()
	if err != nil {
		os.Exit(25)
	}
	return groups
}

func TestExecute(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("credential isolation requires root; run the compiled test binary with sudo")
	}
	t.Setenv("SANDBOX_SECRET", "must-not-be-inherited")
	repo := t.TempDir()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "child"), data, 0755); err != nil {
		t.Fatal(err)
	}
	git := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("/usr/bin/git", args...)
		cmd.Dir = repo
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("fixture git: %v: %s", err, out)
		}
		return strings.TrimSpace(string(out))
	}
	git("init")
	git("add", "child")
	git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-m", "fixture")
	revision := git("rev-parse", "HEAD")
	git("update-server-info")
	httpRepo := httptest.NewServer(http.FileServer(http.Dir(filepath.Join(repo, ".git"))))
	defer httpRepo.Close()
	for _, tc := range []struct {
		mode      string
		tool      string
		wantTools int
		wantError bool
	}{
		{"normal", "", 1, false}, {"paged", "", 2, false}, {"500", "", 500, false},
		{"501", "", 0, true}, {"big", "", 0, true}, {"cycle", "", 0, true},
		{"pages", "", 0, true}, {"cursor-size", "", 0, true},
		{"normal", "tool0", 0, false}, {"error", "tool0", 0, true}, {"result-big", "tool0", 0, true},
	} {
		t.Run(tc.mode+"/"+tc.tool, func(t *testing.T) {
			req := Request{Server: Server{Repository: httpRepo.URL, Revision: revision, InstallCmd: "test \"$(id -u)\" = 1000 && test -z \"$SANDBOX_SECRET\" && touch installed", RunCmd: fmt.Sprintf("exec ./child -test.run=TestSandboxChild sandbox-child %s %d", tc.mode, os.Getpid())}, Tool: tc.tool}
			response := Execute(t.Context(), req)
			if (response.Error != "") != tc.wantError || len(response.Tools) != tc.wantTools {
				t.Fatalf("tools=%d error=%q", len(response.Tools), response.Error)
			}
			if tc.wantError && response.Error != "sandbox execution failed" {
				t.Fatalf("non-fixed error: %q", response.Error)
			}
			if !tc.wantError && tc.tool != "" && (response.Result == nil || response.Result.Content[0].(*mcp.TextContent).Text != "once") {
				t.Fatalf("wrong tool result: %+v", response)
			}
		})
	}
	t.Run("option injection", func(t *testing.T) {
		response := Execute(t.Context(), Request{Server: Server{Repository: httpRepo.URL, Revision: "--help", RunCmd: "true"}})
		if response.Error == "" {
			t.Fatal("accepted option as revision")
		}
	})
	for _, install := range []bool{false, true} {
		t.Run(fmt.Sprintf("hang/install=%t", install), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			start := time.Now()
			server := Server{Repository: httpRepo.URL, RunCmd: "sleep 60"}
			if install {
				server.InstallCmd = "sleep 60"
			}
			response := Execute(ctx, Request{Server: server})
			if response.Error == "" || time.Since(start) > 2*time.Second {
				t.Fatal("execution did not respect timeout")
			}
		})
	}
	t.Run("root-only atomic result", func(t *testing.T) {
		for _, path := range []string{RequestPath, ResultPath} {
			if _, err := os.Lstat(path); !os.IsNotExist(err) {
				t.Skip("reserved runner paths already in use")
			}
		}
		req := Request{Server: Server{Repository: httpRepo.URL, InstallCmd: "touch installed", RunCmd: fmt.Sprintf("exec ./child -test.run=TestSandboxChild sandbox-child protected %d", os.Getpid())}}
		raw, err := json.Marshal(req)
		if err != nil {
			t.Fatal(err)
		}
		for path, content := range map[string][]byte{RequestPath: raw, ResultPath: []byte("old result")} {
			if err := os.WriteFile(path, content, 0600); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Remove(path) })
		}
		Run(t.Context())
		info, err := os.Stat(ResultPath)
		if err != nil || info.Mode().Perm() != 0600 || info.Sys().(*syscall.Stat_t).Uid != 0 {
			t.Fatalf("result is not root-only: %v %v", info, err)
		}
		result, err := os.ReadFile(ResultPath)
		if err != nil {
			t.Fatal(err)
		}
		var response Response
		if err := json.Unmarshal(result, &response); err != nil || response.Error != "" || len(response.Tools) != 1 {
			t.Fatalf("invalid result: %s (%v)", result, err)
		}
	})
}
