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
	if mode == "protected" || mode == "warm" {
		for _, name := range []string{"server.json", "request.json", "result.json"} {
			path := filepath.Join(os.Args[5], name)
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
				if mode != "warm" && (calls != 1 || pages != 0) {
					os.Exit(24)
				}
				if mode == "error" {
					return nil, fmt.Errorf("SANDBOX_SECRET arbitrary provider error")
				}
				text := "once"
				if mode == "warm" {
					text = strconv.Itoa(calls)
				}
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
			definition := Server{Repository: httpRepo.URL, Revision: revision, InstallCmd: "test \"$(id -u)\" = 1000 && test -z \"$SANDBOX_SECRET\" && touch installed", RunCmd: fmt.Sprintf("exec ./child -test.run=TestSandboxChild sandbox-child %s %d", tc.mode, os.Getpid())}
			send, _, _ := runnerFixture(t, t.Context(), definition, time.Second)
			response := send(Request{Tool: tc.tool})
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
		send, _, _ := runnerFixture(t, t.Context(), Server{Repository: httpRepo.URL, Revision: "--help", RunCmd: "true"}, time.Second)
		response := send(Request{})
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
			send, _, _ := runnerFixture(t, ctx, server, time.Second)
			response := send(Request{})
			if response.Error == "" || time.Since(start) > 2*time.Second {
				t.Fatal("execution did not respect timeout")
			}
		})
	}
	t.Run("warm session and idle expiry", func(t *testing.T) {
		definition := Server{Repository: httpRepo.URL, InstallCmd: "touch installed", RunCmd: fmt.Sprintf("exec ./child -test.run=TestSandboxChild sandbox-child warm %d", os.Getpid())}
		send, done, directory := runnerFixture(t, t.Context(), definition, 600*time.Millisecond)
		if response := send(Request{}); response.Error != "" || len(response.Tools) != 1 {
			t.Fatalf("discovery failed: %+v", response)
		}
		for _, want := range []string{"1", "2"} {
			time.Sleep(350 * time.Millisecond)
			response := send(Request{Tool: "tool0"})
			if response.Error != "" || response.Result == nil || response.Result.Content[0].(*mcp.TextContent).Text != want {
				t.Fatalf("stdio process/session was not reused: %+v", response)
			}
		}
		info, err := os.Stat(filepath.Join(directory, "result.json"))
		if err != nil || info.Mode().Perm() != 0600 || info.Sys().(*syscall.Stat_t).Uid != 0 {
			t.Fatalf("result is not root-only: %v %v", info, err)
		}
		select {
		case <-done:
			t.Fatal("expired before the idle deadline")
		case <-time.After(400 * time.Millisecond):
		}
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("runner did not expire while idle without gateway assistance")
		}
	})
}

// runnerFixture drives the actual root-only mailbox and persistent SDK process.
func runnerFixture(t *testing.T, parent context.Context, definition Server, idle time.Duration) (func(Request) Response, <-chan struct{}, string) {
	t.Helper()
	directory := t.TempDir()
	if strings.Contains(definition.RunCmd, "TestSandboxChild") {
		definition.RunCmd += " " + strconv.Quote(directory)
	}
	raw, err := json.Marshal(definition)
	if err != nil || os.WriteFile(filepath.Join(directory, "server.json"), raw, 0600) != nil {
		t.Fatal("could not write runner definition")
	}
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	go func() { defer close(done); Run(ctx, directory, idle) }()
	t.Cleanup(func() { cancel(); <-done })
	sequence := 0
	return func(req Request) Response {
		t.Helper()
		sequence++
		req.ID = strconv.Itoa(sequence)
		raw, err := json.Marshal(req)
		path := filepath.Join(directory, "request.json")
		if err != nil || os.WriteFile(path+".tmp", raw, 0600) != nil || os.Rename(path+".tmp", path) != nil {
			t.Fatal("could not submit runner request")
		}
		deadline := time.NewTimer(5 * time.Second)
		defer deadline.Stop()
		tick := time.NewTicker(5 * time.Millisecond)
		defer tick.Stop()
		for {
			var response Response
			raw, err := os.ReadFile(filepath.Join(directory, "result.json"))
			if err == nil && json.Unmarshal(raw, &response) == nil && response.ID == req.ID {
				return response
			}
			select {
			case <-done:
				return Response{Error: "runner exited"}
			case <-deadline.C:
				t.Fatal("runner did not return a result")
			case <-tick.C:
			}
		}
	}, done, directory
}
