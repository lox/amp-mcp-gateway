package sandbox

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Execute clones and runs one disposable server. It must run as root on an
// otherwise disposable Linux Machine; all external commands run as uid/gid 1000.
// Errors deliberately contain no subprocess diagnostics or supplied values.
func Execute(ctx context.Context, req Request) Response {
	ctx, cancel := context.WithTimeout(ctx, ExecutionTimeout)
	defer cancel()
	done := make(chan Response, 1)
	go func() { done <- execute(ctx, req) }()
	select {
	case response := <-done:
		return response
	case <-ctx.Done():
		return Response{Error: "sandbox execution timed out"}
	}
}

func execute(ctx context.Context, req Request) Response {
	fail := func() Response { return Response{Error: "sandbox execution failed"} }
	u, err := url.Parse(req.Server.Repository)
	if os.Geteuid() != 0 || err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || req.Server.RunCmd == "" || strings.HasPrefix(req.Server.Revision, "-") {
		return fail()
	}
	base, err := os.MkdirTemp("", "mcp-sandbox-")
	if err != nil {
		return fail()
	}
	defer os.RemoveAll(base)
	if os.Chmod(base, 0711) != nil {
		return fail()
	}
	for _, name := range []string{"home", "tmp", "repo"} {
		p := filepath.Join(base, name)
		if os.Mkdir(p, 0700) != nil || os.Chown(p, 1000, 1000) != nil {
			return fail()
		}
	}
	command := func(name string, args ...string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, name, args...)
		cmd.Dir = filepath.Join(base, "repo")
		cmd.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=" + filepath.Join(base, "home"), "TMPDIR=" + filepath.Join(base, "tmp"), "GIT_TERMINAL_PROMPT=0", "GIT_CONFIG_NOSYSTEM=1"}
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 1000, Gid: 1000, NoSetGroups: false}, Setpgid: true}
		cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
		cmd.WaitDelay = time.Second
		return cmd
	}
	// Do not use a shell for git arguments; -- also fences off option injection.
	if command("/usr/bin/git", "clone", "--", req.Server.Repository, ".").Run() != nil {
		return fail()
	}
	if req.Server.Revision != "" && command("/usr/bin/git", "checkout", "--detach", req.Server.Revision, "--").Run() != nil {
		return fail()
	}
	if req.Server.InstallCmd != "" && command("/bin/sh", "-c", req.Server.InstallCmd).Run() != nil {
		return fail()
	}
	cmd := command("/bin/sh", "-c", req.Server.RunCmd)
	client := mcp.NewClient(&mcp.Implementation{Name: "mcp-sandbox", Version: "1"}, &mcp.ClientOptions{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	session, err := client.Connect(ctx, &mcp.CommandTransport{Command: cmd, TerminateDuration: 100 * time.Millisecond}, nil)
	// Kill the whole process group, including servers launched by a shell. Closing
	// the session is best effort and must never delay the response indefinitely.
	defer func() {
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		if session != nil {
			go func() { _ = session.Close() }()
		}
	}()
	if err != nil {
		return fail()
	}
	var response Response
	if req.Tool != "" {
		response.Result, err = session.CallTool(ctx, &mcp.CallToolParams{Name: req.Tool, Arguments: req.Arguments})
		if err != nil || response.Result == nil {
			return fail()
		}
	} else {
		cursor, size := "", 0
		seen := map[string]bool{}
		for {
			page, err := session.ListTools(ctx, &mcp.ListToolsParams{Cursor: cursor})
			if err != nil {
				return fail()
			}
			raw, err := json.Marshal(page.Tools)
			size += len(raw) + len(page.NextCursor)
			if err != nil || size > 2<<20 || len(response.Tools)+len(page.Tools) > 500 {
				return fail()
			}
			response.Tools = append(response.Tools, page.Tools...)
			if page.NextCursor == "" {
				break
			}
			cursor = page.NextCursor
			if seen[cursor] || len(seen) >= 50 {
				return fail()
			}
			seen[cursor] = true
		}
	}
	raw, err := json.Marshal(response)
	if err != nil || len(raw) > ResultLimit {
		return fail()
	}
	return response
}

// Run reads the root-provided request and atomically publishes a root-only result.
// The caller must impose MachineLifetime independently, even if Run hangs.
func Run(ctx context.Context) {
	response := Response{Error: "invalid sandbox request"}
	if f, err := os.Open(RequestPath); err == nil {
		info, statErr := f.Stat()
		raw, readErr := io.ReadAll(io.LimitReader(f, ResultLimit+1))
		_ = f.Close()
		var req Request
		if statErr == nil && info.Mode().IsRegular() && info.Sys().(*syscall.Stat_t).Uid == 0 && info.Mode().Perm()&0022 == 0 && readErr == nil && len(raw) <= ResultLimit && json.Unmarshal(raw, &req) == nil {
			response = Execute(ctx, req)
		}
	}
	raw, err := json.Marshal(response)
	if err != nil {
		return
	}
	f, err := os.CreateTemp(filepath.Dir(ResultPath), ".mcp-result-")
	if err != nil {
		return
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(raw); err != nil {
		_ = f.Close()
		return
	}
	if f.Close() == nil {
		_ = os.Rename(f.Name(), ResultPath)
	}
}
