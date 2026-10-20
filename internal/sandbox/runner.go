package sandbox

import (
	"context"
	"encoding/json"
	"errors"
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

type process struct {
	directory string
	command   *exec.Cmd
	session   *mcp.ClientSession
}

// start owns the persistent child's lifetime separately from its startup budget.
func start(ctx, startup context.Context, definition Server) (p *process, err error) {
	failure := errors.New("sandbox execution failed")
	u, err := url.Parse(definition.Repository)
	if os.Geteuid() != 0 || err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || definition.RunCmd == "" || strings.HasPrefix(definition.Revision, "-") {
		return nil, failure
	}
	base, err := os.MkdirTemp("", "mcp-sandbox-")
	if err != nil {
		return nil, failure
	}
	p = &process{directory: base}
	defer func() {
		if err != nil {
			p.close()
			p = nil
		}
	}()
	if os.Chmod(base, 0711) != nil {
		return p, failure
	}
	for _, name := range []string{"home", "tmp", "repo"} {
		path := filepath.Join(base, name)
		if os.Mkdir(path, 0700) != nil || os.Chown(path, 1000, 1000) != nil {
			return p, failure
		}
	}
	command := func(ctx context.Context, name string, args ...string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, name, args...)
		cmd.Dir = filepath.Join(base, "repo")
		cmd.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=" + filepath.Join(base, "home"), "TMPDIR=" + filepath.Join(base, "tmp"), "GIT_TERMINAL_PROMPT=0", "GIT_CONFIG_NOSYSTEM=1"}
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 1000, Gid: 1000, NoSetGroups: false}, Setpgid: true}
		cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
		cmd.WaitDelay = time.Second
		return cmd
	}
	// Do not use a shell for git arguments; -- also fences off option injection.
	if command(startup, "/usr/bin/git", "clone", "--", definition.Repository, ".").Run() != nil {
		return p, failure
	}
	if definition.Revision != "" && command(startup, "/usr/bin/git", "checkout", "--detach", definition.Revision, "--").Run() != nil {
		return p, failure
	}
	if definition.InstallCmd != "" && command(startup, "/bin/sh", "-c", definition.InstallCmd).Run() != nil {
		return p, failure
	}
	p.command = command(ctx, "/bin/sh", "-c", definition.RunCmd)
	client := mcp.NewClient(&mcp.Implementation{Name: "mcp-sandbox", Version: "1"}, &mcp.ClientOptions{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	p.session, err = client.Connect(startup, &mcp.CommandTransport{Command: p.command, TerminateDuration: 100 * time.Millisecond}, nil)
	if err != nil {
		return p, failure
	}
	return p, nil
}

func (p *process) close() {
	if p.command != nil && p.command.Process != nil {
		_ = syscall.Kill(-p.command.Process.Pid, syscall.SIGKILL)
	}
	if p.session != nil {
		go func() { _ = p.session.Close() }()
	}
	_ = os.RemoveAll(p.directory)
}

func (p *process) request(ctx context.Context, req Request) Response {
	fail := func() Response { return Response{Error: "sandbox execution failed"} }
	var response Response
	var err error
	if req.Tool != "" {
		response.Result, err = p.session.CallTool(ctx, &mcp.CallToolParams{Name: req.Tool, Arguments: req.Arguments})
		if err != nil || response.Result == nil {
			return fail()
		}
	} else {
		cursor, size := "", 0
		seen := map[string]bool{}
		for {
			page, err := p.session.ListTools(ctx, &mcp.ListToolsParams{Cursor: cursor})
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
	response.ID = req.ID
	raw, err := json.Marshal(response)
	if err != nil || len(raw) > ResultLimit {
		return fail()
	}
	return response
}

// Run serves a root-only mailbox, retaining one stdio session until idle. Its
// watchdog is independent of SDK/subprocess cleanup. The caller must exit PID 1
// when Run returns so escaped descendants cannot defeat idle/request deadlines.
func Run(ctx context.Context, directory string, idleTimeout time.Duration) {
	if os.Geteuid() != 0 || idleTimeout <= 0 || os.Chmod(directory, 0700) != nil {
		return
	}
	var definition Server
	if !readFile(filepath.Join(directory, "server.json"), ResultLimit, &definition) {
		return
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	activity := make(chan time.Duration)
	done := make(chan struct{})
	go func() {
		defer close(done)
		var p *process
		defer func() {
			if p != nil {
				p.close()
			}
		}()
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		lastID := ""
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			var req Request
			if !readFile(filepath.Join(directory, "request.json"), RequestLimit, &req) || req.ID == "" || req.ID == lastID {
				continue
			}
			lastID = req.ID
			select {
			case activity <- ExecutionTimeout:
			case <-ctx.Done():
				return
			}
			requestCtx, requestCancel := context.WithTimeout(ctx, ExecutionTimeout)
			var err error
			if p == nil {
				p, err = start(ctx, requestCtx, definition)
			}
			response := Response{Error: "sandbox execution failed"}
			if err == nil {
				response = p.request(requestCtx, req)
			}
			requestCancel()
			response.ID = req.ID
			if !publish(filepath.Join(directory, "result.json"), response) {
				return
			}
			select {
			case activity <- idleTimeout:
			case <-ctx.Done():
				return
			}
			if response.Error != "" {
				// Leave time to collect the failure but never reuse this process.
				<-ctx.Done()
				return
			}
		}
	}()
	timer := time.NewTimer(idleTimeout)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-done:
			return
		case <-timer.C:
			return
		case duration := <-activity:
			timer.Reset(duration)
		}
	}
}

func readFile(path string, limit int64, value any) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	info, statErr := f.Stat()
	raw, readErr := io.ReadAll(io.LimitReader(f, limit+1))
	return statErr == nil && info.Mode().IsRegular() && info.Sys().(*syscall.Stat_t).Uid == 0 && info.Mode().Perm()&0022 == 0 && readErr == nil && int64(len(raw)) <= limit && json.Unmarshal(raw, value) == nil
}

func publish(path string, response Response) bool {
	raw, err := json.Marshal(response)
	if err != nil || len(raw) > ResultLimit {
		return false
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".mcp-result-")
	if err != nil {
		return false
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(raw); err != nil {
		_ = f.Close()
		return false
	}
	return f.Close() == nil && os.Rename(f.Name(), path) == nil
}
