package reviews

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Executor is the consumed Amp boundary. No GitHub credential enters it.
type Executor interface {
	Execute(context.Context, string, Job, func(string) error) (string, error)
	Archive(context.Context, string, string) error
	Usage(context.Context, string, string) (*Usage, error)
}

// CLI uses the same stream protocol as @ampcode/sdk, without a JS service.
// Binary must be an operator-installed absolute path, never browser input.
type CLI struct{ Binary string }

var (
	errAmbiguous = errors.New("Amp execution outcome unknown; inspect the linked thread before rerunning")
	errTransient = errors.New("Amp reported a terminal transient failure")
	errCancelled = errors.New("Amp review cancelled")
)

func (c CLI) command(ctx context.Context, key string, args ...string) (*exec.Cmd, func(), error) {
	if key == "" {
		return nil, nil, errors.New("Amp execution key is required")
	}
	binary := c.Binary
	if binary == "" {
		var err error
		binary, err = exec.LookPath("amp")
		if err != nil {
			return nil, nil, errors.New("Amp CLI is not installed")
		}
	}
	binary, err := filepath.Abs(binary)
	if err != nil {
		return nil, nil, err
	}
	home, err := os.MkdirTemp("", "gateway-review-*")
	if err != nil {
		return nil, nil, err
	}
	cleanup := func() { _ = os.RemoveAll(home) }
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Dir = home
	// Do not inherit service credentials, saved CLI accounts, local plugins,
	// project inference, proxy overrides or this hosting orb's identity.
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "XDG_CONFIG_HOME=" + home + "/config", "XDG_CACHE_HOME=" + home + "/cache", "AMP_API_KEY=" + key, "AMP_URL=https://ampcode.com", "NO_COLOR=1"}
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = 10 * time.Second
	cmd.Stderr = io.Discard // Provider diagnostics can contain credentials/content.
	return cmd, cleanup, nil
}

// Execute retries only explicit terminal transient errors in the same known
// thread. A truncated stream or launch without a thread ID is never replayed.
func (c CLI) Execute(ctx context.Context, key string, j Job, onThread func(string) error) (string, error) {
	thread := ""
	for attempt := 0; attempt < 3; attempt++ {
		args := []string{}
		text := prompt(j)
		if thread != "" {
			args = append(args, "threads", "continue", thread)
			text = "Complete the review if necessary, then return only final review JSON in the required schema."
		}
		args = append(args, "--execute", "--stream-json", "--orb-execute", "--mode", "reviewbot-v1", "--no-archive-after-execute", "--log-file", "/dev/null")
		if thread == "" {
			args = append(args, "--project", j.Project, "--title", "Review "+j.String(), "--visibility", j.Visibility, "--label", "reviewbot")
		}
		result, id, err := c.execute(ctx, key, args, text, thread, onThread)
		if err == nil {
			return result, nil
		}
		if !errors.Is(err, errTransient) || id == "" || attempt == 2 {
			return "", err
		}
		thread = id
		if err := sleep(ctx, []time.Duration{5 * time.Second, 20 * time.Second}[attempt]); err != nil {
			return "", err
		}
	}
	return "", errAmbiguous
}

func (c CLI) execute(ctx context.Context, key string, args []string, prompt, expected string, onThread func(string) error) (string, string, error) {
	processCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd, cleanup, err := c.command(processCtx, key, args...)
	if err != nil {
		return "", "", err
	}
	defer cleanup()
	cmd.Stdin = strings.NewReader(prompt)
	out, err := cmd.StdoutPipe()
	if err != nil {
		return "", "", err
	}
	if err := cmd.Start(); err != nil {
		return "", "", errors.New("could not start Amp CLI")
	}
	var result, thread string
	var outcome error = errAmbiguous
	initialized, finished := false, false
	scanner := bufio.NewScanner(out)
	scanner.Buffer(make([]byte, 4096), 2<<20)
	for scanner.Scan() {
		var message struct {
			Type, Subtype string
			SessionID     string `json:"session_id"`
			Mode          string `json:"agent_mode"`
			IsError       bool   `json:"is_error"`
			Result, Error string
		}
		if json.Unmarshal(scanner.Bytes(), &message) != nil {
			break
		}
		switch message.Type {
		case "system":
			if message.Subtype != "init" {
				continue
			}
			if !threadPattern.MatchString(message.SessionID) {
				finished = true
				break
			}
			thread = message.SessionID
			// Record even an unexpected continuation or duplicate-init thread:
			// it may exist remotely despite violating this stream's contract.
			if err := onThread(thread); err != nil {
				outcome = errors.Join(errAmbiguous, errors.New("could not persist Amp thread"))
				finished = true
				break
			}
			if initialized || expected != "" && thread != expected {
				finished = true
				break
			}
			if message.Mode != "reviewbot-v1" {
				outcome = errors.Join(errAmbiguous, errors.New("Amp mode mismatch: expected reviewbot-v1"))
				finished = true
				break
			}
			initialized = true
		case "result":
			if !initialized || message.SessionID != thread {
				finished = true
				break
			}
			finished = true
			if !message.IsError {
				result = message.Result
				outcome = nil
			} else {
				outcome = errors.New("Amp review failed; inspect the linked thread")
				if regexp.MustCompile(`(?i)user cancel(?:l)?ed|cancel(?:l)?ed by (?:the )?user`).MatchString(message.Error) {
					outcome = errCancelled
				} else if regexp.MustCompile(`(?i)websocket closed|HTTP (408|429|5\d\d)|overload|temporar(?:y|ily) unavailable`).MatchString(message.Error) {
					outcome = errTransient
				}
			}
		}
		if finished {
			break
		}
	}
	// SIGTERM mirrors SDK cancellation; allow it to notify the remote actor,
	// then reap the child. A deadline never turns a late result into success.
	cancel()
	_ = cmd.Wait()
	if ctx.Err() != nil {
		if errors.Is(outcome, errAmbiguous) {
			return "", thread, errors.Join(errAmbiguous, ctx.Err())
		}
		// A validated terminal result confirms the actor stopped, even if
		// cancellation raced with it. Never publish that late result.
		return "", thread, ctx.Err()
	}
	return result, thread, outcome
}

type boundedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.Len() {
		return 0, errors.New("Amp output limit exceeded")
	}
	return b.Buffer.Write(p)
}

func (c CLI) Archive(ctx context.Context, key, id string) error {
	if !threadPattern.MatchString(id) {
		return errors.New("invalid thread ID")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd, cleanup, err := c.command(ctx, key, "threads", "archive", id, "--log-file", "/dev/null")
	if err != nil {
		return err
	}
	defer cleanup()
	reader, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return errors.New("could not start Amp archival")
	}
	scanner := bufio.NewScanner(io.LimitReader(reader, 65536))
	confirmed := false
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), "Thread archived successfully") {
			confirmed = true
			cancel()
			break
		}
	}
	err = cmd.Wait()
	if confirmed || err == nil {
		return nil
	}
	return errors.New("Amp thread archival unavailable")
}

func (c CLI) Usage(ctx context.Context, key, id string) (*Usage, error) {
	if !threadPattern.MatchString(id) {
		return nil, errors.New("invalid thread ID")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd, cleanup, err := c.command(ctx, key, "threads", "usage", "--details", id, "--log-file", "/dev/null")
	if err != nil {
		return nil, err
	}
	defer cleanup()
	output := &boundedBuffer{limit: 4 << 20}
	cmd.Stdout = output
	if cmd.Run() != nil {
		return nil, errors.New("Amp usage unavailable")
	}
	return parseUsage(output.String())
}

func parseUsage(text string) (*Usage, error) {
	value := func(pattern string) (float64, bool) {
		match := regexp.MustCompile(pattern).FindStringSubmatch(text)
		if match == nil {
			return 0, false
		}
		n, err := strconv.ParseFloat(strings.ReplaceAll(match[1], ",", ""), 64)
		return n, err == nil
	}
	cost, c := value(`(?m)^Cost: \$([\d,]+(?:\.\d+)?)$`)
	input, i := value(`(?m)^Input tokens: ([\d,]+)`)
	output, o := value(`(?m)^Output tokens: ([\d,]+)`)
	requests, r := value(`(?m)^Requests: ([\d,]+)$`)
	if !c || !i || !o || !r {
		return nil, errors.New("Amp did not report cost and token counts")
	}
	u := &Usage{CostUSD: cost, InputTokens: int64(input), OutputTokens: int64(output), Requests: int64(requests), SubscriptionUsed: strings.Contains(text, "subscription was used for some inference")}
	if estimate, ok := value(`(?m)^Est\. list price: \$([\d,]+(?:\.\d+)?)$`); ok {
		u.ProviderEstimateUSD = &estimate
	} else if !strings.Contains(text, "Est. list price: N/A") {
		// Older CLI versions report only per-model estimates. All rows must
		// have an estimate; missing/N/A rows must not become a partial total.
		column, rows, total := -1, 0, 0.0
		for _, line := range strings.Split(text, "\n") {
			cells := strings.Split(strings.TrimSpace(line), "|")
			if column < 0 {
				for i, cell := range cells {
					if strings.TrimSpace(cell) == "Est. list price" {
						column = i
					}
				}
				continue
			}
			if len(cells) <= column {
				break
			}
			cell := strings.TrimSpace(cells[column])
			if strings.Contains(cell, "---") {
				continue
			}
			if !strings.HasPrefix(cell, "$") {
				return u, nil
			}
			n, err := strconv.ParseFloat(strings.ReplaceAll(cell[1:], ",", ""), 64)
			if err != nil || n < 0 || math.IsNaN(n) || math.IsInf(n, 0) {
				return u, nil
			}
			total += n
			rows++
		}
		if rows > 0 {
			u.ProviderEstimateUSD = &total
		}
	}
	return u, nil
}

func sleep(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
