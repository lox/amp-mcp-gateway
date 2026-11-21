// Command reviewbench-agent runs the production Amp review (reviewbot-v1 mode,
// embedded methodology, result validation and changed-line anchoring) on one
// ReviewBench pull request, per its agent contract:
// https://github.com/review-bench/ReviewBench/blob/main/AGENT_CONTRACT.md
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"ampcode.com/lox/amp-mcp-gateway/internal/reviews"
)

const mode = "reviewbot-v1"

type finding struct {
	File      string `json:"file"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
	Message   string `json:"message"`
	Producer  string `json:"producer"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "agent:", err)
		os.Exit(1)
	}
}

func run() error {
	env := func(name string) string { return os.Getenv(name) }
	for _, name := range []string{"RB_NWO", "RB_PR_NUMBER", "RB_BASE", "RB_HEAD", "RB_OUT", "AMP_API_KEY"} {
		if env(name) == "" {
			return fmt.Errorf("missing %s", name)
		}
	}
	number, err := strconv.Atoi(env("RB_PR_NUMBER"))
	if err != nil {
		return errors.New("invalid RB_PR_NUMBER")
	}
	agent := cmp(env("RB_AGENT"), "amp-review")
	repo := cmp(env("RB_REPO"), "/work/repo")
	failOn := cmp(env("RB_CONFIG_FAIL_ON"), "high")

	var pr struct{ Title, Body string }
	if b, err := os.ReadFile(cmp(env("RB_PR_JSON"), "/work/pr/pr.json")); err == nil {
		_ = json.Unmarshal(b, &pr)
	}
	diff, err := os.ReadFile(cmp(env("RB_DIFF"), "/work/pr/diff.patch"))
	if err != nil {
		return err
	}
	text := reviews.LocalPrompt(fmt.Sprintf("%s#%d", env("RB_NWO"), number), env("RB_BASE"), env("RB_HEAD"), reviews.Context{Title: pr.Title, Body: pr.Body}, failOn)

	// The ReviewBench run reports which labels never appear in our output.
	fmt.Fprintf(os.Stderr, "agent: mode=%s fail-on=%s\n", mode, failOn)
	timeout := 28 * time.Minute
	if s, err := strconv.Atoi(env("RB_TIMEOUT_SECONDS")); err == nil && s > 120 {
		timeout = time.Duration(s-60) * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := execute(ctx, repo, text)
	if err != nil {
		return err
	}
	result, err := reviews.ParseResult(out)
	if err != nil {
		return err
	}
	result, _, omitted := reviews.Finalize(result, changedLines(string(diff)), failOn)

	findings := []finding{}
	for _, f := range result.Findings {
		findings = append(findings, finding{File: f.Path, StartLine: f.StartLine, EndLine: f.EndLine, Producer: agent,
			Message: fmt.Sprintf("[%s] %s: %s Suggested fix: %s", f.Severity, f.Title, f.Message, f.Suggestion)})
	}
	b, _ := json.MarshalIndent(map[string]any{
		"pr":       map[string]any{"repo": "https://github.com/" + env("RB_NWO"), "pr_number": number, "base": env("RB_BASE"), "head": env("RB_HEAD")},
		"agent":    agent,
		"findings": findings,
	}, "", "  ")
	if err := os.WriteFile(env("RB_OUT"), b, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "agent: %d finding(s), %d omitted off changed lines\n", len(findings), omitted)
	return nil
}

// execute runs the Amp CLI locally in the checkout: the benchmark container is
// the sandbox, and it has no GitHub access an orb could clone from.
func execute(ctx context.Context, repo, prompt string) (string, error) {
	home, err := os.MkdirTemp("", "amp-home-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(home)
	settings := map[string]any{"amp.dangerouslyAllowAll": true}
	if proxy := cmp(os.Getenv("HTTPS_PROXY"), os.Getenv("https_proxy")); proxy != "" {
		settings["amp.proxy"] = proxy
	}
	settingsFile := filepath.Join(home, "settings.json")
	b, _ := json.Marshal(settings)
	if err := os.WriteFile(settingsFile, b, 0o600); err != nil {
		return "", err
	}
	// The image installs the pinned mode plugin in /root/.config/amp/plugins.
	cmd := exec.CommandContext(ctx, "amp", "--execute", "--stream-json", "--mode", mode, "--visibility", "private",
		"--settings-file", settingsFile, "--log-file", "/dev/null", "--no-ide", "--plugin-ready-timeout", "30")
	cmd.Dir = repo
	cmd.Env = append(os.Environ(), "NO_COLOR=1")
	cmd.Stdin = strings.NewReader(prompt)
	cmd.Stderr = os.Stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("could not start Amp CLI: %w", err)
	}
	var result string
	outcome := errors.New("Amp stream ended without a result")
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 4096), 8<<20)
	for scanner.Scan() {
		var m struct {
			Type, Subtype, Result, Error string
			SessionID                    string `json:"session_id"`
			Mode                         string `json:"agent_mode"`
			IsError                      bool   `json:"is_error"`
		}
		if json.Unmarshal(scanner.Bytes(), &m) != nil {
			continue
		}
		switch {
		case m.Type == "system" && m.Subtype == "init":
			fmt.Fprintf(os.Stderr, "agent: thread %s mode=%s\n", m.SessionID, m.Mode)
			if m.Mode != mode {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
				return "", fmt.Errorf("Amp mode mismatch: got %q, want %s", m.Mode, mode)
			}
		case m.Type == "result" && m.IsError:
			outcome = fmt.Errorf("Amp review failed: %s", m.Error)
		case m.Type == "result":
			result, outcome = m.Result, nil
		}
	}
	if err := cmd.Wait(); err != nil && outcome == nil {
		outcome = fmt.Errorf("Amp CLI: %w", err)
	}
	return result, outcome
}

// changedLines maps each file in a unified diff to its added right-side lines.
func changedLines(diff string) map[string]map[int]bool {
	out := map[string]map[int]bool{}
	file, header := "", false
	var patch strings.Builder
	flush := func() {
		if file != "" {
			out[file] = reviews.ChangedLines(patch.String())
		}
		file = ""
		patch.Reset()
	}
	for _, line := range strings.Split(diff, "\n") {
		switch {
		case strings.HasPrefix(line, "diff --git "):
			flush()
			header = true
		case header && strings.HasPrefix(line, "@@"):
			header = false
			patch.WriteString(line + "\n")
		case header && strings.HasPrefix(line, "+++ "):
			if name := strings.TrimPrefix(line, "+++ "); name != "/dev/null" {
				file = strings.TrimPrefix(name, "b/")
			}
		default:
			patch.WriteString(line + "\n")
		}
	}
	flush()
	return out
}

func cmp(v, fallback string) string {
	if v != "" {
		return v
	}
	return fallback
}
