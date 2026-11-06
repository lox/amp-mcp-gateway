package reviews

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCLIStreamAndEnvironmentIsolation(t *testing.T) {
	t.Setenv("GITHUB_PRIVATE_KEY", "must-not-reach-child")
	t.Setenv("GATEWAY_ENCRYPTION_KEY", "must-not-reach-child")
	t.Setenv("AMP_THREAD_ID", "must-not-reach-child")
	for _, tc := range []struct {
		name, mode, resultID string
		omitInit             bool
		wantErr              bool
	}{
		{"valid", "reviewbot-v1", testThread, false, false},
		{"mode-fallback", "medium", testThread, false, true},
		{"wrong-result-thread", "reviewbot-v1", "T-00000000-0000-0000-0000-000000000456", false, true},
		{"no-init", "reviewbot-v1", testThread, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			init, _ := json.Marshal(map[string]any{"type": "system", "subtype": "init", "agent_mode": tc.mode, "session_id": testThread})
			result, _ := json.Marshal(map[string]any{"type": "result", "session_id": tc.resultID, "is_error": false, "result": `{"summary":"ok","findings":[]}`})
			script := "#!/bin/sh\nset -eu\ntest -z \"${GITHUB_PRIVATE_KEY:-}${GATEWAY_ENCRYPTION_KEY:-}${AMP_THREAD_ID:-}\"\ntest \"$AMP_API_KEY\" = 'tenant-execution-key'\ntest \"$PWD\" = \"$HOME\"\ncat >/dev/null\n"
			if !tc.omitInit {
				script += "printf '%s\\n' '" + string(init) + "'\n"
			}
			script += "printf '%s\\n' '" + string(result) + "'\n"
			binary := filepath.Join(t.TempDir(), "amp")
			if err := os.WriteFile(binary, []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			seen := ""
			output, err := (CLI{Binary: binary}).Execute(t.Context(), "tenant-execution-key", Job{Project: "workspace/project", Visibility: "private"}, func(id string) error { seen = id; return nil })
			if (err != nil) != tc.wantErr {
				t.Fatalf("output %q error %v", output, err)
			}
			if !tc.wantErr && (seen != testThread || output != `{"summary":"ok","findings":[]}`) {
				t.Fatal("stream result lost")
			}
		})
	}
}

func TestCLITruncationAndTimeoutNeverReturnSuccess(t *testing.T) {
	for _, block := range []bool{false, true} {
		binary := filepath.Join(t.TempDir(), "amp")
		script := "#!/bin/sh\ncat >/dev/null\n"
		if block {
			script += "exec sleep 20\n"
		}
		if err := os.WriteFile(binary, []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
		_, err := (CLI{Binary: binary}).Execute(ctx, "fake-key", Job{}, func(string) error { return nil })
		cancel()
		if block {
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("timeout: %v", err)
			}
		} else if !errors.Is(err, errAmbiguous) {
			t.Fatalf("truncation: %v", err)
		}
	}
}

func TestUsageDistinguishesCreditsAndProviderEstimate(t *testing.T) {
	report := "Cost: $1.23\nInput tokens: 1,234\nOutput tokens: 23\nRequests: 4\n"
	for _, tc := range []struct {
		suffix   string
		estimate *float64
	}{
		{"Est. list price: N/A", nil},
		{"Est. list price: $3.45", new(3.45)},
		{"| Model | Est. list price |\n| --- | --- |\n| first | $1.25 |\n| second | $2.50 |\n", new(3.75)},
		{"| Model | Est. list price |\n| --- | --- |\n| first | $1.25 |\n| second | N/A |\n", nil},
	} {
		u, err := parseUsage(report + tc.suffix)
		if err != nil {
			t.Fatal(err)
		}
		if u.CostUSD != 1.23 || u.InputTokens != 1234 || u.Requests != 4 || ((u.ProviderEstimateUSD == nil) != (tc.estimate == nil)) {
			t.Fatalf("usage %+v", u)
		}
		if tc.estimate != nil && *u.ProviderEstimateUSD != *tc.estimate {
			t.Fatal("estimate conflated with credits")
		}
	}
}

func TestCLIRejectsDuplicateInitAndWrongContinuation(t *testing.T) {
	init := `{"type":"system","subtype":"init","agent_mode":"reviewbot-v1","session_id":"` + testThread + `"}`
	result := `{"type":"result","session_id":"` + testThread + `","result":"incorrect success"}`
	other := "T-00000000-0000-0000-0000-000000000456"
	for _, tc := range []struct{ expected, second string }{{"", testThread}, {other, testThread}, {"", other}} {
		binary := filepath.Join(t.TempDir(), "amp")
		second := strings.Replace(init, testThread, tc.second, 1)
		script := "#!/bin/sh\ncat >/dev/null\nprintf '%s\\n' '" + init + "' '" + second + "' '" + result + "'\n"
		if err := os.WriteFile(binary, []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
		seen := map[string]bool{}
		_, _, err := (CLI{Binary: binary}).execute(t.Context(), "fake-key", nil, "prompt", tc.expected, func(id string) error { seen[id] = true; return nil })
		if !errors.Is(err, errAmbiguous) {
			t.Fatalf("invalid stream became successful: %v", err)
		}
		if !seen[testThread] || tc.expected == "" && !seen[tc.second] {
			t.Fatal("valid but unexpected thread was not recorded")
		}
	}
}

func TestFindingValidationAndChangedLines(t *testing.T) {
	valid := `{"summary":"ok","findings":[{"severity":"high","title":"bug","message":"impact","suggestion":"fix","path":"a.go","startLine":3,"endLine":4}]}`
	for _, bad := range []string{strings.Replace(valid, `"high"`, `"severe"`, 1), strings.Replace(valid, `"a.go"`, `"../a.go"`, 1), strings.Replace(valid, `"startLine":3`, `"startLine":0`, 1), strings.Replace(valid, `"endLine":4`, `"endLine":2`, 1), `{"summary":"ok","findings":null}`} {
		if _, err := ParseResult(bad); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
	result, err := ParseResult("```json\n" + valid + "\n```")
	if err != nil {
		t.Fatal(err)
	}
	lines := ChangedLines("@@ -2,2 +2,3 @@\n context\n-old\n+one\n+two\n@@ -20,1 +21,2 @@\n context\n+later")
	if len(lines) != 3 || !lines[3] || !lines[4] || !lines[22] {
		t.Fatalf("lines: %+v", lines)
	}
	_, conclusion, _ := finalize(result, map[string]map[int]bool{"a.go": lines}, "critical")
	if conclusion != "neutral" {
		t.Fatal(conclusion)
	}
	_, conclusion, _ = finalize(result, map[string]map[int]bool{"a.go": lines}, "high")
	if conclusion != "failure" {
		t.Fatal(conclusion)
	}
	_, conclusion, omitted := finalize(result, map[string]map[int]bool{"a.go": {4: true}}, "high")
	if conclusion != "success" || omitted != 1 {
		t.Fatal("unchanged finding affected conclusion")
	}
}

func FuzzParseResult(f *testing.F) {
	f.Add(`{"summary":"ok","findings":[]}`)
	f.Add(`{"summary":"ok","findings":[{"severity":"high","title":"bug","message":"impact","suggestion":"fix","path":"a.go","startLine":3,"endLine":4}]}`)
	f.Fuzz(func(t *testing.T, text string) {
		r, err := ParseResult(text)
		if err != nil {
			return
		}
		raw, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		again, err := ParseResult(string(raw))
		if err != nil || len(again.Findings) != len(r.Findings) {
			t.Fatal("valid result does not round-trip")
		}
	})
}
