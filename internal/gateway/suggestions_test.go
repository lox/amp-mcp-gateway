package gateway

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"ampcode.com/lox/amp-mcp-gateway/internal/policy"
	"ampcode.com/lox/amp-mcp-gateway/internal/upstream"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type suggestionTransport func(*http.Request) (*http.Response, error)

func (f suggestionTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestDiscoverySuggestionsReviewAndSave(t *testing.T) {
	for _, mode := range []string{"suggest", "skip", "no-key", "failure", "stale"} {
		t.Run(mode, func(t *testing.T) {
			g, s, _ := fixture(t)
			remote := mcp.NewServer(&mcp.Implementation{Name: "fixture", Version: "1"}, nil)
			schema := map[string]any{"type": "object"}
			for _, name := range []string{"read", "write", "existing"} {
				remote.AddTool(&mcp.Tool{Name: name, InputSchema: schema}, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
					t.Error("discovery executed a tool")
					return nil, nil
				})
			}
			server := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return remote }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true}))
			defer server.Close()
			cfg := g.cfg
			cfg.Connections = []upstream.Connection{{ID: "notes", URL: server.URL, NoAuth: true}}
			cfg.Tools = []Tool{{ID: "notes.existing", Connection: "notes", Name: "existing", InputSchema: schema, Policy: "deny"}}
			cfg.ToolDefaults = map[string]string{"notes": "allow"}
			m, err := upstream.New(cfg.BaseURL, cfg.Connections, s)
			if err != nil {
				t.Fatal(err)
			}
			g, err = New(cfg, s, m)
			if err != nil {
				t.Fatal(err)
			}
			var calls atomic.Int32
			g.policyClient = policy.Client{Key: "test-key", HTTP: &http.Client{Transport: suggestionTransport(func(r *http.Request) (*http.Response, error) {
				calls.Add(1)
				var in struct {
					State struct {
						Name string `json:"name"`
					} `json:"state"`
				}
				if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
					t.Error(err)
				}
				if in.State.Name == "existing" {
					t.Error("classified saved restriction")
				}
				// This lock would deadlock if discovery held it across classification.
				g.mu.Lock()
				if mode == "stale" {
					g.cfg.ToolDefaults["notes"] = "deny"
				}
				g.mu.Unlock()
				body := `{"model":"jev-test","answers":{"safe":{"type":"noul","noul":0.99},"writes":{"type":"noul","noul":0.01},"deletes":{"type":"noul","noul":0},"communicates":{"type":"noul","noul":0},"spends":{"type":"noul","noul":0},"permissions":{"type":"noul","noul":0},"credentials":{"type":"noul","noul":0},"sensitive":{"type":"noul","noul":0},"execution":{"type":"noul","noul":0},"requests":{"type":"noul","noul":0}}}`
				if in.State.Name == "write" {
					body = strings.Replace(body, `"noul":0.01`, `"noul":0.9`, 1)
				}
				if mode == "failure" {
					body = `{}`
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body))}, nil
			})}}
			if mode == "no-key" {
				g.policyClient.Key = ""
			}
			h, cookie := adminUI(t, g, m)
			values := url.Values{}
			if mode == "skip" {
				values.Set("skip_jev", "true")
			}
			w := formRequest(h, cookie, "POST", "/connections/notes/discover", values)
			if mode == "stale" {
				if w.Code != 409 {
					t.Fatalf("stale suggestions accepted: %d", w.Code)
				}
				return
			}
			match := regexp.MustCompile(`name="ticket" value="([^"]+)"`).FindStringSubmatch(w.Body.String())
			if w.Code != 200 || len(match) != 2 {
				t.Fatalf("review: %d %s", w.Code, w.Body.String())
			}
			if (mode == "no-key" || mode == "skip") && calls.Load() != 0 {
				t.Fatal("unexpected classification request")
			}
			if mode == "skip" && !strings.Contains(w.Body.String(), "No tool metadata was sent to TypeSafe") {
				t.Fatal("missing skip explanation")
			}
			if mode == "no-key" && !strings.Contains(w.Body.String(), "TYPESAFE_API_KEY is not set") {
				t.Fatal("no fallback explanation")
			}
			if strings.Contains(w.Body.String(), `name="suggest_policies"`) || strings.Contains(w.Body.String(), "Policy suggestions ·") {
				t.Fatal("legacy suggestion controls still present")
			}
			if mode == "suggest" && (!strings.Contains(w.Body.String(), "Jev suggested Allow") || !strings.Contains(w.Body.String(), "May modify stored data")) {
				t.Fatal("missing inline explanations")
			}
			if mode != "suggest" && (!strings.Contains(w.Body.String(), "Approval fallback") || strings.Contains(w.Body.String(), "Jev suggested")) {
				t.Fatal("fallback incorrectly attributed to Jev")
			}
			if _, ok := g.tools["notes.read"]; ok {
				t.Fatal("published before save")
			}
			draft := g.drafts[match[1]]
			values = url.Values{"ticket": {match[1]}, "default_policy": {"allow"}}
			for i, tool := range draft.Tools {
				want := "require_approval"
				if tool.Name == "existing" {
					want = "deny"
				}
				if tool.Name == "read" && mode == "suggest" {
					want = "allow"
				}
				if tool.Policy != want {
					t.Fatalf("%s: %s, want %s", tool.Name, tool.Policy, want)
				}
				// Owner overrides the suggested read policy before saving.
				if tool.Name == "read" {
					want = "deny"
				}
				values.Set("policy_"+strconv.Itoa(i), want)
			}
			// Refreshing must retain both the override and its original explanation,
			// without sending the already-reviewed metadata again.
			if mode == "suggest" {
				w = formRequest(h, cookie, "POST", "/connections/notes/discover", values)
				match = regexp.MustCompile(`name="ticket" value="([^"]+)"`).FindStringSubmatch(w.Body.String())
				if w.Code != 200 || len(match) != 2 || calls.Load() != 2 {
					t.Fatalf("refresh repeated classification or failed: status=%d calls=%d", w.Code, calls.Load())
				}
				values.Set("ticket", match[1])
				refreshed := g.drafts[match[1]]
				if refreshed.Suggestions["notes.read"].Policy != "allow" || refreshed.Tools[1].Policy != "deny" {
					t.Fatal("refresh lost explanation or owner override")
				}
			}
			if w := formRequest(h, cookie, "POST", "/connections/notes/tools", values); w.Code != 303 {
				t.Fatal(w.Body.String())
			}
			if g.tools["notes.read"].Policy != "deny" || g.tools["notes.write"].Policy != "require_approval" {
				t.Fatal("owner choices not applied")
			}
			if w := formRequest(h, cookie, "POST", "/connections/notes/tools", values); w.Code != 409 {
				t.Fatal("replayed saved draft")
			}
		})
	}
}

func TestSuggestionsPreserveBlockedDefaultsAndUnsavedInheritance(t *testing.T) {
	client := policy.Client{Key: "test", HTTP: &http.Client{Transport: suggestionTransport(func(*http.Request) (*http.Response, error) {
		t.Fatal("should preserve owner choice without classification")
		return nil, nil
	})}}
	for _, def := range []string{"deny", "allow"} {
		tool := Tool{ID: "notes.read", Name: "read"}
		draft := toolDraft{Default: def, Tools: []Tool{tool}, Changes: map[string]string{tool.ID: "New"}}
		var previous []Tool
		if def == "allow" {
			previous = []Tool{tool}
		}
		draft.suggestPolicies(t.Context(), true, client, previous)
		if draft.Tools[0].Policy != "" {
			t.Fatal("overrode inheritance")
		}
	}
}
