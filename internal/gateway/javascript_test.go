package gateway

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"ampcode.com/lox/amp-mcp-gateway/internal/jsintegration"
	"ampcode.com/lox/amp-mcp-gateway/internal/upstream"
)

func TestJavaScriptCandidateRequiresFreshReview(t *testing.T) {
	t.Setenv("JS_REVIEW_TOKEN", "fake-token")
	g, s, b := fixture(t)
	definition := &jsintegration.Definition{Origin: "https://api.example.com", Source: `export function write(a) {return a}`, Tools: []jsintegration.Tool{{Name: "write", Handler: "write", Description: "Write", InputSchema: map[string]any{"type": "object"}, OutputSchema: map[string]any{"type": "object"}}}}
	g.cfg.Connections = []upstream.Connection{{ID: "notes", TokenEnv: "JS_REVIEW_TOKEN", JavaScript: definition}}
	g.cfg.Tools = []Tool{{ID: "notes.write", Connection: "notes", Name: "write", Description: "Write", InputSchema: definition.Tools[0].InputSchema, Policy: "allow", Artifact: definition.Binding("fake-token")}}
	// The source bundle changes without a schema or description change.
	definition.Source += `; // candidate version two`
	var err error
	g, err = New(g.cfg, s, b)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.submit(t.Context(), input("stale-js-call", "test")); err == nil {
		t.Fatal("unreviewed code was callable")
	}
	m, err := upstream.New(g.cfg.BaseURL, g.cfg.Connections, s)
	if err != nil {
		t.Fatal(err)
	}
	h, cookie := adminUI(t, g, m)
	w := formRequest(h, cookie, "POST", "/connections/notes/discover", url.Values{})
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Changed") || !strings.Contains(w.Body.String(), "Source and HTTP capabilities") {
		t.Fatalf("no changed review: %d %s", w.Code, w.Body.String())
	}
	match := regexp.MustCompile(`name="ticket" value="([^"]+)"`).FindStringSubmatch(w.Body.String())
	if len(match) != 2 {
		t.Fatal("no ticket")
	}
	draft := g.drafts[match[1]]
	if len(draft.Tools) != 1 || draft.Tools[0].Policy != "require_approval" || draft.Tools[0].Artifact == g.cfg.Tools[0].Artifact {
		t.Fatalf("old authority survived: %+v", draft)
	}
	w = formRequest(h, cookie, "POST", "/connections/notes/tools", url.Values{"ticket": {match[1]}, "default_policy": {"allow"}, "policy_0": {"require_approval"}})
	if w.Code != 303 {
		t.Fatalf("save: %d %s", w.Code, w.Body.String())
	}
	o, err := g.submit(t.Context(), input("reviewed-js-call", "test"))
	if err != nil || o.Status != "pending" {
		t.Fatalf("not callable after review: %+v %v", o, err)
	}
	if err := s.Decide(t.Context(), o.ID, "owner", true); err != nil {
		t.Fatal(err)
	}
	t.Setenv("JS_REVIEW_TOKEN", "different-generation")
	if _, err := g.submit(t.Context(), input("changed-js-token", "test")); err == nil {
		t.Fatal("credential rotation retained review")
	}
	runWorker(t, g)
	await(t, s, o.ID, "denied")
	if b.calls.Load() != 0 {
		t.Fatal("stale authority reached backend")
	}
}

func TestJavaScriptChangedBundlePreservesBlocks(t *testing.T) {
	t.Setenv("JS_REVIEW_TOKEN", "fake-token")
	for _, policy := range []string{"deny", ""} {
		t.Run("saved-policy-"+policy, func(t *testing.T) {
			g, s, b := fixture(t)
			definition := &jsintegration.Definition{Origin: "https://api.example.com", Source: `export function write(a) {return a}`, Tools: []jsintegration.Tool{{Name: "write", Handler: "write", InputSchema: map[string]any{"type": "object"}, OutputSchema: map[string]any{"type": "object"}}}}
			g.cfg.Connections = []upstream.Connection{{ID: "notes", TokenEnv: "JS_REVIEW_TOKEN", JavaScript: definition}}
			g.cfg.ToolDefaults = map[string]string{"notes": "deny"}
			g.cfg.Tools = []Tool{{ID: "notes.write", Connection: "notes", Name: "write", InputSchema: definition.Tools[0].InputSchema, Policy: policy, Artifact: definition.Binding("fake-token")}}
			definition.Source += "; // changed"
			var err error
			g, err = New(g.cfg, s, b)
			if err != nil {
				t.Fatal(err)
			}
			m, err := upstream.New(g.cfg.BaseURL, g.cfg.Connections, s)
			if err != nil {
				t.Fatal(err)
			}
			h, cookie := adminUI(t, g, m)
			w := formRequest(h, cookie, "POST", "/connections/notes/discover", url.Values{})
			if w.Code != 200 {
				t.Fatalf("discovery: %d", w.Code)
			}
			match := regexp.MustCompile(`name="ticket" value="([^"]+)"`).FindStringSubmatch(w.Body.String())
			if len(match) != 2 {
				t.Fatal("no review ticket")
			}
			tools := g.drafts[match[1]].Tools
			if len(tools) != 1 || tools[0].Policy != "deny" {
				t.Fatalf("block lost after artifact change: %+v", tools)
			}
		})
	}
}

func TestJavaScriptInstallTransitionsNeverRestoreConsent(t *testing.T) {
	_, s, _ := fixture(t)
	t.Setenv("JS_REVIEW_TOKEN", "fake-token")
	dir := t.TempDir()
	file := filepath.Join(dir, "integration.js")
	load := func(source string) Config {
		t.Helper()
		if err := os.WriteFile(file, []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
		cfg := Config{AmpUserID: "owner", Connections: []upstream.Connection{{ID: "js", TokenEnv: "JS_REVIEW_TOKEN", JavaScript: &jsintegration.Definition{Origin: "https://api.example.com", SourceFile: file, Tools: []jsintegration.Tool{{Name: "read", Handler: "read", InputSchema: map[string]any{"type": "object"}, OutputSchema: map[string]any{"type": "object"}}}}}}}
		if err := LoadJavaScript(&cfg); err != nil {
			t.Fatal(err)
		}
		if err := LoadCatalogue(t.Context(), &cfg, s); err != nil {
			t.Fatal(err)
		}
		return cfg
	}
	source := `export function read() {return {v:1}}`
	a := load(source)
	first := a.Connections[0].JavaScript.Binding("fake-token")
	a.Tools = []Tool{{ID: "js.read", Connection: "js", Name: "read", InputSchema: map[string]any{"type": "object"}, Policy: "deny", Artifact: first}}
	raw, _ := json.Marshal(catalogue{Connections: a.Connections, Tools: a.Tools})
	if err := s.SaveCatalogue(t.Context(), raw); err != nil {
		t.Fatal(err)
	}
	same := load(source)
	if same.Connections[0].JavaScript.Binding("fake-token") != first {
		t.Fatal("unchanged startup invalidated review")
	}
	candidate := load(source + "; // version two")
	if candidate.Connections[0].JavaScript.Binding("fake-token") == first {
		t.Fatal("code change kept generation")
	}
	reverted := load(source)
	if reverted.Connections[0].JavaScript.Binding("fake-token") == first {
		t.Fatal("A-B-A restored consent")
	}
	if len(reverted.Tools) != 1 || reverted.Tools[0].Policy != "deny" {
		t.Fatal("lost saved block")
	}
	retained := reverted.Connections[0].JavaScript.Source
	if err := os.WriteFile(file, []byte("throw new Error('mutable file')"), 0600); err != nil {
		t.Fatal(err)
	}
	m, err := upstream.New("http://localhost", reverted.Connections, s)
	if err != nil {
		t.Fatal(err)
	}
	tools, err := m.ListTools(context.Background(), "js")
	if err != nil || len(tools) != 1 || reverted.Connections[0].JavaScript.Source != retained {
		t.Fatalf("reread mutable source: %v %v", tools, err)
	}
	removed := Config{}
	if err := LoadCatalogue(t.Context(), &removed, s); err != nil {
		t.Fatal(err)
	}
	if len(removed.Connections) != 0 || len(removed.Tools) != 0 {
		t.Fatal("removed static code restored from saved catalogue")
	}
	readded := load(source)
	if readded.Connections[0].JavaScript.Generation == reverted.Connections[0].JavaScript.Generation {
		t.Fatal("remove-readd restored generation")
	}
}
