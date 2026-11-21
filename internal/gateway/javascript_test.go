package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"ampcode.com/lox/amp-mcp-gateway/internal/jsintegration"
	"ampcode.com/lox/amp-mcp-gateway/internal/upstream"
)

func javascriptUploadRequest(t *testing.T, h http.Handler, cookie *http.Cookie, path, bundle, token, revision string) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("bundle", "bundle.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write([]byte(bundle)); err != nil {
		t.Fatal(err)
	}
	for key, value := range map[string]string{"token": token, "revision": revision} {
		if err := writer.WriteField(key, value); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", path, &body)
	r.Header.Set("Content-Type", writer.FormDataContentType())
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestJavaScriptUploadReviewAndReplacement(t *testing.T) {
	t.Setenv("TYPESAFE_API_KEY", "")
	g, s, _ := fixture(t)
	m, err := upstream.New(g.cfg.BaseURL, g.cfg.Connections, s)
	if err != nil {
		t.Fatal(err)
	}
	h, cookie := adminUI(t, g, m)
	bundle := `{"ID":"custom","Origin":"https://api.example.com","Source":"throw new Error('upload must not evaluate source')","Tools":[{"Name":"read","Handler":"read","InputSchema":{"type":"object"},"OutputSchema":{"type":"object"},"HTTP":[{"Method":"GET","Path":"/items"}]}]}`
	upload := func(raw, token, revision string) *httptest.ResponseRecorder {
		t.Helper()
		path := "/connections/javascript"
		if revision != "" {
			path = "/connections/custom/javascript"
		}
		return javascriptUploadRequest(t, h, cookie, path, raw, token, revision)
	}
	if w := javascriptUploadRequest(t, h, nil, "/connections/javascript", bundle, "fake-upload-token", ""); w.Code != 303 || w.Header().Get("Location") == "/connections/custom/tools" {
		t.Fatalf("unauthenticated upload accepted: %d", w.Code)
	}
	if w := upload(bundle, "fake-upload-token", ""); w.Code != 303 {
		t.Fatalf("upload: %d %s", w.Code, w.Body.String())
	}
	if _, ok := g.tools["custom.read"]; ok {
		t.Fatal("unreviewed upload exposed a tool")
	}
	review := func(policy string) {
		t.Helper()
		w := formRequest(h, cookie, "POST", "/connections/custom/discover", url.Values{"skip_jev": {"1"}})
		match := regexp.MustCompile(`name="ticket" value="([^"]+)"`).FindStringSubmatch(w.Body.String())
		if w.Code != 200 || len(match) != 2 {
			t.Fatalf("review: %d %s", w.Code, w.Body.String())
		}
		if got := g.drafts[match[1]].Tools[0].Policy; got != "require_approval" {
			t.Fatalf("new/replaced tool inherited permissive default: %q", got)
		}
		w = formRequest(h, cookie, "POST", "/connections/custom/tools", url.Values{"ticket": {match[1]}, "default_policy": {"allow"}, "policy_0": {policy}})
		if w.Code != 303 {
			t.Fatalf("save: %d %s", w.Code, w.Body.String())
		}
	}
	review("allow")
	first := g.javascriptArtifact("custom")
	for _, path := range []string{"/connections/custom/tools", "/connections/custom/settings", "/connections/custom/javascript"} {
		w := formRequest(h, cookie, "GET", path, nil)
		if w.Code != 200 || strings.Contains(w.Body.String(), "fake-upload-token") {
			t.Fatalf("token leaked or missing page: %s %d", path, w.Code)
		}
	}
	var call callInput
	if err := json.Unmarshal([]byte(`{"request_id":"custom-before-replace","calls":[{"tool_id":"custom.read","arguments":{}}]}`), &call); err != nil {
		t.Fatal(err)
	}
	if o, err := g.submit(t.Context(), call); err != nil || o.Status != "ready" {
		t.Fatalf("reviewed tool not callable: %v %v", o, err)
	}
	// A byte-for-byte replacement must pause old authority, not restore it.
	if w := upload(bundle, "", first); w.Code != 303 {
		t.Fatalf("replace: %d %s", w.Code, w.Body.String())
	}
	if o, err := s.Get(t.Context(), "custom-before-replace"); err != nil || o.Status != "denied" {
		t.Fatalf("replacement retained queued authority: %v %v", o, err)
	}
	if _, err := g.submit(t.Context(), call); err == nil {
		t.Fatal("replaced tool accepted another call")
	}
	second := g.javascriptArtifact("custom")
	if first == second {
		t.Fatal("replacement reused consent identity")
	}
	if _, ok := g.tools["custom.read"]; ok {
		t.Fatal("old tool still callable after replacement")
	}
	if w := upload(bundle, "", first); w.Code != 409 {
		t.Fatalf("stale replacement accepted: %d", w.Code)
	}
	review("require_approval")
	// Rotation is a replacement too, even when source is unchanged.
	if w := upload(bundle, "rotated-fake-token", second); w.Code != 303 {
		t.Fatalf("rotate: %d %s", w.Code, w.Body.String())
	}
	if _, ok := g.tools["custom.read"]; ok {
		t.Fatal("credential rotation retained consent")
	}
	cfg := g.cfg
	cfg.Connections = nil
	if err := LoadCatalogue(t.Context(), &cfg, s); err != nil {
		t.Fatal(err)
	}
	var restored *upstream.Connection
	for i := range cfg.Connections {
		if cfg.Connections[i].ID == "custom" {
			restored = &cfg.Connections[i]
		}
	}
	if restored == nil || restored.BearerToken != "rotated-fake-token" || restored.JavaScript.Source != "throw new Error('upload must not evaluate source')" || restored.JavaScriptBinding() != g.javascriptArtifact("custom") {
		t.Fatal("uploaded source, token or generation lost across reload")
	}
	other, _, _ := fixture(t)
	if other.connectionView("custom") != nil {
		t.Fatal("bundle crossed owner stores")
	}
	if w := formRequest(h, cookie, "GET", "/connections/custom/settings", nil); !strings.Contains(w.Body.String(), `action="/connections/custom/remove"`) {
		t.Fatal("uploaded bundle has no removal control")
	}
	if w := formRequest(h, cookie, "POST", "/connections/custom/remove", url.Values{"confirm": {"remove"}}); w.Code != 303 {
		t.Fatalf("remove uploaded bundle: %d %s", w.Code, w.Body.String())
	}
	cfg.Connections = nil
	if err := LoadCatalogue(t.Context(), &cfg, s); err != nil {
		t.Fatal(err)
	}
	for _, c := range cfg.Connections {
		if c.ID == "custom" {
			t.Fatal("removed upload resurrected after restart")
		}
	}
}

func TestJavaScriptUploadRejectsAuthorityAndHostPaths(t *testing.T) {
	g, s, _ := fixture(t)
	m, err := upstream.New(g.cfg.BaseURL, g.cfg.Connections, s)
	if err != nil {
		t.Fatal(err)
	}
	h, cookie := adminUI(t, g, m)
	valid := `{"ID":"custom","Origin":"https://api.example.com","Source":"export function read(){return {}}","Tools":[{"Name":"read","Handler":"read","InputSchema":{"type":"object"},"OutputSchema":{"type":"object"},"HTTP":[{"Method":"GET","Path":"/items"}]}]}`
	for _, raw := range []string{
		strings.Replace(valid, `"ID":"custom"`, `"ID":"custom","SourceFile":"/etc/passwd"`, 1),
		strings.Replace(valid, `"ID":"custom"`, `"ID":"custom","Generation":"chosen"`, 1),
		strings.Replace(valid, `"ID":"custom"`, `"ID":"custom","BearerToken":"embedded"`, 1),
		strings.Replace(valid, `"Handler":"read"`, `"Handler":"read","Policy":"allow"`, 1),
		strings.Replace(valid, `"GET"`, `"CONNECT"`, 1),
		strings.Replace(valid, `/items`, `/../private`, 1),
		strings.Replace(valid, `https://api.example.com`, `https://127.0.0.1`, 1),
		valid + `{}`,
		strings.Repeat("x", (1<<20)+1),
	} {
		w := javascriptUploadRequest(t, h, cookie, "/connections/javascript", raw, "secret-never-echo", "")
		if w.Code != 400 || strings.Contains(w.Body.String(), "secret-never-echo") {
			t.Fatalf("invalid upload: %d", w.Code)
		}
	}
	if g.connectionView("custom") != nil {
		t.Fatal("invalid upload persisted")
	}
	// Uploads cannot replace a remote connection by reusing its ID.
	raw := strings.Replace(valid, `"custom"`, `"notes"`, 1)
	if w := javascriptUploadRequest(t, h, cookie, "/connections/javascript", raw, "fake", ""); w.Code != 400 {
		t.Fatalf("duplicate upload: %d", w.Code)
	}
}

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

func TestJavaScriptConnectionCanBeDisabledButNotRemoved(t *testing.T) {
	t.Setenv("JS_REVIEW_TOKEN", "fake-token")
	g, s, b := fixture(t)
	definition := &jsintegration.Definition{Origin: "https://api.example.com", Source: `export function write(a) {return a}`, Tools: []jsintegration.Tool{{Name: "write", Handler: "write", Description: "Write", InputSchema: map[string]any{"type": "object"}, OutputSchema: map[string]any{"type": "object"}}}}
	g.cfg.Connections = []upstream.Connection{{ID: "notes", TokenEnv: "JS_REVIEW_TOKEN", JavaScript: definition}}
	g.cfg.Tools = []Tool{{ID: "notes.write", Connection: "notes", Name: "write", Description: "Write", InputSchema: definition.Tools[0].InputSchema, Policy: "allow", Artifact: definition.Binding("fake-token")}}
	g, err := New(g.cfg, s, b)
	if err != nil {
		t.Fatal(err)
	}
	m, err := upstream.New(g.cfg.BaseURL, g.cfg.Connections, s)
	if err != nil {
		t.Fatal(err)
	}
	h, cookie := adminUI(t, g, m)
	if w := formRequest(h, cookie, "GET", "/connections/notes/settings", nil); w.Code != 200 || strings.Contains(w.Body.String(), `action="/connections/notes/remove"`) || !strings.Contains(w.Body.String(), `action="/connections/notes/disable"`) {
		t.Fatalf("settings: %d %s", w.Code, w.Body.String())
	}
	if w := formRequest(h, cookie, "POST", "/connections/notes/remove", url.Values{"confirm": {"remove"}}); w.Code != 409 || !g.remoteConnection("notes") {
		t.Fatalf("removed operator-installed connection: %d", w.Code)
	}
	if w := formRequest(h, cookie, "POST", "/connections/notes/disable", nil); w.Code != 303 {
		t.Fatalf("disable: %d %s", w.Code, w.Body.String())
	}
	if _, err := g.submit(t.Context(), input("disabled-js-call", "test")); err == nil {
		t.Fatal("disabled JavaScript connection was callable")
	}
}
