package gateway

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"ampcode.com/lox/mcp-gateway/internal/browserauth"
	"ampcode.com/lox/mcp-gateway/internal/upstream"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func adminUI(t *testing.T, g *Gateway, m *upstream.Manager) (http.Handler, *http.Cookie) {
	t.Helper()
	a, err := browserauth.New(t.Context(), browserauth.Config{BaseURL: "http://localhost", SessionKey: base64.StdEncoding.EncodeToString(make([]byte, 32)), Demo: true, DemoPassword: "test-login", OwnerSubject: "owner"})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	a.Register(mux)
	mux.Handle("/", g.UI(a, m))
	r := httptest.NewRequest("POST", "/login", strings.NewReader("password=test-login"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return mux, w.Result().Cookies()[0]
}

func formRequest(h http.Handler, cookie *http.Cookie, method, path string, values url.Values) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(values.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestAddConnectionPersistsWithoutPublishingTools(t *testing.T) {
	g, s, _ := fixture(t)
	m, err := upstream.New(g.cfg.BaseURL, g.cfg.Connections, s)
	if err != nil {
		t.Fatal(err)
	}
	h, cookie := adminUI(t, g, m)
	values := url.Values{"id": {"new-server"}, "url": {"https://mcp.example.com/mcp"}, "account": {"Personal"}, "auth": {"bearer"}, "token": {"private-bearer-canary"}}
	if w := formRequest(h, nil, "POST", "/connections", values); w.Code != 303 || w.Header().Get("Location") != "/login" {
		t.Fatal("unauthenticated add accepted")
	}
	r := httptest.NewRequest("POST", "/connections", strings.NewReader(values.Encode()))
	r.AddCookie(cookie)
	r.Header.Set("Origin", "https://attacker.example")
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("cross-origin add accepted")
	}
	w = formRequest(h, cookie, "POST", "/connections", values)
	if w.Code != 303 {
		t.Fatalf("add: %d %s", w.Code, w.Body.String())
	}
	if len(g.tools) != 1 {
		t.Fatal("add published tools")
	}
	var restored Config
	if err := LoadCatalogue(t.Context(), &restored, s); err != nil {
		t.Fatal(err)
	}
	if len(restored.Connections) != 2 || restored.Connections[1].BearerToken != "private-bearer-canary" || !restored.Connections[1].PublicOnly {
		t.Fatal("connection not restored")
	}
	for _, path := range []string{"/", "/connections/new-server/tools"} {
		w := formRequest(h, cookie, "GET", path, nil)
		if w.Code != 200 || strings.Contains(w.Body.String(), "private-bearer-canary") {
			t.Fatal("unsafe connection page")
		}
	}
	w = formRequest(h, cookie, "POST", "/connections", values)
	if w.Code != 400 || strings.Contains(w.Body.String(), "private-bearer-canary") {
		t.Fatal("duplicate accepted or secret reflected")
	}
	values.Set("id", "private")
	values.Set("url", "https://127.0.0.1/mcp")
	if w := formRequest(h, cookie, "POST", "/connections", values); w.Code != 400 {
		t.Fatal("private URL accepted")
	}
}

func TestDiscoverReviewPublishAndRevoke(t *testing.T) {
	g, s, _ := fixture(t)
	remote := mcp.NewServer(&mcp.Implementation{Name: "fixture", Version: "1"}, nil)
	schema := map[string]any{"type": "object", "properties": map[string]any{"text": map[string]any{"type": "string"}}, "required": []string{"text"}}
	add := func(description string) {
		remote.AddTool(&mcp.Tool{Name: "write", Description: description, InputSchema: schema}, func(ctx context.Context, r *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "written"}}}, nil
		})
	}
	add("Write a fixture note")
	server := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return remote }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true}))
	defer server.Close()
	cfg := g.cfg
	cfg.Connections = []upstream.Connection{{ID: "notes", URL: server.URL, NoAuth: true}}
	cfg.Tools = nil
	m, err := upstream.New(cfg.BaseURL, cfg.Connections, s)
	if err != nil {
		t.Fatal(err)
	}
	g, err = New(cfg, s, m)
	if err != nil {
		t.Fatal(err)
	}
	h, cookie := adminUI(t, g, m)
	discover := func() string {
		t.Helper()
		w := formRequest(h, cookie, "POST", "/connections/notes/discover", nil)
		match := regexp.MustCompile(`name="ticket" value="([^"]+)"`).FindStringSubmatch(w.Body.String())
		if w.Code != 200 || len(match) != 2 {
			t.Fatalf("review failed: %d %s", w.Code, w.Body.String())
		}
		return match[1]
	}
	ticket := discover()
	if _, err := g.submit(t.Context(), input("not-yet-enabled", "test")); err == nil {
		t.Fatal("discovery enabled tool without save")
	}
	if g.drafts[ticket].Tools[0].Policy != "" || g.drafts[ticket].Default != "require_approval" {
		t.Fatal("new tool did not inherit approval default")
	}
	save := func(ticket, policy string) *httptest.ResponseRecorder {
		return formRequest(h, cookie, "POST", "/connections/notes/tools", url.Values{"ticket": {ticket}, "default_policy": {"require_approval"}, "policy_0": {policy}})
	}
	if w := save(ticket, "require_approval"); w.Code != 303 {
		t.Fatalf("save: %d %s", w.Code, w.Body.String())
	}
	o, err := g.submit(t.Context(), input("approval-required", "test"))
	if err != nil || o.Status != "pending" {
		t.Fatalf("policy not enforced: %v %v", o, err)
	}
	if w := save(ticket, "allow"); w.Code != 409 {
		t.Fatal("review replay accepted")
	}
	oldTicket := discover()
	if g.drafts[oldTicket].Tools[0].Policy != "require_approval" {
		t.Fatal("unchanged tool lost policy")
	}
	newTicket := discover()
	if w := save(newTicket, "deny"); w.Code != 303 {
		t.Fatal(w.Body.String())
	}
	if w := save(oldTicket, "allow"); w.Code != 409 {
		t.Fatal("stale review overwrote newer policy")
	}
	o, _ = s.Get(t.Context(), "approval-required")
	if o.Status != "denied" {
		t.Fatal("pending request survived policy change")
	}
	if w := save(discover(), "allow"); w.Code != 303 {
		t.Fatal(w.Body.String())
	}
	// A remotely changed description resets permission in the review, without
	// changing the published catalogue until an explicit save.
	add("Changed operation meaning")
	changed := discover()
	if g.drafts[changed].Tools[0].Policy != "require_approval" || g.tools["notes.write"].Policy != "allow" {
		t.Fatal("incorrect drift review behavior")
	}
	if w := save(changed, "require_approval"); w.Code != 303 {
		t.Fatal(w.Body.String())
	}
	if err := LoadCatalogue(t.Context(), &cfg, s); err != nil {
		t.Fatal(err)
	}
	restored, err := New(cfg, s, m)
	if err != nil || restored.tools["notes.write"].Policy != "require_approval" {
		t.Fatal("published policies not restored")
	}
	runWorker(t, restored)
	if _, err := restored.submit(t.Context(), input("approved-runtime", "after restart")); err != nil {
		t.Fatal(err)
	}
	if err := s.Decide(t.Context(), "approved-runtime", "human", true); err != nil {
		t.Fatal(err)
	}
	result := await(t, s, "approved-runtime", "succeeded")
	if !strings.Contains(string(result.Result), "written") {
		t.Fatal("did not execute discovered tool")
	}
	// Uploaded schemas/arguments cannot replace the server-side review snapshot.
	raw, _ := json.Marshal(restored.tools["notes.write"].InputSchema)
	if !strings.Contains(string(raw), "text") {
		t.Fatal("lost pinned schema")
	}
}

func TestRefreshDefaultsExceptionsAndOfflineEditing(t *testing.T) {
	g, s, _ := fixture(t)
	remote := mcp.NewServer(&mcp.Implementation{Name: "fixture", Version: "1"}, nil)
	schema := map[string]any{"type": "object"}
	for _, name := range []string{"blocked", "changed", "new", "unchanged"} {
		description := "original"
		if name == "changed" || name == "blocked" {
			description = "different behavior"
		}
		remote.AddTool(&mcp.Tool{Name: name, Description: description, InputSchema: schema}, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			t.Error("policy editing executed a tool")
			return nil, nil
		})
	}
	server := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return remote }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true}))
	defer server.Close()
	cfg := g.cfg
	cfg.Connections = []upstream.Connection{{ID: "notes", URL: server.URL, NoAuth: true}}
	cfg.ToolDefaults = map[string]string{"notes": "allow"}
	cfg.Tools = nil
	for name, policy := range map[string]string{"blocked": "deny", "changed": "", "unchanged": "allow", "gone": "require_approval"} {
		cfg.Tools = append(cfg.Tools, Tool{ID: "notes." + name, Connection: "notes", Name: name, Description: "original", InputSchema: schema, Policy: policy})
	}
	m, err := upstream.New(cfg.BaseURL, cfg.Connections, s)
	if err != nil {
		t.Fatal(err)
	}
	g, err = New(cfg, s, m)
	if err != nil {
		t.Fatal(err)
	}
	h, cookie := adminUI(t, g, m)
	ticketFrom := func(w *httptest.ResponseRecorder) string {
		t.Helper()
		match := regexp.MustCompile(`name="ticket" value="([^"]+)"`).FindStringSubmatch(w.Body.String())
		if w.Code != 200 || len(match) != 2 {
			t.Fatalf("no edit ticket: %d %s", w.Code, w.Body.String())
		}
		return match[1]
	}
	ticket := ticketFrom(formRequest(h, cookie, "POST", "/connections/notes/discover", nil))
	draft := g.drafts[ticket]
	if len(draft.Removed) != 1 || draft.Removed[0] != "notes.gone" || draft.Changes["notes.new"] != "New" || draft.Changes["notes.changed"] != "Changed" {
		t.Fatal("wrong change summary", draft.Changes, draft.Removed)
	}
	for _, tool := range draft.Tools {
		want := map[string]string{"blocked": "deny", "changed": "require_approval", "new": "", "unchanged": "allow"}[tool.Name]
		if tool.Policy != want {
			t.Fatalf("%s: %q, want %q", tool.Name, tool.Policy, want)
		}
	}
	save := func(ticket, defaultPolicy string) *httptest.ResponseRecorder {
		values := url.Values{"ticket": {ticket}, "default_policy": {defaultPolicy}}
		for i, tool := range g.drafts[ticket].Tools {
			policy := tool.Policy
			if policy == "" {
				policy = "inherit"
			}
			values.Set("policy_"+strconv.Itoa(i), policy)
		}
		return formRequest(h, cookie, "POST", "/connections/notes/tools", values)
	}
	if w := save(ticket, "allow"); w.Code != 303 {
		t.Fatal(w.Body.String())
	}
	if _, ok := g.tools["notes.gone"]; ok {
		t.Fatal("removed tool stayed available")
	}
	if g.tools["notes.new"].Policy != "allow" || g.tools["notes.changed"].Policy != "require_approval" {
		t.Fatal("incorrect effective refresh policies")
	}
	if err := LoadCatalogue(t.Context(), &cfg, s); err != nil {
		t.Fatal(err)
	}
	g, err = New(cfg, s, m)
	if err != nil || g.cfg.ToolDefaults["notes"] != "allow" || g.tools["notes.changed"].Policy != "require_approval" {
		t.Fatal("policies not restored", err)
	}
	h, cookie = adminUI(t, g, m)
	server.Close() // Saved policy edits must not depend on provider availability.
	ticket = ticketFrom(formRequest(h, cookie, "GET", "/connections/notes/tools", nil))
	before := digest(g.catalogue())
	bad := formRequest(h, cookie, "POST", "/connections/notes/tools", url.Values{"ticket": {ticket}, "default_policy": {"deny"}})
	if bad.Code != 400 || digest(g.catalogue()) != before {
		t.Fatal("partial form changed live policy")
	}
	if w := save(ticket, "deny"); w.Code != 303 {
		t.Fatal(w.Body.String())
	}
	if g.tools["notes.new"].Policy != "deny" || g.tools["notes.unchanged"].Policy != "allow" || g.tools["notes.blocked"].Policy != "deny" {
		t.Fatal("default edit lost exceptions")
	}
}

func TestConnectionDefaultExecution(t *testing.T) {
	g, s, b := fixture(t)
	cfg := g.cfg
	cfg.Tools = append([]Tool(nil), cfg.Tools...)
	cfg.Tools[0].Policy = ""
	for _, tc := range []struct{ policy, status string }{{"require_approval", "pending"}, {"allow", "ready"}, {"deny", "denied"}} {
		cfg.ToolDefaults = map[string]string{"notes": tc.policy}
		next, err := New(cfg, s, b)
		if err != nil {
			t.Fatal(err)
		}
		o, err := next.submit(t.Context(), input("default-"+tc.policy, "hello"))
		if err != nil || o.Status != tc.status {
			t.Fatalf("%s: %s, %v", tc.policy, o.Status, err)
		}
	}
	// A legacy explicit block stays blocked even with an allow default.
	cfg.Tools[0].Policy = "deny"
	cfg.ToolDefaults["notes"] = "allow"
	next, err := New(cfg, s, b)
	if err != nil {
		t.Fatal(err)
	}
	if next.tools["notes.write"].Policy != "deny" {
		t.Fatal("default overrode exception")
	}
}

func TestOAuthStatusPage(t *testing.T) {
	for _, tc := range []struct{ status, help, action string }{
		{"Connected", "OAuth credentials saved. Fetch tools to check access", "Reconnect OAuth"},
		{"Not connected", "Connect your provider account", "Connect OAuth"},
		{"Reconnect required", "saved token has expired", "Reconnect OAuth"},
		{"Status unavailable", "Could not read saved credentials", "Reconnect OAuth"},
	} {
		t.Run(tc.status, func(t *testing.T) {
			w := httptest.NewRecorder()
			err := page.Execute(w, map[string]any{"ToolReview": true, "Connection": map[string]any{"ID": "notes", "OAuth": true, "AuthStatus": tc.status}})
			if err != nil {
				t.Fatal(err)
			}
			for _, text := range []string{">" + tc.status + "</span>", tc.help, ">" + tc.action + "</a>", `role="status"`} {
				if !strings.Contains(w.Body.String(), text) {
					t.Fatalf("missing %q", text)
				}
			}
		})
	}
}

func TestCatalogueRejectsExternalSchemaReferences(t *testing.T) {
	g, _, _ := fixture(t)
	cfg := g.cfg
	cfg.Tools = append([]Tool(nil), cfg.Tools...)
	cfg.Tools[0].InputSchema = map[string]any{"$ref": "file:///etc/passwd"}
	if _, err := New(cfg, g.store, g.backend); err == nil {
		t.Fatal("external schema reference accepted")
	}
}
