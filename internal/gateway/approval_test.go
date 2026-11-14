package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"ampcode.com/lox/amp-mcp-gateway/internal/store"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestExactApprovalPreservesMCPNumbers(t *testing.T) {
	g, s, b := fixture(t)
	g.cfg.Tools[0].InputSchema = map[string]any{"type": "object"}
	var err error
	g, err = New(g.cfg, s, b)
	if err != nil {
		t.Fatal(err)
	}
	g.cfg.Demo = true
	mcpHandler, _ := g.DemoHandlers("number-test")
	server := httptest.NewServer(mcpHandler)
	defer server.Close()
	client := mcp.NewClient(&mcp.Implementation{Name: "number-test", Version: "1"}, nil)
	session, err := client.Connect(t.Context(), &mcp.StreamableClientTransport{Endpoint: server.URL, HTTPClient: &http.Client{Transport: bearer{"number-test"}}, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	result, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "call_tools", Arguments: json.RawMessage(`{"request_id":"large-number","calls":[{"tool_id":"notes.write","arguments":{"id":9007199254740993}}]}`)})
	if err != nil || result.IsError {
		t.Fatalf("call: %v %v", result, err)
	}
	o, err := s.Get(t.Context(), "large-number")
	if err != nil {
		t.Fatal(err)
	}
	if o.Arguments["id"] != json.Number("9007199254740993") {
		t.Fatalf("number changed: %v", o.Arguments["id"])
	}
}

func TestRememberApprovalForm(t *testing.T) {
	for _, tc := range []struct {
		name   string
		values url.Values
		status int
		grants int
	}{
		{"once ignores stale fields", url.Values{"breadth": {"connection"}, "scope": {"project"}, "expiry": {"never"}}, 303, 0},
		{"remember exact", url.Values{"remember": {"on"}, "breadth": {"exact"}, "scope": {"thread"}, "expiry": {"never"}}, 303, 1},
		{"remember connection", url.Values{"remember": {"on"}, "breadth": {"connection"}, "scope": {"project"}, "expiry": {"24h"}}, 303, 1},
		{"missing options", url.Values{"remember": {"on"}}, 400, 0},
		{"invalid expiry", url.Values{"remember": {"on"}, "breadth": {"tool"}, "scope": {"thread"}, "expiry": {"forever"}}, 400, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g, s, _ := fixture(t)
			g.cfg.AmpUserID = "user-owner"
			ctx := withAmpIdentity(t.Context(), ampIdentity{Subject: "amp:user-owner", UserID: "user-owner", ThreadID: "T-01a0b6d8-e50f-7723-941c-60bca63723ba", ProjectID: "project"})
			o, err := g.submit(ctx, input("remember-form", "exact text"))
			if err != nil {
				t.Fatal(err)
			}
			h, cookie := adminUI(t, g, nil)
			w := formRequest(h, cookie, "POST", "/operations/"+o.ID+"/approve", tc.values)
			if w.Code != tc.status {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
			grants, err := s.ApprovalGrants(t.Context())
			if err != nil || len(grants) != tc.grants {
				t.Fatalf("grants = %v: %v", grants, err)
			}
			got, err := s.Get(t.Context(), o.ID)
			if err != nil {
				t.Fatal(err)
			}
			want := "pending"
			if tc.status == 303 {
				want = "ready"
			}
			if got.Status != want {
				t.Fatalf("operation = %s, want %s", got.Status, want)
			}
		})
	}
}

func TestConnectionApprovalCatalogueBinding(t *testing.T) {
	g, s, b := fixture(t)
	g.cfg.AmpUserID = "user-owner"
	second := g.cfg.Tools[0]
	second.ID, second.Name = "notes.delete", "delete"
	g.cfg.Tools = append(g.cfg.Tools, second)
	var err error
	g, err = New(g.cfg, s, b)
	if err != nil {
		t.Fatal(err)
	}
	ctx := withAmpIdentity(t.Context(), ampIdentity{Subject: "amp:user-owner", UserID: "user-owner", ThreadID: "T-01a0b6d8-e50f-7723-941c-60bca63723ba", ProjectID: "project"})
	first, err := g.submit(ctx, input("connection-source", "first"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ApproveWithOptions(t.Context(), first.ID, "owner", store.ApprovalOptions{Breadth: "connection", Scope: "project", Expiry: "never"}); err != nil {
		t.Fatal(err)
	}
	in := input("cross-tool", "different")
	in.Calls[0].ToolID = second.ID
	queued, err := g.submit(ctx, in)
	if err != nil || queued.Status != "ready" {
		t.Fatalf("cross tool = %s: %v", queued.Status, err)
	}
	// Simulate a restart with a newly discovered tool, without relying on the
	// catalogue-save path's eager revocation of grants.
	third := second
	third.ID, third.Name = "notes.new", "new"
	g.cfg.Tools = append(g.cfg.Tools, third)
	g, err = New(g.cfg, s, b)
	if err != nil {
		t.Fatal(err)
	}
	in.RequestID, in.Calls[0].ToolID = "new-tool", third.ID
	fresh, err := g.submit(ctx, in)
	if err != nil || fresh.Status != "pending" {
		t.Fatalf("changed catalogue = %s: %v", fresh.Status, err)
	}
	runWorker(t, g)
	await(t, s, queued.ID, "denied")
	if b.calls.Load() != 0 {
		t.Fatal("old catalogue consent dispatched")
	}
}

func TestReadTrustApprovalFlow(t *testing.T) {
	g, s, b := fixture(t)
	g.cfg.AmpUserID = "user-owner"
	tool := func(name, class, policy string) Tool {
		t := g.cfg.Tools[0]
		t.ID, t.Name, t.Class, t.Policy = "notes."+name, name, class, policy
		return t
	}
	g.cfg.Tools = []Tool{tool("list", "read", "require_approval"), tool("search", "read", "require_approval"), tool("write", "write", "require_approval"), tool("draft", "", "require_approval"), tool("purge", "read", "deny")}
	var err error
	g, err = New(g.cfg, s, b)
	if err != nil {
		t.Fatal(err)
	}
	identity := func(thread string) context.Context {
		return withAmpIdentity(t.Context(), ampIdentity{Subject: "amp:user-owner", UserID: "user-owner", ThreadID: thread, ProjectID: "project"})
	}
	ctx := identity("T-01a0b6d8-e50f-7723-941c-60bca63723ba")
	call := func(ctx context.Context, id, name string) store.Operation {
		t.Helper()
		in := input(id, "query")
		in.Calls[0].ToolID = "notes." + name
		o, err := g.submit(ctx, in)
		if err != nil {
			t.Fatal(err)
		}
		return o
	}
	h, cookie := adminUI(t, g, nil)
	page := func(path string) string {
		t.Helper()
		w := formRequest(h, cookie, "GET", path, nil)
		if w.Code != 200 {
			t.Fatalf("%s: %d", path, w.Code)
		}
		return w.Body.String()
	}
	trust := url.Values{"trust": {"read"}, "scope": {"thread"}, "expiry": {"1h"}}

	call(ctx, "write-request", "write")
	if strings.Contains(page("/operations/write-request"), "allow reads") {
		t.Fatal("a write offered read trust")
	}
	if w := formRequest(h, cookie, "POST", "/operations/write-request/approve", trust); w.Code != 400 {
		t.Fatalf("read trust from a write: %d", w.Code)
	}
	call(ctx, "read-source", "list")
	review := page("/operations/read-source")
	if !strings.Contains(review, "Approve &amp; allow reads in this thread") || !strings.Contains(review, "<code>list</code>, <code>search</code></p>") {
		t.Fatalf("read trust offer missing or lists the wrong tools:\n%s", review)
	}
	never := url.Values{"trust": {"read"}, "scope": {"thread"}, "expiry": {"never"}}
	if w := formRequest(h, cookie, "POST", "/operations/read-source/approve", never); w.Code != 400 {
		t.Fatalf("indefinite read trust: %d", w.Code)
	}
	if w := formRequest(h, cookie, "POST", "/operations/read-source/approve", trust); w.Code != 303 {
		t.Fatalf("grant read trust: %d %s", w.Code, w.Body.String())
	}
	if o := call(ctx, "read-auto", "search"); o.Status != "ready" || o.ApprovalBreadth != "read" {
		t.Fatalf("trusted read = %+v", o)
	}
	for _, name := range []string{"write", "draft"} {
		if o := call(ctx, name+"-after", name); o.Status != "pending" {
			t.Fatalf("%s ran under read trust: %s", name, o.Status)
		}
	}
	if o := call(identity("T-01a0b6d8-e50f-7723-941c-60bca63723bb"), "other-thread", "search"); o.Status != "pending" {
		t.Fatalf("thread trust covered another thread: %s", o.Status)
	}
	if !strings.Contains(page("/operations/read-auto"), "Allowed by your thread read trust") {
		t.Fatal("automatic read does not name its trust")
	}
	if strings.Contains(page("/approval-grants"), "/revoke") {
		t.Fatal("read trust listed as a standing approval")
	}
	grants, err := s.ApprovalGrants(t.Context())
	if err != nil || len(grants) != 1 {
		t.Fatalf("grants = %v: %v", grants, err)
	}
	if manage := page("/read-trust"); !strings.Contains(manage, "/read-trust/"+grants[0].ID+"/revoke") {
		t.Fatalf("read trust page does not offer revocation:\n%s", manage)
	}
	if w := formRequest(h, cookie, "POST", "/read-trust/"+grants[0].ID+"/revoke", nil); w.Code != 303 {
		t.Fatalf("revoke: %d", w.Code)
	}
	if o := call(ctx, "after-revoke", "search"); o.Status != "pending" {
		t.Fatalf("revoked read trust still applied: %s", o.Status)
	}
	if !strings.Contains(page("/audit?period=all"), "Read trust revoked") {
		t.Fatal("audit history does not name the read trust revocation")
	}
}

func TestBrowserToolsHaveFixedClasses(t *testing.T) {
	_, s, b := fixture(t)
	cfg := Config{AmpUserID: "owner", BaseURL: "http://localhost"}
	ConfigureChrome(&cfg)
	g, err := New(cfg, s, b)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"snapshot": "read", "screenshot": "read", "status": "read", "scroll": "write", "click": "high_risk", "type": "high_risk", "navigate": "high_risk"}
	for _, tool := range g.tools {
		if got := g.toolClass(tool); got != want[tool.Name] {
			t.Errorf("%s class = %q, want %q", tool.ID, got, want[tool.Name])
		}
	}
	if g.readTrustAvailable(store.Operation{Class: "read", Connection: "browser", AmpUserID: "owner", AmpThreadID: "thread"}) {
		t.Fatal("browser reads offered read trust")
	}
	for i := range cfg.Tools {
		if cfg.Tools[i].ID == "browser.click" {
			cfg.Tools[i].Class = "read"
		}
	}
	if _, err := New(cfg, s, b); err == nil {
		t.Fatal("browser click was reclassified as Read")
	}
}
