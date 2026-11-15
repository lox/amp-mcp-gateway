package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
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

func TestTrustApprovalForm(t *testing.T) {
	for _, tc := range []struct {
		name   string
		values url.Values
		status int
		grant  string // breadth:scope:expiry of the saved grant, if any
	}{
		{"approve once", url.Values{"trust": {"once"}}, 303, ""},
		{"no trust field approves once", nil, 303, ""},
		{"thread trusts the connection forever", url.Values{"trust": {"thread"}}, 303, "connection:thread:never"},
		{"project trusts the connection forever", url.Values{"trust": {"project"}}, 303, "connection:project:never"},
		{"thread trusts the tool forever", url.Values{"trust": {"thread-tool"}}, 303, "tool:thread:never"},
		{"project trusts the tool forever", url.Values{"trust": {"project-tool"}}, 303, "tool:project:never"},
		{"a stale page's exact 24-hour choice is refused, not widened", url.Values{"trust": {"thread"}, "arguments": {"exact"}, "expiry": {"24h"}}, 400, ""},
		{"a stale page's tool choice is refused", url.Values{"trust": {"project"}, "covers": {"tool"}}, 400, ""},
		{"stale fields do not block approve once", url.Values{"trust": {"once"}, "arguments": {"exact"}, "expiry": {"24h"}}, 303, ""},
		{"unknown trust", url.Values{"trust": {"connection"}}, 400, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g, s, _ := fixture(t)
			g.cfg.AmpUserID = "user-owner"
			ctx := withAmpIdentity(t.Context(), ampIdentity{Subject: "amp:user-owner", UserID: "user-owner", ThreadID: "T-01a0b6d8-e50f-7723-941c-60bca63723ba", ProjectID: "project"})
			o, err := g.submit(ctx, input("trust-form", "exact text"))
			if err != nil {
				t.Fatal(err)
			}
			h, cookie := adminUI(t, g, nil)
			w := formRequest(h, cookie, "POST", "/operations/"+o.ID+"/approve", tc.values)
			if w.Code != tc.status {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
			grants, err := s.ApprovalGrants(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			got := ""
			if len(grants) == 1 && grants[0].Connection == o.Connection && (grants[0].Breadth == "connection") == (grants[0].Tool == "") && (grants[0].Tool == "" || grants[0].Tool == o.Tool) {
				got = grants[0].Breadth + ":" + grants[0].Scope + ":" + grants[0].Expiry
			}
			if got != tc.grant || len(grants) > 1 || (tc.grant == "" && len(grants) != 0) {
				t.Fatalf("grants = %+v, want %q", grants, tc.grant)
			}
			op, err := s.Get(t.Context(), o.ID)
			if err != nil {
				t.Fatal(err)
			}
			want := "pending"
			if tc.status == 303 {
				want = "ready"
			}
			if op.Status != want {
				t.Fatalf("operation = %s, want %s", op.Status, want)
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
