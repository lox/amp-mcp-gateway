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
