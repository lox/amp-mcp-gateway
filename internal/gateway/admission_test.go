package gateway

import (
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"

	"ampcode.com/lox/amp-mcp-gateway/internal/store"
	"ampcode.com/lox/amp-mcp-gateway/internal/upstream"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestProposalAdmissionPreservesExistingDecisions(t *testing.T) {
	for _, decision := range []string{"apply", "discard"} {
		t.Run(decision, func(t *testing.T) {
			g, _, _ := fixture(t)
			path := filepath.Join(t.TempDir(), "capacity.db")
			s, err := store.Open(path, base64.StdEncoding.EncodeToString(make([]byte, 32)))
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			g.store = s
			in := policyInput{Changes: []policyChange{{Connection: "notes", Default: "deny"}}}
			proposal, err := g.proposePolicies(t.Context(), in)
			if err != nil {
				t.Fatal(err)
			}
			db, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			// Represent durable history from earlier proposal batches or restarts.
			if _, err := db.Exec(`WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<49999)
INSERT INTO events(operation,kind,actor,time) SELECT '', 'policy-proposed', 'fixture', 0 FROM n`); err != nil {
				t.Fatal(err)
			}
			for range 3 {
				if _, err := g.proposePolicies(t.Context(), in); !errors.Is(err, store.ErrCapacity) {
					t.Fatal("proposal bypassed durable admission", err)
				}
			}
			if len(g.proposals) != 1 {
				t.Fatal("rejected proposal published a ticket")
			}
			var count int
			if err := db.QueryRow("SELECT count(*) FROM events").Scan(&count); err != nil || count != 50000 {
				t.Fatal("rejected proposals grew history", err)
			}
			m, err := upstream.New(g.cfg.BaseURL, g.cfg.Connections, s)
			if err != nil {
				t.Fatal(err)
			}
			h, cookie := adminUI(t, g, m)
			u, err := url.Parse(proposal.ReviewURL)
			if err != nil {
				t.Fatal(err)
			}
			if w := formRequest(h, cookie, "POST", u.Path+"/"+decision, nil); w.Code != 303 {
				t.Fatalf("capacity blocked %s: %d", decision, w.Code)
			}
			if len(g.proposals) != 0 {
				t.Fatal("decision did not consume existing proposal")
			}
		})
	}
}

func TestMCPRejectsUnadmittedOperations(t *testing.T) {
	g, s, backend := fixture(t)
	for i := range 16 {
		if _, err := g.submit(t.Context(), input(fmt.Sprintf("pending-%d", i), "fixture")); err != nil {
			t.Fatal(err)
		}
	}
	server := httptest.NewServer(g.MCP("capacity-fixture"))
	defer server.Close()
	client := mcp.NewClient(&mcp.Implementation{Name: "capacity-test", Version: "1"}, nil)
	session, err := client.Connect(t.Context(), &mcp.StreamableClientTransport{Endpoint: server.URL, HTTPClient: &http.Client{Transport: bearer{"capacity-fixture"}}, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	result, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "call_tools", Arguments: input("excess", "fixture")})
	if err != nil || !result.IsError {
		t.Fatal("capacity did not return an MCP tool error", err)
	}
	if _, err := s.Get(t.Context(), "excess"); !errors.Is(err, sql.ErrNoRows) || backend.calls.Load() != 0 {
		t.Fatal("unadmitted operation was retained or dispatched")
	}
}
