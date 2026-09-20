package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestToolSearchBoundsAndSemantics(t *testing.T) {
	g, _, _ := fixture(t)
	first := g.tools["notes.write"]
	first.Description = "Write café notes"
	g.tools[first.ID] = first
	second := first
	second.ID = "notes.read"
	second.Description = "Read café notes"
	g.tools[second.ID] = second
	denied := first
	denied.ID, denied.Policy = "notes.secret", "deny"
	g.tools[denied.ID] = denied
	server := httptest.NewServer(g.MCP("fixture-search-token"))
	defer server.Close()
	client := mcp.NewClient(&mcp.Implementation{Name: "search-test", Version: "1"}, nil)
	session, err := client.Connect(t.Context(), &mcp.StreamableClientTransport{Endpoint: server.URL, HTTPClient: &http.Client{Transport: bearer{"fixture-search-token"}}, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	terms := []string{}
	for i := range 33 {
		terms = append(terms, fmt.Sprintf("word%d", i))
	}
	for _, tc := range []struct {
		name, query string
		wantError   bool
		want        string
	}{
		{"repeated attack", strings.Repeat("missing ", 4096), true, ""},
		{"term count", strings.Join(terms, " "), true, ""},
		{"byte boundary", strings.Repeat("x", 1024), false, ""},
		{"byte overflow", strings.Repeat("x", 1025), true, ""},
		{"UTF-8 overflow", strings.Repeat("雪", 342), true, ""},
		{"term boundary", strings.Join(terms[:32], " "), false, ""},
		{"duplicates", strings.Repeat("NoTeS ", 50), false, "notes.read,notes.write"},
		{"Unicode", " CAFÉ\u2003NOTES ", false, "notes.read,notes.write"},
		{"AND", "notes write", false, "notes.write"},
		{"missing term", "notes absent write", false, ""},
		{"empty", "", false, "notes.read,notes.write"},
		{"whitespace", " \t\u2003", false, "notes.read,notes.write"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			found, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "find_tools", Arguments: map[string]any{"query": tc.query}})
			if err != nil || found.IsError != tc.wantError {
				t.Fatalf("error=%v, want tool error=%t", err, tc.wantError)
			}
			if tc.wantError {
				return
			}
			raw, err := json.Marshal(found.StructuredContent)
			if err != nil {
				t.Fatal(err)
			}
			var out struct{ Tools []Tool }
			if err := json.Unmarshal(raw, &out); err != nil {
				t.Fatal(err)
			}
			ids := []string{}
			for _, tool := range out.Tools {
				if tool.InputSchema == nil || tool.Policy != "require_approval" {
					t.Fatal("lost schema or permission policy")
				}
				ids = append(ids, tool.ID)
			}
			if strings.Join(ids, ",") != tc.want {
				t.Fatalf("matched %v, want %s", ids, tc.want)
			}
		})
	}
	// The byte cap applies after JSON escape decoding, before waiting on a writer.
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	g.mu.Lock()
	found, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "find_tools", Arguments: json.RawMessage(`{"query":"` + strings.Repeat(`\u0061`, 1025) + `"}`)})
	g.mu.Unlock()
	if err != nil || !found.IsError {
		t.Fatalf("escaped oversized query waited for catalogue lock: %v", err)
	}
}
