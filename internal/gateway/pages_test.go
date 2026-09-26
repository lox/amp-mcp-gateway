package gateway

import (
	"strings"
	"testing"

	"ampcode.com/lox/amp-mcp-gateway/internal/upstream"
)

func TestFocusedPages(t *testing.T) {
	g, s, _ := fixture(t)
	m, err := upstream.New(g.cfg.BaseURL, g.cfg.Connections, s)
	if err != nil {
		t.Fatal(err)
	}
	h, cookie := adminUI(t, g, m)
	for _, tc := range []struct{ path, want, absent string }{
		{"/operations", "Nothing needs your approval", "Add MCP"},
		{"/operations?view=all", "No operations yet", "Add MCP"},
		{"/connections", "Add MCP", "Nothing needs your approval"},
		{"/connections/notes/settings", "Connection settings", "Default permission for tools"},
		{"/connections/notes/tools", "Default permission for tools", "Connection settings"},
		{"/audit", "No events yet", "Add MCP"},
		{"/approval-grants", "No standing approvals", "Nothing needs your approval"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			if w := formRequest(h, nil, "GET", tc.path, nil); w.Code != 303 || w.Header().Get("Location") != "/login" {
				t.Fatal("page did not require authentication")
			}
			w := formRequest(h, cookie, "GET", tc.path, nil)
			body := w.Body.String()
			if w.Code != 200 || !strings.Contains(body, tc.want) || strings.Contains(body, tc.absent) || !strings.HasSuffix(body, "</body></html>") {
				t.Fatalf("incorrect page: status=%d, want=%q, absent=%q", w.Code, tc.want, tc.absent)
			}
		})
	}
	if w := formRequest(h, cookie, "GET", "/", nil); w.Code != 303 || w.Header().Get("Location") != "/operations" {
		t.Fatal("home did not redirect to operations")
	}
	if w := formRequest(h, cookie, "GET", "/connections/missing/settings", nil); w.Code != 404 {
		t.Fatal("missing connection did not return 404")
	}

	first, err := g.submit(t.Context(), input("first-request", "first-private-argument"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := g.submit(t.Context(), input("second-request", "second-private-argument"))
	if err != nil {
		t.Fatal(err)
	}
	if w := formRequest(h, cookie, "POST", "/operations/"+first.ID+"/deny", nil); w.Code != 303 {
		t.Fatal("could not deny request")
	}
	pending := formRequest(h, cookie, "GET", "/operations", nil).Body.String()
	all := formRequest(h, cookie, "GET", "/operations?view=all", nil).Body.String()
	if strings.Contains(pending, first.ID) || !strings.Contains(pending, second.ID) || !strings.Contains(all, first.ID) || strings.Contains(all, "private-argument") {
		t.Fatal("operation views did not filter or exposed payloads")
	}
	review := formRequest(h, cookie, "GET", "/operations/"+first.ID, nil).Body.String()
	if !strings.Contains(review, `href="/operations/`+second.ID+`">Review next request`) || !strings.Contains(review, "Request history") || !strings.Contains(review, "<td>denied</td>") {
		t.Fatal("review lost the next request or request history")
	}
	if strings.Count(review, "<td>pending</td>") != 1 {
		t.Fatal("request history included another operation")
	}
}
