package gateway

import (
	"strings"
	"testing"

	"ampcode.com/lox/amp-mcp-gateway/internal/upstream"
)

func TestFocusedPages(t *testing.T) {
	g, s, _ := fixture(t)
	g.cfg.Connections = append(g.cfg.Connections, upstream.Connection{ID: "browser", Account: "Selected Chrome tab", Browser: true})
	m, err := upstream.New(g.cfg.BaseURL, g.cfg.Connections, s)
	if err != nil {
		t.Fatal(err)
	}
	h, cookie := adminUI(t, g, m)
	for _, tc := range []struct{ path, want, absent string }{
		{"/operations", "Nothing needs your approval", "Add MCP"},
		{"/integrations", "Fly.io", "Nothing needs your approval"},
		{"/integrations/fly", "Connect Fly.io", "Nothing needs your approval"},
		{"/connections", "Add MCP", "Nothing needs your approval"},
		{"/integrations", "Set up Chrome", "Add MCP"},
		{"/connections/notes/settings", "Connection settings", "Default permission for tools"},
		{"/connections/notes/tools", "Default permission for tools", "Connection settings"},
		{"/audit", "No matching requests", "Add MCP"},
		{"/audit?view=events", "No events yet", "Add MCP"},
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
	if w := formRequest(h, cookie, "GET", "/operations?view=all", nil); w.Code != 303 || w.Header().Get("Location") != "/audit" {
		t.Fatal("retired all-operations view did not redirect to audit")
	}
	if w := formRequest(h, cookie, "GET", "/connections/missing/settings", nil); w.Code != 404 {
		t.Fatal("missing connection did not return 404")
	}
	if body := formRequest(h, cookie, "GET", "/connections", nil).Body.String(); strings.Contains(body, "Selected Chrome tab") {
		t.Fatal("native browser integration appeared in remote MCP connections")
	}

	first, err := g.submit(t.Context(), input("first-request", "first-private-argument"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := g.submit(t.Context(), input("second-request", "second-private-argument"))
	if err != nil {
		t.Fatal(err)
	}
	oneOff := formRequest(h, cookie, "GET", "/operations/"+second.ID, nil).Body.String()
	if !strings.Contains(oneOff, ">Approve once</button>") || !strings.Contains(oneOff, ">Deny</button>") || strings.Contains(oneOff, "Remember this approval") {
		t.Fatal("request without verified Amp thread identity offered reusable approval controls")
	}
	if w := formRequest(h, cookie, "POST", "/operations/"+first.ID+"/deny", nil); w.Code != 303 {
		t.Fatal("could not deny request")
	}
	pending := formRequest(h, cookie, "GET", "/operations", nil).Body.String()
	if strings.Contains(pending, first.ID) || !strings.Contains(pending, second.ID) || strings.Contains(pending, "All operations") || strings.Contains(pending, "private-argument") {
		t.Fatal("approvals view did not filter or exposed payloads")
	}
	review := formRequest(h, cookie, "GET", "/operations/"+first.ID, nil).Body.String()
	if !strings.Contains(review, `href="/operations/`+second.ID+`">Review next request`) || !strings.Contains(review, `href="/audit" aria-current="page"`) || !strings.Contains(review, `href="/audit">← Audit`) || !strings.Contains(review, "Request history") || !strings.Contains(review, "<td>denied</td>") {
		t.Fatal("review lost the next request or request history")
	}
	if strings.Count(review, "<td>pending</td>") != 1 {
		t.Fatal("request history included another operation")
	}
	g.cfg.AmpUserID = "user-owner"
	identity := ampIdentity{Subject: "amp:user-owner", UserID: "user-owner", WorkspaceID: "workspace-one", ProjectID: "project-one", ThreadID: "T-01a0b6d8-e50f-7723-941c-60bca63723ba"}
	remembered, err := g.submit(withAmpIdentity(t.Context(), identity), input("remember-request", "remember-private-argument"))
	if err != nil {
		t.Fatal(err)
	}
	rememberReview := formRequest(h, cookie, "GET", "/operations/"+remembered.ID, nil).Body.String()
	if !strings.Contains(rememberReview, `href="/operations" aria-current="page"`) || !strings.Contains(rememberReview, `href="/operations">← Approvals`) {
		t.Fatal("pending request did not return to approvals")
	}
	for _, want := range []string{`name="remember" value="on"`, `name="breadth"`, `value="exact"`, `value="tool"`, `value="connection"`, `name="scope"`, `value="thread"`, `value="project"`, `name="expiry"`, `value="never"`, `value="1h"`, `value="24h"`, "Same tool + same arguments", "This thread", "Until revoked", "Approve & remember"} {
		if !strings.Contains(rememberReview, want) {
			t.Fatalf("remember approval review missing %q", want)
		}
	}
}
