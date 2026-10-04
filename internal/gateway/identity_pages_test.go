package gateway

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"ampcode.com/lox/amp-mcp-gateway/internal/browserauth"
	"ampcode.com/lox/amp-mcp-gateway/internal/store"
	"ampcode.com/lox/amp-mcp-gateway/internal/upstream"
)

func TestIdentityNamesOnApprovalAndAuditPages(t *testing.T) {
	g, s, _ := fixture(t)
	g.cfg.AmpUserID = "user-alice"
	names := browserauth.ProjectNames{WorkspaceID: "workspace-one", WorkspaceName: "Example team", Projects: map[string]string{"project-one": "team/gateway"}}
	g.ProjectNames = func(context.Context) browserauth.ProjectNames { return names }
	identity := ampIdentity{Subject: "amp:user-alice", UserID: "user-alice", WorkspaceID: "workspace-one", ProjectID: "project-one", ThreadID: "T-01a0b6d8-e50f-7723-941c-60bca63723ba"}
	for _, id := range []string{"review-names", "standing-source"} {
		if _, err := g.submit(withAmpIdentity(t.Context(), identity), input(id, id)); err != nil {
			t.Fatal(err)
		}
	}
	m, err := upstream.New(g.cfg.BaseURL, g.cfg.Connections, s)
	if err != nil {
		t.Fatal(err)
	}
	h, cookie := adminUI(t, g, m)
	// Signed fixture session, using adminUI's disposable key. Exercise the real
	// auth middleware and both full-page and fragment rendering paths.
	payload, _ := json.Marshal(map[string]any{"s": "user-alice", "e": time.Now().Add(time.Hour).Unix(), "p": browserauth.Profile{Name: "Alice Example"}})
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, make([]byte, 32))
	_, _ = mac.Write([]byte(encoded))
	cookie.Value = encoded + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	approved := formRequest(h, cookie, "POST", "/operations/standing-source/approve", url.Values{"remember": {"on"}, "breadth": {"exact"}, "scope": {"project"}, "expiry": {"never"}})
	if approved.Code != 303 {
		t.Fatal("could not save project approval")
	}
	for _, path := range []string{"/operations/review-names", "/approval-grants"} {
		w := formRequest(h, cookie, "GET", path, nil)
		for _, want := range []string{"team/gateway", "project-one", "Example team", "workspace-one"} {
			if w.Code != 200 || !strings.Contains(w.Body.String(), want) {
				t.Fatalf("%s missing %q", path, want)
			}
		}
	}
	// Renames and failed lookups only change display, never the grant identity.
	names.Projects["project-one"] = "team/<Renamed>"
	if body := formRequest(h, cookie, "GET", "/approval-grants", nil).Body.String(); !strings.Contains(body, "team/&lt;Renamed&gt;") || strings.Contains(body, "team/<Renamed>") {
		t.Fatal("renamed project was not escaped")
	}
	names.WorkspaceID = "different-workspace"
	if body := formRequest(h, cookie, "GET", "/operations/review-names", nil).Body.String(); strings.Contains(body, "Renamed") || !strings.Contains(body, "project-one") {
		t.Fatal("label matched the project ID but not its workspace")
	}
	names = browserauth.ProjectNames{WorkspaceID: "workspace-one", WorkspaceName: "Example team", Projects: map[string]string{"project-one": "team/gateway"}}
	grants, err := s.ApprovalGrants(t.Context())
	if err != nil || len(grants) != 1 || grants[0].AmpProjectID != "project-one" || grants[0].AmpWorkspaceID != "workspace-one" {
		t.Fatal("display lookup changed grant identity")
	}
	if _, err := s.Submit(t.Context(), store.Operation{ID: "other-actor", AmpUserID: "user-bob", Status: "pending", Created: time.Now().Unix(), Expires: time.Now().Add(time.Hour).Unix()}); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/audit?period=all", "/audit?view=events", "/operations/standing-source"} {
		for _, fragment := range []bool{false, true} {
			r := httptest.NewRequest("GET", path, nil)
			r.AddCookie(cookie)
			if fragment {
				r.Header.Set("HX-Request", "true")
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			body := w.Body.String()
			if w.Code != 200 || !strings.Contains(body, "Alice Example") || !strings.Contains(body, "amp:user-alice") {
				t.Fatalf("%s fragment=%t lost display name or original ID", path, fragment)
			}
			if strings.Contains(body, "<strong>Alice Example</strong><br>amp:user-bob") {
				t.Fatal("unknown actor was attributed to the logged-in user")
			}
			if _, other, found := strings.Cut(body, `data-request-id="other-actor"`); found {
				other, _, _ = strings.Cut(other, "</details>")
				if strings.Contains(other, "Alice Example") || !strings.Contains(other, "amp:user-bob") {
					t.Fatal("other actor's audit entry used the current profile")
				}
			}
		}
	}
	if os.Getenv("AMP_NAMES_PREVIEW") == "1" {
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/fixture/login" {
				http.SetCookie(w, cookie)
				http.Redirect(w, r, "/operations/review-names", http.StatusSeeOther)
				return
			}
			h.ServeHTTP(w, r)
		}))
		server.Listener.Close()
		server.Listener, err = net.Listen("tcp", "127.0.0.1:8096")
		if err != nil {
			t.Fatal(err)
		}
		server.Start()
		defer server.Close()
		t.Log("Names fixture ready on loopback :8096/fixture/login")
		time.Sleep(30 * time.Minute)
	}
}
