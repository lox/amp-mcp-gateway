package gateway

import (
	"encoding/base64"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"ampcode.com/lox/amp-mcp-gateway/internal/browserauth"
	"ampcode.com/lox/amp-mcp-gateway/internal/store"
	"ampcode.com/lox/amp-mcp-gateway/internal/upstream"
)

func TestAuditHistoryRenderingAndFilters(t *testing.T) {
	g, s, _ := fixture(t)
	for i, status := range []string{"succeeded", "failed", "unknown"} {
		o := store.Operation{ID: fmt.Sprintf("audit-%d", i), Tool: "notes.<unsafe>", Connection: "notes", Account: "Personal notes", Subject: "owner", Status: "ready", Created: time.Now().Unix(), Expires: time.Now().Add(time.Hour).Unix(), Arguments: map[string]any{"secret": "private-argument"}}
		if i == 0 {
			o.AmpUserID = "user_audit"
		}
		if _, err := s.Submit(t.Context(), o); err != nil {
			t.Fatal(err)
		}
		claimed, err := s.Claim(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Finish(t.Context(), claimed, status, []byte(`{"text":"private-result"}`)); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		query string
		count int
	}{
		{"", 3}, {"?outcome=investigate", 2}, {"?outcome=failed", 1},
		{"?outcome=failed&preset=all", 3}, {"?outcome=succeeded&preset=investigate", 2},
		{"?q=AUDIT-1&connection=notes", 1}, {"?connection=removed", 0}, {"?q=private-argument", 0},
	} {
		w := httptest.NewRecorder()
		g.audit(w, httptest.NewRequest("GET", "/audit"+tc.query, nil))
		body := w.Body.String()
		if w.Code != 200 || strings.Count(body, `<details class="audit-entry"`) != tc.count || !strings.HasSuffix(strings.TrimSpace(body), "</body></html>") {
			t.Fatalf("%s: incomplete/wrong result %d", tc.query, w.Code)
		}
		if strings.Contains(body, "<style") || !strings.Contains(body, `href="/assets/ui.css"`) {
			t.Fatal("audit must use the shared compiled stylesheet")
		}
		if w.Header().Get("Cache-Control") != "no-store" || strings.Contains(body, "private-result") || strings.Contains(body, "notes.<unsafe>") {
			t.Fatal("sensitive payload, unsafe HTML or cacheable response")
		}
		if tc.query != "?q=private-argument" && strings.Contains(body, "private-argument") {
			t.Fatal("argument leaked into history")
		}
		r := httptest.NewRequest("GET", "/audit"+tc.query, nil)
		r.Header.Set("HX-Request", "true")
		fragment := httptest.NewRecorder()
		g.audit(fragment, r)
		if fragment.Code != 200 || strings.Count(fragment.Body.String(), `<details class="audit-entry"`) != tc.count || strings.Contains(fragment.Body.String(), "<html") || strings.Contains(fragment.Body.String(), "<form") || fragment.Header().Get("Vary") != "HX-Request" {
			t.Fatalf("incorrect filtered live fragment for %s", tc.query)
		}
		if tc.count == 3 {
			for _, want := range []string{"Execution may already have happened.", "Allowed by policy", "notes.&lt;unsafe&gt;", "The upstream reported an error.", "/operations/audit-1", "Verified user", "amp:user_audit"} {
				if !strings.Contains(body, want) {
					t.Fatalf("missing %q", want)
				}
			}
		}
	}
	for _, query := range []string{"?zone=invalid", "?period=bad", "?outcome=bad", "?before=123", "?before_id=a", "?before=-1&before_id=a", "?until=bad", "?until=999999999999", "?q=" + strings.Repeat("a", 257)} {
		w := httptest.NewRecorder()
		g.audit(w, httptest.NewRequest("GET", "/audit"+query, nil))
		if w.Code != 400 {
			t.Fatalf("invalid query accepted: %s", query)
		}
	}
}

func TestAuditPaginationPreservesFiltersAndTimeWindow(t *testing.T) {
	g, s, _ := fixture(t)
	now := time.Now().Unix()
	for i := range 27 {
		o := store.Operation{ID: fmt.Sprintf("audit-%02d", i), Tool: "notes.write", Connection: "notes", Status: "denied", Created: now - 100}
		if _, err := s.Submit(t.Context(), o); err != nil {
			t.Fatal(err)
		}
	}
	w := httptest.NewRecorder()
	g.audit(w, httptest.NewRequest("GET", "/audit?q=audit&connection=notes&outcome=denied&period=7d&zone=UTC", nil))
	match := regexp.MustCompile(`href="([^"]+)">Older matching requests`).FindStringSubmatch(w.Body.String())
	if len(match) != 2 {
		t.Fatal("missing pagination link")
	}
	next, err := url.Parse(html.UnescapeString(match[1]))
	if err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{"q": "audit", "connection": "notes", "outcome": "denied", "period": "7d", "zone": "UTC", "before_id": "audit-02"} {
		if next.Query().Get(key) != want {
			t.Fatalf("lost %s in cursor", key)
		}
	}
	if next.Query().Get("until") == "" {
		t.Fatal("moving time window")
	}
	w = httptest.NewRecorder()
	g.audit(w, httptest.NewRequest("GET", next.String(), nil))
	if w.Code != 200 || strings.Count(w.Body.String(), `<details class="audit-entry"`) != 2 || strings.Contains(w.Body.String(), "Older matching requests") {
		t.Fatal("incorrect final page")
	}
}

func TestAuditAuthorisationLabels(t *testing.T) {
	for _, tc := range []struct {
		events []store.Event
		want   string
	}{
		{[]store.Event{{Kind: "ready"}}, "Allowed by policy"},
		{[]store.Event{{Kind: "pending"}, {Kind: "ready"}}, "Approved once"},
		{[]store.Event{{Kind: "denied"}}, "Denied by policy"},
		{[]store.Event{{Kind: "pending"}, {Kind: "denied", Actor: "owner"}}, "Denied"},
		{[]store.Event{{Kind: "ready"}, {Kind: "denied", Actor: "connection-reauthorized"}}, "Denied after connection reauthorisation"},
		{[]store.Event{{Kind: "running"}, {Kind: "denied", Actor: "gateway"}}, "Blocked by execution-time policy check"},
		{[]store.Event{{Kind: "pending"}, {Kind: "approval-project"}, {Kind: "ready"}}, "Approved for this request"},
		{[]store.Event{{Kind: "pending"}, {Kind: "approval-thread"}}, "Standing thread approval created"},
		{[]store.Event{{Kind: "ready"}, {Kind: "denied", Actor: "approval-grant-unavailable"}}, "Standing approval expired or revoked"},
		{[]store.Event{{Kind: "lease-redeemed"}}, "Credential lease redeemed"},
	} {
		if got := auditEvent(store.AuditRequest{Events: tc.events}, len(tc.events)-1); got != tc.want {
			t.Fatalf("got %q, want %q", got, tc.want)
		}
	}
	for _, scope := range []string{"thread", "project"} {
		request := store.AuditRequest{Operation: store.OperationSummary{ApprovalScope: scope}, Events: []store.Event{{Kind: "ready"}}}
		if got := auditEvent(request, 0); got != "Allowed by standing "+scope+" approval" {
			t.Fatalf("standing grant confused with allow policy: %q", got)
		}
	}
}

func TestRawAuditRetainsConfigurationEvents(t *testing.T) {
	g, s, _ := fixture(t)
	if err := s.SaveCatalogue(t.Context(), []byte(`{}`), store.Event{Kind: "policy-applied", Actor: "owner"}); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	g.audit(w, httptest.NewRequest("GET", "/audit?view=events", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "policy-applied") || !strings.Contains(w.Body.String(), "<time datetime=") {
		t.Fatal("raw audit hid configuration events or their timestamps")
	}
}

func TestAuditStandingApprovalAttribution(t *testing.T) {
	for _, scope := range []string{"thread", "project"} {
		t.Run(scope, func(t *testing.T) {
			g, s, _ := fixture(t)
			o := store.Operation{ID: "source", Tool: "notes.create", Connection: "notes", Subject: "owner", AmpUserID: "requester", AmpThreadID: "thread", AmpProjectID: "project", Binding: "binding", Status: "pending", Created: time.Now().Unix(), Expires: time.Now().Add(time.Hour).Unix()}
			if _, err := s.Submit(t.Context(), o); err != nil {
				t.Fatal(err)
			}
			if err := s.Approve(t.Context(), o.ID, "original<approver>", scope); err != nil {
				t.Fatal(err)
			}
			o.ID = "consumer"
			consumer, err := s.Submit(t.Context(), o)
			if err != nil || consumer.Status != "ready" {
				t.Fatalf("grant not applied: %+v %v", consumer, err)
			}
			if err := s.RevokeApprovalGrant(t.Context(), consumer.ApprovalGrant, "revoker"); err != nil {
				t.Fatal(err)
			}
			// Replacing the active grant must not change the historical approver.
			o.ID = "replacement"
			if _, err := s.Submit(t.Context(), o); err != nil {
				t.Fatal(err)
			}
			if err := s.Approve(t.Context(), o.ID, "replacement-approver", scope); err != nil {
				t.Fatal(err)
			}
			rows, _, err := s.Audit(t.Context(), store.AuditFilter{Query: "consumer"})
			if err != nil || len(rows) != 1 {
				t.Fatalf("audit: %v", err)
			}
			approval := rows[0].StandingApproval
			if approval == nil || approval.Actor != "original<approver>" || approval.Operation != "source" || approval.Kind != "approval-"+scope || rows[0].Events[0].Actor != "amp:requester" {
				t.Fatalf("lost original authority or changed recorded requester: %+v", rows[0])
			}
			w := httptest.NewRecorder()
			g.audit(w, httptest.NewRequest("GET", "/audit?q=consumer", nil))
			for _, want := range []string{"Requested by Amp caller", "Originally approved by", "original&lt;approver&gt;", `href="/operations/source"`} {
				if !strings.Contains(w.Body.String(), want) {
					t.Fatalf("missing %q", want)
				}
			}
			if strings.Contains(w.Body.String(), "replacement-approver") || strings.Contains(w.Body.String(), "original<approver>") {
				t.Fatal("wrong or unescaped approver")
			}
		})
	}
}

func TestAuditRouteRequiresBrowserAuthentication(t *testing.T) {
	g, s, _ := fixture(t)
	a, err := browserauth.New(t.Context(), browserauth.Config{BaseURL: "http://localhost", SessionKey: base64.StdEncoding.EncodeToString(make([]byte, 32)), Demo: true, DemoPassword: "demo-only", OwnerSubject: "owner"})
	if err != nil {
		t.Fatal(err)
	}
	m, err := upstream.New("http://localhost", g.cfg.Connections, s)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	a.Register(mux)
	mux.Handle("/", g.UI(a, m))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "/audit", nil))
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login" {
		t.Fatal("audit accessible without browser authentication")
	}
	login := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/login", strings.NewReader("password=demo-only"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	mux.ServeHTTP(login, r)
	r = httptest.NewRequest("GET", "/audit", nil)
	r.AddCookie(login.Result().Cookies()[0])
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "No matching requests") {
		t.Fatal("authenticated audit unavailable")
	}
}
