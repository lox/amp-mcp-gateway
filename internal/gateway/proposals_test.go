package gateway

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"ampcode.com/lox/mcp-gateway/internal/upstream"
)

func TestPolicyProposalBatch(t *testing.T) {
	g, s, _ := fixture(t)
	g.cfg.Connections = append(g.cfg.Connections, upstream.Connection{ID: "mail", URL: "http://localhost/mail", NoAuth: true})
	g.cfg.ToolDefaults = map[string]string{"mail": "allow"}
	for _, item := range []struct{ name, policy string }{{"read", ""}, {"send", ""}, {"blocked", "deny"}, {"exception", "require_approval"}} {
		g.cfg.Tools = append(g.cfg.Tools, Tool{ID: "mail." + item.name, Name: item.name, Connection: "mail", Policy: item.policy, InputSchema: map[string]any{"type": "object"}})
	}
	var err error
	g, err = New(g.cfg, s, g.backend)
	if err != nil {
		t.Fatal(err)
	}
	m, err := upstream.New(g.cfg.BaseURL, g.cfg.Connections, s)
	if err != nil {
		t.Fatal(err)
	}
	h, cookie := adminUI(t, g, m)
	before := digest(g.catalogue())
	input := policyInput{Changes: []policyChange{
		{Connection: "mail", Default: "require_approval", Tools: map[string]string{"mail.read": "allow"}},
		{Connection: "notes", Default: "deny"},
	}}
	result, err := g.proposePolicies(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	if digest(g.catalogue()) != before {
		t.Fatal("proposal changed authority")
	}
	u, _ := url.Parse(result.ReviewURL)
	// Ordinary page views and another proposal must not replace the review.
	formRequest(h, cookie, "GET", "/connections/mail/tools", nil)
	if _, err := g.proposePolicies(t.Context(), input); err != nil {
		t.Fatal(err)
	}
	w := formRequest(h, cookie, "GET", u.Path, nil)
	for _, want := range []string{"Allow → Require approval", "Allow → Allow", "Block → Block", "mail.exception", "No verified Amp user", "Apply proposed changes"} {
		if w.Code != 200 || !strings.Contains(w.Body.String(), want) {
			t.Fatalf("missing %q: %d %s", want, w.Code, w.Body.String())
		}
	}
	// Extra form values cannot replace the immutable stored batch.
	w = formRequest(h, cookie, "POST", u.Path+"/apply", url.Values{"default_policy": {"allow"}, "policy_0": {"deny"}, "connection": {"other"}})
	if w.Code != 303 {
		t.Fatal(w.Code, w.Body.String())
	}
	for id, want := range map[string]string{"mail.read": "allow", "mail.send": "require_approval", "mail.blocked": "deny", "mail.exception": "require_approval", "notes.write": "require_approval"} {
		if g.tools[id].Policy != want {
			t.Fatalf("%s = %s, want %s", id, g.tools[id].Policy, want)
		}
	}
	if g.cfg.defaultPolicy("notes") != "deny" {
		t.Fatal("second connection not applied")
	}
	var restored Config
	if err := LoadCatalogue(t.Context(), &restored, s); err != nil || digest(restored.Tools) != digest(g.cfg.Tools) {
		t.Fatal("batch not persisted", err)
	}
	if w := formRequest(h, cookie, "POST", u.Path+"/apply", nil); w.Code != 409 {
		t.Fatal("replay accepted")
	}
	events, err := s.Events(t.Context())
	if err != nil || events[0].Kind != "policy-applied" || !strings.HasPrefix(events[0].Actor, "owner · proposal ") {
		t.Fatal("missing human audit", events, err)
	}
}

func TestPolicyProposalBoundaries(t *testing.T) {
	for _, scenario := range []string{"unauthenticated", "bearer-only", "csrf", "expired", "stale", "cross-connection", "discard", "get-apply"} {
		t.Run(scenario, func(t *testing.T) {
			g, s, _ := fixture(t)
			m, err := upstream.New(g.cfg.BaseURL, g.cfg.Connections, s)
			if err != nil {
				t.Fatal(err)
			}
			h, cookie := adminUI(t, g, m)
			result, err := g.proposePolicies(t.Context(), policyInput{Changes: []policyChange{{Connection: "notes", Tools: map[string]string{"notes.write": "allow"}}}})
			if err != nil {
				t.Fatal(err)
			}
			u, _ := url.Parse(result.ReviewURL)
			ticket := strings.TrimPrefix(u.Path, "/policy-proposals/")
			path, method, want := u.Path+"/apply", "POST", 409
			switch scenario {
			case "unauthenticated", "bearer-only":
				cookie = nil
				want = 303
			case "csrf":
				want = 403
			case "expired":
				p := g.proposals[ticket]
				p.Expires = time.Now().Add(-time.Second)
				g.proposals[ticket] = p
			case "stale":
				g.cfg.Tools[0].Description = "new schema description"
			case "cross-connection":
				path = "/connections/notes/tools"
			case "discard":
				path = u.Path + "/discard"
				want = 303
			case "get-apply":
				method = "GET"
				want = 405
			}
			before := digest(g.catalogue())
			r := httptest.NewRequest(method, path, strings.NewReader(url.Values{"ticket": {ticket}, "default_policy": {"allow"}, "policy_0": {"allow"}}.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if cookie != nil {
				r.AddCookie(cookie)
			}
			if scenario == "csrf" {
				r.Header.Set("Origin", "https://attacker.example")
			}
			if scenario == "bearer-only" {
				r.Header.Set("Authorization", "Bearer agent-token")
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != want || digest(g.catalogue()) != before {
				t.Fatalf("%d want %d or authority changed: %s", w.Code, want, w.Body.String())
			}
			if scenario == "discard" {
				if w := formRequest(h, cookie, "POST", u.Path+"/apply", nil); w.Code != 409 {
					t.Fatal("discarded proposal applied")
				}
			}
		})
	}
}

func TestPolicyProposalValidationAndAttribution(t *testing.T) {
	g, s, _ := fixture(t)
	for _, changes := range [][]policyChange{
		nil, {{Connection: "missing", Default: "allow"}}, {{Connection: "notes", Default: "invalid"}},
		{{Connection: "notes", Tools: map[string]string{"other.write": "allow"}}},
		{{Connection: "notes", Tools: map[string]string{"notes.write": ""}}},
		{{Connection: "notes", Default: "allow"}, {Connection: "notes", Default: "deny"}},
		{{Connection: "notes"}},
	} {
		if _, err := g.proposePolicies(t.Context(), policyInput{Changes: changes}); err == nil {
			t.Fatalf("accepted invalid batch: %v", changes)
		}
	}
	g.cfg.AmpUserID = "verified-user"
	input := policyInput{Changes: []policyChange{{Connection: "notes", Tools: map[string]string{"notes.write": "inherit"}}}}
	if _, err := g.proposePolicies(t.Context(), input); err == nil {
		t.Fatal("missing identity accepted")
	}
	identity := ampIdentity{UserID: "verified-user", ThreadID: "T-00000000-0000-0000-0000-000000000001"}
	result, err := g.proposePolicies(withAmpIdentity(t.Context(), identity), input)
	if err != nil {
		t.Fatal(err)
	}
	m, _ := upstream.New(g.cfg.BaseURL, g.cfg.Connections, s)
	h, cookie := adminUI(t, g, m)
	u, _ := url.Parse(result.ReviewURL)
	w := formRequest(h, cookie, "GET", u.Path, nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Verified Amp user") || !strings.Contains(w.Body.String(), identity.ThreadID) {
		t.Fatal("missing verified attribution", w.Body.String())
	}
	if w := formRequest(h, cookie, "POST", u.Path+"/apply", nil); w.Code != 303 || g.cfg.Tools[0].Policy != "" {
		t.Fatal("inherit did not remove exception")
	}
}

func TestPolicyProposalRunningAndQueuedOperations(t *testing.T) {
	g, s, _ := fixture(t)
	m, err := upstream.New(g.cfg.BaseURL, g.cfg.Connections, s)
	if err != nil {
		t.Fatal(err)
	}
	h, cookie := adminUI(t, g, m)
	o, err := g.submit(t.Context(), input("running-policy-test", "running"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Decide(t.Context(), o.ID, "owner", true); err != nil {
		t.Fatal(err)
	}
	running, err := s.Claim(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	queued, err := g.submit(t.Context(), input("queued-policy-test", "pending"))
	if err != nil {
		t.Fatal(err)
	}
	result, err := g.proposePolicies(t.Context(), policyInput{Changes: []policyChange{{Connection: "notes", Default: "allow"}}})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(result.ReviewURL)
	before := digest(g.catalogue())
	if w := formRequest(h, cookie, "POST", u.Path+"/apply", nil); w.Code != 409 || digest(g.catalogue()) != before {
		t.Fatal("changed running authority")
	}
	events, err := s.Events(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if e.Kind == "policy-applied" {
			t.Fatal("failed save audited as applied")
		}
	}
	if err := s.Finish(t.Context(), running, "succeeded", nil); err != nil {
		t.Fatal(err)
	}
	if w := formRequest(h, cookie, "POST", u.Path+"/apply", nil); w.Code != 303 {
		t.Fatal("retry failed", w.Code)
	}
	got, err := s.Get(t.Context(), queued.ID)
	if err != nil || got.Status != "denied" {
		t.Fatal("queued authority survived", got.Status, err)
	}
}

func TestPolicyProposalCapacity(t *testing.T) {
	g, _, _ := fixture(t)
	in := policyInput{Changes: []policyChange{{Connection: "notes", Default: "allow"}}}
	for range 32 {
		if _, err := g.proposePolicies(t.Context(), in); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := g.proposePolicies(t.Context(), in); err == nil {
		t.Fatal("unbounded proposals")
	}
	for ticket, p := range g.proposals {
		p.Expires = time.Now().Add(-time.Second)
		g.proposals[ticket] = p
	}
	if _, err := g.proposePolicies(t.Context(), in); err != nil || len(g.proposals) != 1 {
		t.Fatal("expired capacity not reclaimed", err)
	}
}

func TestCatalogueSaveConsumesPolicyProposals(t *testing.T) {
	g, s, _ := fixture(t)
	m, err := upstream.New(g.cfg.BaseURL, g.cfg.Connections, s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.proposePolicies(t.Context(), policyInput{Changes: []policyChange{{Connection: "notes", Default: "allow"}}}); err != nil {
		t.Fatal(err)
	}
	g.mu.Lock()
	err = g.saveCatalogue(t.Context(), g.catalogue(), m)
	g.mu.Unlock()
	if err != nil || len(g.proposals) != 0 {
		t.Fatal("identical save resurrects old proposals", err)
	}
}
