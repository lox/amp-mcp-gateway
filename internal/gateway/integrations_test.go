package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	flytoken "ampcode.com/lox/amp-mcp-gateway/internal/fly"
	"ampcode.com/lox/amp-mcp-gateway/internal/upstream"
	"github.com/superfly/macaroon"
	"github.com/superfly/macaroon/flyio"
)

func gatewayFlyToken(t *testing.T) string {
	t.Helper()
	m, err := macaroon.New([]byte("gateway-fixture"), flyio.LocationPermission, macaroon.SigningKey(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := m.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return macaroon.ToAuthorizationHeader(raw)
}

func TestFlyIntegrationSetupAndCredentialLease(t *testing.T) {
	g, s, _ := fixture(t)
	m, err := upstream.New(g.cfg.BaseURL, g.cfg.Connections, s)
	if err != nil {
		t.Fatal(err)
	}
	h, cookie := adminUI(t, g, m)
	parent := gatewayFlyToken(t)
	values := url.Values{"account": {"Fixture Fly app"}, "token": {parent}, "policy": {"require_approval"}}
	if w := formRequest(h, nil, "POST", "/integrations/fly", values); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login" {
		t.Fatal("unauthenticated integration setup accepted")
	}
	r := httptest.NewRequest("POST", "/integrations/fly", strings.NewReader(values.Encode()))
	r.AddCookie(cookie)
	r.Header.Set("Origin", "https://attacker.example")
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatal("cross-origin integration setup accepted")
	}
	w = formRequest(h, cookie, "POST", "/integrations/fly", values)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/integrations/fly?saved=1" {
		t.Fatalf("save: %d %s", w.Code, w.Body.String())
	}
	invalid := formRequest(h, cookie, "POST", "/integrations/fly", url.Values{"account": {"Fixture Fly app"}, "policy": {"invalid"}})
	if invalid.Code != http.StatusBadRequest || !strings.Contains(invalid.Body.String(), "Disconnect Fly.io") {
		t.Fatalf("configured state lost after invalid edit: %d %s", invalid.Code, invalid.Body.String())
	}
	for _, path := range []string{"/integrations", "/integrations/fly", "/operations", "/audit"} {
		page := formRequest(h, cookie, "GET", path, nil)
		if page.Code != http.StatusOK || strings.Contains(page.Body.String(), parent) {
			t.Fatalf("integration credential exposed on %s", path)
		}
	}
	var restored Config
	if err := LoadCatalogue(t.Context(), &restored, s); err != nil {
		t.Fatal(err)
	}
	if len(restored.Integrations) != 1 || restored.Integrations[0].Credential != parent || restored.Tools[1].ID != "fly.request_token" {
		t.Fatalf("Fly integration not restored: %#v %#v", restored.Integrations, restored.Tools)
	}
	var request callInput
	request.RequestID = "fly-lease-request"
	request.Calls = append(request.Calls, struct {
		ToolID    string         `json:"tool_id"`
		Arguments map[string]any `json:"arguments"`
	}{ToolID: "fly.request_token", Arguments: map[string]any{"duration_seconds": 600, "purpose": "deploy the reviewed build"}})
	o, err := g.submit(t.Context(), request)
	if err != nil || o.Status != "pending" {
		t.Fatalf("submit: %#v, %v", o, err)
	}
	if err := s.Decide(t.Context(), o.ID, "owner", true); err != nil {
		t.Fatal(err)
	}
	runWorker(t, g)
	o = await(t, s, o.ID, "succeeded")
	if strings.Contains(string(o.Result), parent) {
		t.Fatal("parent token returned through MCP")
	}
	var result struct {
		Structured struct {
			RedemptionURL string `json:"redemption_url"`
		} `json:"structuredContent"`
	}
	if err := json.Unmarshal(o.Result, &result); err != nil || result.Structured.RedemptionURL == "" {
		t.Fatalf("missing redemption URL: %s, %v", o.Result, err)
	}
	redeemURL, err := url.Parse(result.Structured.RedemptionURL)
	if err != nil {
		t.Fatal(err)
	}
	leaseMux := http.NewServeMux()
	leaseMux.Handle("POST /leases/{id}", g.Leases("gateway-test-token"))
	unauthorized := httptest.NewRecorder()
	leaseMux.ServeHTTP(unauthorized, httptest.NewRequest("POST", redeemURL.Path, nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatal("unauthenticated redemption accepted")
	}
	redeem := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", redeemURL.Path, nil)
		r.Header.Set("Authorization", "Bearer gateway-test-token")
		w := httptest.NewRecorder()
		leaseMux.ServeHTTP(w, r)
		return w
	}
	issued := redeem()
	if issued.Code != http.StatusOK || issued.Header().Get("Cache-Control") != "no-store" || issued.Body.String() == parent {
		t.Fatalf("redemption: %d %s", issued.Code, issued.Body.String())
	}
	permission, _, err := flyio.ParsePermissionAndDischargeTokens(issued.Body.String())
	if err != nil {
		t.Fatal(err)
	}
	child, err := macaroon.Decode(permission)
	if err != nil {
		t.Fatal(err)
	}
	windows := macaroon.GetCaveats[*macaroon.ValidityWindow](&child.UnsafeCaveats)
	if len(windows) != 1 || time.Unix(windows[0].NotAfter, 0).After(time.Now().Add(11*time.Minute)) {
		t.Fatalf("child token lifetime not bounded: %#v", windows)
	}
	if second := redeem(); second.Code != http.StatusGone {
		t.Fatal("redemption URL was not single-use")
	}
}

func TestFlyCredentialChangeInvalidatesUnredeemedLease(t *testing.T) {
	g, s, b := fixture(t)
	parent := gatewayFlyToken(t)
	integration := Integration{ID: flyIntegrationID, Provider: "fly", Account: "Fixture", Credential: parent}
	g.cfg.Integrations = []Integration{integration}
	g.cfg.Tools = append(g.cfg.Tools, flyTool("allow"))
	var err error
	g, err = New(g.cfg, s, b)
	if err != nil {
		t.Fatal(err)
	}
	result, err := g.callIntegration(operationContext{Context: t.Context()}, integration, flyRequestToken, map[string]any{"duration_seconds": 600, "purpose": "test invalidation"})
	if err != nil {
		t.Fatal(err)
	}
	redeemURL, err := url.Parse(result.StructuredContent.(map[string]any)["redemption_url"].(string))
	if err != nil {
		t.Fatal(err)
	}
	replacement, err := flytoken.Attenuate(parent, time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	g.cfg.Integrations[0].Credential = replacement

	mux := http.NewServeMux()
	mux.Handle("POST /leases/{id}", g.Leases("gateway-test-token"))
	redeem := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", redeemURL.Path, nil)
		r.Header.Set("Authorization", "Bearer gateway-test-token")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	if w := redeem(); w.Code != http.StatusGone {
		t.Fatalf("lease survived credential replacement: %d %s", w.Code, w.Body.String())
	}
	g.cfg.Integrations[0].Credential = parent
	if w := redeem(); w.Code != http.StatusGone {
		t.Fatal("invalidated lease became usable after restoring the credential")
	}
}

func TestFlyPolicyCanUseAgentProposalFlow(t *testing.T) {
	g, s, b := fixture(t)
	g.cfg.Integrations = []Integration{{ID: flyIntegrationID, Provider: "fly", Account: "Fixture", Credential: gatewayFlyToken(t)}}
	g.cfg.Tools = append(g.cfg.Tools, flyTool("require_approval"))
	var err error
	g, err = New(g.cfg, s, b)
	if err != nil {
		t.Fatal(err)
	}
	m, err := upstream.New(g.cfg.BaseURL, g.cfg.Connections, s)
	if err != nil {
		t.Fatal(err)
	}
	h, cookie := adminUI(t, g, m)
	proposal, err := g.proposePolicies(t.Context(), policyInput{Changes: []policyChange{{Connection: flyIntegrationID, Tools: map[string]string{"fly.request_token": "deny"}}}})
	if err != nil {
		t.Fatal(err)
	}
	reviewURL, err := url.Parse(proposal.ReviewURL)
	if err != nil {
		t.Fatal(err)
	}
	if w := formRequest(h, cookie, "POST", reviewURL.Path+"/apply", nil); w.Code != http.StatusSeeOther {
		t.Fatalf("apply proposal: %d %s", w.Code, w.Body.String())
	}
	if g.tools["fly.request_token"].Policy != "deny" {
		t.Fatal("Fly policy proposal was not applied")
	}
}
