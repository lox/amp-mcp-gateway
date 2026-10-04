package gateway

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	flytoken "ampcode.com/lox/amp-mcp-gateway/internal/fly"
	"ampcode.com/lox/amp-mcp-gateway/internal/store"
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
	g, s, b := fixture(t)
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
	for _, path := range []string{"/integrations", "/integrations/fly", "/approvals", "/audit"} {
		page := formRequest(h, cookie, "GET", path, nil)
		if page.Code != http.StatusOK || strings.Contains(page.Body.String(), parent) {
			t.Fatalf("integration credential exposed on %s", path)
		}
	}
	restored := g.cfg
	if err := LoadCatalogue(t.Context(), &restored, s); err != nil {
		t.Fatal(err)
	}
	if len(restored.Integrations) != 1 || restored.Integrations[0].Credential != parent || restored.Integrations[0].Policy != "require_approval" || len(restored.Tools) != 1 {
		t.Fatalf("Fly integration not restored: %#v %#v", restored.Integrations, restored.Tools)
	}
	restarted, err := New(restored, s, b)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := restarted.tools["fly.request_token"]; !ok {
		t.Fatal("restored integration did not synthesize its tool")
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
	g.cfg.Demo = true
	_, leaseHandler := g.DemoHandlers("gateway-test-token")
	leaseMux.Handle("POST /leases/{id}", leaseHandler)
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

func TestSecretAccessUsesStandingApprovalsAndIdentityBoundRedemption(t *testing.T) {
	g, s, _ := fixture(t)
	m, err := upstream.New(g.cfg.BaseURL, g.cfg.Connections, s)
	if err != nil {
		t.Fatal(err)
	}
	h, cookie := adminUI(t, g, m)
	secret := "fixture-secret-value\nwith-second-line"
	values := url.Values{"id": {"deploy_key"}, "name": {"Deployment key"}, "value": {secret}, "policy": {"require_approval"}}
	if w := formRequest(h, cookie, "POST", "/integrations/secrets", values); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/integrations/secrets?saved=1" {
		t.Fatalf("save secret: %d %s", w.Code, w.Body.String())
	}
	for _, path := range []string{"/integrations", "/integrations/secrets", "/approvals", "/audit"} {
		page := formRequest(h, cookie, "GET", path, nil)
		if page.Code != http.StatusOK || strings.Contains(page.Body.String(), secret) {
			t.Fatalf("secret exposed on %s", path)
		}
	}
	restored := g.cfg
	if err := LoadCatalogue(t.Context(), &restored, s); err != nil || len(restored.Integrations) != 1 || restored.Integrations[0].Credential != secret {
		t.Fatalf("secret did not survive encrypted catalogue reload: %#v, %v", restored.Integrations, err)
	}
	if tool, ok := g.tools["deploy_key.request_secret"]; !ok || tool.Policy != "require_approval" {
		t.Fatalf("secret tool not published: %#v", tool)
	}

	threadOne := ampIdentity{Subject: "amp:user-owner:thread:one", UserID: "user-owner", WorkspaceID: "workspace-one", ProjectID: "project-one", ThreadID: "T-01a0b6d8-e50f-7723-941c-60bca63723ba"}
	threadTwo := threadOne
	threadTwo.Subject = "amp:user-owner:thread:two"
	threadTwo.ThreadID = "T-01a0b6d8-e50f-7723-941c-60bca63723bb"
	otherProject := threadTwo
	otherProject.ProjectID = "project-two"

	request := func(id, purpose string) callInput {
		var in callInput
		in.RequestID = id
		in.Calls = append(in.Calls, struct {
			ToolID    string         `json:"tool_id"`
			Arguments map[string]any `json:"arguments"`
		}{ToolID: "deploy_key.request_secret", Arguments: map[string]any{"purpose": purpose}})
		return in
	}
	first, err := g.submit(withAmpIdentity(t.Context(), threadOne), request("secret-first", "deploy reviewed build"))
	if err != nil || first.Status != "pending" {
		t.Fatalf("first request: %#v, %v", first, err)
	}
	if err := s.ApproveWithOptions(t.Context(), first.ID, "owner", store.ApprovalOptions{Breadth: "tool", Scope: "project", Expiry: "never"}); err != nil {
		t.Fatal(err)
	}
	runWorker(t, g)
	first = await(t, s, first.ID, "succeeded")
	if strings.Contains(string(first.Result), secret) {
		t.Fatal("secret returned in MCP operation result")
	}
	second, err := g.submit(withAmpIdentity(t.Context(), threadTwo), request("secret-second", "rotate deployment"))
	if err != nil || second.Status != "ready" || second.ApprovalScope != "project" {
		t.Fatalf("project grant did not authorize another thread: %#v, %v", second, err)
	}
	third, err := g.submit(withAmpIdentity(t.Context(), otherProject), request("secret-third", "deploy elsewhere"))
	if err != nil || third.Status != "pending" {
		t.Fatalf("project grant crossed project boundary: %#v, %v", third, err)
	}

	var result struct {
		Structured struct {
			RedemptionURL string `json:"redemption_url"`
		} `json:"structuredContent"`
	}
	if err := json.Unmarshal(first.Result, &result); err != nil || result.Structured.RedemptionURL == "" {
		t.Fatalf("missing redemption URL: %s, %v", first.Result, err)
	}
	redeemURL, err := url.Parse(result.Structured.RedemptionURL)
	if err != nil {
		t.Fatal(err)
	}
	leaseMux := http.NewServeMux()
	leaseMux.Handle("POST /leases/{id}", g.Leases("gateway-test-token"))
	redeem := func(identity ampIdentity) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", redeemURL.Path, nil)
		r.Header.Set("Authorization", "Bearer gateway-test-token")
		r = r.WithContext(withAmpIdentity(r.Context(), identity))
		w := httptest.NewRecorder()
		leaseMux.ServeHTTP(w, r)
		return w
	}
	if wrong := redeem(threadTwo); wrong.Code != http.StatusGone {
		t.Fatalf("lease redeemed by another thread: %d %s", wrong.Code, wrong.Body.String())
	}
	issued := redeem(threadOne)
	if issued.Code != http.StatusOK || issued.Body.String() != secret || issued.Header().Get("Cache-Control") != "no-store" || issued.Header().Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("secret redemption: %d %q", issued.Code, issued.Body.String())
	}
	if second := redeem(threadOne); second.Code != http.StatusGone {
		t.Fatal("secret redemption URL was not single-use")
	}
}

func TestSecretRotationInvalidatesQueuedAuthorityAndLeases(t *testing.T) {
	g, s, _ := fixture(t)
	m, err := upstream.New(g.cfg.BaseURL, g.cfg.Connections, s)
	if err != nil {
		t.Fatal(err)
	}
	h, cookie := adminUI(t, g, m)
	values := url.Values{"id": {"api_key"}, "name": {"API key"}, "value": {"first-value"}, "policy": {"allow"}}
	if w := formRequest(h, cookie, "POST", "/integrations/secrets", values); w.Code != http.StatusSeeOther {
		t.Fatalf("save secret: %d %s", w.Code, w.Body.String())
	}
	integration, _ := g.integration("api_key")
	result, err := g.callIntegration(operationContext{Context: t.Context(), Operation: store.Operation{ID: "secret-lease"}}, integration, secretRequest, map[string]any{"purpose": "test rotation"})
	if err != nil {
		t.Fatal(err)
	}
	redeemURL, err := url.Parse(result.StructuredContent.(map[string]any)["redemption_url"].(string))
	if err != nil {
		t.Fatal(err)
	}
	values.Set("value", "second-value")
	if w := formRequest(h, cookie, "POST", "/integrations/secrets", values); w.Code != http.StatusSeeOther {
		t.Fatalf("rotate secret: %d %s", w.Code, w.Body.String())
	}
	r := httptest.NewRequest("POST", redeemURL.Path, nil)
	r.Header.Set("Authorization", "Bearer gateway-test-token")
	w := httptest.NewRecorder()
	leaseMux := http.NewServeMux()
	leaseMux.Handle("POST /leases/{id}", g.Leases("gateway-test-token"))
	leaseMux.ServeHTTP(w, r)
	if w.Code != http.StatusGone {
		t.Fatalf("lease survived rotation: %d %s", w.Code, w.Body.String())
	}
}

func TestFlyIntegrationRegeneratesToolWithoutPersistingIt(t *testing.T) {
	g, s, b := fixture(t)
	g.cfg.Integrations = []Integration{{ID: flyIntegrationID, Provider: "fly", Account: "Fixture", Credential: gatewayFlyToken(t), Policy: "allow"}}
	g.cfg.Tools = append(g.cfg.Tools, flyTool("deny"))

	restarted, err := New(g.cfg, s, b)
	if err != nil {
		t.Fatal(err)
	}
	if restarted.tools["fly.request_token"].Policy != "allow" || restarted.cfg.Integrations[0].Policy != "allow" {
		t.Fatal("generated tool did not use integration policy")
	}
	if got := restarted.catalogue(); len(got.Tools) != 1 || got.Tools[0].ID == "fly.request_token" {
		t.Fatalf("generated Fly tool remained in persisted catalogue: %#v", got.Tools)
	}
}

func TestFlyCredentialChangeInvalidatesUnredeemedLease(t *testing.T) {
	g, s, b := fixture(t)
	parent := gatewayFlyToken(t)
	integration := Integration{ID: flyIntegrationID, Provider: "fly", Account: "Fixture", Credential: parent, Policy: "allow"}
	g.cfg.Integrations = []Integration{integration}
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
	g.cfg.Demo = true
	_, leaseHandler := g.DemoHandlers("gateway-test-token")
	mux.Handle("POST /leases/{id}", leaseHandler)
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
	g.cfg.Integrations = []Integration{{ID: flyIntegrationID, Provider: "fly", Account: "Fixture", Credential: gatewayFlyToken(t), Policy: "require_approval"}}
	var err error
	g, err = New(g.cfg, s, b)
	if err != nil {
		t.Fatal(err)
	}
	private := true
	if _, err := g.proposePolicies(t.Context(), policyInput{Changes: []policyChange{{Connection: flyIntegrationID, Private: &private}}}); err == nil {
		t.Fatal("native integration accepted a private-connection proposal")
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
	var restored Config
	if err := LoadCatalogue(t.Context(), &restored, s); err != nil {
		t.Fatal(err)
	}
	if len(restored.Integrations) != 1 || restored.Integrations[0].Policy != "deny" || len(restored.Tools) != 1 {
		t.Fatalf("native policy was not persisted independently of legacy tools: %#v %#v", restored.Integrations, restored.Tools)
	}
}

func TestStaleFlyRemovalDoesNotDeleteRemoteConnectionTools(t *testing.T) {
	g, s, b := fixture(t)
	g.cfg.Connections = append(g.cfg.Connections, upstream.Connection{ID: flyIntegrationID, URL: "http://localhost/fly", Account: "Remote Fly MCP", NoAuth: true})
	g.cfg.Tools = append(g.cfg.Tools, Tool{ID: "fly.remote", Connection: flyIntegrationID, Name: "remote", Policy: "allow", InputSchema: map[string]any{"type": "object"}})
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
	if w := formRequest(h, cookie, "POST", "/integrations/fly/remove", nil); w.Code != http.StatusConflict {
		t.Fatalf("stale removal returned %d: %s", w.Code, w.Body.String())
	}
	if _, ok := g.tools["fly.remote"]; !ok {
		t.Fatal("stale removal deleted remote connection tool")
	}
}

func TestFailedFlySaveDoesNotMutateLiveIntegration(t *testing.T) {
	g, s, _ := fixture(t)
	m, err := upstream.New(g.cfg.BaseURL, g.cfg.Connections, s)
	if err != nil {
		t.Fatal(err)
	}
	h, cookie := adminUI(t, g, m)
	parent := gatewayFlyToken(t)
	values := url.Values{"account": {"Fixture"}, "token": {parent}, "policy": {"require_approval"}}
	if w := formRequest(h, cookie, "POST", "/integrations/fly", values); w.Code != http.StatusSeeOther {
		t.Fatalf("configure Fly: %d %s", w.Code, w.Body.String())
	}
	o, err := g.submit(t.Context(), input("running-during-fly-save", "payload"))
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
	replacement, err := flytoken.Attenuate(parent, time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	values.Set("token", replacement)
	values.Set("policy", "allow")
	if w := formRequest(h, cookie, "POST", "/integrations/fly", values); w.Code != http.StatusBadRequest {
		t.Fatalf("save during dispatch returned %d: %s", w.Code, w.Body.String())
	}
	if w := formRequest(h, cookie, "POST", "/integrations/fly/remove", nil); w.Code != http.StatusConflict {
		t.Fatalf("remove during dispatch returned %d: %s", w.Code, w.Body.String())
	}
	integration, ok := g.integration(flyIntegrationID)
	if !ok || integration.Credential != parent || integration.Policy != "require_approval" || g.tools["fly.request_token"].Policy != "require_approval" {
		t.Fatalf("failed save mutated live integration: %#v %#v", integration, g.tools["fly.request_token"])
	}
	if err := s.Finish(t.Context(), running, "failed", nil); err != nil {
		t.Fatal(err)
	}
}

func TestFlyLeaseCapacityIsDefiniteFailure(t *testing.T) {
	g, s, b := fixture(t)
	integration := Integration{ID: flyIntegrationID, Provider: "fly", Account: "Fixture", Credential: gatewayFlyToken(t), Policy: "allow"}
	g.cfg.Integrations = []Integration{integration}
	var err error
	g, err = New(g.cfg, s, b)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 32 {
		lease := store.CredentialLease{ID: fmt.Sprintf("full-%d", i), OperationID: fmt.Sprintf("lease-%d", i), Integration: flyIntegrationID, CredentialDigest: digest(integration.Credential), Expires: time.Now().Add(time.Minute).Unix()}
		if err := s.CreateCredentialLease(t.Context(), lease); err != nil {
			t.Fatal(err)
		}
	}
	var request callInput
	request.RequestID = "capacity-failure"
	request.Calls = append(request.Calls, struct {
		ToolID    string         `json:"tool_id"`
		Arguments map[string]any `json:"arguments"`
	}{ToolID: "fly.request_token", Arguments: map[string]any{"duration_seconds": 600, "purpose": "test capacity"}})
	if _, err := g.submit(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	runWorker(t, g)
	o := await(t, s, request.RequestID, "failed")
	if !strings.Contains(string(o.Result), "Too many unredeemed") {
		t.Fatalf("missing retryable capacity result: %s", o.Result)
	}
}
