package gateway

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ampcode.com/lox/amp-mcp-gateway/internal/store"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestAmpIdentity(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keys := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "test", Algorithm: "RS256", Use: "sig"}}})
	}))
	defer keys.Close()
	g, s, _ := fixture(t)
	g.cfg.AmpUserID = "user-owner"
	verifier := oidc.NewVerifier(ampIssuer, oidc.NewRemoteKeySet(t.Context(), keys.URL), &oidc.Config{ClientID: g.cfg.BaseURL, SupportedSigningAlgs: []string{"RS256"}})
	h := g.ampMCP(verifier)
	thread := "T-01a0b6d8-e50f-7723-941c-60bca63723ba"
	mint := func(change func(map[string]any)) string {
		claims := map[string]any{"iss": ampIssuer, "aud": g.cfg.BaseURL, "sub": "workspace:workspace-123:project:project-456:user:user-owner:thread:" + thread, "user_id": "user-owner", "workspace_id": "workspace-123", "project_id": "project-456", "thread_id": thread, "thread_visibility": "private", "thread_multiplayer": false, "thread_non_owner_can_influence": false, "token_use": "mcp", "jti": "token-123", "iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix()}
		change(claims)
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "test"))
		if err != nil {
			t.Fatal(err)
		}
		payload, _ := json.Marshal(claims)
		signed, err := signer.Sign(payload)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := signed.CompactSerialize()
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	for name, change := range map[string]func(map[string]any){
		"other user":      func(c map[string]any) { c["user_id"] = "user-other" },
		"wrong issuer":    func(c map[string]any) { c["iss"] = "https://evil.example" },
		"wrong audience":  func(c map[string]any) { c["aud"] = "another-service" },
		"expired":         func(c map[string]any) { c["exp"] = time.Now().Add(-time.Minute).Unix() },
		"orb token":       func(c map[string]any) { c["token_use"] = "exchanged" },
		"wrong token use": func(c map[string]any) { c["token_use"] = "request" },
		"missing thread":  func(c map[string]any) { delete(c, "thread_id") },
		"unsafe thread":   func(c map[string]any) { c["thread_id"] = "../../evil" },
		"missing subject": func(c map[string]any) { delete(c, "sub") },
		"invalid multiplayer": func(c map[string]any) {
			c["thread_multiplayer"] = "false"
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/mcp", nil)
			r.Header.Set("Authorization", "Bearer "+mint(change))
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("got %d", w.Code)
			}
		})
	}
	leaseAuth := g.ampAuthenticated(verifier, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if identity, _ := r.Context().Value(ampIdentityKey{}).(ampIdentity); identity.ThreadID != thread {
			t.Fatal("verified identity was not attached")
		}
		w.WriteHeader(http.StatusNoContent)
	}), true)
	for name, tokenUse := range map[string]string{"automatic MCP identity": "mcp", "orb-minted identity": "exchanged"} {
		t.Run("lease accepts "+name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/leases/test", nil)
			r.Header.Set("Authorization", "Bearer "+mint(func(c map[string]any) { c["token_use"] = tokenUse }))
			w := httptest.NewRecorder()
			leaseAuth.ServeHTTP(w, r)
			if w.Code != http.StatusNoContent {
				t.Fatalf("got %d", w.Code)
			}
		})
	}
	server := httptest.NewServer(h)
	defer server.Close()
	token := mint(func(map[string]any) {})
	parts := strings.Split(token, ".")
	parts[2] = strings.Repeat("A", len(parts[2]))
	for _, raw := range []string{"", "shared-token", strings.Join(parts, ".")} {
		r := httptest.NewRequest("POST", "/mcp", nil)
		r.Header.Set("Authorization", "Bearer "+raw)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Fatal("invalid signature/token accepted")
		}
	}
	r := httptest.NewRequest("POST", "/mcp", nil)
	r.Header.Set("Authorization", "Bearer "+mint(func(c map[string]any) {
		delete(c, "workspace_id")
		delete(c, "project_id")
	}))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code == http.StatusUnauthorized {
		t.Fatal("optional workspace and project claims were required")
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	session, err := client.Connect(t.Context(), &mcp.StreamableClientTransport{Endpoint: server.URL, HTTPClient: &http.Client{Transport: bearer{token}}, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	result, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "call_tools", Arguments: input("amp-request-001", "verified caller")})
	if err != nil || result.IsError {
		t.Fatalf("submit %v %v", result, err)
	}
	o, err := s.Get(t.Context(), "amp-request-001")
	if err != nil || o.AmpSubject == "" || o.AmpUserID != "user-owner" || o.AmpWorkspaceID != "workspace-123" || o.AmpProjectID != "project-456" || o.AmpThreadID != thread || !o.AmpThreadContext || o.AmpThreadVisibility != "private" || o.AmpThreadMultiplayer || o.AmpThreadNonOwnerCanInfluence || o.Subject != "owner" {
		t.Fatalf("identity not persisted: %+v %v", o, err)
	}
	events, err := s.Events(t.Context())
	if err != nil || len(events) != 1 || events[0].Actor != "amp:user-owner" {
		t.Fatalf("submission actor: %v %v", events, err)
	}
	w = httptest.NewRecorder()
	g.render(w, map[string]any{"Operation": o, "Owner": "owner"})
	if !strings.Contains(w.Body.String(), `href="https://ampcode.com/threads/`+thread+`"`) || !strings.Contains(w.Body.String(), "user-owner") || !strings.Contains(w.Body.String(), "workspace-123") || !strings.Contains(w.Body.String(), "project-456") || !strings.Contains(w.Body.String(), "Thread visibility") || !strings.Contains(w.Body.String(), "Multiplayer") || !strings.Contains(w.Body.String(), "Non-owner influence") {
		t.Fatal("missing identity link")
	}
	result, err = session.CallTool(t.Context(), &mcp.CallToolParams{Name: "call_tools", Arguments: input("amp-request-001", "verified caller")})
	if err != nil || result.IsError {
		t.Fatal("same-thread retry rejected")
	}
	// A changed caller thread must not silently reuse another thread's request.
	ctx := withAmpIdentity(t.Context(), ampIdentity{Subject: o.AmpSubject, UserID: "user-owner", WorkspaceID: "workspace-123", ProjectID: "project-456", ThreadID: "T-01a0b6d8-e50f-7723-941c-60bca63723bb"})
	if _, err := g.submit(ctx, input("amp-request-001", "verified caller")); err == nil {
		t.Fatal("cross-thread idempotency accepted")
	}
	ctx = withAmpIdentity(t.Context(), ampIdentity{Subject: o.AmpSubject, UserID: "user-owner", WorkspaceID: "workspace-123", ProjectID: "project-other", ThreadID: thread})
	if _, err := g.submit(ctx, input("amp-request-001", "verified caller")); err == nil {
		t.Fatal("cross-project idempotency accepted")
	}
	if _, err := g.submit(t.Context(), input("amp-request-002", "no identity")); err == nil {
		t.Fatal("missing verified identity accepted")
	}
}

func TestAmpStandingApprovalAppliesThroughGateway(t *testing.T) {
	g, s, _ := fixture(t)
	g.cfg.AmpUserID = "user-owner"
	identity := ampIdentity{Subject: "workspace:workspace-one:project:project-one:user:user-owner:thread:T-01a0b6d8-e50f-7723-941c-60bca63723ba", UserID: "user-owner", WorkspaceID: "workspace-one", ProjectID: "project-one", ThreadID: "T-01a0b6d8-e50f-7723-941c-60bca63723ba"}
	ctx := withAmpIdentity(t.Context(), identity)
	first, err := g.submit(ctx, input("standing-first", "first"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Approve(t.Context(), first.ID, "owner", "thread"); err != nil {
		t.Fatal(err)
	}
	second, err := g.submit(ctx, input("standing-second", "second"))
	if err != nil || second.Status != "ready" {
		t.Fatalf("thread grant did not authorize gateway submission: %s, %v", second.Status, err)
	}
	identity.ThreadID = "T-01a0b6d8-e50f-7723-941c-60bca63723bb"
	identity.Subject = "workspace:workspace-one:project:project-one:user:user-owner:thread:T-01a0b6d8-e50f-7723-941c-60bca63723bb"
	third, err := g.submit(withAmpIdentity(t.Context(), identity), input("standing-third", "third"))
	if err != nil || third.Status != "pending" {
		t.Fatalf("thread grant escaped to another gateway thread: %s, %v", third.Status, err)
	}
}

func TestPrivateConnectionRequiresPrivateSoloAmpThread(t *testing.T) {
	g, s, b := fixture(t)
	g.cfg.AmpUserID = "user-owner"
	g.cfg.PrivateConnections = map[string]bool{"notes": true}
	tool := g.tools["notes.write"]
	tool.Policy = "require_approval"
	g.tools[tool.ID] = tool
	thread := "T-01a0b6d8-e50f-7723-941c-60bca63723ba"
	base := ampIdentity{Subject: "workspace:workspace-one:project:project-one:user:user-owner:thread:" + thread, UserID: "user-owner", WorkspaceID: "workspace-one", ProjectID: "project-one", ThreadID: thread, ThreadVisibility: "private"}
	no, yes := false, true
	base.ThreadMultiplayer, base.ThreadNonOwnerCanInfluence = &no, &no

	o, err := g.submit(withAmpIdentity(t.Context(), base), input("private-call", "private value"))
	if err != nil || o.Status != "pending" || !o.Private || !o.AmpThreadContext || o.AmpThreadVisibility != "private" {
		t.Fatalf("private call: %+v, %v", o, err)
	}
	if err := s.Approve(t.Context(), o.ID, "owner", "thread"); err != nil {
		t.Fatal(err)
	}
	runWorker(t, g)
	completed := await(t, s, o.ID, "succeeded")
	if b.calls.Load() != 1 || !strings.Contains(string(completed.Result), "private value") {
		t.Fatalf("private call did not execute exactly once: %d, %s", b.calls.Load(), completed.Result)
	}
	if got, err := g.getOperation(withAmpIdentity(t.Context(), base), o.ID); err != nil || got.ID != o.ID || len(got.Result) == 0 {
		t.Fatalf("private result unavailable to owner: %+v, %v", got, err)
	}

	for _, tc := range []struct {
		name   string
		change func(*ampIdentity)
	}{
		{"shared", func(i *ampIdentity) { i.ThreadVisibility = "thread_workspace_shared" }},
		{"public", func(i *ampIdentity) { i.ThreadVisibility = "public_unlisted" }},
		{"multiplayer", func(i *ampIdentity) { i.ThreadMultiplayer = &yes }},
		{"non-owner influence", func(i *ampIdentity) { i.ThreadNonOwnerCanInfluence = &yes }},
		{"missing claims", func(i *ampIdentity) { i.ThreadMultiplayer = nil }},
		{"unknown visibility", func(i *ampIdentity) { i.ThreadVisibility = "future_mode" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			identity := base
			tc.change(&identity)
			if _, err := g.submit(withAmpIdentity(t.Context(), identity), input("private-"+strings.ReplaceAll(tc.name, " ", "-"), "private value")); err == nil || err.Error() != "unknown tool" {
				t.Fatalf("private call did not fail as an unknown tool: %v", err)
			}
			if _, err := g.getOperation(withAmpIdentity(t.Context(), identity), o.ID); err == nil {
				t.Fatal("private result exposed")
			}
		})
	}
	if stored, err := s.Get(t.Context(), o.ID); err != nil || !stored.Private {
		t.Fatalf("private operation not durably marked: %+v, %v", stored, err)
	}
}

func TestMakingConnectionPrivateHidesEarlierResults(t *testing.T) {
	g, s, _ := fixture(t)
	g.cfg.AmpUserID = "user-owner"
	tool := g.tools["notes.write"]
	tool.Policy = "allow"
	g.tools[tool.ID] = tool
	thread := "T-01a0b6d8-e50f-7723-941c-60bca63723ba"
	no := false
	private := ampIdentity{UserID: "user-owner", ThreadID: thread, ThreadVisibility: "private", ThreadMultiplayer: &no, ThreadNonOwnerCanInfluence: &no}
	o, err := g.submit(withAmpIdentity(t.Context(), private), input("before-private", "historical result"))
	if err != nil || o.Private {
		t.Fatalf("initial operation: %+v, %v", o, err)
	}
	runWorker(t, g)
	await(t, s, o.ID, "succeeded")
	if err := s.SaveCatalogueProtecting(t.Context(), []byte(`{}`), map[string]bool{"notes": true}); err != nil {
		t.Fatal(err)
	}
	g.cfg.PrivateConnections = map[string]bool{"notes": true}
	shared := private
	shared.ThreadVisibility = "thread_workspace_shared"
	if _, err := g.getOperation(withAmpIdentity(t.Context(), shared), o.ID); err == nil {
		t.Fatal("earlier result exposed after connection became private")
	}
	if got, err := g.getOperation(withAmpIdentity(t.Context(), private), o.ID); err != nil || len(got.Result) == 0 {
		t.Fatalf("earlier result unavailable in private context: %+v, %v", got, err)
	}
	delete(g.cfg.PrivateConnections, "notes")
	if _, err := g.submit(withAmpIdentity(t.Context(), shared), input(o.ID, "historical result")); err == nil || err.Error() != "unknown tool" {
		t.Fatalf("idempotent retry exposed private result after privacy was disabled: %v", err)
	}
}

func TestAmpRetryAcceptsOperationFromBeforeExpandedIdentity(t *testing.T) {
	g, s, _ := fixture(t)
	g.cfg.AmpUserID = "user-owner"
	thread := "T-01a0b6d8-e50f-7723-941c-60bca63723ba"
	args := map[string]any{"text": "created before upgrade"}
	legacy := store.Operation{
		ID:          "legacy-retry",
		Tool:        "notes.write",
		Connection:  "notes",
		Account:     "test account",
		Subject:     "owner",
		AmpUserID:   "user-owner",
		AmpThreadID: thread,
		Arguments:   args,
		Binding:     g.bindings["notes.write"],
		Status:      "pending",
		Created:     time.Now().Unix(),
		Expires:     time.Now().Add(time.Minute).Unix(),
	}
	legacy.Digest = digest([]any{legacy.Tool, legacy.Arguments, legacy.Binding, legacy.Model, legacy.AmpUserID, legacy.AmpThreadID})
	if _, err := s.Submit(t.Context(), legacy); err != nil {
		t.Fatal(err)
	}
	identity := ampIdentity{Subject: "workspace:workspace-one:project:project-one:user:user-owner:thread:" + thread, UserID: "user-owner", WorkspaceID: "workspace-one", ProjectID: "project-one", ThreadID: thread}
	got, err := g.submit(withAmpIdentity(t.Context(), identity), input(legacy.ID, "created before upgrade"))
	if err != nil || got.Digest != legacy.Digest {
		t.Fatalf("legacy retry rejected: %+v, %v", got, err)
	}
	if _, err := g.submit(withAmpIdentity(t.Context(), identity), input(legacy.ID, "changed after upgrade")); err == nil {
		t.Fatal("changed legacy retry accepted")
	}
}

func TestAmpAudience(t *testing.T) {
	for _, tc := range []struct {
		base, want string
	}{
		{"https://GATEWAY.example.com:443/", "https://gateway.example.com"},
		{"https://gateway.example.com:0443", "https://gateway.example.com"},
		{"https://gateway.example.com:8443", "https://gateway.example.com:8443"},
		{"https://bücher.example", "https://xn--bcher-kva.example"},
		{"https://[2001:db8::1]:443", "https://[2001:db8::1]"},
		{"https://[2001:0db8:0000:0000:0000:0000:0000:0001]:8443", "https://[2001:db8::1]:8443"},
	} {
		t.Run(tc.base, func(t *testing.T) {
			got, err := ampAudience(tc.base)
			if err != nil || got != tc.want {
				t.Fatalf("ampAudience(%q) = %q, %v; want %q", tc.base, got, err, tc.want)
			}
		})
	}
	for _, base := range []string{"http://gateway.example.com", "https://gateway.example.com/mcp", "https://user@gateway.example.com", "https://127.000.000.001"} {
		if got, err := ampAudience(base); err == nil {
			t.Errorf("ampAudience(%q) = %q, want error", base, got)
		}
	}
}

func TestIdentityConfigurationInvalidatesApproval(t *testing.T) {
	for name, change := range map[string]func(*Config){
		"Amp user":      func(c *Config) { c.AmpUserID = "different-user" },
		"Google domain": func(c *Config) { c.HostedDomain = "different.example" },
		"Google client": func(c *Config) { c.ClientID = "different-client" },
	} {
		t.Run(name, func(t *testing.T) {
			g, s, b := fixture(t)
			o, err := g.submit(t.Context(), input("identity-change-001", "must not execute"))
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Decide(t.Context(), o.ID, "owner", true); err != nil {
				t.Fatal(err)
			}
			cfg := g.cfg
			change(&cfg)
			updated, err := New(cfg, s, b)
			if err != nil {
				t.Fatal(err)
			}
			runWorker(t, updated)
			await(t, s, o.ID, "denied")
			if b.calls.Load() != 0 {
				t.Fatal("dispatched stale approval")
			}
		})
	}
}
