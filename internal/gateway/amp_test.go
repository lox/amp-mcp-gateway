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
		claims := map[string]any{"iss": ampIssuer, "aud": g.cfg.BaseURL, "sub": "user:user-owner:thread:" + thread, "user_id": "user-owner", "thread_id": thread, "token_use": "exchanged", "iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix()}
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
		"wrong token use": func(c map[string]any) { c["token_use"] = "request" },
		"missing thread":  func(c map[string]any) { delete(c, "thread_id") },
		"unsafe thread":   func(c map[string]any) { c["thread_id"] = "../../evil" },
		"missing subject": func(c map[string]any) { delete(c, "sub") },
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
	if err != nil || o.AmpUserID != "user-owner" || o.AmpThreadID != thread || o.Subject != "owner" {
		t.Fatalf("identity not persisted: %+v %v", o, err)
	}
	events, err := s.Events(t.Context())
	if err != nil || len(events) != 1 || events[0].Actor != "amp:user-owner" {
		t.Fatalf("submission actor: %v %v", events, err)
	}
	w := httptest.NewRecorder()
	g.render(w, map[string]any{"Operation": o, "Owner": "owner"})
	if !strings.Contains(w.Body.String(), `href="https://ampcode.com/threads/`+thread+`"`) || !strings.Contains(w.Body.String(), "user-owner") {
		t.Fatal("missing identity link")
	}
	result, err = session.CallTool(t.Context(), &mcp.CallToolParams{Name: "call_tools", Arguments: input("amp-request-001", "verified caller")})
	if err != nil || result.IsError {
		t.Fatal("same-thread retry rejected")
	}
	// A changed caller thread must not silently reuse another thread's request.
	ctx := withAmpIdentity(t.Context(), ampIdentity{UserID: "user-owner", ThreadID: "T-01a0b6d8-e50f-7723-941c-60bca63723bb"})
	if _, err := g.submit(ctx, input("amp-request-001", "verified caller")); err == nil {
		t.Fatal("cross-thread idempotency accepted")
	}
	if _, err := g.submit(t.Context(), input("amp-request-002", "no identity")); err == nil {
		t.Fatal("missing verified identity accepted")
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
