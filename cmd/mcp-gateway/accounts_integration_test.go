package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"ampcode.com/lox/amp-mcp-gateway/internal/browserauth"
	"ampcode.com/lox/amp-mcp-gateway/internal/gateway"
	"ampcode.com/lox/amp-mcp-gateway/internal/store"
	"ampcode.com/lox/amp-mcp-gateway/internal/upstream"
	"github.com/go-jose/go-jose/v4"
)

type identityTransport struct {
	base   http.RoundTripper
	issuer string
}

func (tr identityTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Host == "ampcode.com" {
		r = r.Clone(r.Context())
		u, _ := url.Parse(tr.issuer + strings.TrimPrefix(r.URL.Path, "/api/workload-identity"))
		r.URL = u
		r.Header.Set("X-Test-Amp", "true")
	}
	return tr.base.RoundTrip(r)
}

// Exercise the actual application wiring, OIDC callbacks and signed Amp requests.
// The only replacement is the identity provider; no external services or secrets.
func TestTwoAccountAuthenticationAndIsolation(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "fixture"))
	if err != nil {
		t.Fatal(err)
	}
	mint := func(claims map[string]any) string {
		t.Helper()
		claims["exp"] = time.Now().Add(time.Hour).Unix()
		raw, err := json.Marshal(claims)
		if err != nil {
			t.Fatal(err)
		}
		signed, err := signer.Sign(raw)
		if err != nil {
			t.Fatal(err)
		}
		token, err := signed.CompactSerialize()
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	var issuer string
	var tokens sync.Map
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			iss := issuer
			if r.Header.Get("X-Test-Amp") == "true" {
				iss = "https://ampcode.com/api/workload-identity"
			}
			json.NewEncoder(w).Encode(map[string]any{"issuer": iss, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}})
		case "/keys":
			json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "fixture", Algorithm: "RS256", Use: "sig"}}})
		case "/token":
			token, ok := tokens.LoadAndDelete(r.FormValue("code"))
			if !ok {
				http.Error(w, "invalid code", 400)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"access_token": "fixture", "token_type": "Bearer", "id_token": token})
		default:
			http.NotFound(w, r)
		}
	}))
	defer provider.Close()
	issuer = provider.URL
	originalTransport := http.DefaultTransport
	http.DefaultTransport = identityTransport{base: originalTransport, issuer: issuer}
	defer func() { http.DefaultTransport = originalTransport }()

	cfg, secrets := accountFixture(t)
	cfg.Issuer = issuer
	cfg.Connections = []upstream.Connection{{ID: "notes", URL: "https://notes.example/mcp", Account: "Alice's private notes", NoAuth: true}}
	cfg.Tools = []gateway.Tool{{ID: "notes.create", Connection: "notes", Name: "create", Policy: "require_approval", InputSchema: map[string]any{"type": "object"}}}
	configs, err := cfg.accounts(secrets)
	if err != nil {
		t.Fatal(err)
	}
	var runtimes []*accountRuntime
	hosts := map[string]http.Handler{}
	for _, c := range configs {
		runtime, err := newAccount(t.Context(), c, browserauth.Config{Issuer: issuer, ClientID: "client", ClientSecret: "fixture-secret"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { runtime.store.Close() }()
		runtimes = append(runtimes, runtime)
		host, _ := accountHost(c.Config.BaseURL)
		hosts[host] = runtime.handler
	}
	router := http.NewCrossOriginProtection().Handler(accountRouter(hosts))
	request := func(method, origin, path string, body io.Reader, cookie *http.Cookie, bearer string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, origin+path, body)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		if bearer != "" {
			r.Header.Set("Authorization", "Bearer "+bearer)
		}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept", "application/json, text/event-stream")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		return w
	}
	login := func(origin, subject string, want int) *http.Cookie {
		t.Helper()
		start := request("GET", origin, "/login", nil, nil, "")
		u, err := url.Parse(start.Header().Get("Location"))
		if err != nil || u.Query().Get("nonce") == "" {
			t.Fatal("missing OIDC challenge", err)
		}
		if u.Query().Get("redirect_uri") != origin+"/auth/callback" {
			t.Fatal("wrong account callback")
		}
		code := rand.Text()
		tokens.Store(code, mint(map[string]any{"iss": issuer, "sub": subject, "aud": "client", "nonce": u.Query().Get("nonce")}))
		end := request("GET", origin, "/auth/callback?state="+url.QueryEscape(u.Query().Get("state"))+"&code="+code, nil, start.Result().Cookies()[0], "")
		if end.Code != want {
			t.Fatalf("login %s as %s: %d %s", origin, subject, end.Code, end.Body.String())
		}
		for _, cookie := range end.Result().Cookies() {
			if cookie.Name == "mcp_gateway_session" {
				return cookie
			}
		}
		return nil
	}
	alice, bob := configs[0].Config.BaseURL, configs[1].Config.BaseURL
	aCookie := login(alice, "alice-sub", 303)
	bCookie := login(bob, "bob-sub", 303)
	if aCookie == nil || bCookie == nil {
		t.Fatal("no session cookies")
	}
	login(bob, "alice-sub", 401)
	login(alice, "bob-sub", 401)
	for _, path := range []string{"/connections", "/operations", "/audit", "/approval-grants", "/integrations/chrome", "/integrations/fly", "/events"} {
		for _, cross := range []struct {
			origin string
			cookie *http.Cookie
		}{{alice, bCookie}, {bob, aCookie}} {
			if w := request("GET", cross.origin, path, nil, cross.cookie, ""); w.Code != 303 {
				t.Fatalf("cross-account cookie at %s: %d", path, w.Code)
			}
		}
	}
	if w := request("GET", alice, "/connections", nil, aCookie, ""); w.Code != 200 || !strings.Contains(w.Body.String(), "Alice&#39;s private notes") {
		t.Fatal("owner cannot see connection", w.Code)
	}
	if w := request("GET", bob, "/connections", nil, bCookie, ""); w.Code != 200 || strings.Contains(w.Body.String(), "private notes") {
		t.Fatal("connection catalogue crossed accounts", w.Code)
	}
	ampToken := func(origin, user string) string {
		return mint(map[string]any{"iss": "https://ampcode.com/api/workload-identity", "aud": origin, "sub": "amp-" + user, "user_id": user, "thread_id": "T-01a0b6d8-e50f-7723-941c-60bca63723ba", "token_use": "mcp"})
	}
	aToken, bToken := ampToken(alice, "user_alice"), ampToken(bob, "user_bob")
	call := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"call_tools","arguments":{"request_id":"same-request-001","calls":[{"tool_id":"notes.create","arguments":{"text":"alice-secret"}}]}}}`
	if w := request("POST", alice, "/mcp", strings.NewReader(call), nil, aToken); w.Code != 200 || !strings.Contains(w.Body.String(), "pending") {
		t.Fatalf("owner submit: %d %s", w.Code, w.Body.String())
	}
	for _, tc := range []struct{ origin, token string }{{alice, bToken}, {bob, aToken}, {bob, ampToken(bob, "user_alice")}} {
		for _, path := range []string{"/mcp", "/leases/same-request-001"} {
			if w := request("POST", tc.origin, path, strings.NewReader(call), nil, tc.token); w.Code != 401 {
				t.Fatalf("foreign token accepted at %s: %d", path, w.Code)
			}
		}
	}
	for _, path := range []string{"/operations/same-request-001", "/operations/same-request-001/image", "/connections/notes/tools"} {
		if w := request("GET", bob, path, nil, bCookie, ""); w.Code != 404 {
			t.Fatalf("foreign resource at %s: %d", path, w.Code)
		}
	}
	if w := request("POST", bob, "/operations/same-request-001/approve", nil, bCookie, ""); w.Code < 400 {
		t.Fatal("foreign approval accepted")
	}
	operation, err := runtimes[0].store.Get(t.Context(), "same-request-001")
	if err != nil || operation.Status != "pending" {
		t.Fatal("foreign approval affected owner", err)
	}
	lookup := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_operation","arguments":{"id":"same-request-001"}}}`
	if w := request("POST", bob, "/mcp", strings.NewReader(lookup), nil, bToken); w.Code != 200 || !strings.Contains(w.Body.String(), "operation unavailable") || strings.Contains(w.Body.String(), "alice-secret") {
		t.Fatalf("foreign result lookup: %d %s", w.Code, w.Body.String())
	}
	if w := request("POST", alice, "/operations/same-request-001/approve", nil, aCookie, ""); w.Code != 303 {
		t.Fatal("owner approval failed", w.Code)
	}
	if approved, err := runtimes[0].store.Get(t.Context(), operation.ID); err != nil || approved.Status != "ready" {
		t.Fatal("owner approval was not persisted", err)
	}
	// Identical IDs remain independent, including after reopening the additional account.
	_, err = runtimes[1].store.Submit(t.Context(), store.Operation{ID: operation.ID, Subject: "bob-sub", Status: "denied", Digest: "bob-digest", Created: time.Now().Unix()})
	if err != nil {
		t.Fatal(err)
	}
	if err := runtimes[1].store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := store.Open(configs[1].Config.Database, configs[1].Secrets.EncryptionKey)
	if err != nil {
		t.Fatal(err)
	}
	runtimes[1].store = reopened
	op, err := reopened.Get(t.Context(), operation.ID)
	if err != nil || op.Subject != "bob-sub" || op.Digest != "bob-digest" {
		t.Fatal("account restart lost or mixed state", err)
	}
}
