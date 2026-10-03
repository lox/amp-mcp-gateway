package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ampcode.com/lox/amp-mcp-gateway/internal/browserauth"
	"ampcode.com/lox/amp-mcp-gateway/internal/gateway"
	"ampcode.com/lox/amp-mcp-gateway/internal/store"
	"github.com/go-jose/go-jose/v4"
)

type ampIdentityTransport struct {
	base   http.RoundTripper
	issuer string
}

func (tr ampIdentityTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Host == "ampcode.com" {
		r = r.Clone(r.Context())
		r.URL, _ = url.Parse(tr.issuer + strings.TrimPrefix(r.URL.Path, "/api/workload-identity"))
	}
	return tr.base.RoundTrip(r)
}

// This uses the real workload verifier behind the registry's untrusted JWT hint.
// A valid signature is insufficient when the selected account's user or audience differs.
func TestRegistryWorkloadRoutingStillVerifiesSignedAccountClaims(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "fixture"))
	if err != nil {
		t.Fatal(err)
	}
	var issuer string
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": "https://ampcode.com/api/workload-identity", "jwks_uri": issuer + "/keys", "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token"})
		case "/keys":
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "fixture", Algorithm: "RS256", Use: "sig"}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer provider.Close()
	issuer = provider.URL
	original := http.DefaultTransport
	http.DefaultTransport = ampIdentityTransport{base: original, issuer: issuer}
	defer func() { http.DefaultTransport = original }()

	secrets := accountSecrets()
	base := accountConfig{Config: gateway.Config{BaseURL: "https://gateway.example", Database: filepath.Join(t.TempDir(), "gateway.db"), OwnerSubject: "google-alice", AmpUserID: "amp-alice", Issuer: "browser-issuer", ClientID: "browser-client", HostedDomain: "example.com"}, Secrets: secrets}
	authCfg := browserauth.Config{Demo: true, DemoPassword: "fixture", OwnerSubject: "google-alice"}
	primary, err := newAccount(t.Context(), base, authCfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer primary.store.Close()
	r, err := newRegistry(t.Context(), primary, base, func(c accountConfig) (*accountRuntime, error) { return newAccount(t.Context(), c, authCfg, nil) })
	if err != nil {
		t.Fatal(err)
	}
	defer r.close()
	if err := r.link(t.Context(), "google-bob", "amp-bob"); err != nil {
		t.Fatal(err)
	}

	mint := func(user, audience string) string {
		t.Helper()
		claims, _ := json.Marshal(map[string]any{"iss": "https://ampcode.com/api/workload-identity", "aud": audience, "sub": "actor", "user_id": user, "thread_id": "T-01a0b6d8-e50f-7723-941c-60bca63723ba", "thread_visibility": "private", "thread_multiplayer": false, "thread_non_owner_can_influence": false, "token_use": "mcp", "exp": time.Now().Add(time.Hour).Unix()})
		signed, err := signer.Sign(claims)
		if err != nil {
			t.Fatal(err)
		}
		token, err := signed.CompactSerialize()
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	request := func(token string) int {
		req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		w := httptest.NewRecorder()
		r.workload(w, req)
		return w.Code
	}
	if got := request(mint("amp-alice", base.Config.BaseURL)); got != http.StatusOK {
		t.Fatalf("valid primary token: %d", got)
	}
	if got := request(mint("amp-bob", base.Config.BaseURL)); got != http.StatusOK {
		t.Fatalf("valid linked token: %d", got)
	}
	now := time.Now()
	private := store.Operation{ID: "alice-private", Subject: "google-alice", AmpUserID: "amp-alice", AmpThreadID: "T-01a0b6d8-e50f-7723-941c-60bca63723ba", Private: true, Status: "succeeded", Digest: "alice-secret-digest", Result: json.RawMessage(`{"secret":"alice-private-result"}`), Created: now.Unix(), Expires: now.Add(time.Hour).Unix()}
	if _, err := primary.store.Submit(t.Context(), private); err != nil {
		t.Fatal(err)
	}
	bob := r.users["amp-bob"]
	own := store.Operation{ID: "bob-own-operation", Subject: "google-bob", AmpUserID: "amp-bob", Status: "succeeded", Digest: "bob-digest", Result: json.RawMessage(`{"owner":"bob"}`), Created: now.Unix(), Expires: now.Add(time.Hour).Unix()}
	if _, err := bob.store.Submit(t.Context(), own); err != nil {
		t.Fatal(err)
	}
	lookup := func(token, id string) string {
		req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_operation","arguments":{"id":"`+id+`"}}}`))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		w := httptest.NewRecorder()
		r.workload(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("lookup %s returned %d: %s", id, w.Code, w.Body.String())
		}
		return w.Body.String()
	}
	bobToken := mint("amp-bob", base.Config.BaseURL)
	if body := lookup(bobToken, private.ID); !strings.Contains(body, "operation unavailable") || strings.Contains(body, "alice-private-result") {
		t.Fatalf("Bob read primary private operation: %s", body)
	}
	if body := lookup(bobToken, own.ID); !strings.Contains(body, `bob`) || strings.Contains(body, "operation unavailable") {
		t.Fatalf("Bob could not read own operation: %s", body)
	}
	aliceToken := mint("amp-alice", base.Config.BaseURL)
	if body := lookup(aliceToken, private.ID); !strings.Contains(body, "alice-private-result") {
		t.Fatalf("primary owner could not read private operation: %s", body)
	}
	if err := bob.store.Approve(t.Context(), private.ID, "google-bob", "once"); err == nil {
		t.Fatal("Bob approved primary private operation through his account")
	}
	unchanged, err := primary.store.Get(t.Context(), private.ID)
	if err != nil || unchanged.Status != "succeeded" {
		t.Fatalf("Bob's approval attempt changed primary operation: %#v, %v", unchanged, err)
	}
	pendingBob := own
	pendingBob.ID, pendingBob.Status = "bob-pending-operation", "pending"
	if _, err := bob.store.Submit(t.Context(), pendingBob); err != nil {
		t.Fatal(err)
	}
	if err := bob.store.Approve(t.Context(), pendingBob.ID, "google-bob", "once"); err != nil {
		t.Fatalf("Bob could not approve own operation: %v", err)
	}
	if approved, err := bob.store.Get(t.Context(), pendingBob.ID); err != nil || approved.Status != "ready" {
		t.Fatalf("Bob's own approval was not persisted: %#v, %v", approved, err)
	}
	// Exercise routing from browserauth's authenticated subject, including the
	// actual approval handler, rather than relying only on separate store objects.
	browserRequest := func(subject, method, path string) *httptest.ResponseRecorder {
		t.Helper()
		auth, err := browserauth.New(t.Context(), browserauth.Config{
			BaseURL: base.Config.BaseURL, OwnerSubject: subject, SessionKey: secrets.SessionKey,
			Demo: true, DemoPassword: "fixture-password",
		})
		if err != nil {
			t.Fatal(err)
		}
		mux := http.NewServeMux()
		auth.Register(mux)
		login := httptest.NewRequest("POST", "/login", strings.NewReader("password=fixture-password"))
		login.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		session := httptest.NewRecorder()
		mux.ServeHTTP(session, login)
		if session.Code != http.StatusSeeOther {
			t.Fatal("fixture login failed")
		}
		req := httptest.NewRequest(method, path, nil)
		for _, cookie := range session.Result().Cookies() {
			req.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		auth.Require(http.HandlerFunc(r.browser)).ServeHTTP(w, req)
		return w
	}
	if w := browserRequest("google-alice", "GET", "/operations/alice-private"); w.Code != 200 || !strings.Contains(w.Body.String(), "alice-private-result") {
		t.Fatalf("owner browser lookup: %d %s", w.Code, w.Body.String())
	}
	if w := browserRequest("google-bob", "GET", "/operations/alice-private"); w.Code != 404 || strings.Contains(w.Body.String(), "alice-private-result") {
		t.Fatalf("cross-account browser lookup: %d", w.Code)
	}
	if w := browserRequest("unlinked-subject", "GET", "/operations"); w.Code != 303 || w.Header().Get("Location") != "/account" {
		t.Fatal("unlinked browser was not sent to linking")
	}
	pendingAlice := private
	pendingAlice.ID, pendingAlice.Status = "alice-pending", "pending"
	if _, err := primary.store.Submit(t.Context(), pendingAlice); err != nil {
		t.Fatal(err)
	}
	if w := browserRequest("google-bob", "POST", "/operations/alice-pending/approve"); w.Code < 400 {
		t.Fatal("cross-account browser approval accepted")
	}
	if op, err := primary.store.Get(t.Context(), pendingAlice.ID); err != nil || op.Status != "pending" {
		t.Fatal("foreign browser approval changed primary operation")
	}
	if w := browserRequest("google-alice", "POST", "/operations/alice-pending/approve"); w.Code != 303 {
		t.Fatalf("owner browser approval failed: %d %s", w.Code, w.Body.String())
	}
	parts := strings.Split(bobToken, ".")
	var tamperedClaims map[string]any
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	_ = json.Unmarshal(payload, &tamperedClaims)
	tamperedClaims["user_id"] = "amp-alice"
	payload, _ = json.Marshal(tamperedClaims)
	parts[1] = base64.RawURLEncoding.EncodeToString(payload)
	for name, token := range map[string]string{
		"wrong audience": mint("amp-alice", "https://foreign.example"),
		"tampered routing hint selects another account": strings.Join(parts, "."),
	} {
		if got := request(token); got != http.StatusUnauthorized {
			t.Fatalf("%s accepted: %d", name, got)
		}
	}
}
