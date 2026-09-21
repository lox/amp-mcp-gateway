package browserauth

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

func TestOIDCRealHandshakeAndClaims(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name         string
		hostedDomain string
		claimDomain  string
		claimSubject string
		wantSuccess  bool
		wantReason   string
	}{
		{name: "generic OIDC without domain", claimSubject: "owner-123", wantSuccess: true},
		{name: "valid hosted domain", hostedDomain: "ljd.cc", claimDomain: "ljd.cc", claimSubject: "owner-123", wantSuccess: true},
		{name: "missing hosted domain claim", hostedDomain: "ljd.cc", claimSubject: "owner-123", wantReason: "hosted_domain"},
		{name: "wrong hosted domain claim", hostedDomain: "ljd.cc", claimDomain: "other.example", claimSubject: "owner-123", wantReason: "hosted_domain"},
		{name: "same domain wrong owner", hostedDomain: "ljd.cc", claimDomain: "ljd.cc", claimSubject: "other-owner", wantReason: "owner"},
		{name: "wrong nonce", claimSubject: "owner-123", wantReason: "nonce"},
		{name: "wrong audience", claimSubject: "owner-123", wantReason: "id_token_verification"},
		{name: "expired", claimSubject: "owner-123", wantReason: "id_token_verification"},
		{name: "exchange rejected", wantReason: "token_exchange"},
		{name: "missing ID token", wantReason: "missing_id_token"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logs bytes.Buffer
			previousLogger := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
			defer slog.SetDefault(previousLogger)
			var issuer, nonce, challenge string
			mux := http.NewServeMux()
			mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}})
			})
			mux.HandleFunc("GET /keys", func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "fixture", Algorithm: "RS256", Use: "sig"}}})
			})
			mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
				if tt.name == "exchange rejected" {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusBadRequest)
					w.Write([]byte(`{"error":"invalid_client","error_description":"sensitive-provider-response"}`))
					return
				}
				if tt.name == "missing ID token" {
					w.Header().Set("Content-Type", "application/json")
					w.Write([]byte(`{"access_token":"fixture-access","token_type":"Bearer"}`))
					return
				}
				r.ParseForm()
				sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
				if base64.RawURLEncoding.EncodeToString(sum[:]) != challenge {
					t.Error("missing or invalid PKCE verifier")
					http.Error(w, "invalid", 400)
					return
				}
				claims := map[string]any{"iss": issuer, "sub": tt.claimSubject, "aud": "gateway", "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(), "nonce": nonce}
				if tt.claimDomain != "" {
					claims["hd"] = tt.claimDomain
				}
				switch tt.name {
				case "wrong nonce":
					claims["nonce"] = "other-nonce"
				case "wrong audience":
					claims["aud"] = "other-client"
				case "expired":
					claims["exp"] = time.Now().Add(-time.Hour).Unix()
				}
				signer, e := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "fixture"))
				if e != nil {
					t.Error(e)
					return
				}
				payload, _ := json.Marshal(claims)
				signed, e := signer.Sign(payload)
				if e != nil {
					t.Error(e)
					return
				}
				raw, e := signed.CompactSerialize()
				if e != nil {
					t.Error(e)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]any{"access_token": "fixture-access", "token_type": "Bearer", "id_token": raw})
			})
			idp := httptest.NewServer(mux)
			defer idp.Close()
			issuer = idp.URL
			a, err := New(t.Context(), Config{BaseURL: "https://gateway.example", Issuer: issuer, ClientID: "gateway", ClientSecret: "fixture-secret", OwnerSubject: "owner-123", HostedDomain: tt.hostedDomain, SessionKey: base64.StdEncoding.EncodeToString(make([]byte, 32))})
			if err != nil {
				t.Fatal(err)
			}
			app := http.NewServeMux()
			a.Register(app)
			login := httptest.NewRecorder()
			app.ServeHTTP(login, httptest.NewRequest("GET", "/login", nil))
			location, err := url.Parse(login.Header().Get("Location"))
			if err != nil {
				t.Fatal(err)
			}
			nonce = location.Query().Get("nonce")
			challenge = location.Query().Get("code_challenge")
			if nonce == "" || challenge == "" {
				t.Fatal("missing nonce/PKCE")
			}
			if got := location.Query().Get("hd"); got != tt.hostedDomain {
				t.Fatalf("hosted domain hint = %q, want %q", got, tt.hostedDomain)
			}
			wantScope := "openid"
			if tt.hostedDomain != "" {
				wantScope = "openid email"
			}
			if got := location.Query().Get("scope"); got != wantScope {
				t.Fatalf("scope = %q, want %q", got, wantScope)
			}
			callback := func() *httptest.ResponseRecorder {
				r := httptest.NewRequest("GET", "/auth/callback?state="+url.QueryEscape(location.Query().Get("state"))+"&code=fixture-code", nil)
				r.AddCookie(login.Result().Cookies()[0])
				w := httptest.NewRecorder()
				app.ServeHTTP(w, r)
				return w
			}
			if tt.name == "generic OIDC without domain" {
				for i := 1; i < 128; i++ {
					w := httptest.NewRecorder()
					r := httptest.NewRequest("GET", "/login", nil)
					r.RemoteAddr = fmt.Sprintf("192.0.3.%d:1234", i)
					app.ServeHTTP(w, r)
					if w.Code != http.StatusSeeOther {
						t.Fatalf("fill login capacity: status=%d", w.Code)
					}
				}
				excess := httptest.NewRecorder()
				app.ServeHTTP(excess, httptest.NewRequest("GET", "/login", nil))
				if excess.Code != http.StatusServiceUnavailable {
					t.Fatalf("full login capacity: status=%d", excess.Code)
				}
			}
			res := callback()
			want := http.StatusUnauthorized
			if tt.wantSuccess {
				want = http.StatusSeeOther
			}
			if res.Code != want {
				t.Fatalf("status %d: %s", res.Code, res.Body.String())
			}
			if tt.wantReason != "" && !strings.Contains(logs.String(), "reason="+tt.wantReason) {
				t.Fatalf("missing failure reason %q: %s", tt.wantReason, logs.String())
			}
			for _, sensitive := range []string{"sensitive-provider-response", "fixture-access", "fixture-secret", "fixture-code", "owner-123", "other-owner", nonce, challenge} {
				if strings.Contains(logs.String(), sensitive) {
					t.Fatal("authentication logs contain sensitive data")
				}
			}
			session := false
			for _, c := range res.Result().Cookies() {
				if c.Name == sessionCookie && c.MaxAge > 0 {
					session = true
				}
			}
			if session != tt.wantSuccess {
				t.Fatal("incorrect session issuance")
			}
			if tt.name == "generic OIDC without domain" {
				fresh := httptest.NewRecorder()
				app.ServeHTTP(fresh, httptest.NewRequest("GET", "/login", nil))
				if fresh.Code != http.StatusSeeOther {
					t.Fatalf("callback did not release login capacity: status=%d", fresh.Code)
				}
			}
			if callback().Code != http.StatusBadRequest {
				t.Fatal("OAuth state replay accepted")
			}
		})
	}
}
