package browserauth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

func TestOIDCRealHandshakeAndClaims(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"valid", "wrong subject", "wrong nonce", "wrong audience", "expired"} {
		t.Run(scenario, func(t *testing.T) {
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
				r.ParseForm()
				sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
				if base64.RawURLEncoding.EncodeToString(sum[:]) != challenge {
					t.Error("missing or invalid PKCE verifier")
					http.Error(w, "invalid", 400)
					return
				}
				claims := map[string]any{"iss": issuer, "sub": "owner-123", "aud": "gateway", "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(), "nonce": nonce}
				switch scenario {
				case "wrong subject":
					claims["sub"] = "other-owner"
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
			a, err := New(t.Context(), Config{BaseURL: "https://gateway.example", Issuer: issuer, ClientID: "gateway", ClientSecret: "fixture-secret", OwnerSubject: "owner-123", SessionKey: base64.StdEncoding.EncodeToString(make([]byte, 32))})
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
			callback := func() *httptest.ResponseRecorder {
				r := httptest.NewRequest("GET", "/auth/callback?state="+url.QueryEscape(location.Query().Get("state"))+"&code=fixture-code", nil)
				r.AddCookie(login.Result().Cookies()[0])
				w := httptest.NewRecorder()
				app.ServeHTTP(w, r)
				return w
			}
			res := callback()
			want := http.StatusUnauthorized
			if scenario == "valid" {
				want = http.StatusSeeOther
			}
			if res.Code != want {
				t.Fatalf("status %d: %s", res.Code, res.Body.String())
			}
			session := false
			for _, c := range res.Result().Cookies() {
				if c.Name == sessionCookie && c.MaxAge > 0 {
					session = true
				}
			}
			if session != (scenario == "valid") {
				t.Fatal("incorrect session issuance")
			}
			if callback().Code != http.StatusBadRequest {
				t.Fatal("OAuth state replay accepted")
			}
		})
	}
}
