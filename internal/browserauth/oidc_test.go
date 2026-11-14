package browserauth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/oauth2"
)

func TestAmpHandshake(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "fixture"))
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"valid", "valid access hash", "valid userinfo", "valid mismatched userinfo", "valid unavailable userinfo", "valid oversized profile", "valid unsafe picture", "wrong access hash", "wrong workspace", "missing workspace", "workspace unavailable", "workspace malformed", "workspace redirect", "machine actor", "empty actor", "actor failure", "actor unauthorized", "actor forbidden", "actor malformed", "wrong nonce", "wrong audience", "expired", "exchange rejected", "missing ID token", "save failed", "swapped state", "duplicate state"} {
		t.Run(scenario, func(t *testing.T) {
			var logs bytes.Buffer
			previousLogger := slog.Default()
			slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
			t.Cleanup(func() { slog.SetDefault(previousLogger) })
			var issuer, nonce, challenge string
			mux := http.NewServeMux()
			write := func(w http.ResponseWriter, v any) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(v)
			}
			mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
				write(w, map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/keys", "userinfo_endpoint": issuer + "/userinfo", "id_token_signing_alg_values_supported": []string{"RS256"}})
			})
			mux.HandleFunc("GET /keys", func(w http.ResponseWriter, r *http.Request) {
				write(w, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "fixture", Algorithm: "RS256", Use: "sig"}}})
			})
			mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
				_ = r.ParseForm()
				sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
				if base64.RawURLEncoding.EncodeToString(sum[:]) != challenge || r.Form.Get("resource") != "https://ampcode.com/api/v2" {
					t.Error("bad PKCE/resource")
				}
				if scenario == "exchange rejected" {
					http.Error(w, "sensitive provider response", 400)
					return
				}
				claims := map[string]any{"iss": issuer, "sub": "oidc-subject-not-an-amp-id", "aud": "client", "exp": time.Now().Add(time.Hour).Unix(), "nonce": nonce, "name": "Alice Example", "picture": "https://images.example/alice.png"}
				if strings.Contains(scenario, "userinfo") {
					delete(claims, "name")
					delete(claims, "picture")
				}
				switch scenario {
				case "valid oversized profile":
					claims["name"], claims["picture"] = strings.Repeat("x", 5000), "https://images.example/"+strings.Repeat("x", 5000)
				case "valid unsafe picture":
					claims["picture"] = "javascript:alert(1)"
				case "valid access hash":
					hash := sha256.Sum256([]byte("access-secret"))
					claims["at_hash"] = base64.RawURLEncoding.EncodeToString(hash[:16])
				case "wrong access hash":
					claims["at_hash"] = "wrong"
				case "wrong nonce":
					claims["nonce"] = "wrong"
				case "wrong audience":
					claims["aud"] = "wrong"
				case "expired":
					claims["exp"] = time.Now().Add(-time.Hour).Unix()
				}
				raw, e := jwt.Signed(signer).Claims(claims).Serialize()
				if e != nil {
					t.Error(e)
				}
				response := map[string]any{"access_token": "access-secret", "refresh_token": "refresh-secret", "token_type": "Bearer", "expires_in": 3600, "id_token": raw}
				if scenario == "missing ID token" {
					delete(response, "id_token")
				}
				write(w, response)
			})
			mux.HandleFunc("GET /userinfo", func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer access-secret" {
					t.Error("userinfo did not use access token")
				}
				if scenario == "valid unavailable userinfo" {
					http.Error(w, "unavailable", 503)
					return
				}
				sub := "oidc-subject-not-an-amp-id"
				if scenario == "valid mismatched userinfo" {
					sub = "other-person"
				}
				write(w, map[string]string{"sub": sub, "name": "Alice Example", "picture": "https://images.example/alice.png"})
			})
			mux.HandleFunc("GET /actor", func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer access-secret" {
					t.Error("actor did not use access token")
				}
				id, kind := "amp-user", "user"
				switch scenario {
				case "machine actor":
					kind = "m2m"
				case "empty actor":
					id = ""
				case "actor failure":
					http.Error(w, "secret", 500)
					return
				case "actor unauthorized":
					http.Error(w, "access-secret", 401)
					return
				case "actor forbidden":
					http.Error(w, "sensitive upstream details", 403)
					return
				case "actor malformed":
					_, _ = w.Write([]byte("sensitive invalid JSON"))
					return
				}
				// The current actor API has no workspace field, even on success.
				write(w, map[string]any{"actor": map[string]any{"type": kind, "id": id, "scopes": []string{"amp.api:workspace.projects:view"}}})
			})
			mux.HandleFunc("GET /workspaces/{workspace}/projects", func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer access-secret" || r.URL.Query().Get("limit") != "1" {
					t.Error("wrong workspace authorization request")
				}
				if r.PathValue("workspace") != "allowed-workspace" {
					// Following a redirect to another accessible workspace must not admit login.
					write(w, map[string]any{"projects": []any{}})
					return
				}
				switch scenario {
				case "wrong workspace":
					http.Error(w, "sensitive workspace denial", 403)
				case "missing workspace":
					http.Error(w, "sensitive missing workspace", 404)
				case "workspace unavailable":
					http.Error(w, "sensitive provider failure", 500)
				case "workspace malformed":
					_, _ = w.Write([]byte(`{"error":"sensitive unexpected response"}`))
				case "workspace redirect":
					http.Redirect(w, r, "/workspaces/foreign-workspace/projects?limit=1", http.StatusFound)
				default:
					// Membership does not require having any projects.
					write(w, map[string]any{"projects": []any{}})
				}
			})
			server := httptest.NewServer(mux)
			defer server.Close()
			issuer = server.URL
			stored := false
			a, err := New(t.Context(), Config{BaseURL: "https://gateway.example", Issuer: issuer, ActorURL: issuer + "/actor", ClientID: "client", ClientSecret: "secret", WorkspaceID: "allowed-workspace", SessionKey: base64.StdEncoding.EncodeToString(make([]byte, 32)), Login: func(_ context.Context, id string, token *oauth2.Token) error {
				if scenario == "save failed" {
					return errors.New("sensitive storage details")
				}
				if id != "amp-user" || token.AccessToken != "access-secret" || token.RefreshToken != "refresh-secret" {
					t.Fatal("wrong identity or credentials")
				}
				stored = true
				return nil
			}})
			if err != nil {
				t.Fatal(err)
			}
			app := http.NewServeMux()
			a.Register(app)
			login := httptest.NewRecorder()
			app.ServeHTTP(login, httptest.NewRequest("GET", "/auth/amp/login", nil))
			location, _ := url.Parse(login.Header().Get("Location"))
			q := location.Query()
			nonce, challenge = q.Get("nonce"), q.Get("code_challenge")
			if nonce == "" || challenge == "" || q.Get("resource") != "https://ampcode.com/api/v2" || q.Get("scope") != "openid profile email offline_access amp.api:workspace.projects:view" || q.Get("redirect_uri") != "https://gateway.example/auth/amp/callback" {
				t.Fatal("bad authorization parameters")
			}
			callback := func() *httptest.ResponseRecorder {
				state := q.Get("state")
				if scenario == "swapped state" {
					state = "other"
				}
				path := "/auth/amp/callback?state=" + url.QueryEscape(state) + "&code=fixture"
				if scenario == "duplicate state" {
					path += "&state=other"
				}
				r := httptest.NewRequest("GET", path, nil)
				r.AddCookie(login.Result().Cookies()[0])
				w := httptest.NewRecorder()
				app.ServeHTTP(w, r)
				return w
			}
			w := callback()
			want := http.StatusUnauthorized
			success := strings.HasPrefix(scenario, "valid")
			if success {
				want = http.StatusSeeOther
			}
			if scenario == "save failed" {
				want = http.StatusServiceUnavailable
			}
			if scenario == "swapped state" || scenario == "duplicate state" {
				want = http.StatusBadRequest
			}
			if w.Code != want {
				t.Fatalf("got %d: %s", w.Code, w.Body)
			}
			if stored != success {
				t.Fatal("invalid login saved account")
			}
			for _, c := range w.Result().Cookies() {
				if c.Name != sessionCookie || c.MaxAge <= 0 {
					continue
				}
				if !success || !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode {
					t.Fatal("unsafe session issuance")
				}
				r := httptest.NewRequest("GET", "/", nil)
				r.AddCookie(c)
				session, ok := a.session(r)
				if !ok || session.Subject != "amp-user" {
					t.Fatal("lost canonical Amp identity")
				}
				if len(c.String()) > 4096 {
					t.Fatal("profile exceeded browser cookie limit")
				}
				wantProfile := Profile{Name: "Alice Example", Picture: "https://images.example/alice.png"}
				if scenario == "valid mismatched userinfo" || scenario == "valid unavailable userinfo" || scenario == "valid oversized profile" {
					wantProfile = Profile{Name: "amp-user"}
				}
				if scenario == "valid unsafe picture" {
					wantProfile.Picture = ""
				}
				a.Require(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
					if got := User(r.Context()); got != wantProfile {
						t.Fatalf("profile = %#v, want %#v", got, wantProfile)
					}
				})).ServeHTTP(httptest.NewRecorder(), r)
			}
			if strings.Contains(w.Body.String(), "secret") || strings.Contains(w.Body.String(), "sensitive") {
				t.Fatal("leaked sensitive error")
			}
			if strings.Contains(logs.String(), "secret") || strings.Contains(logs.String(), "sensitive") {
				t.Fatal("leaked credentials or upstream response in logs")
			}
			if detail := map[string]string{
				"wrong workspace": "workspace endpoint returned HTTP 403", "missing workspace": "workspace endpoint returned HTTP 404",
				"workspace unavailable": "workspace endpoint returned HTTP 500", "workspace malformed": "invalid workspace response",
				"workspace redirect": "workspace endpoint returned HTTP 302",
				"machine actor":      "actor is not a user", "empty actor": "missing actor ID",
				"actor failure": "actor endpoint returned HTTP 500", "actor unauthorized": "actor endpoint returned HTTP 401",
				"actor forbidden": "actor endpoint returned HTTP 403", "actor malformed": "invalid actor response JSON",
			}[scenario]; detail != "" {
				var event struct{ Reason, Detail string }
				if err := json.Unmarshal(logs.Bytes(), &event); err != nil || event.Reason != "actor" || event.Detail != detail {
					t.Fatalf("missing safe actor diagnostic: %s", logs.String())
				}
			}
			if callback().Code != http.StatusBadRequest {
				t.Fatal("replayed callback accepted")
			}
		})
	}
}

func TestCustomWorkspaceAPIBase(t *testing.T) {
	var issuer string
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/keys"})
	}))
	defer idp.Close()
	issuer = idp.URL
	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fixture-token" {
			t.Error("wrong API token")
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v2/actor":
			_, _ = w.Write([]byte(`{"actor":{"type":"user","id":"custom-user","scopes":["amp.api:workspace.projects:view"]}}`))
		case "/api/v2/workspaces/custom-workspace/projects":
			_, _ = w.Write([]byte(`{"projects":[]}`))
		default:
			t.Error("wrong custom API path")
			http.NotFound(w, r)
		}
	}))
	defer api.Close()
	cfg := Config{BaseURL: "https://gateway.example", Issuer: issuer, APIBaseURL: api.URL + "/api/v2/", ClientID: "client", ClientSecret: "fixture", WorkspaceID: "custom-workspace", SessionKey: base64.StdEncoding.EncodeToString(make([]byte, 32)), Login: func(context.Context, string, *oauth2.Token) error { return nil }}
	a, err := New(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	a.client = api.Client() // Trust only this fixture's TLS certificate.
	if id, err := a.actor(t.Context(), "fixture-token"); err != nil || id != "custom-user" {
		t.Fatalf("custom API actor = %q, %v", id, err)
	}
	w := httptest.NewRecorder()
	a.login(w, httptest.NewRequest("GET", "/auth/amp/login", nil))
	location, _ := url.Parse(w.Header().Get("Location"))
	if location.Query().Get("resource") != "https://ampcode.com/api/v2" {
		t.Fatal("custom domain changed OAuth resource")
	}
	for _, invalid := range []string{"http://workspace.example/api/v2", "https://user:secret@workspace.example/api/v2", "https://workspace.example/other", "https://workspace.example/api/v2?token=x", "https://workspace.example/api/v2#fragment", "https:///api/v2"} {
		cfg.APIBaseURL = invalid
		if _, err := New(t.Context(), cfg); err == nil {
			t.Fatalf("accepted invalid API base %q", invalid)
		}
	}
}
