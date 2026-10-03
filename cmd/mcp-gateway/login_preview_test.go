package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ampcode.com/lox/amp-mcp-gateway/internal/browserauth"
	"ampcode.com/lox/amp-mcp-gateway/internal/gateway"
	"ampcode.com/lox/amp-mcp-gateway/internal/store"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/oauth2"
)

// AMP_LOGIN_PREVIEW=1 keeps this signed local fixture on loopback :8095 for
// browser inspection. No production credentials, configuration or endpoints.
func TestAmpLoginBrowserRoundTrip(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "fixture"))
	if err != nil {
		t.Fatal(err)
	}
	idpMux := http.NewServeMux()
	idp := httptest.NewServer(idpMux)
	defer idp.Close()
	write := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	idpMux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		write(w, map[string]any{"issuer": idp.URL, "authorization_endpoint": idp.URL + "/authorize", "token_endpoint": idp.URL + "/token", "jwks_uri": idp.URL + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}})
	})
	idpMux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		write(w, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "fixture", Algorithm: "RS256", Use: "sig"}}})
	})
	idpMux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		http.Redirect(w, r, q.Get("redirect_uri")+"?state="+url.QueryEscape(q.Get("state"))+"&code="+url.QueryEscape(q.Get("nonce")), http.StatusSeeOther)
	})
	idpMux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		raw, err := jwt.Signed(signer).Claims(map[string]any{"iss": idp.URL, "sub": "fixture-oidc-user", "aud": "fixture-client", "exp": time.Now().Add(time.Hour).Unix(), "nonce": r.Form.Get("code")}).Serialize()
		if err != nil {
			http.Error(w, "fixture signing failed", 500)
			return
		}
		write(w, map[string]any{"access_token": "fixture-access", "refresh_token": "fixture-refresh", "token_type": "Bearer", "expires_in": 3600, "id_token": raw})
	})
	idpMux.HandleFunc("/actor", func(w http.ResponseWriter, r *http.Request) {
		write(w, map[string]any{"actor": map[string]string{"type": "user", "id": "amp-fixture-alice"}, "workspace": map[string]string{"id": "fixture-workspace"}})
	})
	app := httptest.NewUnstartedServer(nil)
	preview := os.Getenv("AMP_LOGIN_PREVIEW") == "1"
	if preview {
		app.Listener.Close()
		app.Listener, err = net.Listen("tcp", "127.0.0.1:8095")
		if err != nil {
			t.Fatal(err)
		}
	}
	baseURL := "http://" + app.Listener.Addr().String()
	var registry *accountRegistry
	auth, err := browserauth.New(t.Context(), browserauth.Config{BaseURL: baseURL, Issuer: idp.URL, ActorURL: idp.URL + "/actor", ClientID: "fixture-client", ClientSecret: "fixture-secret", WorkspaceID: "fixture-workspace", SessionKey: accountSecrets().SessionKey, Login: func(ctx context.Context, id string, token *oauth2.Token) (string, error) {
		return registry.login(ctx, id, token)
	}})
	if err != nil {
		t.Fatal(err)
	}
	base := accountConfig{Config: gateway.Config{Database: filepath.Join(t.TempDir(), "gateway.db"), OwnerSubject: "legacy-fixture-alice", AmpUserID: "amp-fixture-alice", Issuer: "legacy-issuer"}, Secrets: accountSecrets()}
	open := func(c accountConfig) (*accountRuntime, error) {
		s, err := store.Open(c.Config.Database, c.Secrets.EncryptionKey)
		return &accountRuntime{store: s, handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/account", http.StatusSeeOther) })}, err
	}
	primary, err := open(base)
	if err != nil {
		t.Fatal(err)
	}
	defer primary.store.Close()
	registry, err = newRegistry(t.Context(), primary, base, open)
	if err != nil {
		t.Fatal(err)
	}
	defer registry.close()
	app.Config.Handler = sharedAccountHandler(auth, registry)
	app.Start()
	defer app.Close()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 10 * time.Second}
	res, err := client.Get(baseURL + "/auth/amp/login")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 200 || res.Request.URL.Path != "/account" {
		t.Fatalf("login ended at %s (%d)", res.Request.URL.Path, res.StatusCode)
	}
	res, err = client.Post(baseURL+"/logout", "application/x-www-form-urlencoded", strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.Request.URL.Path != "/login" {
		t.Fatal("logout did not return to login")
	}
	if preview {
		t.Log("Amp login fixture ready on loopback :8095")
		time.Sleep(30 * time.Minute)
	}
}
