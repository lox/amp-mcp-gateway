package amplink

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

type fixture struct {
	handler       http.Handler
	issuer        *httptest.Server
	subject       string
	nonce         string
	challenge     string
	linkedSubject string
	linkedAmpID   string
	linkErr       error
	wrongNonce    bool
	actorType     string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{subject: "google-user", actorType: "user"}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, &jose.SignerOptions{ExtraHeaders: map[jose.HeaderKey]any{jose.HeaderKey("kid"): "test-key"}})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	f.issuer = httptest.NewServer(mux)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"issuer": f.issuer.URL, "authorization_endpoint": f.issuer.URL + "/authorize", "token_endpoint": f.issuer.URL + "/token", "jwks_uri": f.issuer.URL + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "test-key", Algorithm: "RS256", Use: "sig"}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil || r.Form.Get("code") != "good-code" || f.challenge != pkceChallenge(r.Form.Get("code_verifier")) || r.Form.Get("resource") != "https://ampcode.com/api/v2" {
			http.Error(w, "token request rejected: secret body", http.StatusBadRequest)
			return
		}
		nonce := f.nonce
		if f.wrongNonce {
			nonce = "wrong"
		}
		raw, err := jwt.Signed(signer).Claims(map[string]any{"iss": f.issuer.URL, "sub": "amp-oidc-user", "aud": "client", "exp": time.Now().Add(time.Minute).Unix(), "iat": time.Now().Unix(), "nonce": nonce}).Serialize()
		if err != nil {
			t.Fatal(err)
		}
		writeJSON(w, map[string]any{"access_token": "access-secret", "token_type": "Bearer", "expires_in": 60, "id_token": raw})
	})
	mux.HandleFunc("/actor", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer access-secret" {
			http.Error(w, "bad token", http.StatusUnauthorized)
			return
		}
		writeJSON(w, map[string]any{"actor": map[string]string{"type": f.actorType, "id": "amp-user-id"}})
	})
	h, err := New(context.Background(), Config{
		BaseURL: "http://gateway.example", ClientID: "client", ClientSecret: "client-secret",
		IssuerURL: f.issuer.URL, ActorURL: f.issuer.URL + "/actor", InsecureCookies: true,
		Subject: func(context.Context) string { return f.subject }, Current: func(subject string) string {
			if subject == f.linkedSubject {
				return f.linkedAmpID
			}
			return ""
		},
		Link: func(_ context.Context, subject, ampID string) error {
			f.linkedSubject, f.linkedAmpID = subject, ampID
			return f.linkErr
		},
	})
	if err != nil {
		f.issuer.Close()
		t.Fatal(err)
	}
	f.handler = h
	t.Cleanup(f.issuer.Close)
	return f
}

func (f *fixture) begin(t *testing.T) (string, *http.Cookie) {
	t.Helper()
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/auth/amp/link", nil))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("start status = %d: %s", w.Code, w.Body.String())
	}
	location, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	q := location.Query()
	f.nonce, f.challenge = q.Get("nonce"), q.Get("code_challenge")
	if strings.Join(q["scope"], "") != "openid profile email" || q.Get("resource") != "https://ampcode.com/api/v2" || q.Get("code_challenge_method") != "S256" {
		t.Fatalf("authorize query = %v", q)
	}
	return q.Get("state"), w.Result().Cookies()[0]
}

func (f *fixture) callback(state string, cookie *http.Cookie) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/auth/amp/callback?state="+url.QueryEscape(state)+"&code=good-code", nil)
	r.AddCookie(cookie)
	f.handler.ServeHTTP(w, r)
	return w
}

func TestSignedOAuthHandshakeLinksActor(t *testing.T) {
	f := newFixture(t)
	state, cookie := f.begin(t)
	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode || cookie.Secure {
		t.Fatalf("fixture cookie attributes = %#v", cookie)
	}
	w := f.callback(state, cookie)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/account" || f.linkedSubject != "google-user" || f.linkedAmpID != "amp-user-id" {
		t.Fatalf("callback = %d %q, linked %q to %q", w.Code, w.Body.String(), f.linkedSubject, f.linkedAmpID)
	}
	if replay := f.callback(state, cookie); replay.Code != http.StatusBadRequest {
		t.Fatalf("replay status = %d", replay.Code)
	}
	start := httptest.NewRecorder()
	f.handler.ServeHTTP(start, httptest.NewRequest(http.MethodGet, "/auth/amp/link", nil))
	if start.Header().Get("Location") != "/account" || len(start.Result().Cookies()) != 0 {
		t.Fatal("already linked user created another pending link")
	}
}

func TestRepeatedStartsCannotConsumeOtherUsersLinkCapacity(t *testing.T) {
	f := newFixture(t)
	oldState, oldCookie := f.begin(t)
	for range maxPending + 1 {
		f.begin(t)
	}
	if w := f.callback(oldState, oldCookie); w.Code != http.StatusBadRequest {
		t.Fatal("superseded attempt was not invalidated")
	}
	f.subject = "other-google-user"
	state, cookie := f.begin(t)
	if w := f.callback(state, cookie); w.Code != http.StatusSeeOther || f.linkedSubject != "other-google-user" {
		t.Fatal("one user exhausted another user's linking capacity")
	}
}

func TestCallbackRejectsSwappedSubjectWrongStateNonceAndActor(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*fixture, *string)
		want   int
	}{
		{"swapped session", func(f *fixture, _ *string) { f.subject = "other-google-user" }, http.StatusBadRequest},
		{"wrong state", func(_ *fixture, state *string) { *state = "wrong" }, http.StatusBadRequest},
		{"wrong nonce", func(f *fixture, _ *string) { f.wrongNonce = true }, http.StatusUnauthorized},
		{"non-user actor", func(f *fixture, _ *string) { f.actorType = "workspace" }, http.StatusUnauthorized},
		{"duplicate identity", func(f *fixture, _ *string) { f.linkErr = errors.New("already linked") }, http.StatusConflict},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newFixture(t)
			state, cookie := f.begin(t)
			test.mutate(f, &state)
			w := f.callback(state, cookie)
			if w.Code != test.want || strings.Contains(w.Body.String(), "already linked") || strings.Contains(w.Body.String(), "secret") {
				t.Fatalf("callback = %d %q", w.Code, w.Body.String())
			}
		})
	}
}

func TestAccountPageUsesNavigationForLogin(t *testing.T) {
	f := newFixture(t)
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/account", nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Sign in with Amp") || strings.Contains(w.Body.String(), `name="amp`) {
		t.Fatalf("account page = %d %q", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `<a class="button primary" href="/auth/amp/link">`) || strings.Contains(w.Body.String(), `action="/auth/amp/link"`) {
		t.Fatal("form-action CSP would block cross-origin login redirects")
	}
}

func TestLinkedAccountPageUsesApprovalsNavigation(t *testing.T) {
	f := newFixture(t)
	f.linkedSubject, f.linkedAmpID = f.subject, "amp-user-id"
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/account", nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `<a href="/approvals"><span class="nav-symbol" aria-hidden="true">↗</span>Approvals</a>`) {
		t.Fatalf("linked account navigation = %d %q", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), `href="/operations"`) || strings.Contains(w.Body.String(), `>Operations</a>`) {
		t.Fatal("linked account page retained legacy operations navigation")
	}
}

func TestProductionStateCookieIsSecure(t *testing.T) {
	// Production HTTPS behavior is covered directly because constructing another
	// provider would add no protocol coverage.
	inner := &handler{insecure: false}
	w := httptest.NewRecorder()
	inner.setStateCookie(w, "state", 600)
	cookie := w.Result().Cookies()[0]
	if !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode || cookie.MaxAge != 600 {
		t.Fatalf("weak state cookie: %#v", cookie)
	}
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		panic(fmt.Sprintf("encode fixture response: %v", err))
	}
}
