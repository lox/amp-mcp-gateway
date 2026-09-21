// Package browserauth provides owner-only browser authentication for the
// gateway's approval UI.
package browserauth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	sessionCookie = "mcp_gateway_session"
	stateCookie   = "mcp_gateway_oidc"
	sessionTTL    = 12 * time.Hour
	stateTTL      = 10 * time.Minute
)

type subjectKey struct{}

// Config configures owner authentication. Demo mode is deliberately separate
// from OIDC mode and requires both Demo and DemoPassword.
type Config struct {
	BaseURL      string
	Issuer       string
	ClientID     string
	ClientSecret string
	OwnerSubject string
	HostedDomain string
	SessionKey   string
	DemoPassword string
	Demo         bool
	PortalUserID string // Explicit orb-only trusted-proxy authentication; never a cookie identity.
}

// Auth owns browser authentication state and handlers.
type Auth struct {
	baseURL      *url.URL
	key          []byte
	secure       bool
	demo         bool
	password     string
	owner        string
	hostedDomain string
	portalUserID string

	oauth    oauth2.Config
	verifier *oidc.IDTokenVerifier

	mu     sync.Mutex
	states map[string]pendingState
	now    func() time.Time
}

type pendingState struct {
	nonce    string
	verifier string
	expires  time.Time
}

type cookieValue struct {
	Subject string `json:"s"`
	State   string `json:"t,omitempty"`
	Expires int64  `json:"e"`
}

// New validates c and initializes OIDC discovery in production mode.
func New(ctx context.Context, c Config) (*Auth, error) {
	base, err := url.Parse(c.BaseURL)
	if err != nil || base.Scheme == "" || base.Host == "" || base.User != nil || (base.Scheme != "http" && base.Scheme != "https") || (base.Path != "" && base.Path != "/") || base.RawQuery != "" || base.Fragment != "" {
		return nil, errors.New("browserauth: BaseURL must be an HTTP(S) origin URL")
	}
	key, err := base64.StdEncoding.Strict().DecodeString(c.SessionKey)
	if err != nil || len(key) != 32 {
		return nil, errors.New("browserauth: SessionKey must be base64 encoding of exactly 32 bytes")
	}
	a := &Auth{
		baseURL:      base,
		key:          key,
		secure:       base.Scheme == "https",
		demo:         c.Demo,
		password:     c.DemoPassword,
		owner:        c.OwnerSubject,
		hostedDomain: c.HostedDomain,
		states:       make(map[string]pendingState),
		now:          time.Now,
	}
	if c.PortalUserID != "" {
		if c.Demo || c.DemoPassword != "" || c.Issuer != "" || c.ClientID != "" || c.ClientSecret != "" || c.HostedDomain != "" || base.Scheme != "https" || c.OwnerSubject != "amp-portal:"+c.PortalUserID {
			return nil, errors.New("browserauth: portal mode requires HTTPS, an Amp portal owner and no OIDC/demo configuration")
		}
		a.portalUserID = c.PortalUserID
		return a, nil
	}
	if c.Demo {
		if c.DemoPassword == "" {
			return nil, errors.New("browserauth: DemoPassword is required in demo mode")
		}
		if c.Issuer != "" || c.ClientID != "" || c.ClientSecret != "" || c.HostedDomain != "" {
			return nil, errors.New("browserauth: OIDC configuration is not allowed in demo mode")
		}
		if a.owner == "" {
			a.owner = "demo-owner"
		}
		return a, nil
	}
	if c.DemoPassword != "" {
		return nil, errors.New("browserauth: DemoPassword requires Demo mode")
	}
	if c.Issuer == "" || c.ClientID == "" || c.ClientSecret == "" || c.OwnerSubject == "" {
		return nil, errors.New("browserauth: Issuer, ClientID, ClientSecret, and OwnerSubject are required in production")
	}
	ctx = oidc.ClientContext(ctx, &http.Client{Timeout: 20 * time.Second})
	provider, err := oidc.NewProvider(ctx, c.Issuer)
	if err != nil {
		return nil, fmt.Errorf("browserauth: discover issuer: %w", err)
	}
	a.oauth = oauth2.Config{
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  a.endpoint("auth/callback"),
		Scopes:       []string{oidc.ScopeOpenID},
	}
	if c.HostedDomain != "" {
		// Google requires email or profile alongside openid. Request no profile data.
		a.oauth.Scopes = append(a.oauth.Scopes, "email")
	}
	a.verifier = provider.Verifier(&oidc.Config{ClientID: c.ClientID})
	return a, nil
}

// Register registers the authentication endpoints on mux.
func (a *Auth) Register(mux *http.ServeMux) {
	cop := http.NewCrossOriginProtection()
	if a.portalUserID != "" {
		mux.Handle("GET /login", a.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/", http.StatusSeeOther)
		})))
		mux.Handle("POST /logout", cop.Handler(a.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			a.clearCookie(w, sessionCookie)
			fmt.Fprintln(w, "This development instance uses your Amp portal identity. Sign out of Amp to end browser access.")
		}))))
		mux.HandleFunc("/auth/callback", http.NotFound)
		return
	}
	mux.Handle("/login", cop.Handler(http.HandlerFunc(a.login)))
	mux.Handle("/auth/callback", http.HandlerFunc(a.callback))
	mux.Handle("/logout", cop.Handler(http.HandlerFunc(a.logout)))
}

// Require redirects unauthenticated requests to the login page and otherwise
// adds the authenticated subject to the request context.
func (a *Auth) Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.portalUserID != "" {
			if !a.portalOwner(r) {
				http.Error(w, "This development gateway requires the owner's authenticated Amp portal.", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), subjectKey{}, a.owner)))
			return
		}
		sub, ok := a.sessionSubject(r)
		if !ok || sub != a.owner {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), subjectKey{}, sub)))
	})
}

// Portal headers are trusted only from the local proxy. Other orb processes are
// inside this trust boundary; this is not suitable for a shared/untrusted host.
func (a *Auth) portalOwner(r *http.Request) bool {
	peer, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil || !peer.Addr().IsLoopback() || r.Host != a.baseURL.Host || len(r.Header.Values("X-Amp-User-ID")) != 1 || r.Header.Get("X-Amp-User-ID") != a.portalUserID || len(r.Header.Values("X-Amp-Authenticated")) != 1 {
		return false
	}
	seen, authenticated := false, false
	for _, entry := range strings.Split(r.Header.Get("X-Amp-Authenticated"), ",") {
		key, value, _ := strings.Cut(strings.TrimSpace(entry), "=")
		if key == "amp-user" {
			if seen {
				return false
			}
			seen, authenticated = true, value == "yes"
		}
	}
	return authenticated
}

// Subject returns the authenticated subject installed by Require, or an empty
// string outside an authenticated request.
func Subject(ctx context.Context) string {
	s, _ := ctx.Value(subjectKey{}).(string)
	return s
}

func (a *Auth) sessionSubject(r *http.Request) (string, bool) {
	value, ok := a.readSignedCookie(r, sessionCookie)
	if !ok || value.Subject == "" || value.State != "" {
		return "", false
	}
	return value.Subject, true
}

func (a *Auth) login(w http.ResponseWriter, r *http.Request) {
	if a.demo {
		a.demoLogin(w, r)
		return
	}
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	state, err := randomString(32)
	if err != nil {
		http.Error(w, "authentication unavailable", http.StatusInternalServerError)
		return
	}
	nonce, err := randomString(32)
	if err != nil {
		http.Error(w, "authentication unavailable", http.StatusInternalServerError)
		return
	}
	verifier := oauth2.GenerateVerifier()
	expires := a.now().Add(stateTTL)
	a.mu.Lock()
	for k, v := range a.states {
		if !v.expires.After(a.now()) {
			delete(a.states, k)
		}
	}
	a.states[state] = pendingState{nonce: nonce, verifier: verifier, expires: expires}
	a.mu.Unlock()
	a.setSignedCookie(w, stateCookie, cookieValue{State: state, Expires: expires.Unix()}, stateTTL)
	authOptions := []oauth2.AuthCodeOption{oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)}
	if a.hostedDomain != "" {
		authOptions = append(authOptions, oauth2.SetAuthURLParam("hd", a.hostedDomain))
	}
	http.Redirect(w, r, a.oauth.AuthCodeURL(state, authOptions...), http.StatusSeeOther)
}

func (a *Auth) demoLogin(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = loginPage.Execute(w, nil)
	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		if err := r.ParseForm(); err != nil || subtle.ConstantTimeCompare([]byte(r.Form.Get("password")), []byte(a.password)) != 1 {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusUnauthorized)
			_ = loginPage.Execute(w, "Incorrect password")
			return
		}
		a.setSignedCookie(w, sessionCookie, cookieValue{Subject: a.owner, Expires: a.now().Add(sessionTTL).Unix()}, sessionTTL)
		http.Redirect(w, r, "/", http.StatusSeeOther)
	default:
		methodNotAllowed(w, http.MethodGet+", "+http.MethodPost)
	}
}

func (a *Auth) callback(w http.ResponseWriter, r *http.Request) {
	if a.demo {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	cv, ok := a.readSignedCookie(r, stateCookie)
	a.clearCookie(w, stateCookie)
	if !ok || cv.State == "" || r.URL.Query().Get("state") != cv.State {
		http.Error(w, "invalid authentication state", http.StatusBadRequest)
		return
	}
	a.mu.Lock()
	pending, exists := a.states[cv.State]
	delete(a.states, cv.State)
	a.mu.Unlock()
	if !exists || !pending.expires.After(a.now()) {
		http.Error(w, "invalid authentication state", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	token, err := a.oauth.Exchange(ctx, r.URL.Query().Get("code"), oauth2.VerifierOption(pending.verifier))
	if err != nil {
		// Never log provider errors: they can include credentials or token responses.
		slog.Warn("browser authentication failed", "reason", "token_exchange")
		http.Error(w, "authentication failed", http.StatusUnauthorized)
		return
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		slog.Warn("browser authentication failed", "reason", "missing_id_token")
		http.Error(w, "authentication failed", http.StatusUnauthorized)
		return
	}
	idToken, err := a.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		slog.Warn("browser authentication failed", "reason", "id_token_verification")
		http.Error(w, "authentication failed", http.StatusUnauthorized)
		return
	}
	if idToken.Nonce != pending.nonce {
		slog.Warn("browser authentication failed", "reason", "nonce")
		http.Error(w, "authentication failed", http.StatusUnauthorized)
		return
	}
	if idToken.Subject != a.owner {
		slog.Warn("browser authentication failed", "reason", "owner")
		http.Error(w, "authentication failed", http.StatusUnauthorized)
		return
	}
	if a.hostedDomain != "" {
		var claims struct {
			HostedDomain string `json:"hd"`
		}
		if err := idToken.Claims(&claims); err != nil || claims.HostedDomain != a.hostedDomain {
			slog.Warn("browser authentication failed", "reason", "hosted_domain")
			http.Error(w, "authentication failed", http.StatusUnauthorized)
			return
		}
	}
	a.setSignedCookie(w, sessionCookie, cookieValue{Subject: idToken.Subject, Expires: a.now().Add(sessionTTL).Unix()}, sessionTTL)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *Auth) logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	a.clearCookie(w, sessionCookie)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (a *Auth) endpoint(path string) string {
	u := *a.baseURL
	u.Path = strings.TrimRight(u.Path, "/") + "/" + path
	return u.String()
}

func (a *Auth) setSignedCookie(w http.ResponseWriter, name string, value cookieValue, ttl time.Duration) {
	payload, _ := json.Marshal(value)
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, a.key)
	_, _ = mac.Write([]byte(encoded))
	signed := encoded + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	http.SetCookie(w, &http.Cookie{Name: name, Value: signed, Path: "/", MaxAge: int(ttl.Seconds()), HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteLaxMode})
}

func (a *Auth) readSignedCookie(r *http.Request, name string) (cookieValue, bool) {
	cookie, err := r.Cookie(name)
	if err != nil || len(cookie.Value) > 1024 {
		return cookieValue{}, false
	}
	parts := strings.Split(cookie.Value, ".")
	if len(parts) != 2 {
		return cookieValue{}, false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return cookieValue{}, false
	}
	mac := hmac.New(sha256.New, a.key)
	_, _ = mac.Write([]byte(parts[0]))
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return cookieValue{}, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return cookieValue{}, false
	}
	var value cookieValue
	if json.Unmarshal(payload, &value) != nil || value.Expires <= a.now().Unix() {
		return cookieValue{}, false
	}
	return value, true
}

func (a *Auth) clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteLaxMode})
}

func randomString(bytes int) (string, error) {
	b := make([]byte, bytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func methodNotAllowed(w http.ResponseWriter, allow string) {
	w.Header().Set("Allow", allow)
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

var loginPage = template.Must(template.New("login").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Gateway sign in</title><style>
body{margin:0;background:#f4f1ea;color:#20231f;font:16px system-ui,sans-serif;display:grid;place-items:center;min-height:100vh}
main{background:white;padding:2.5rem;border-radius:16px;box-shadow:0 12px 40px #0002;width:min(22rem,calc(100% - 4rem))}
h1{margin:.2rem 0}.badge{color:#735c0f;background:#fff1b8;padding:.25rem .55rem;border-radius:99px;font-size:.75rem;font-weight:700}
label,input,button{display:block;width:100%;box-sizing:border-box}label{margin-top:1.5rem;font-weight:600}input{margin:.45rem 0 1rem;padding:.75rem;border:1px solid #aaa;border-radius:8px}button{padding:.8rem;border:0;border-radius:8px;background:#22543d;color:white;font-weight:700}.error{color:#a11}
</style></head><body><main><span class="badge">DEMO MODE</span><h1>Owner sign in</h1><p>This demo uses a local password.</p>{{if .}}<p class="error">{{.}}</p>{{end}}<form method="post" action="/login"><label for="password">Password</label><input id="password" name="password" type="password" required autofocus><button type="submit">Sign in</button></form></main></body></html>`))
