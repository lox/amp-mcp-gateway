// Package amplink links an authenticated gateway account to an Amp user via OIDC.
package amplink

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"ampcode.com/lox/amp-mcp-gateway/internal/browserauth"
	"ampcode.com/lox/amp-mcp-gateway/internal/webui"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	defaultIssuer = "https://auth.ampcode.com"
	defaultActor  = "https://ampcode.com/api/v2/actor"
	ampResource   = "https://ampcode.com/api/v2"
	stateCookie   = "amp_link_state"
	stateTTL      = 10 * time.Minute
	maxPending    = 128
	maxActorBody  = 64 << 10
)

// Config configures Sign in with Amp. IssuerURL, ActorURL, HTTPClient,
// Subject, and InsecureCookies exist to support isolated local fixtures; leave
// them zero-valued in production.
type Config struct {
	BaseURL      string
	ClientID     string
	ClientSecret string
	Current      func(subject string) string
	Link         func(context.Context, string, string) error

	IssuerURL       string
	ActorURL        string
	HTTPClient      *http.Client
	Subject         func(context.Context) string
	InsecureCookies bool
}

type pendingState struct {
	subject  string
	nonce    string
	verifier string
	expires  time.Time
}

type handler struct {
	oauth    oauth2.Config
	verifier *oidc.IDTokenVerifier
	actorURL string
	client   *http.Client
	current  func(string) string
	link     func(context.Context, string, string) error
	subject  func(context.Context) string
	insecure bool

	mu     sync.Mutex
	states map[string]pendingState
	now    func() time.Time
}

// New constructs the account-linking handler. The caller should still wrap it
// in browserauth.Auth.Require so every endpoint has an authenticated subject.
func New(ctx context.Context, cfg Config) (http.Handler, error) {
	if cfg.BaseURL == "" || cfg.ClientID == "" || cfg.ClientSecret == "" || cfg.Current == nil || cfg.Link == nil {
		return nil, errors.New("amplink: BaseURL, ClientID, ClientSecret, Current, and Link are required")
	}
	base, err := url.Parse(cfg.BaseURL)
	if err != nil || base.Host == "" || (base.Scheme != "https" && !(cfg.InsecureCookies && base.Scheme == "http")) || base.User != nil || (base.Path != "" && base.Path != "/") || base.RawQuery != "" || base.Fragment != "" {
		return nil, errors.New("amplink: BaseURL must be an absolute HTTPS URL")
	}
	issuer, actor := cfg.IssuerURL, cfg.ActorURL
	if issuer == "" {
		issuer = defaultIssuer
	}
	if actor == "" {
		actor = defaultActor
	}
	if (cfg.IssuerURL == "") != (cfg.ActorURL == "") {
		return nil, errors.New("amplink: IssuerURL and ActorURL overrides must be supplied together")
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	copyClient := *client
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	client = &copyClient
	discoveryCtx := oidc.ClientContext(ctx, client)
	provider, err := oidc.NewProvider(discoveryCtx, issuer)
	if err != nil {
		return nil, fmt.Errorf("amplink: discover issuer: %w", err)
	}
	subject := cfg.Subject
	if subject == nil {
		subject = browserauth.Subject
	}
	h := &handler{
		actorURL: actor, client: client, current: cfg.Current, link: cfg.Link,
		subject: subject, insecure: cfg.InsecureCookies, states: make(map[string]pendingState), now: time.Now,
	}
	h.oauth = oauth2.Config{
		ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret, Endpoint: provider.Endpoint(),
		RedirectURL: strings.TrimSuffix(cfg.BaseURL, "/") + "/auth/amp/callback",
		Scopes:      []string{oidc.ScopeOpenID, "profile", "email"},
	}
	h.verifier = provider.Verifier(&oidc.Config{ClientID: cfg.ClientID})
	mux := http.NewServeMux()
	mux.HandleFunc("GET /assets/ui.css", webui.Stylesheet)
	mux.HandleFunc("GET /account", h.account)
	mux.HandleFunc("POST /auth/amp/link", h.start)
	mux.HandleFunc("GET /auth/amp/callback", h.callback)
	return http.NewCrossOriginProtection().Handler(mux), nil
}

func (h *handler) account(w http.ResponseWriter, r *http.Request) {
	subject := h.subject(r.Context())
	if subject == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = accountPage.Execute(w, struct{ AmpID string }{AmpID: h.current(subject)})
}

func (h *handler) start(w http.ResponseWriter, r *http.Request) {
	subject := h.subject(r.Context())
	if subject == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	state, err := randomString()
	if err != nil {
		http.Error(w, "account linking unavailable", http.StatusInternalServerError)
		return
	}
	nonce, err := randomString()
	if err != nil {
		http.Error(w, "account linking unavailable", http.StatusInternalServerError)
		return
	}
	pending := pendingState{subject: subject, nonce: nonce, verifier: oauth2.GenerateVerifier(), expires: h.now().Add(stateTTL)}
	h.mu.Lock()
	now := h.now()
	for key, item := range h.states {
		if !item.expires.After(now) {
			delete(h.states, key)
		}
	}
	if len(h.states) >= maxPending {
		h.mu.Unlock()
		http.Error(w, "too many pending account links; try again later", http.StatusServiceUnavailable)
		return
	}
	h.states[state] = pending
	h.mu.Unlock()
	h.setStateCookie(w, state, int(stateTTL/time.Second))
	options := []oauth2.AuthCodeOption{
		oidc.Nonce(nonce), oauth2.S256ChallengeOption(pending.verifier),
		oauth2.SetAuthURLParam("resource", ampResource),
	}
	http.Redirect(w, r, h.oauth.AuthCodeURL(state, options...), http.StatusSeeOther)
}

func (h *handler) callback(w http.ResponseWriter, r *http.Request) {
	stateValues := r.URL.Query()["state"]
	cookie, cookieErr := r.Cookie(stateCookie)
	h.clearStateCookie(w)
	if cookieErr != nil || len(stateValues) != 1 || stateValues[0] == "" || cookie.Value != stateValues[0] {
		http.Error(w, "invalid account linking state", http.StatusBadRequest)
		return
	}
	h.mu.Lock()
	pending, ok := h.states[stateValues[0]]
	delete(h.states, stateValues[0]) // One use, including failed provider callbacks.
	h.mu.Unlock()
	subject := h.subject(r.Context())
	if !ok || !pending.expires.After(h.now()) || subject == "" || pending.subject != subject {
		http.Error(w, "invalid account linking state", http.StatusBadRequest)
		return
	}
	query := r.URL.Query()
	if len(query["code"]) != 1 || query.Get("code") == "" || len(query["error"]) != 0 {
		http.Error(w, "Amp authentication failed", http.StatusUnauthorized)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	ctx = context.WithValue(ctx, oauth2.HTTPClient, h.client)
	token, err := h.oauth.Exchange(ctx, query.Get("code"), oauth2.VerifierOption(pending.verifier), oauth2.SetAuthURLParam("resource", ampResource))
	if err != nil {
		http.Error(w, "Amp authentication failed", http.StatusUnauthorized)
		return
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		http.Error(w, "Amp authentication failed", http.StatusUnauthorized)
		return
	}
	idToken, err := h.verifier.Verify(ctx, rawIDToken)
	if err != nil || idToken.Nonce != pending.nonce {
		http.Error(w, "Amp authentication failed", http.StatusUnauthorized)
		return
	}
	ampID, err := h.actor(ctx, token.AccessToken)
	if err != nil {
		http.Error(w, "Amp authentication failed", http.StatusUnauthorized)
		return
	}
	if err := h.link(ctx, subject, ampID); err != nil {
		// Callback errors may encode storage details; keep them server-side and generic.
		http.Error(w, "Amp account could not be linked", http.StatusConflict)
		return
	}
	http.Redirect(w, r, "/account", http.StatusSeeOther)
}

func (h *handler) actor(ctx context.Context, accessToken string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.actorURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	response, err := h.client.Do(req)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxActorBody))
		return "", errors.New("actor endpoint rejected token")
	}
	var actor struct {
		Actor struct {
			Type string `json:"type"`
			ID   string `json:"id"`
		} `json:"actor"`
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxActorBody+1))
	if err != nil || len(body) > maxActorBody {
		return "", errors.New("invalid actor response")
	}
	if err := json.Unmarshal(body, &actor); err != nil || actor.Actor.Type != "user" || strings.TrimSpace(actor.Actor.ID) == "" {
		return "", errors.New("invalid actor")
	}
	return actor.Actor.ID, nil
}

func (h *handler) setStateCookie(w http.ResponseWriter, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: stateCookie, Value: value, Path: "/auth/amp", MaxAge: maxAge, HttpOnly: true, Secure: !h.insecure, SameSite: http.SameSiteLaxMode})
}

func (h *handler) clearStateCookie(w http.ResponseWriter) { h.setStateCookie(w, "", -1) }

func randomString() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

var accountPage = template.Must(template.New("account").Parse(`<!doctype html>
<html lang="en" class="dashboard"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Amp MCP Gateway · Account</title><link rel="stylesheet" href="/assets/ui.css"></head>
<body><a class="skip" href="#main">Skip to content</a><header class="topbar"><a class="brand" href="/account"><span class="brand-mark" aria-hidden="true"></span>gateway<span class="brand-slash" aria-hidden="true">/</span></a><span class="product-name">Account settings</span><form method="post" action="/logout"><button>Sign out</button></form></header>
<div class="shell"><aside class="sidebar"><nav aria-label="Main navigation">{{if .AmpID}}<a href="/operations"><span class="nav-symbol" aria-hidden="true">↗</span>Operations</a><a href="/connections"><span class="nav-symbol" aria-hidden="true">⊞</span>Connections</a><a href="/integrations"><span class="nav-symbol" aria-hidden="true">◇</span>Integrations</a><a href="/audit"><span class="nav-symbol" aria-hidden="true">≡</span>Audit</a>{{end}}<a href="/account" aria-current="page"><span class="nav-symbol" aria-hidden="true">@</span>Account</a></nav></aside><main id="main"><h1>Account</h1><p class="sub">Connect your authenticated gateway account to your Amp identity.</p><section class="card">{{if .AmpID}}<h2>Amp account</h2><p><span class="badge succeeded">Connected</span></p><dl><dt>Amp ID</dt><dd><code>{{.AmpID}}</code></dd></dl><p class="help">Account links cannot be changed here.</p>{{else}}<h2>Link Amp</h2><p>Sign in with Amp to verify and link your identity.</p><form method="post" action="/auth/amp/link"><button class="primary" type="submit">Sign in with Amp</button></form>{{end}}</section></main></div></body></html>`))
