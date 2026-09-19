package upstream

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

type reauthorizer interface {
	Reauthorize(context.Context, string, []byte) error
}

const stateCookie = "mcp_gateway_oauth_state"

// Register installs the OAuth connect and callback handlers on mux.
func (m *Manager) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /connections/{id}/connect", m.connectHandler)
	mux.HandleFunc("GET /connections/{id}/callback", m.callbackHandler)
}

func (m *Manager) connectHandler(w http.ResponseWriter, r *http.Request) {
	c, ok := m.conns[r.PathValue("id")]
	if !ok || c.config.OAuth == nil {
		http.NotFound(w, r)
		return
	}
	if c.config.OAuth.ClientSecretEnv != "" && getenv(c.config.OAuth.ClientSecretEnv) == "" {
		http.Error(w, "OAuth client credentials are unavailable", http.StatusServiceUnavailable)
		return
	}
	state, err := randomString(32)
	if err != nil {
		http.Error(w, "could not start authorization", http.StatusInternalServerError)
		return
	}
	verifier := oauth2.GenerateVerifier()
	m.stateMu.Lock()
	now := time.Now()
	for key, pending := range m.states {
		if now.After(pending.expires) {
			delete(m.states, key)
		}
	}
	m.states[state] = pendingState{connection: c.config.ID, verifier: verifier, expires: now.Add(stateLifetime)}
	m.stateMu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: stateCookie, Value: state, Path: "/connections/" + c.config.ID + "/callback", HttpOnly: true, Secure: strings.HasPrefix(m.baseURL, "https://"), SameSite: http.SameSiteLaxMode, MaxAge: int(stateLifetime.Seconds())})
	location := m.oauthConfig(c.config).AuthCodeURL(state, oauth2.S256ChallengeOption(verifier))
	http.Redirect(w, r, location, http.StatusFound)
}

func (m *Manager) callbackHandler(w http.ResponseWriter, r *http.Request) {
	c, ok := m.conns[r.PathValue("id")]
	if !ok || c.config.OAuth == nil {
		http.NotFound(w, r)
		return
	}
	cookie, err := r.Cookie(stateCookie)
	if err != nil || cookie.Value == "" {
		http.Error(w, "invalid authorization state", http.StatusBadRequest)
		return
	}
	m.stateMu.Lock()
	pending, found := m.states[cookie.Value]
	delete(m.states, cookie.Value)
	m.stateMu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: stateCookie, Path: "/connections/" + c.config.ID + "/callback", MaxAge: -1, HttpOnly: true, Secure: strings.HasPrefix(m.baseURL, "https://"), SameSite: http.SameSiteLaxMode})
	if r.URL.Query().Get("state") != cookie.Value || !found || pending.connection != c.config.ID || time.Now().After(pending.expires) {
		http.Error(w, "invalid authorization state", http.StatusBadRequest)
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" || r.URL.Query().Get("error") != "" {
		http.Error(w, "authorization was not completed", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()
	ctx = context.WithValue(ctx, oauth2.HTTPClient, &http.Client{Timeout: requestTimeout, CheckRedirect: rejectRedirect})
	token, err := m.oauthConfig(c.config).Exchange(ctx, code, oauth2.VerifierOption(pending.verifier))
	if err != nil {
		http.Error(w, "authorization exchange failed", http.StatusBadGateway)
		return
	}
	raw, err := json.Marshal(token)
	if err == nil {
		c.mu.Lock()
		if replacement, ok := m.store.(reauthorizer); ok {
			err = replacement.Reauthorize(ctx, tokenKey(c.config), raw)
		} else {
			err = m.store.SaveToken(ctx, tokenKey(c.config), raw)
		}
		c.mu.Unlock()
	}
	if err != nil {
		http.Error(w, "authorization could not be saved", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (m *Manager) oauthConfig(c Connection) *oauth2.Config {
	o := c.OAuth
	secret := ""
	if o.ClientSecretEnv != "" {
		secret = getenv(o.ClientSecretEnv)
	}
	return &oauth2.Config{ClientID: o.ClientID, ClientSecret: secret, Endpoint: oauth2.Endpoint{AuthURL: o.AuthURL, TokenURL: o.TokenURL}, RedirectURL: m.baseURL + "/connections/" + c.ID + "/callback", Scopes: append([]string(nil), o.Scopes...)}
}

var getenv = func(key string) string { return strings.TrimSpace(os.Getenv(key)) }

func randomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
