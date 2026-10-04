package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"ampcode.com/lox/amp-mcp-gateway/internal/browserauth"
	"ampcode.com/lox/amp-mcp-gateway/internal/browserbridge"
	"ampcode.com/lox/amp-mcp-gateway/internal/gateway"
)

func (r *accountRegistry) browser(w http.ResponseWriter, req *http.Request) {
	r.mu.RLock()
	account := r.users[browserauth.Subject(req.Context())]
	r.mu.RUnlock()
	if account == nil {
		http.Error(w, "account unavailable", http.StatusForbidden)
		return
	}
	account.handler.ServeHTTP(w, req)
}

func (r *accountRegistry) workload(w http.ResponseWriter, req *http.Request) {
	// The unverified hint selects a runtime, never grants access. Its Amp
	// middleware verifies signature, audience, expiry, token use and exact user.
	raw, _ := strings.CutPrefix(req.Header.Get("Authorization"), "Bearer ")
	var hint struct {
		UserID string `json:"user_id"`
	}
	parts := strings.Split(raw, ".")
	if len(raw) <= 16384 && len(parts) == 3 {
		if payload, err := base64.RawURLEncoding.DecodeString(parts[1]); err == nil {
			_ = json.Unmarshal(payload, &hint)
		}
	}
	r.mu.RLock()
	account := r.users[hint.UserID]
	r.mu.RUnlock()
	if account == nil {
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "unauthorized", 401)
		return
	}
	account.handler.ServeHTTP(w, req)
}

func (r *accountRegistry) browserManager(code string) *browserbridge.Manager {
	id, _, ok := strings.Cut(code, ".")
	if !ok {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, account := range r.users {
		if account.browser.RoutingID == id {
			return account.browser
		}
	}
	return nil
}

func accountHost(origin string) (string, error) {
	canonical, err := gateway.CanonicalOrigin(origin)
	return strings.TrimPrefix(canonical, "https://"), err
}

func accountRouter(expectedHost string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/healthz" {
			fmt.Fprintln(w, "ok")
			return
		}
		host, err := accountHost("https://" + r.Host)
		if err != nil || host != expectedHost {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}
