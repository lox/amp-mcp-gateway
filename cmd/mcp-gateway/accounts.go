package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"sync"

	"ampcode.com/lox/amp-mcp-gateway/internal/browserauth"
	"ampcode.com/lox/amp-mcp-gateway/internal/browserbridge"
	"ampcode.com/lox/amp-mcp-gateway/internal/demo"
	"ampcode.com/lox/amp-mcp-gateway/internal/gateway"
)

type deploymentConfig struct {
	gateway.Config
	AmpLoginClientID string
}

type accountConfig struct {
	Config  gateway.Config
	Secrets demo.Secrets
	auth    *browserauth.Auth
}

// accountRegistry serializes one-to-one linking and owns all account runtimes.
// Only the OAuth callback calls link; unverified workload hints never create state.
type accountRegistry struct {
	mu       sync.RWMutex
	ctx      context.Context
	primary  *accountRuntime
	config   accountConfig
	key      string
	links    map[string]string
	users    map[string]*accountRuntime
	subjects map[string]*accountRuntime
	open     func(accountConfig) (*accountRuntime, error)
	start    func(*accountRuntime)
}

func newRegistry(ctx context.Context, primary *accountRuntime, config accountConfig, open func(accountConfig) (*accountRuntime, error)) (*accountRegistry, error) {
	identity, _ := json.Marshal([]string{config.Config.Issuer, config.Config.ClientID, config.Config.HostedDomain})
	key := fmt.Sprintf("account-links/v1/%x", sha256.Sum256(identity))
	r := &accountRegistry{ctx: ctx, primary: primary, config: config, key: key, links: map[string]string{}, users: map[string]*accountRuntime{}, subjects: map[string]*accountRuntime{}, open: open}
	raw, err := primary.store.LoadToken(ctx, key)
	if err != nil {
		return nil, err
	}
	if len(raw) != 0 {
		if err := json.Unmarshal(raw, &r.links); err != nil || r.links == nil {
			return nil, errors.New("invalid saved account links")
		}
	}
	owner, user := config.Config.OwnerSubject, config.Config.AmpUserID
	if old := r.links[owner]; old != "" && old != user {
		return nil, errors.New("configured owner identity conflicts with saved link")
	}
	r.links[owner] = user
	r.users[user], r.subjects[owner] = primary, primary
	for subject, ampID := range r.links {
		if subject == owner {
			continue
		}
		if subject == "" || ampID == "" || r.users[ampID] != nil {
			r.close()
			return nil, errors.New("conflicting saved account links")
		}
		cfg, err := r.userConfig(subject, ampID)
		if err != nil {
			r.close()
			return nil, err
		}
		account, err := open(cfg)
		if err != nil {
			r.close()
			return nil, err
		}
		r.users[ampID], r.subjects[subject] = account, account
	}
	return r, nil
}

func (r *accountRegistry) current(subject string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.links[subject]
}

func (r *accountRegistry) link(ctx context.Context, subject, ampID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.ctx.Err(); err != nil {
		return errors.New("gateway is shutting down")
	}
	if subject == "" || ampID == "" {
		return errors.New("missing identity")
	}
	if old := r.links[subject]; old != "" {
		if old == ampID {
			return nil
		}
		return errors.New("account already linked")
	}
	if r.users[ampID] != nil {
		return errors.New("Amp identity already linked")
	}
	cfg, err := r.userConfig(subject, ampID)
	if err != nil {
		return err
	}
	account, err := r.open(cfg)
	if err != nil {
		return err
	}
	r.links[subject] = ampID
	raw, err := json.Marshal(r.links)
	if err == nil {
		err = r.primary.store.SaveToken(ctx, r.key, raw)
	}
	if err != nil {
		delete(r.links, subject)
		account.store.Close()
		return err
	}
	r.users[ampID], r.subjects[subject] = account, account
	if r.start != nil {
		r.start(account)
	}
	return nil
}

func (r *accountRegistry) userConfig(subject, ampID string) (accountConfig, error) {
	c := r.config.Config
	identity, _ := json.Marshal([]string{c.Issuer, subject, ampID})
	id := sha256.Sum256(identity)
	key, err := accountKey(r.config.Secrets.EncryptionKey, "storage", identity)
	if err != nil {
		return accountConfig{}, err
	}
	return accountConfig{Config: gateway.Config{
		BaseURL: c.BaseURL, OwnerSubject: subject, AmpUserID: ampID,
		Database: filepath.Join(c.Database+".accounts", hex.EncodeToString(id[:])+".db"),
		Issuer:   c.Issuer, ClientID: c.ClientID, HostedDomain: c.HostedDomain, AccountLink: true,
	}, Secrets: demo.Secrets{EncryptionKey: key, SessionKey: r.config.Secrets.SessionKey}, auth: r.config.auth}, nil
}

func (r *accountRegistry) browser(w http.ResponseWriter, req *http.Request) {
	r.mu.RLock()
	account := r.subjects[browserauth.Subject(req.Context())]
	r.mu.RUnlock()
	if account == nil {
		http.Redirect(w, req, "/account", http.StatusSeeOther)
		return
	}
	account.handler.ServeHTTP(w, req)
}

func (r *accountRegistry) workload(w http.ResponseWriter, req *http.Request) {
	// Decode only a bounded routing hint. The selected runtime's Amp middleware
	// still verifies signature, audience, expiry, token use AND its exact user ID
	// before exposing any tools, results or credentials.
	raw, _ := strings.CutPrefix(req.Header.Get("Authorization"), "Bearer ")
	var hint struct {
		UserID string `json:"user_id"`
	}
	parts := strings.Split(raw, ".")
	if len(raw) <= 16384 && len(parts) == 3 {
		payload, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err == nil {
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
	for _, account := range r.subjects {
		if account.browser.RoutingID == id {
			return account.browser
		}
	}
	return nil
}

// close is called after HTTP serving and workers stop, or during failed startup.
// The primary account is closed by main.
func (r *accountRegistry) close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, account := range r.subjects {
		if account != r.primary {
			account.store.Close()
		}
	}
}

func accountKey(master, purpose string, identity []byte) (string, error) {
	key, err := base64.StdEncoding.Strict().DecodeString(master)
	if err != nil || len(key) != 32 {
		return "", errors.New("account master keys must be base64-encoded 32 bytes")
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("amp-mcp-gateway/account/v1/" + purpose + "\x00"))
	mac.Write(identity)
	return base64.StdEncoding.EncodeToString(mac.Sum(nil)), nil
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
