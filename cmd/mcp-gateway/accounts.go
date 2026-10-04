package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"ampcode.com/lox/amp-mcp-gateway/internal/browserauth"
	"ampcode.com/lox/amp-mcp-gateway/internal/browserbridge"
	"ampcode.com/lox/amp-mcp-gateway/internal/demo"
	"ampcode.com/lox/amp-mcp-gateway/internal/gateway"
	"ampcode.com/lox/amp-mcp-gateway/internal/store"
	"golang.org/x/oauth2"
)

type deploymentConfig struct {
	gateway.Config
	AmpLoginClientID string
	AmpWorkspaceID   string
	AmpAPIBaseURL    string
}

type accountConfig struct {
	Config   gateway.Config
	Secrets  demo.Secrets
	auth     *browserauth.Auth
	verifier *gateway.AmpVerifier
}

// Bind before catalogue/configuration loading can mutate the account. Once a
// database is bound, disabling linking must not allow its identity to change.
func bindAccountIdentity(ctx context.Context, s *store.Store, cfg gateway.Config) error {
	const key = "gateway-account-identity/v1"
	identity, _ := json.Marshal([]string{cfg.Issuer, cfg.OwnerSubject, cfg.AmpUserID})
	stored, err := s.LoadToken(ctx, key)
	if err != nil {
		return err
	}
	if len(stored) != 0 {
		if !bytes.Equal(stored, identity) {
			return errors.New("database account identity cannot be reassigned")
		}
		return nil
	}
	if cfg.AccountLink {
		return s.SaveToken(ctx, key, identity)
	}
	return nil
}

// accountRegistry serializes one-to-one linking and owns all account runtimes.
// Only the OAuth callback calls link; unverified workload hints never create state.
type accountRegistry struct {
	linkMu   sync.Mutex // Serialize creation without blocking existing-account routing.
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

const provisioningKey = "amp-account-provisioning/v1"

func newRegistry(ctx context.Context, primary *accountRuntime, config accountConfig, open func(accountConfig) (*accountRuntime, error)) (*accountRegistry, error) {
	identity, _ := json.Marshal([]string{config.Config.Issuer, config.Config.HostedDomain})
	legacyKey := fmt.Sprintf("account-links/v1/%x", sha256.Sum256(identity))
	const key = "amp-accounts/v1"
	r := &accountRegistry{ctx: ctx, primary: primary, config: config, key: key, links: map[string]string{}, users: map[string]*accountRuntime{}, subjects: map[string]*accountRuntime{}, open: open}
	raw, err := primary.store.LoadToken(ctx, key)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		raw, err = primary.store.LoadToken(ctx, legacyKey)
		if err != nil {
			return nil, err
		}
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
	pending, err := primary.store.LoadToken(ctx, provisioningKey)
	if err != nil {
		return nil, err
	}
	creating := ""
	if len(pending) != 0 {
		var identity []string
		if json.Unmarshal(pending, &identity) != nil || len(identity) != 2 || identity[0] == "" || identity[1] == "" {
			return nil, errors.New("invalid account provisioning marker")
		}
		subject, ampID := identity[0], identity[1]
		if old := r.links[subject]; old != "" {
			if old != ampID {
				return nil, errors.New("account provisioning marker conflicts with saved link")
			}
		} else {
			creating = subject
			r.links[subject] = ampID
		}
	}
	entries, err := os.ReadDir(config.Config.Database + ".accounts")
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	unreferenced := make(map[string]bool)
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".db") {
			unreferenced[entry.Name()] = true
		}
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
		// Only new links may create databases. A partial restore must not
		// silently replace a persisted account with empty state.
		if _, err := os.Stat(cfg.Config.Database); err != nil && !(subject == creating && errors.Is(err, os.ErrNotExist)) {
			r.close()
			return nil, fmt.Errorf("open saved account database (restore the complete account data before restarting): %w", err)
		}
		delete(unreferenced, filepath.Base(cfg.Config.Database))
		account, err := open(cfg)
		if err != nil {
			r.close()
			return nil, err
		}
		r.users[ampID], r.subjects[subject] = account, account
	}
	if len(unreferenced) != 0 {
		r.close()
		return nil, errors.New("account databases are missing from the registry; restore legacy Issuer/HostedDomain and the complete primary database")
	}
	// Commit the fixed registry key only after every legacy database opened.
	raw, err = json.Marshal(r.links)
	if err == nil {
		err = primary.store.SaveToken(ctx, key, raw)
	}
	if err == nil && len(pending) != 0 {
		err = primary.store.SaveToken(ctx, provisioningKey, nil)
	}
	if err != nil {
		r.close()
		return nil, err
	}
	return r, nil
}

func (r *accountRegistry) current(subject string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.links[subject]
}

// login resolves Amp IDs through existing bindings before creating accounts.
// Legacy subjects remain storage identities, never authentication credentials.
func (r *accountRegistry) login(ctx context.Context, ampID string, token *oauth2.Token) (string, error) {
	r.mu.RLock()
	subject := ""
	for sub, id := range r.links {
		if id == ampID {
			subject = sub
			break
		}
	}
	r.mu.RUnlock()
	if subject == "" {
		subject = "amp:" + ampID
		if err := r.link(ctx, subject, ampID); err != nil {
			return "", err
		}
	}
	r.mu.RLock()
	account := r.users[ampID]
	r.mu.RUnlock()
	account.tokenMu.Lock()
	defer account.tokenMu.Unlock()
	retained := *token
	if retained.RefreshToken == "" {
		raw, err := account.store.LoadToken(ctx, "amp-api-oauth/v1")
		if err != nil {
			return "", err
		}
		var previous oauth2.Token
		if len(raw) != 0 {
			if err := json.Unmarshal(raw, &previous); err != nil {
				return "", err
			}
			retained.RefreshToken = previous.RefreshToken
		}
	}
	raw, err := json.Marshal(&retained)
	if err == nil {
		err = account.store.SaveToken(ctx, "amp-api-oauth/v1", raw)
	}
	if err != nil {
		return "", err
	}
	account.names = browserauth.ProjectNames{}
	account.namesUntil = time.Time{}
	return subject, nil
}

func (r *accountRegistry) link(ctx context.Context, subject, ampID string) error {
	r.linkMu.Lock()
	defer r.linkMu.Unlock()
	if err := r.ctx.Err(); err != nil {
		return errors.New("gateway is shutting down")
	}
	if subject == "" || ampID == "" {
		return errors.New("missing identity")
	}
	r.mu.RLock()
	old, used := r.links[subject], r.users[ampID] != nil
	next := maps.Clone(r.links)
	r.mu.RUnlock()
	if old != "" {
		if old == ampID {
			return nil
		}
		return errors.New("account already linked")
	}
	if used {
		return errors.New("Amp identity already linked")
	}
	cfg, err := r.userConfig(subject, ampID)
	if err != nil {
		return err
	}
	// Record intent before creating a file. Startup can finish this exact
	// account without treating arbitrary unreferenced databases as new users.
	pending, err := r.primary.store.LoadToken(ctx, provisioningKey)
	if err != nil {
		return err
	}
	if len(pending) != 0 {
		return errors.New("account provisioning interrupted; restart to recover before creating another account")
	}
	pending, err = json.Marshal([]string{subject, ampID})
	if err != nil {
		return err
	}
	if err := r.primary.store.SaveToken(ctx, provisioningKey, pending); err != nil {
		return err
	}
	account, err := r.open(cfg)
	if err != nil {
		return err
	}
	next[subject] = ampID
	raw, err := json.Marshal(next)
	if err == nil {
		err = r.primary.store.SaveToken(ctx, r.key, raw)
	}
	if err == nil {
		err = r.primary.store.SaveToken(ctx, provisioningKey, nil)
	}
	if err != nil {
		account.store.Close()
		return err
	}
	r.mu.Lock()
	r.links = next
	r.users[ampID], r.subjects[subject] = account, account
	r.mu.Unlock()
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
	}, Secrets: demo.Secrets{EncryptionKey: key, SessionKey: r.config.Secrets.SessionKey}, auth: r.config.auth, verifier: r.config.verifier}, nil
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
	r.linkMu.Lock()
	defer r.linkMu.Unlock()
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
