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
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"ampcode.com/lox/amp-mcp-gateway/internal/browserauth"
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

const (
	registryKey     = "accounts"
	provisioningKey = "account-provisioning"
	identityKey     = "account-identity"
)

func bindAccountIdentity(ctx context.Context, s *store.Store, cfg gateway.Config) error {
	if cfg.AmpUserID == "" {
		return errors.New("AmpUserID is required")
	}
	stored, err := s.LoadToken(ctx, identityKey)
	if err != nil {
		return err
	}
	if len(stored) != 0 && !bytes.Equal(stored, []byte(cfg.AmpUserID)) {
		return errors.New("database account identity cannot be reassigned")
	}
	if len(stored) == 0 {
		return s.SaveToken(ctx, identityKey, []byte(cfg.AmpUserID))
	}
	return nil
}

// accountRegistry owns isolated runtimes keyed only by verified Amp user ID.
type accountRegistry struct {
	provisionMu sync.Mutex
	mu          sync.RWMutex
	ctx         context.Context
	primary     *accountRuntime
	config      accountConfig
	users       map[string]*accountRuntime
	open        func(accountConfig) (*accountRuntime, error)
	start       func(*accountRuntime)
}

func newRegistry(ctx context.Context, primary *accountRuntime, config accountConfig, open func(accountConfig) (*accountRuntime, error)) (*accountRegistry, error) {
	r := &accountRegistry{ctx: ctx, primary: primary, config: config, users: map[string]*accountRuntime{config.Config.AmpUserID: primary}, open: open}
	raw, err := primary.store.LoadToken(ctx, registryKey)
	if err != nil {
		return nil, err
	}
	ids := []string{config.Config.AmpUserID}
	if len(raw) != 0 && (json.Unmarshal(raw, &ids) != nil || !slices.Contains(ids, config.Config.AmpUserID)) {
		return nil, errors.New("invalid account registry")
	}
	pending, err := primary.store.LoadToken(ctx, provisioningKey)
	if err != nil {
		return nil, err
	}
	creating := string(pending)
	if creating != "" {
		if slices.Contains(ids, creating) {
			// Publication already completed. A missing database is now an
			// incomplete restore, not unfinished account creation.
			creating = ""
		} else {
			ids = append(ids, creating)
		}
	}
	entries, err := os.ReadDir(config.Config.Database + ".accounts")
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	unreferenced := map[string]bool{}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".db") {
			unreferenced[entry.Name()] = true
		}
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if id == "" || strings.TrimSpace(id) != id || seen[id] {
			r.close()
			return nil, errors.New("invalid or duplicate account ID")
		}
		seen[id] = true
		if id == config.Config.AmpUserID {
			continue
		}
		cfg, err := r.userConfig(id)
		if err != nil {
			r.close()
			return nil, err
		}
		if _, err := os.Stat(cfg.Config.Database); err != nil && !(id == creating && errors.Is(err, os.ErrNotExist)) {
			r.close()
			return nil, fmt.Errorf("restore complete account data before restarting: %w", err)
		}
		delete(unreferenced, filepath.Base(cfg.Config.Database))
		account, err := open(cfg)
		if err != nil {
			r.close()
			return nil, err
		}
		r.users[id] = account
	}
	if len(unreferenced) != 0 {
		r.close()
		return nil, errors.New("account databases missing from registry; restore the complete dataset")
	}
	if err := r.save(ctx, ids); err != nil {
		r.close()
		return nil, err
	}
	return r, nil
}

func (r *accountRegistry) save(ctx context.Context, ids []string) error {
	slices.Sort(ids)
	raw, err := json.Marshal(ids)
	if err == nil {
		err = r.primary.store.SaveToken(ctx, registryKey, raw)
	}
	if err == nil {
		err = r.primary.store.SaveToken(ctx, provisioningKey, nil)
	}
	return err
}

func (r *accountRegistry) current(id string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.users[id] != nil {
		return id
	}
	return ""
}

func (r *accountRegistry) login(ctx context.Context, id string, token *oauth2.Token) error {
	if err := r.provision(ctx, id); err != nil {
		return err
	}
	r.mu.RLock()
	account := r.users[id]
	r.mu.RUnlock()
	account.tokenMu.Lock()
	defer account.tokenMu.Unlock()
	retained := *token
	if retained.RefreshToken == "" {
		raw, err := account.store.LoadToken(ctx, "amp-api-oauth/v1")
		if err != nil {
			return err
		}
		var previous oauth2.Token
		if len(raw) != 0 && json.Unmarshal(raw, &previous) != nil {
			return errors.New("invalid saved Amp credentials")
		}
		retained.RefreshToken = previous.RefreshToken
	}
	raw, err := json.Marshal(&retained)
	if err == nil {
		err = account.store.SaveToken(ctx, "amp-api-oauth/v1", raw)
	}
	if err != nil {
		return err
	}
	account.names = browserauth.ProjectNames{}
	account.namesUntil = time.Time{}
	return nil
}

func (r *accountRegistry) provision(ctx context.Context, id string) error {
	r.provisionMu.Lock()
	defer r.provisionMu.Unlock()
	if err := r.ctx.Err(); err != nil {
		return errors.New("gateway is shutting down")
	}
	if id == "" || len(id) > 256 || strings.TrimSpace(id) != id {
		return errors.New("invalid Amp user ID")
	}
	r.mu.RLock()
	exists := r.users[id] != nil
	r.mu.RUnlock()
	if exists {
		return nil
	}
	pending, err := r.primary.store.LoadToken(ctx, provisioningKey)
	if err != nil {
		return err
	}
	if len(pending) != 0 {
		return errors.New("account provisioning interrupted; restart to recover")
	}
	cfg, err := r.userConfig(id)
	if err != nil {
		return err
	}
	if _, err := os.Stat(cfg.Config.Database); !errors.Is(err, os.ErrNotExist) {
		return errors.New("unregistered account database already exists or is inaccessible")
	}
	if err := r.primary.store.SaveToken(ctx, provisioningKey, []byte(id)); err != nil {
		return err
	}
	account, err := r.open(cfg)
	if err != nil {
		return err
	}
	r.mu.RLock()
	ids := make([]string, 0, len(r.users)+1)
	for user := range r.users {
		ids = append(ids, user)
	}
	r.mu.RUnlock()
	if err := r.save(ctx, append(ids, id)); err != nil {
		account.store.Close()
		return err
	}
	r.mu.Lock()
	r.users[id] = account
	r.mu.Unlock()
	if r.start != nil {
		r.start(account)
	}
	return nil
}

func (r *accountRegistry) userConfig(id string) (accountConfig, error) {
	c := r.config.Config
	identity := []byte(id)
	hash := sha256.Sum256(identity)
	key, err := accountKey(r.config.Secrets.EncryptionKey, "storage", identity)
	if err != nil {
		return accountConfig{}, err
	}
	return accountConfig{Config: gateway.Config{BaseURL: c.BaseURL, AmpUserID: id, Database: filepath.Join(c.Database+".accounts", hex.EncodeToString(hash[:])+".db"), AccountPage: true}, Secrets: demo.Secrets{EncryptionKey: key, SessionKey: r.config.Secrets.SessionKey}, auth: r.config.auth, verifier: r.config.verifier}, nil
}

// The primary is closed by main, after serving and workers stop.
func (r *accountRegistry) close() {
	r.provisionMu.Lock()
	defer r.provisionMu.Unlock()
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, account := range r.users {
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
	mac.Write([]byte("amp-mcp-gateway/account/v2/" + purpose + "\x00"))
	mac.Write(identity)
	return base64.StdEncoding.EncodeToString(mac.Sum(nil)), nil
}
