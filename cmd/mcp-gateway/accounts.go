package main

import (
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

	"ampcode.com/lox/amp-mcp-gateway/internal/demo"
	"ampcode.com/lox/amp-mcp-gateway/internal/gateway"
)

// Each account has its own origin, authentication, ledger and credential store.
// The original top-level account retains its existing database and keys.
type deploymentConfig struct {
	gateway.Config
	Accounts []account
}

type account struct {
	BaseURL, OwnerSubject, AmpUserID string
}

type accountConfig struct {
	Config  gateway.Config
	Secrets demo.Secrets
}

func (c deploymentConfig) accounts(secrets demo.Secrets) ([]accountConfig, error) {
	out := []accountConfig{{c.Config, secrets}}
	if len(c.Accounts) == 0 {
		return out, nil
	}
	if c.Issuer == "" || c.ClientID == "" || c.OwnerSubject == "" || c.AmpUserID == "" || c.Database == "" {
		return nil, errors.New("multiple accounts require OIDC, AmpUserID, OwnerSubject and Database on the primary account")
	}
	primaryHost, err := accountHost(c.BaseURL)
	if err != nil {
		return nil, err
	}
	hosts := map[string]bool{primaryHost: true}
	subjects := map[string]bool{c.OwnerSubject: true}
	users := map[string]bool{c.AmpUserID: true}
	for _, a := range c.Accounts {
		host, err := accountHost(a.BaseURL)
		if err != nil {
			return nil, err
		}
		if a.OwnerSubject == "" || a.AmpUserID == "" || hosts[host] || subjects[a.OwnerSubject] || users[a.AmpUserID] {
			return nil, errors.New("accounts require distinct origins, OIDC subjects and Amp user IDs")
		}
		hosts[host], subjects[a.OwnerSubject], users[a.AmpUserID] = true, true, true
		// Length-delimited identity encoding; never recycle a removed user's data
		// when the same hostname is assigned to a different identity.
		identity, err := json.Marshal([]string{c.Issuer, a.OwnerSubject, a.AmpUserID})
		if err != nil {
			return nil, err
		}
		id := sha256.Sum256(identity)
		key, err := accountKey(secrets.EncryptionKey, "storage", identity)
		if err != nil {
			return nil, err
		}
		session, err := accountKey(secrets.SessionKey, "session", identity)
		if err != nil {
			return nil, err
		}
		out = append(out, accountConfig{
			Config: gateway.Config{
				BaseURL: a.BaseURL, OwnerSubject: a.OwnerSubject, AmpUserID: a.AmpUserID,
				Database: filepath.Join(c.Database+".accounts", hex.EncodeToString(id[:])+".db"),
				Issuer:   c.Issuer, ClientID: c.ClientID, HostedDomain: c.HostedDomain,
			},
			Secrets: demo.Secrets{EncryptionKey: key, SessionKey: session},
		})
	}
	return out, nil
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
	if err != nil {
		return "", err
	}
	return strings.TrimPrefix(canonical, "https://"), nil
}

func accountRouter(accounts map[string]http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Fly health probes need no account hostname and reveal no account state.
		if r.Method == http.MethodGet && r.URL.Path == "/healthz" {
			fmt.Fprintln(w, "ok")
			return
		}
		host, err := accountHost("https://" + r.Host)
		h, ok := accounts[host]
		if err != nil || !ok {
			http.NotFound(w, r)
			return
		}
		h.ServeHTTP(w, r)
	})
}
