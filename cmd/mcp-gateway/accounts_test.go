package main

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"ampcode.com/lox/amp-mcp-gateway/internal/demo"
	"ampcode.com/lox/amp-mcp-gateway/internal/gateway"
	"ampcode.com/lox/amp-mcp-gateway/internal/upstream"
)

func accountFixture(t *testing.T) (deploymentConfig, demo.Secrets) {
	t.Helper()
	return deploymentConfig{Config: gateway.Config{
			BaseURL: "https://alice.example", Database: filepath.Join(t.TempDir(), "gateway.db"),
			OwnerSubject: "alice-sub", AmpUserID: "user_alice", Issuer: "https://issuer.example", ClientID: "client",
			Connections: []upstream.Connection{{ID: "alice-only"}},
		}, Accounts: []account{{BaseURL: "https://bob.example", OwnerSubject: "bob-sub", AmpUserID: "user_bob"}}},
		demo.Secrets{EncryptionKey: base64.StdEncoding.EncodeToString(make([]byte, 32)), SessionKey: base64.StdEncoding.EncodeToString(make([]byte, 32)), GatewayToken: "legacy-root-token"}
}

func TestAccountsIsolateStateAndPreserveLegacy(t *testing.T) {
	cfg, secrets := accountFixture(t)
	accounts, err := cfg.accounts(secrets)
	if err != nil {
		t.Fatal(err)
	}
	a, b := accounts[0], accounts[1]
	if a.Config.Database != cfg.Database || a.Secrets != secrets || len(a.Config.Connections) != 1 {
		t.Fatal("existing account changed")
	}
	if b.Config.OwnerSubject != "bob-sub" || b.Config.AmpUserID != "user_bob" || b.Config.Issuer != cfg.Issuer || b.Config.ClientID != cfg.ClientID || len(b.Config.Connections) != 0 || len(b.Config.Tools) != 0 || len(b.Config.Integrations) != 0 {
		t.Fatal("additional account inherits another user's state or loses its identity")
	}
	if b.Config.Database == a.Config.Database || b.Secrets.EncryptionKey == a.Secrets.EncryptionKey || b.Secrets.SessionKey == a.Secrets.SessionKey || b.Secrets.EncryptionKey == b.Secrets.SessionKey || b.Secrets.GatewayToken != "" {
		t.Fatal("account databases or credentials are shared")
	}
	for _, change := range []func(*deploymentConfig){
		func(c *deploymentConfig) { c.Accounts[0].OwnerSubject = "replacement-sub" },
		func(c *deploymentConfig) { c.Accounts[0].AmpUserID = "user_replacement" },
		func(c *deploymentConfig) { c.Issuer = "https://different-issuer.example" },
	} {
		changed, _ := accountFixture(t)
		changed.Database = cfg.Database
		change(&changed)
		next, err := changed.accounts(secrets)
		if err != nil {
			t.Fatal(err)
		}
		if next[1].Config.Database == b.Config.Database || next[1].Secrets == b.Secrets {
			t.Fatal("identity reassignment inherited old state")
		}
	}
	// Moving a hostname must not move the user's durable ledger.
	cfg.Accounts[0].BaseURL = "https://new-bob.example"
	next, err := cfg.accounts(secrets)
	if err != nil || next[1].Config.Database != b.Config.Database {
		t.Fatal("origin change lost durable state", err)
	}
}

func TestAccountsRejectUnsafeConfiguration(t *testing.T) {
	for name, mutate := range map[string]func(*deploymentConfig){
		"duplicate host":       func(c *deploymentConfig) { c.Accounts[0].BaseURL = c.BaseURL },
		"case alias":           func(c *deploymentConfig) { c.Accounts[0].BaseURL = "https://ALICE.example:443" },
		"port alias":           func(c *deploymentConfig) { c.Accounts[0].BaseURL = "https://alice.example:0443" },
		"duplicate subject":    func(c *deploymentConfig) { c.Accounts[0].OwnerSubject = c.OwnerSubject },
		"duplicate Amp user":   func(c *deploymentConfig) { c.Accounts[0].AmpUserID = c.AmpUserID },
		"missing Amp identity": func(c *deploymentConfig) { c.Accounts[0].AmpUserID = "" },
		"legacy root":          func(c *deploymentConfig) { c.AmpUserID = "" },
		"no OIDC":              func(c *deploymentConfig) { c.Issuer = "" },
		"path origin":          func(c *deploymentConfig) { c.Accounts[0].BaseURL += "/bob" },
		"insecure origin":      func(c *deploymentConfig) { c.Accounts[0].BaseURL = "http://bob.example" },
	} {
		t.Run(name, func(t *testing.T) {
			cfg, secrets := accountFixture(t)
			mutate(&cfg)
			if _, err := cfg.accounts(secrets); err == nil {
				t.Fatal("unsafe configuration accepted")
			}
		})
	}
}

func TestAccountRoutingRejectsUnknownHostsAndForwardingHeaders(t *testing.T) {
	h := accountRouter(map[string]http.Handler{
		"alice.example":         http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(201) }),
		"bob.example":           http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(202) }),
		"xn--bcher-kva.example": http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(203) }),
	})
	for _, tc := range []struct {
		host, path string
		status     int
	}{
		{"alice.example", "/operations", 201}, {"BOB.example:443", "/operations", 202},
		{"alice.example:0443", "/operations", 201}, {"bücher.example", "/operations", 203},
		{"unknown.example", "/operations", 404}, {"alice.example:444", "/mcp", 404},
		{"unknown.example", "/healthz", 200},
	} {
		r := httptest.NewRequest("GET", "https://"+tc.host+tc.path, nil)
		r.Header.Set("X-Forwarded-Host", "alice.example")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatalf("%s%s: got %d, want %d", tc.host, tc.path, w.Code, tc.status)
		}
	}
}
