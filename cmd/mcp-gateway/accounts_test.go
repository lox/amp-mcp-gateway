package main

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"ampcode.com/lox/amp-mcp-gateway/internal/browserbridge"
	"ampcode.com/lox/amp-mcp-gateway/internal/demo"
	"ampcode.com/lox/amp-mcp-gateway/internal/gateway"
	"ampcode.com/lox/amp-mcp-gateway/internal/store"
)

func accountSecrets() demo.Secrets {
	return demo.Secrets{EncryptionKey: base64.StdEncoding.EncodeToString(make([]byte, 32)), SessionKey: base64.StdEncoding.EncodeToString(make([]byte, 32))}
}

func TestCanonicalHostGate(t *testing.T) {
	h := accountRouter("gateway.example", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	for _, tc := range []struct {
		host, path string
		status     int
	}{
		{"GATEWAY.example:443", "/account", 204},
		{"foreign.example", "/account", 404},
		{"foreign.example", "/healthz", 200},
	} {
		req := httptest.NewRequest("GET", "https://"+tc.host+tc.path, nil)
		req.Header.Set("X-Forwarded-Host", "gateway.example")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != tc.status {
			t.Fatalf("%s%s: got %d, want %d", tc.host, tc.path, w.Code, tc.status)
		}
	}
}

func TestRegistryDerivesIsolatedStableAccountState(t *testing.T) {
	secrets := accountSecrets()
	db := filepath.Join(t.TempDir(), "gateway.db")
	s, err := store.Open(db, secrets.EncryptionKey)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	primary := &accountRuntime{store: s}
	base := accountConfig{Config: gateway.Config{BaseURL: "https://gateway.example", Database: db, OwnerSubject: "google-primary", AmpUserID: "amp-primary", Issuer: "https://accounts.google.com", ClientID: "browser-client", HostedDomain: "example.com"}, Secrets: secrets}
	var opened []accountConfig
	r, err := newRegistry(t.Context(), primary, base, func(c accountConfig) (*accountRuntime, error) {
		opened = append(opened, c)
		child, err := store.Open(c.Config.Database, c.Secrets.EncryptionKey)
		return &accountRuntime{store: child, browser: &browserbridge.Manager{}}, err
	})
	if err != nil {
		t.Fatal(err)
	}
	defer r.close()
	if err := r.link(t.Context(), "google-bob", "amp-bob"); err != nil {
		t.Fatal(err)
	}
	if len(opened) != 1 {
		t.Fatalf("opened %d accounts", len(opened))
	}
	child := opened[0]
	if child.Config.Database == db || child.Secrets.EncryptionKey == secrets.EncryptionKey || child.Config.OwnerSubject != "google-bob" || child.Config.AmpUserID != "amp-bob" {
		t.Fatalf("linked account was not isolated: %#v", child.Config)
	}
	if child.Secrets.SessionKey != secrets.SessionKey || child.auth != base.auth {
		t.Fatal("linked account did not retain the shared browser authentication boundary")
	}
	if err := r.link(t.Context(), "google-other", "amp-bob"); err == nil {
		t.Fatal("duplicate Amp identity accepted")
	}
	if err := r.link(t.Context(), "google-bob", "amp-other"); err == nil {
		t.Fatal("subject relink accepted")
	}
	childStore := r.subjects["google-bob"].store
	_, err = childStore.Submit(t.Context(), store.Operation{ID: "bob-operation", Subject: "google-bob", Status: "pending", Digest: "bob-only", Created: 1})
	if err != nil {
		t.Fatal(err)
	}
	r.close()

	opened = nil
	restarted, err := newRegistry(t.Context(), primary, base, func(c accountConfig) (*accountRuntime, error) {
		opened = append(opened, c)
		child, openErr := store.Open(c.Config.Database, c.Secrets.EncryptionKey)
		return &accountRuntime{store: child, browser: &browserbridge.Manager{}}, openErr
	})
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.close()
	if len(opened) != 1 || restarted.current("google-bob") != "amp-bob" {
		t.Fatalf("restart did not restore unique linkage: opened=%d current=%q", len(opened), restarted.current("google-bob"))
	}
	op, err := restarted.subjects["google-bob"].store.Get(t.Context(), "bob-operation")
	if err != nil || op.Digest != "bob-only" {
		t.Fatalf("restart lost child state: operation=%#v err=%v", op, err)
	}
	if _, err := primary.store.Get(t.Context(), "bob-operation"); err == nil {
		t.Fatal("child operation leaked into primary store")
	}
	if err := restarted.link(t.Context(), "google-other", "amp-bob"); err == nil {
		t.Fatal("restored Amp identity was not unique")
	}
}

func TestWorkloadRejectsMissingMalformedAndUnknownRoutingHints(t *testing.T) {
	r := &accountRegistry{users: map[string]*accountRuntime{}}
	for _, token := range []string{"", "not-a-jwt", "e30.e30.", "e30.eyJ1c2VyX2lkIjoiZm9yZWlnbiJ9."} {
		req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		r.workload(w, req)
		if w.Code != http.StatusUnauthorized || w.Header().Get("WWW-Authenticate") != "Bearer" {
			t.Fatalf("token %q: status=%d challenge=%q", token, w.Code, w.Header().Get("WWW-Authenticate"))
		}
	}
}

func TestRegistryStopsLinkingAfterShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := &accountRegistry{ctx: ctx}
	if err := r.link(context.Background(), "subject", "user"); err == nil {
		t.Fatal("link accepted during shutdown")
	}
}
