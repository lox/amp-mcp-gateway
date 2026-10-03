package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"ampcode.com/lox/amp-mcp-gateway/internal/gateway"
	"ampcode.com/lox/amp-mcp-gateway/internal/store"
	"golang.org/x/oauth2"
)

func TestAmpLoginMigratesLegacyAccountsWithoutRekeying(t *testing.T) {
	ctx := t.Context()
	base := accountConfig{Config: gateway.Config{Database: filepath.Join(t.TempDir(), "gateway.db"), Issuer: "https://accounts.google.com", HostedDomain: "legacy.example", OwnerSubject: "google-alice", AmpUserID: "amp-alice", AccountLink: true}, Secrets: accountSecrets()}
	primaryStore, err := store.Open(base.Config.Database, base.Secrets.EncryptionKey)
	if err != nil {
		t.Fatal(err)
	}
	defer primaryStore.Close()
	if err := bindAccountIdentity(ctx, primaryStore, base.Config); err != nil {
		t.Fatal(err)
	}
	// Seed exactly the previous release's registry format, not the new writer.
	identity, _ := json.Marshal([]string{"https://accounts.google.com", "legacy.example"})
	legacyKey := fmt.Sprintf("account-links/v1/%x", sha256.Sum256(identity))
	if err := primaryStore.SaveToken(ctx, legacyKey, []byte(`{"google-alice":"amp-alice","google-bob":"amp-bob"}`)); err != nil {
		t.Fatal(err)
	}
	deriver := &accountRegistry{config: base}
	childConfig, err := deriver.userConfig("google-bob", "amp-bob")
	if err != nil {
		t.Fatal(err)
	}
	// Frozen pre-migration SHA-256 path and HMAC storage key. Do not derive the
	// expected values using the implementation under test.
	if filepath.Base(childConfig.Config.Database) != "eb6f69f4cbdd7a8b7e87d568d296ef6a8d870725817fd42bf8a3ecd1f08262ab.db" || childConfig.Secrets.EncryptionKey != "KwAS1jx0s/6Qwpqd8FKu9zL6AsvwG4mg9tkJVrk2NbY=" {
		t.Fatal("legacy storage derivation changed")
	}
	childStore, err := store.Open(childConfig.Config.Database, childConfig.Secrets.EncryptionKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := bindAccountIdentity(ctx, childStore, childConfig.Config); err != nil {
		t.Fatal(err)
	}
	if err := childStore.SaveToken(ctx, "provider", []byte("bob-private-provider-credential")); err != nil {
		t.Fatal(err)
	}
	if _, err := childStore.Submit(ctx, store.Operation{ID: "old-approval", Subject: "google-bob", AmpUserID: "amp-bob", Status: "pending", Digest: "immutable-old-digest", Created: 1}); err != nil {
		t.Fatal(err)
	}
	childStore.Close()
	opened := 0
	open := func(c accountConfig) (*accountRuntime, error) {
		opened++
		s, err := store.Open(c.Config.Database, c.Secrets.EncryptionKey)
		if err != nil {
			return nil, err
		}
		if err := bindAccountIdentity(ctx, s, c.Config); err != nil {
			s.Close()
			return nil, err
		}
		return &accountRuntime{store: s}, nil
	}
	primary := &accountRuntime{store: primaryStore}
	wrongNamespace := base
	wrongNamespace.Config.HostedDomain = "changed.example"
	if bad, err := newRegistry(ctx, primary, wrongNamespace, open); err == nil {
		bad.close()
		t.Fatal("missing legacy registry silently replaced existing accounts")
	}
	if raw, err := primaryStore.LoadToken(ctx, "amp-accounts/v1"); err != nil || len(raw) != 0 {
		t.Fatal("failed migration published a new registry")
	}
	r, err := newRegistry(ctx, primary, base, open)
	if err != nil {
		t.Fatal(err)
	}
	defer r.close()
	for _, user := range []string{"alice", "bob", "new"} {
		sub, err := r.login(ctx, "amp-"+user, &oauth2.Token{AccessToken: user + "-access-secret", RefreshToken: user + "-refresh-secret", Expiry: time.Now().Add(time.Hour)})
		if err != nil {
			t.Fatal(err)
		}
		want := "google-" + user
		if user == "new" {
			want = "amp:amp-new"
		}
		if sub != want {
			t.Fatalf("%s routed to %s instead of %s", user, sub, want)
		}
	}
	if opened != 2 || r.users["amp-alice"] != primary {
		t.Fatal("login created replacement accounts")
	}
	if raw, err := r.users["amp-bob"].store.LoadToken(ctx, "provider"); err != nil || string(raw) != "bob-private-provider-credential" {
		t.Fatal("legacy derived key/data lost")
	}
	if op, err := r.users["amp-bob"].store.Get(ctx, "old-approval"); err != nil || op.Subject != "google-bob" || op.Digest != "immutable-old-digest" {
		t.Fatal("legacy approval identity changed")
	}
	for _, user := range []string{"alice", "bob", "new"} {
		raw, err := r.users["amp-"+user].store.LoadToken(ctx, "amp-api-oauth/v1")
		var token oauth2.Token
		if err != nil || json.Unmarshal(raw, &token) != nil || token.AccessToken != user+"-access-secret" || token.RefreshToken != user+"-refresh-secret" {
			t.Fatal("OAuth tokens crossed accounts or were not retained")
		}
	}
	r.close()
	r, err = newRegistry(ctx, primary, base, open)
	if err != nil {
		t.Fatal(err)
	}
	defer r.close()
	if r.current("google-bob") != "amp-bob" {
		t.Fatal("restart lost migrated binding")
	}
	// Inspect SQLite and WAL bytes, not LoadToken's intentional decryption.
	for _, name := range []string{childConfig.Config.Database, childConfig.Config.Database + "-wal"} {
		raw, err := os.ReadFile(name)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(raw, []byte("bob-access-secret")) || bytes.Contains(raw, []byte("bob-refresh-secret")) {
			t.Fatal("OAuth token stored in plaintext")
		}
	}
}
