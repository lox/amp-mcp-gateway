package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"ampcode.com/lox/amp-mcp-gateway/internal/demo"
	"ampcode.com/lox/amp-mcp-gateway/internal/gateway"
	"ampcode.com/lox/amp-mcp-gateway/internal/store"
	"golang.org/x/sys/unix"
	_ "modernc.org/sqlite"
)

type migrationFixture struct {
	dir, config, primary, child, key string
	identities                       map[string][]byte
	catalogues                       map[string][]byte
	credentials                      map[string]map[string][]byte
}

func makeMigrationFixture(t *testing.T) migrationFixture {
	t.Helper()
	dir := t.TempDir()
	f := migrationFixture{
		dir: dir, config: filepath.Join(dir, "legacy.json"), primary: filepath.Join(dir, "legacy.db"),
		key: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x41}, 32)),
		identities: map[string][]byte{
			"owner": []byte(`["","owner-subject","owner"]`),
			"child": []byte(`["","child-subject","child"]`),
		},
		catalogues: map[string][]byte{
			"owner": []byte(`{"Connections":[{"ID":"notes","URL":"https://notes.example/mcp","BearerToken":"owner-bearer"}],"ToolDefaults":{"notes":"require_approval"}}`),
			"child": []byte(`{"Connections":[{"ID":"docs","URL":"https://docs.example/mcp","BearerToken":"child-bearer"}],"ToolDefaults":{"docs":"deny"}}`),
		},
		credentials: map[string]map[string][]byte{
			"owner": {"amp-api-oauth/v1": []byte(`{"refresh_token":"owner-amp"}`), "provider/oauth": []byte("owner-provider")},
			"child": {"amp-api-oauth/v1": []byte(`{"refresh_token":"child-amp"}`), "provider/oauth": []byte("child-provider")},
		},
	}
	childHash := sha256.Sum256(f.identities["child"])
	f.child = filepath.Join(f.primary+".accounts", hex.EncodeToString(childHash[:])+".db")
	links, _ := json.Marshal(map[string]string{"owner-subject": "owner", "child-subject": "child"})
	rootTokens := cloneTokens(f.credentials["owner"])
	rootTokens[legacyRegistryKey] = links
	rootTokens[legacyIdentityKey] = f.identities["owner"]
	writeLegacyDB(t, f.primary, f.key, f.catalogues["owner"], rootTokens, 0)
	childKey := deriveLegacyKey(t, f.key, f.identities["child"])
	childTokens := cloneTokens(f.credentials["child"])
	childTokens[legacyIdentityKey] = f.identities["child"]
	writeLegacyDB(t, f.child, childKey, f.catalogues["child"], childTokens, 0)
	cfg := legacyDeploymentConfig{deploymentConfig: deploymentConfig{Config: gateway.Config{BaseURL: "https://gateway.example", Database: f.primary, AmpUserID: "owner"}}, OwnerSubject: "owner-subject"}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.config, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return f
}

func cloneTokens(in map[string][]byte) map[string][]byte {
	out := make(map[string][]byte, len(in))
	for key, value := range in {
		out[key] = bytes.Clone(value)
	}
	return out
}

func deriveLegacyKey(t *testing.T, master string, identity []byte) string {
	t.Helper()
	key, err := base64.StdEncoding.DecodeString(master)
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("amp-mcp-gateway/account/v1/storage\x00"))
	mac.Write(identity)
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func deriveCurrentKey(t *testing.T, master, id string) string {
	t.Helper()
	key, err := base64.StdEncoding.DecodeString(master)
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("amp-mcp-gateway/account/v2/storage\x00"))
	mac.Write([]byte(id))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func writeLegacyDB(t *testing.T, path, key string, catalogue []byte, tokens map[string][]byte, version int) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	keyBytes, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE catalogue (id INTEGER PRIMARY KEY, payload BLOB NOT NULL); CREATE TABLE tokens (id TEXT PRIMARY KEY, payload BLOB NOT NULL); CREATE TABLE operations (id TEXT PRIMARY KEY, payload BLOB); INSERT INTO operations VALUES ('discarded',x'01');`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("PRAGMA user_version=" + strconv.Itoa(version)); err != nil {
		t.Fatal(err)
	}
	seal := func(id string, value []byte) []byte { return aead.Seal(nil, nil, value, []byte(id)) }
	if _, err := db.Exec("INSERT INTO catalogue VALUES(1,?)", seal("catalogue", catalogue)); err != nil {
		t.Fatal(err)
	}
	for id, value := range tokens {
		if _, err := db.Exec("INSERT INTO tokens VALUES(?,?)", id, seal("token:"+id, value)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestMigrateAccountsEndToEnd(t *testing.T) {
	f := makeMigrationFixture(t)
	before := sourceBytes(t, f)
	oldCWD, _ := os.Getwd()
	outside := t.TempDir()
	if err := os.Chdir(outside); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldCWD) })
	destinationArg := "migrated"
	if err := migrateAccounts(t.Context(), f.config, destinationArg, f.key); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(outside, destinationArg)
	assertSourceBytes(t, f, before)
	raw, err := os.ReadFile(filepath.Join(destination, "gateway.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg deploymentConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Database != filepath.Join(destination, "gateway.db") || !filepath.IsAbs(cfg.Database) {
		t.Fatalf("destination database = %q, want absolute migrated path", cfg.Database)
	}
	childHash := sha256.Sum256([]byte("child"))
	expectedChild := filepath.Join(cfg.Database+".accounts", hex.EncodeToString(childHash[:])+".db")
	child, err := store.Open(expectedChild, deriveCurrentKey(t, f.key, "child"))
	if err != nil {
		t.Fatalf("open child at independently derived path/key: %v", err)
	}
	if err := child.Close(); err != nil {
		t.Fatal(err)
	}

	primary, err := store.Open(cfg.Database, f.key)
	if err != nil {
		t.Fatal(err)
	}
	defer primary.Close()
	registryCfg := accountConfig{Config: cfg.Config, Secrets: demo.Secrets{EncryptionKey: f.key}}
	opened := map[string]*store.Store{"owner": primary}
	registry, err := newRegistry(context.Background(), &accountRuntime{store: primary}, registryCfg, func(c accountConfig) (*accountRuntime, error) {
		s, err := store.Open(c.Config.Database, c.Secrets.EncryptionKey)
		if err == nil {
			opened[c.Config.AmpUserID] = s
		}
		return &accountRuntime{store: s}, err
	})
	if err != nil {
		t.Fatalf("restart registry: %v", err)
	}
	defer registry.close()
	for _, id := range []string{"owner", "child"} {
		s := opened[id]
		if s == nil {
			t.Fatalf("account %q not restored", id)
		}
		catalogue, err := s.LoadCatalogue(t.Context())
		if err != nil || !bytes.Equal(catalogue, f.catalogues[id]) {
			t.Fatalf("%s catalogue = %q, %v", id, catalogue, err)
		}
		for token, want := range f.credentials[id] {
			got, err := s.LoadToken(t.Context(), token)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("%s token %s = %q, %v", id, token, got, err)
			}
		}
		identity, _ := s.LoadToken(t.Context(), identityKey)
		if string(identity) != id {
			t.Fatalf("%s binding = %q", id, identity)
		}
		operations, err := s.List(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		events, err := s.Events(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if len(operations) != 0 || len(events) != 0 {
			t.Fatalf("%s retained history: operations=%d events=%d", id, len(operations), len(events))
		}
	}
}

func TestMigrateAccountsRejectsInvalidSourcesAtomically(t *testing.T) {
	tests := map[string]func(*testing.T, migrationFixture) string{
		"wrong key": func(t *testing.T, f migrationFixture) string {
			return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x22}, 32))
		},
		"missing child": func(t *testing.T, f migrationFixture) string {
			if err := os.Remove(f.child); err != nil {
				t.Fatal(err)
			}
			return f.key
		},
		"orphan child": func(t *testing.T, f migrationFixture) string {
			writeLegacyDB(t, filepath.Join(f.primary+".accounts", strings.Repeat("a", 64)+".db"), f.key, []byte(`{}`), map[string][]byte{}, 0)
			return f.key
		},
		"duplicate ids": func(t *testing.T, f migrationFixture) string {
			replaceRootRegistry(t, f, map[string]string{"owner-subject": "owner", "other": "owner"}, nil)
			return f.key
		},
		"pending provisioning": func(t *testing.T, f migrationFixture) string {
			replaceRootRegistry(t, f, map[string]string{"owner-subject": "owner", "child-subject": "child"}, []byte("child"))
			return f.key
		},
		"bound mismatch": func(t *testing.T, f migrationFixture) string {
			replaceRootRegistry(t, f, map[string]string{"owner-subject": "different", "child-subject": "child"}, nil)
			return f.key
		},
		"locked source": func(t *testing.T, f migrationFixture) string {
			lock, err := os.OpenFile(f.primary+".lock", os.O_CREATE|os.O_RDWR, 0600)
			if err != nil {
				t.Fatal(err)
			}
			if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { lock.Close() })
			return f.key
		},
		"wrong schema": func(t *testing.T, f migrationFixture) string {
			db, err := sql.Open("sqlite", f.primary)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec("PRAGMA user_version=1"); err != nil {
				t.Fatal(err)
			}
			db.Close()
			return f.key
		},
		"existing destination": func(t *testing.T, f migrationFixture) string { return f.key },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			f := makeMigrationFixture(t)
			destination := filepath.Join(f.dir, "destination")
			if name == "existing destination" {
				if err := os.Mkdir(destination, 0700); err != nil {
					t.Fatal(err)
				}
			}
			key := mutate(t, f)
			if err := migrateAccounts(t.Context(), f.config, destination, key); err == nil {
				t.Fatal("migration unexpectedly succeeded")
			}
			if name != "existing destination" {
				if _, err := os.Stat(destination); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("destination published: %v", err)
				}
			}
			stages, _ := filepath.Glob(filepath.Join(f.dir, ".gateway-migration-*"))
			if len(stages) != 0 {
				t.Fatalf("staging directories remain: %v", stages)
			}
		})
	}
}

func replaceRootRegistry(t *testing.T, f migrationFixture, links map[string]string, pending []byte) {
	t.Helper()
	if err := os.Remove(f.primary); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(links)
	tokens := cloneTokens(f.credentials["owner"])
	tokens[legacyRegistryKey], tokens[legacyIdentityKey] = raw, f.identities["owner"]
	if pending != nil {
		tokens[legacyProvisioningKey] = pending
	}
	writeLegacyDB(t, f.primary, f.key, f.catalogues["owner"], tokens, 0)
}

func sourceBytes(t *testing.T, f migrationFixture) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	for _, path := range []string{f.primary, f.child} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		out[path] = raw
	}
	return out
}

func assertSourceBytes(t *testing.T, f migrationFixture, before map[string][]byte) {
	t.Helper()
	for path, want := range before {
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("source %s changed: %v", path, err)
		}
	}
}

func TestMigratePrivateCatalogue(t *testing.T) {
	raw := []byte(`{"Connections":[{"ID":"notes","BearerToken":"fixture-secret"}],"ToolDefaults":{"notes":"deny","other":"allow"},"PrivateConnectionPolicies":[{"ID":"notes","Default":"require_approval"}],"Tools":[{"ID":"notes.read","Connection":"notes","Policy":"deny","PrivatePolicy":"allow"},{"ID":"notes.write","Connection":"notes","Policy":"deny","PrivatePolicy":""},{"ID":"other.delete","Connection":"other","Policy":"deny"}]}`)
	got, err := migrateCatalogue(raw)
	if err != nil {
		t.Fatal(err)
	}
	var cfg gateway.Config
	if err := json.Unmarshal(got, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Connections[0].BearerToken != "fixture-secret" || !cfg.PrivateConnections["notes"] || cfg.PrivateConnections["other"] || cfg.ToolDefaults["notes"] != "require_approval" || cfg.ToolDefaults["other"] != "allow" || cfg.Tools[0].Policy != "allow" || cfg.Tools[1].Policy != "" || cfg.Tools[2].Policy != "deny" {
		t.Fatal("migration changed credentials, privacy or effective policies")
	}
	if bytes.Contains(got, []byte("PrivatePolicy")) || bytes.Contains(got, []byte("PrivateConnectionPolicies")) {
		t.Fatal("rollback encoding retained")
	}
}
