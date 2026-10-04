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
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"ampcode.com/lox/amp-mcp-gateway/internal/browserbridge"
	"ampcode.com/lox/amp-mcp-gateway/internal/demo"
	"ampcode.com/lox/amp-mcp-gateway/internal/gateway"
	"ampcode.com/lox/amp-mcp-gateway/internal/store"
	"ampcode.com/lox/amp-mcp-gateway/internal/upstream"
	"github.com/gorilla/websocket"
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

func TestMigrateBrowserReconnectCredentials(t *testing.T) {
	f := makeMigrationFixture(t)
	codes := make(map[string]string)
	for _, id := range []string{"owner", "child"} {
		path, key := f.primary, f.key
		if id == "child" {
			path, key = f.child, deriveLegacyKey(t, f.key, f.identities[id])
		}
		prefix := sha256.Sum256(f.identities[id])
		codes[id] = fmt.Sprintf("%x.%s-reconnect-secret", prefix[:12], id)
		hash := sha256.Sum256([]byte(codes[id]))
		target := sha256.Sum256([]byte(`["install","share",42]`))
		payload, err := json.Marshal(map[string]any{"hash": hash[:], "created": 1, "paired": true, "target": fmt.Sprintf("%x", target)})
		if err != nil {
			t.Fatal(err)
		}
		keyBytes, _ := base64.StdEncoding.DecodeString(key)
		block, _ := aes.NewCipher(keyBytes)
		aead, _ := cipher.NewGCMWithRandomNonce(block)
		db, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec("CREATE TABLE browser_pairings (id TEXT PRIMARY KEY, payload BLOB NOT NULL)"); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec("INSERT INTO browser_pairings VALUES (?,?)", "browser", aead.Seal(nil, nil, payload, []byte("browser-pairing:browser"))); err != nil {
			t.Fatal(err)
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
	}
	before := sourceBytes(t, f)
	destination := filepath.Join(f.dir, "migrated")
	if err := migrateAccounts(t.Context(), f.config, destination, f.key); err != nil {
		t.Fatal(err)
	}
	assertSourceBytes(t, f, before)
	registry := &accountRegistry{users: make(map[string]*accountRuntime)}
	for _, id := range []string{"owner", "child"} {
		path, key := filepath.Join(destination, "gateway.db"), f.key
		if id == "child" {
			hash := sha256.Sum256([]byte(id))
			path, key = filepath.Join(path+".accounts", hex.EncodeToString(hash[:])+".db"), deriveCurrentKey(t, f.key, id)
		}
		s, err := store.Open(path, key)
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		manager, err := browserbridge.New(t.Context(), []upstream.Connection{{ID: "browser", Browser: true}}, nil, s)
		if err != nil {
			t.Fatal(err)
		}
		registry.users[id] = &accountRuntime{browser: manager}
	}
	server := httptest.NewServer(browserbridge.SocketRouter(registry.browserManager))
	defer server.Close()
	for id, code := range codes {
		if registry.browserManager(code) != registry.users[id].browser || registry.browserManager(code+"tampered") != nil {
			t.Fatalf("migrated credential routed to the wrong account: %s", id)
		}
		ws, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), http.Header{"Origin": {"chrome-extension://extension-id"}})
		if err != nil {
			t.Fatal(err)
		}
		if err := ws.WriteJSON(map[string]any{"type": "hello", "pairing_code": code, "install_id": "install", "share_id": "share", "tab_id": 42}); err != nil {
			t.Fatal(err)
		}
		var response map[string]string
		if err := ws.ReadJSON(&response); err != nil || response["type"] != "paired" || response["reconnect_code"] != code {
			t.Fatalf("migrated reconnect failed for %s: %v, %v", id, response, err)
		}
		ws.Close()
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

func TestMigratePreReleasePrivateCatalogues(t *testing.T) {
	for _, tc := range []struct {
		name, fields, tool, wantDefault, wantTool string
	}{
		{"default marker", `"ToolDefaults":{"notes":"deny"},"PrivateToolDefaults":["notes"]`, `"Policy":"require_approval"`, "allow", "require_approval"},
		{"tool marker", `"ToolDefaults":{"notes":"require_approval"}`, `"Policy":"deny","Private":true`, "require_approval", "allow"},
		{"private tool policy", `"ToolDefaults":{"notes":"deny"}`, `"Policy":"private"`, "deny", "allow"},
		{"private default policy", `"ToolDefaults":{"notes":"private"}`, `"Policy":"deny"`, "allow", "deny"},
		{"marker precedence", `"ToolDefaults":{"notes":"private"},"PrivateConnectionPolicies":[{"ID":"notes","Default":"deny"}],"PrivateToolDefaults":["notes"]`, `"Policy":"private","Private":true,"PrivatePolicy":"deny"`, "allow", "deny"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := []byte(fmt.Sprintf(`{%s,"Tools":[{"ID":"notes.read","Connection":"notes",%s},{"ID":"other.read","Connection":"other","Policy":"deny"}]}`, tc.fields, tc.tool))
			got, err := migrateCatalogue(raw)
			if err != nil {
				t.Fatal(err)
			}
			var cfg gateway.Config
			if err := json.Unmarshal(got, &cfg); err != nil {
				t.Fatal(err)
			}
			if !cfg.PrivateConnections["notes"] || cfg.PrivateConnections["other"] || cfg.ToolDefaults["notes"] != tc.wantDefault || cfg.Tools[0].Policy != tc.wantTool || cfg.Tools[1].Policy != "deny" {
				t.Fatalf("migration changed effective private policy: %s", got)
			}
			for _, obsolete := range []string{"PrivateToolDefaults", "PrivateConnectionPolicies", "PrivatePolicy", `"Private":`, `"private"`} {
				if bytes.Contains(got, []byte(obsolete)) {
					t.Fatalf("migration retained %s: %s", obsolete, got)
				}
			}
		})
	}
}

func TestMigrateAccountsPreservesGeneratedFlyPolicy(t *testing.T) {
	for _, policy := range []string{"allow", "deny"} {
		t.Run(policy, func(t *testing.T) {
			f := makeMigrationFixture(t)
			f.catalogues["owner"] = []byte(fmt.Sprintf(`{"Integrations":[{"ID":"fly","Provider":"fly","Credential":"fixture-parent-token"}],"Tools":[{"ID":"fly.request_token","Connection":"fly","Name":"request_token","Policy":%q}],"ToolDefaults":{"fly":"require_approval"}}`, policy))
			replaceRootRegistry(t, f, map[string]string{"owner-subject": "owner", "child-subject": "child"}, nil)
			dest := filepath.Join(f.dir, "migrated")
			if err := migrateAccounts(t.Context(), f.config, dest, f.key); err != nil {
				t.Fatal(err)
			}
			s, err := store.Open(filepath.Join(dest, "gateway.db"), f.key)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			var cfg gateway.Config
			if err := gateway.LoadCatalogue(t.Context(), &cfg, s); err != nil {
				t.Fatal(err)
			}
			if len(cfg.Integrations) != 1 || cfg.Integrations[0].Policy != policy || cfg.Integrations[0].Credential != "fixture-parent-token" {
				t.Fatal("migration changed native integration authority")
			}
		})
	}
}

func TestPublishMigrationNeverReplacesExistingDirectory(t *testing.T) {
	parent := t.TempDir()
	stage, dest := filepath.Join(parent, "stage"), filepath.Join(parent, "dest")
	if err := os.Mkdir(stage, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dest, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stage, "sentinel"), []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := publishMigration(stage, dest); !errors.Is(err, os.ErrExist) {
		t.Fatalf("exclusive publish = %v", err)
	}
	if _, err := os.Stat(filepath.Join(stage, "sentinel")); err != nil {
		t.Fatal("failed publication moved source")
	}
	entries, err := os.ReadDir(dest)
	if err != nil || len(entries) != 0 {
		t.Fatal("failed publication changed destination")
	}
}
