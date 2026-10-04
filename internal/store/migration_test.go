package store

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
	_ "modernc.org/sqlite"
)

func legacyFixture(t *testing.T) (string, string, []byte, map[string][]byte) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "legacy.db")
	keyBytes := bytes.Repeat([]byte{0x42}, 32)
	key := base64.StdEncoding.EncodeToString(keyBytes)
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		t.Fatal(err)
	}
	seal := func(id string, value []byte) []byte {
		return aead.Seal(nil, nil, value, []byte(id))
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`
CREATE TABLE catalogue (id INTEGER PRIMARY KEY CHECK(id=1), payload BLOB NOT NULL);
CREATE TABLE tokens (id TEXT PRIMARY KEY, payload BLOB NOT NULL);
CREATE TABLE operations (id TEXT PRIMARY KEY, status TEXT, created INTEGER, expires INTEGER, payload BLOB);
`); err != nil {
		t.Fatal(err)
	}
	catalogue := []byte(`{"connections":[{"id":"notes","credential":"catalogue-secret"}]}`)
	tokens := map[string][]byte{
		"notes:oauth":     []byte(`{"access_token":"access-secret"}`),
		"amp:registry":    []byte(`{"registry_token":"registry-secret"}`),
		"second-provider": []byte("rotated-secret"),
	}
	if _, err := db.Exec("INSERT INTO catalogue VALUES(1,?)", seal("catalogue", catalogue)); err != nil {
		t.Fatal(err)
	}
	for id, token := range tokens {
		if _, err := db.Exec("INSERT INTO tokens VALUES(?,?)", id, seal("token:"+id, token)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec("INSERT INTO operations VALUES('discard-me','succeeded',1,2,?)", []byte("not-an-operation-ciphertext")); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	return path, key, catalogue, tokens
}

func TestReadLegacySnapshot(t *testing.T) {
	path, key, wantCatalogue, wantTokens := legacyFixture(t)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := ReadLegacySnapshot(t.Context(), path, key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(snapshot.Catalogue, wantCatalogue) || len(snapshot.Tokens) != len(wantTokens) {
		t.Fatalf("snapshot lost credentials: catalogue=%q tokens=%v", snapshot.Catalogue, snapshot.Tokens)
	}
	for id, want := range wantTokens {
		if !bytes.Equal(snapshot.Tokens[id], want) {
			t.Fatalf("token %q = %q, want %q", id, snapshot.Tokens[id], want)
		}
	}
	destination, _, _ := testStore(t)
	if err := destination.SaveCatalogue(t.Context(), snapshot.Catalogue); err != nil {
		t.Fatal(err)
	}
	for id, token := range snapshot.Tokens {
		if err := destination.SaveToken(t.Context(), id, token); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := destination.LoadCatalogue(t.Context()); err != nil || !bytes.Equal(got, wantCatalogue) {
		t.Fatalf("imported catalogue = %q, %v", got, err)
	}
	for id, want := range wantTokens {
		if got, err := destination.LoadToken(t.Context(), id); err != nil || !bytes.Equal(got, want) {
			t.Fatalf("imported token %q = %q, %v", id, got, err)
		}
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("snapshot read mutated legacy database")
	}
}

func TestReadLegacySnapshotFailures(t *testing.T) {
	path, key, _, _ := legacyFixture(t)
	t.Run("wrong key", func(t *testing.T) {
		wrong := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x24}, 32))
		if _, err := ReadLegacySnapshot(t.Context(), path, wrong); err == nil {
			t.Fatal("wrong key accepted")
		}
	})
	t.Run("missing source", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "missing.db")
		if _, err := ReadLegacySnapshot(t.Context(), missing, key); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("missing source error = %v", err)
		}
		if _, err := os.Stat(missing); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("missing source was created")
		}
	})
	t.Run("locked source", func(t *testing.T) {
		lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0600)
		if err != nil {
			t.Fatal(err)
		}
		defer lock.Close()
		if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadLegacySnapshot(context.Background(), path, key); err == nil || !strings.Contains(err.Error(), "already in use") {
			t.Fatalf("locked source error = %v", err)
		}
	})
	t.Run("wrong schema", func(t *testing.T) {
		db, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec("PRAGMA user_version=1"); err != nil {
			t.Fatal(err)
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadLegacySnapshot(t.Context(), path, key); err == nil || !strings.Contains(err.Error(), "expected 0") {
			t.Fatalf("wrong schema error = %v", err)
		}
	})
}

func TestLegacySnapshotReaderRetainsLocks(t *testing.T) {
	path, key, _, _ := legacyFixture(t)
	reader := NewLegacySnapshotReader()
	if _, err := reader.Read(t.Context(), path, key); err != nil {
		t.Fatal(err)
	}
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err == nil {
		t.Fatal("source lock released before reader close")
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatalf("source lock retained after reader close: %v", err)
	}
}

func TestSchemaEpoch(t *testing.T) {
	t.Run("fresh database", func(t *testing.T) {
		s, path, _ := testStore(t)
		var version int
		if err := s.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != schemaVersion {
			t.Fatalf("schema version = %d, %v", version, err)
		}
		if _, err := os.Stat(path); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("legacy database", func(t *testing.T) {
		path, key, _, _ := legacyFixture(t)
		before, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Open(path, key); err == nil || !strings.Contains(err.Error(), "explicit offline migration") {
			t.Fatalf("legacy open error = %v", err)
		}
		after, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(before, after) {
			t.Fatal("legacy rejection mutated database")
		}
	})
	t.Run("future database", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "future.db")
		db, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec("PRAGMA user_version=2"); err != nil {
			t.Fatal(err)
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		key := base64.StdEncoding.EncodeToString(make([]byte, 32))
		if _, err := Open(path, key); err == nil || !strings.Contains(err.Error(), "unsupported database schema version 2") {
			t.Fatalf("future open error = %v", err)
		}
	})
}
