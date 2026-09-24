package store

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testStore(t *testing.T) (*Store, string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ledger.db")
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	s, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, path, key
}
func operation(id, status string) Operation {
	return Operation{ID: id, Tool: "notes.create", Subject: "owner", Digest: "digest", Status: status, Created: time.Now().Unix(), Expires: time.Now().Add(time.Minute).Unix(), Arguments: map[string]any{"text": "sensitive-request-value"}}
}

func TestApprovalAndClaimSingleWinner(t *testing.T) {
	s, _, _ := testStore(t)
	ctx := t.Context()
	if _, err := s.Submit(ctx, operation("op-1", "pending")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Claim(ctx); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("unapproved claim: %v", err)
	}
	var wins atomic.Int32
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			if s.Decide(ctx, "op-1", "human", true) == nil {
				wins.Add(1)
			}
		})
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("approval winners %d", wins.Load())
	}
	wins.Store(0)
	for range 20 {
		wg.Go(func() {
			if _, err := s.Claim(ctx); err == nil {
				wins.Add(1)
			} else if !errors.Is(err, sql.ErrNoRows) {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("claim winners %d", wins.Load())
	}
	events, err := s.Events(ctx)
	if err != nil || len(events) != 3 {
		t.Fatalf("events %v, %v", events, err)
	}
}

func TestRestartRecoveryIdempotencyAndEncryption(t *testing.T) {
	s, path, key := testStore(t)
	ctx := t.Context()
	o := operation("pending-id", "pending")
	if _, err := s.Submit(ctx, o); err != nil {
		t.Fatal(err)
	}
	o.Arguments = map[string]any{"text": "tampered"}
	o.Digest = "different"
	if _, err := s.Submit(ctx, o); err == nil {
		t.Fatal("mutated retry accepted")
	}
	if _, err := Open(path, key); err == nil {
		t.Fatal("second process lock accepted")
	}
	if err := s.SaveToken(ctx, "provider", []byte("credential-material")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Submit(ctx, operation("running-id", "ready")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Claim(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	wrongKey := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 32)))
	if wrong, err := Open(path, wrongKey); err == nil {
		wrong.Close()
		t.Fatal("opened existing ledger with wrong key")
	}
	s2, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	for id, want := range map[string]string{"pending-id": "pending", "running-id": "unknown"} {
		got, err := s2.Get(ctx, id)
		if err != nil || got.Status != want {
			t.Fatalf("%s: %s %v", id, got.Status, err)
		}
	}
	b, err := s2.LoadToken(ctx, "provider")
	if err != nil || string(b) != "credential-material" {
		t.Fatalf("token persistence %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"credential-material", "sensitive-request-value"} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("plaintext persisted")
		}
	}
}

func TestLegacyDigestOnlyMatchesOperationsWithoutNewIdentity(t *testing.T) {
	s, _, _ := testStore(t)
	ctx := t.Context()
	legacy := operation("legacy-id", "pending")
	legacy.Digest = "legacy-digest"
	legacy.AmpUserID = "user-one"
	legacy.AmpThreadID = "thread-one"
	if _, err := s.Submit(ctx, legacy); err != nil {
		t.Fatal(err)
	}
	retry := legacy
	retry.Digest = "current-digest"
	retry.LegacyDigest = "legacy-digest"
	retry.AmpSubject = "workspace:one:user:user-one:thread:thread-one"
	retry.AmpWorkspaceID = "workspace-one"
	if got, err := s.Submit(ctx, retry); err != nil || got.Digest != "legacy-digest" {
		t.Fatalf("legacy retry: %v, %v", got, err)
	}

	current := operation("current-id", "pending")
	current.Digest = "legacy-digest"
	current.AmpWorkspaceID = "workspace-one"
	if _, err := s.Submit(ctx, current); err != nil {
		t.Fatal(err)
	}
	current.Digest = "current-digest"
	current.LegacyDigest = "legacy-digest"
	if _, err := s.Submit(ctx, current); err == nil {
		t.Fatal("legacy digest accepted for operation with current identity fields")
	}
}

func TestExpiredDeniedAndTamperedCiphertext(t *testing.T) {
	s, _, _ := testStore(t)
	ctx := context.Background()
	o := operation("expired", "pending")
	o.Expires = time.Now().Add(-time.Second).Unix()
	s.Submit(ctx, o)
	if s.Decide(ctx, o.ID, "human", true) == nil {
		t.Fatal("expired approval accepted")
	}
	s.Claim(ctx)
	got, _ := s.Get(ctx, o.ID)
	if got.Status != "expired" {
		t.Fatal(got.Status)
	}
	s.Submit(ctx, operation("deny", "pending"))
	if err := s.Decide(ctx, "deny", "human", false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Claim(ctx); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal(err)
	}
	b := s.seal("a", []byte("secret"))
	if _, err := s.open("b", b); err == nil {
		t.Fatal("ciphertext moved across identities")
	}
	b[len(b)-1] ^= 1
	if _, err := s.open("a", b); err == nil {
		t.Fatal("tamper accepted")
	}
}

func TestReauthorizationInvalidatesQueueButCannotChangeRunningGrant(t *testing.T) {
	s, _, _ := testStore(t)
	ctx := t.Context()
	if err := s.SaveToken(ctx, "provider", []byte("old")); err != nil {
		t.Fatal(err)
	}
	for id, status := range map[string]string{"waiting": "pending", "approved": "ready"} {
		if _, err := s.Submit(ctx, operation(id, status)); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Reauthorize(ctx, "provider", []byte("new")); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"waiting", "approved"} {
		o, err := s.Get(ctx, id)
		if err != nil || o.Status != "denied" {
			t.Fatalf("%s: %s %v", id, o.Status, err)
		}
	}
	if _, err := s.Submit(ctx, operation("running", "ready")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Claim(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.Reauthorize(ctx, "provider", []byte("unsafe")); err == nil {
		t.Fatal("replaced running grant")
	}
	raw, err := s.LoadToken(ctx, "provider")
	if err != nil || string(raw) != "new" {
		t.Fatalf("grant changed: %v", err)
	}
	events, err := s.Events(ctx)
	if err != nil {
		t.Fatal(err)
	}
	denials := 0
	for _, e := range events {
		if e.Kind == "denied" && e.Actor == "connection-reauthorized" {
			denials++
		}
	}
	if denials != 2 {
		t.Fatalf("reauthorization audit events: %d", denials)
	}
}
