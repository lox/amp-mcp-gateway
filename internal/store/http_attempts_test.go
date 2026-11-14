package store

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestHTTPAttemptsRunningOrderedAndImmutable(t *testing.T) {
	s, _, _ := testStore(t)
	for _, status := range []string{"pending", "ready", "denied", "expired", "succeeded", "failed", "unknown", "missing"} {
		if status != "missing" {
			if _, err := s.Submit(t.Context(), operation(status, status)); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := s.BeginHTTPAttempt(t.Context(), status, json.RawMessage(`{}`)); err == nil {
			t.Fatalf("began attempt under %s parent", status)
		}
		if err := s.CompleteHTTPAttempt(t.Context(), status, 1, json.RawMessage(`{}`)); err == nil {
			t.Fatalf("completed attempt under %s parent", status)
		}
	}
	o := operation("running", "running")
	if _, err := s.Submit(t.Context(), o); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 3; i++ {
		if sequence, err := s.BeginHTTPAttempt(t.Context(), o.ID, json.RawMessage(`{"url":"https://example.test"}`)); err != nil || sequence != i {
			t.Fatalf("sequence=%d err=%v", sequence, err)
		}
	}
	response := json.RawMessage(`{"status":200}`)
	// Completion order need not match dispatch order.
	for _, sequence := range []int{3, 1} {
		if err := s.CompleteHTTPAttempt(t.Context(), o.ID, sequence, response); err != nil {
			t.Fatal(err)
		}
	}
	for _, sequence := range []int{0, 1, 4, 11} {
		if err := s.CompleteHTTPAttempt(t.Context(), o.ID, sequence, response); err == nil {
			t.Fatalf("completed missing, invalid or immutable sequence %d", sequence)
		}
	}
	attempts, err := s.HTTPAttempts(t.Context(), o.ID)
	if err != nil || len(attempts) != 3 {
		t.Fatalf("attempts=%v err=%v", attempts, err)
	}
	for i, attempt := range attempts {
		if attempt.Sequence != i+1 || (i == 1) != (attempt.Response == nil) {
			t.Fatalf("unordered or lost unknown outcome: %+v", attempt)
		}
	}
	if err := s.Finish(t.Context(), o, "succeeded", response); err != nil {
		t.Fatal(err)
	}
	if err := s.CompleteHTTPAttempt(t.Context(), o.ID, 2, response); err == nil {
		t.Fatal("completed attempt after parent finished")
	}
}

func TestHTTPAttemptsEncryptedReopenNeverReplay(t *testing.T) {
	s, path, key := testStore(t)
	o := operation("journaled", "running")
	if _, err := s.Submit(t.Context(), o); err != nil {
		t.Fatal(err)
	}
	request := json.RawMessage(`{"body":"sensitive-journal-request"}`)
	response := json.RawMessage(`{"body":"sensitive-journal-response"}`)
	for range 2 {
		if _, err := s.BeginHTTPAttempt(t.Context(), o.ID, request); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.CompleteHTTPAttempt(t.Context(), o.ID, 1, response); err != nil {
		t.Fatal(err)
	}
	var encryptedRequest, encryptedResponse []byte
	if err := s.db.QueryRow("SELECT request,response FROM http_attempts WHERE operation=? AND sequence=1", o.ID).Scan(&encryptedRequest, &encryptedResponse); err != nil {
		t.Fatal(err)
	}
	for _, aad := range []string{httpAttemptAAD(o.ID, 2, "request"), httpAttemptAAD("other", 1, "request"), httpAttemptAAD(o.ID, 1, "response")} {
		if _, err := s.open(aad, encryptedRequest); err == nil {
			t.Fatalf("accepted request with wrong AAD %s", aad)
		}
	}
	if bytes.Contains(encryptedRequest, request) || bytes.Contains(encryptedResponse, response) {
		t.Fatal("journal payload was not encrypted")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"", "-wal"} {
		raw, err := os.ReadFile(path + suffix)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		if bytes.Contains(raw, []byte("sensitive-journal-")) {
			t.Fatal("plaintext journal persisted")
		}
	}
	wrongKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	if wrong, err := Open(path, wrongKey); err == nil {
		wrong.Close()
		t.Fatal("wrong key accepted")
	}
	s, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	attempts, err := s.HTTPAttempts(t.Context(), o.ID)
	if err != nil || len(attempts) != 2 || !bytes.Equal(attempts[0].Request, request) || !bytes.Equal(attempts[0].Response, response) || attempts[1].Response != nil {
		t.Fatalf("reopen changed journal: %+v %v", attempts, err)
	}
	if got, err := s.Submit(t.Context(), o); err != nil || got.Status != "unknown" {
		t.Fatalf("retry did not preserve unknown: %+v %v", got, err)
	}
	if _, err := s.Claim(t.Context()); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("restart replayed journaled work: %v", err)
	}
	if _, err := s.BeginHTTPAttempt(t.Context(), o.ID, request); err == nil {
		t.Fatal("restart permitted new dispatch under unknown parent")
	}
	if err := s.CompleteHTTPAttempt(t.Context(), o.ID, 2, response); err == nil {
		t.Fatal("restart changed ambiguous attempt")
	}
}

func jsonStringOfSize(size int) json.RawMessage {
	return json.RawMessage(`"` + strings.Repeat("x", size-2) + `"`)
}

func TestHTTPAttemptBounds(t *testing.T) {
	s, _, _ := testStore(t)
	if _, err := s.Submit(t.Context(), operation("bounds", "running")); err != nil {
		t.Fatal(err)
	}
	for _, request := range []json.RawMessage{nil, json.RawMessage(`{`), jsonStringOfSize(maxHTTPRequestBytes + 1)} {
		if _, err := s.BeginHTTPAttempt(t.Context(), "bounds", request); err == nil {
			t.Fatal("invalid or oversized request accepted")
		}
	}
	if sequence, err := s.BeginHTTPAttempt(t.Context(), "bounds", jsonStringOfSize(maxHTTPRequestBytes)); err != nil || sequence != 1 {
		t.Fatalf("exact request bound rejected: %d %v", sequence, err)
	}
	for _, response := range []json.RawMessage{nil, json.RawMessage(`{`), jsonStringOfSize(maxHTTPResponseBytes + 1)} {
		if err := s.CompleteHTTPAttempt(t.Context(), "bounds", 1, response); err == nil {
			t.Fatal("invalid or oversized response accepted")
		}
	}
	if err := s.CompleteHTTPAttempt(t.Context(), "bounds", 1, jsonStringOfSize(maxHTTPResponseBytes)); err != nil {
		t.Fatal("exact response bound rejected", err)
	}
	for i := 2; i <= 4; i++ {
		if _, err := s.BeginHTTPAttempt(t.Context(), "bounds", json.RawMessage(`{}`)); err != nil {
			t.Fatal(err)
		}
		responseSize := maxHTTPResponseBytes
		if i == 4 {
			if err := s.CompleteHTTPAttempt(t.Context(), "bounds", i, jsonStringOfSize(responseSize)); !errors.Is(err, ErrCapacity) {
				t.Fatal("total response overflow accepted", err)
			}
			responseSize -= maxHTTPRequestBytes + 6
		}
		if err := s.CompleteHTTPAttempt(t.Context(), "bounds", i, jsonStringOfSize(responseSize)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.BeginHTTPAttempt(t.Context(), "bounds", json.RawMessage(`{}`)); !errors.Is(err, ErrCapacity) {
		t.Fatal("dispatched beyond exact 8 MiB operation bound", err)
	}
}

func TestHTTPAttemptConcurrentSequenceLimit(t *testing.T) {
	s, _, _ := testStore(t)
	if _, err := s.Submit(t.Context(), operation("concurrent", "running")); err != nil {
		t.Fatal(err)
	}
	var accepted atomic.Int32
	var workers sync.WaitGroup
	for range 32 {
		workers.Go(func() {
			if _, err := s.BeginHTTPAttempt(t.Context(), "concurrent", json.RawMessage(`{}`)); err == nil {
				accepted.Add(1)
			} else if !errors.Is(err, ErrCapacity) {
				t.Error(err)
			}
		})
	}
	workers.Wait()
	attempts, err := s.HTTPAttempts(t.Context(), "concurrent")
	if err != nil || accepted.Load() != 10 || len(attempts) != 10 {
		t.Fatalf("accepted %d attempts, read %d: %v", accepted.Load(), len(attempts), err)
	}
	for i, attempt := range attempts {
		if attempt.Sequence != i+1 {
			t.Fatal("concurrent writes lost ordering")
		}
	}
}

func TestHTTPAttemptLedgerAdmissionAndCleanup(t *testing.T) {
	s, _, _ := testStore(t)
	o := operation("admission", "running")
	if _, err := s.Submit(t.Context(), o); err != nil {
		t.Fatal(err)
	}
	var existingBytes int64
	if err := s.db.QueryRow(`SELECT (SELECT sum(length(payload)) FROM operations)+
(SELECT sum(length(cast(operation AS BLOB))+length(cast(kind AS BLOB))+length(cast(actor AS BLOB))) FROM events)`).Scan(&existingBytes); err != nil {
		t.Fatal(err)
	}
	request := json.RawMessage(`{}`)
	s.limits.bytes = existingBytes + int64(len(request)+s.aead.Overhead()+len(o.ID)) - 1
	if _, err := s.BeginHTTPAttempt(t.Context(), o.ID, request); !errors.Is(err, ErrCapacity) {
		t.Fatal("new request bypassed admission", err)
	}
	s.limits.bytes++
	if sequence, err := s.BeginHTTPAttempt(t.Context(), o.ID, request); err != nil || sequence != 1 {
		t.Fatalf("exact ledger admission boundary rejected: %d %v", sequence, err)
	}
	if _, err := s.BeginHTTPAttempt(t.Context(), o.ID, request); !errors.Is(err, ErrCapacity) {
		t.Fatal("retained attempt ignored by admission", err)
	}
	if err := s.CompleteHTTPAttempt(t.Context(), o.ID, 1, jsonStringOfSize(4096)); err != nil {
		t.Fatal("ledger capacity lost known response", err)
	}
	if err := s.Finish(t.Context(), o, "succeeded", request); err != nil {
		t.Fatal("ledger capacity blocked Finish", err)
	}
	// Without retained attempts this new intent would fit exactly. The response
	// must still count after its parent reaches a terminal state.
	if err := s.db.QueryRow(`SELECT (SELECT sum(length(payload)) FROM operations)+
(SELECT sum(length(cast(operation AS BLOB))+length(cast(kind AS BLOB))+length(cast(actor AS BLOB))) FROM events)`).Scan(&existingBytes); err != nil {
		t.Fatal(err)
	}
	newOperation := operation("new", "denied")
	raw, err := json.Marshal(newOperation)
	if err != nil {
		t.Fatal(err)
	}
	s.limits.bytes = existingBytes + int64(len(raw)+s.aead.Overhead()+len(newOperation.ID)+len(newOperation.Status)+len("amp:"+newOperation.AmpUserID))
	if _, err := s.Submit(t.Context(), newOperation); !errors.Is(err, ErrCapacity) {
		t.Fatal("retained attempts did not block new intent", err)
	}
	s.limits.bytes = existingBytes + int64(len("new-intent"))
	if err := s.AdmitEvent(t.Context(), Event{Kind: "new-intent"}); !errors.Is(err, ErrCapacity) {
		t.Fatal("retained attempts did not block new event", err)
	}
	if _, err := s.db.Exec("DELETE FROM operations WHERE id=?", o.ID); err != nil {
		t.Fatal(err)
	}
	if attempts, err := s.HTTPAttempts(t.Context(), o.ID); err != nil || len(attempts) != 0 {
		t.Fatal("operation cleanup orphaned attempts", err)
	}
}

func TestHTTPAttemptRollbackProtectionSurvivesRewrites(t *testing.T) {
	s, _, _ := testStore(t)
	o := operation("journaled", "running")
	o.Connection = "notes"
	if _, err := s.Submit(t.Context(), o); err != nil {
		t.Fatal(err)
	}
	checkLegacy := func(wantReadable bool) {
		t.Helper()
		var encrypted []byte
		if err := s.db.QueryRow("SELECT payload FROM operations WHERE id=?", o.ID).Scan(&encrypted); err != nil {
			t.Fatal(err)
		}
		if _, err := s.open("operation:"+o.ID, encrypted); (err == nil) != wantReadable {
			t.Fatalf("legacy readability=%t, want %t", err == nil, wantReadable)
		}
		if _, err := s.Get(t.Context(), o.ID); err != nil {
			t.Fatal("current reader lost operation", err)
		}
	}
	checkLegacy(true)
	if _, err := s.BeginHTTPAttempt(t.Context(), o.ID, json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	checkLegacy(false)
	if err := s.Finish(t.Context(), o, "succeeded", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	checkLegacy(false)
	if err := s.SaveCatalogueProtecting(t.Context(), []byte(`{}`), map[string]bool{"notes": true}); err != nil {
		t.Fatal(err)
	}
	checkLegacy(false)
}
