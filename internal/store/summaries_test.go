package store

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestSummaryIntegrityAndAtomicSubmission(t *testing.T) {
	s, _, _ := testStore(t)
	o := operation("summary", "pending")
	if _, err := s.Submit(t.Context(), o); err != nil {
		t.Fatal(err)
	}
	var encrypted []byte
	if err := s.db.QueryRow("SELECT payload FROM operation_summaries WHERE id=?", o.ID).Scan(&encrypted); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encrypted, []byte(o.Tool)) {
		t.Fatal("summary stored plaintext metadata")
	}
	if _, err := s.open("operation:"+o.ID, encrypted); err == nil {
		t.Fatal("summary ciphertext accepted as an operation")
	}
	if _, err := s.db.Exec("UPDATE operation_summaries SET payload=?", []byte("damaged")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.List(t.Context()); err == nil {
		t.Fatal("listing accepted damaged summary")
	}
	if _, err := s.Get(t.Context(), o.ID); err != nil {
		t.Fatalf("summary damage affected full retrieval: %v", err)
	}
	if _, err := s.db.Exec("DELETE FROM operation_summaries"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.List(t.Context()); err == nil {
		t.Fatal("listing silently omitted a missing summary")
	}
	if _, err := s.db.Exec(`CREATE TRIGGER reject_summary BEFORE INSERT ON operation_summaries BEGIN SELECT RAISE(ABORT, 'test failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Submit(t.Context(), operation("rejected", "pending")); err == nil {
		t.Fatal("submission ignored summary persistence failure")
	}
	var count int
	if err := s.db.QueryRow("SELECT (SELECT count(*) FROM operations WHERE id='rejected')+(SELECT count(*) FROM events WHERE operation='rejected')").Scan(&count); err != nil || count != 0 {
		t.Fatalf("failed submission was not atomic: count=%d err=%v", count, err)
	}
}

func TestSummaryBackfillFailurePrecedesRecovery(t *testing.T) {
	s, path, key := testStore(t)
	if err := s.SaveToken(t.Context(), "key-check", []byte("fixture")); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"a", "z"} {
		o := operation(id, "running")
		raw, err := json.Marshal(o)
		if err != nil {
			t.Fatal(err)
		}
		b := s.seal("operation:"+id, raw)
		if id == "z" {
			b = []byte("damaged")
		}
		if _, err := s.db.Exec("INSERT INTO operations VALUES (?,?,?,?,?)", id, o.Status, o.Created, o.Expires, b); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if reopened, err := Open(path, key); err == nil {
		reopened.Close()
		t.Fatal("backfill accepted damaged legacy operation")
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var summaries, recovered, events int
	if err := db.QueryRow(`SELECT (SELECT count(*) FROM operation_summaries), (SELECT count(*) FROM operations WHERE status!='running'), (SELECT count(*) FROM events)`).Scan(&summaries, &recovered, &events); err != nil {
		t.Fatal(err)
	}
	if summaries != 0 || recovered != 0 || events != 0 {
		t.Fatalf("failed backfill mutated ledger: summaries=%d recovered=%d events=%d", summaries, recovered, events)
	}
}

func TestListDoesNotReadOperationPayload(t *testing.T) {
	s, _, _ := testStore(t)
	o := operation("listed", "pending")
	o.Account = "private-account-label"
	if _, err := s.Submit(t.Context(), o); err != nil {
		t.Fatal(err)
	}
	if err := s.Decide(t.Context(), o.ID, "owner", false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("UPDATE operations SET payload=? WHERE id=?", []byte("unreadable full payload"), o.ID); err != nil {
		t.Fatal(err)
	}
	listed, err := s.List(t.Context())
	if err != nil {
		t.Fatalf("metadata listing read the full operation: %v", err)
	}
	if len(listed) != 1 || listed[0].ID != o.ID || listed[0].Tool != o.Tool || listed[0].Account != o.Account || listed[0].Status != "denied" {
		t.Fatal("listing lost metadata or used a stale status")
	}
	if _, err := s.Get(t.Context(), o.ID); err == nil {
		t.Fatal("full operation retrieval accepted damaged ciphertext")
	}
}

func TestListOrderingAndLimit(t *testing.T) {
	s, _, _ := testStore(t)
	for i := range 105 {
		o := operation(fmt.Sprintf("op-%03d", i), "denied")
		o.Created = int64(i)
		if _, err := s.Submit(t.Context(), o); err != nil {
			t.Fatal(err)
		}
	}
	listed, err := s.List(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 100 {
		t.Fatalf("listed %d operations, want 100", len(listed))
	}
	for i, o := range listed {
		if o.ID != fmt.Sprintf("op-%03d", 104-i) {
			t.Fatalf("unexpected order at %d: %s", i, o.ID)
		}
	}
}

func TestLegacySummaryBackfill(t *testing.T) {
	s, path, key := testStore(t)
	o := operation("legacy", "running")
	o.Account = "legacy-private-account"
	o.Result = json.RawMessage(`{"value":"` + strings.Repeat("x", 1<<20) + `"}`)
	raw, err := json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := s.seal("operation:"+o.ID, raw)
	if _, err := s.db.Exec("INSERT INTO operations VALUES (?,?,?,?,?)", o.ID, o.Status, o.Created, o.Expires, ciphertext); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	listed, err := reopened.List(t.Context())
	if err != nil || len(listed) != 1 || listed[0].Account != o.Account || listed[0].Status != "unknown" {
		t.Fatalf("legacy list failed: %v", err)
	}
	var stored []byte
	if err := reopened.db.QueryRow("SELECT payload FROM operations WHERE id=?", o.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored, ciphertext) {
		t.Fatal("backfill changed immutable operation payload")
	}
	got, err := reopened.Get(t.Context(), o.ID)
	if err != nil || !bytes.Equal(got.Result, o.Result) || got.Arguments["text"] != o.Arguments["text"] {
		t.Fatalf("backfill changed full operation: %v", err)
	}
	if _, err := reopened.db.Exec("UPDATE operations SET payload=? WHERE id=?", []byte("unreadable"), o.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.List(t.Context()); err != nil {
		t.Fatalf("backfilled list still reads full payload: %v", err)
	}
}
