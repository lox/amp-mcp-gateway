package store

import (
	"bytes"
	"fmt"
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

func TestListStatusFiltersBeforeLimitWithoutReadingPayload(t *testing.T) {
	s, _, _ := testStore(t)
	for i := range 102 {
		o := operation(fmt.Sprintf("op-%03d", i), "denied")
		o.Created = int64(i)
		if i == 0 {
			o.Status = "pending"
		}
		if _, err := s.Submit(t.Context(), o); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.db.Exec("UPDATE operations SET payload=?", []byte("unreadable full payload")); err != nil {
		t.Fatal(err)
	}
	listed, err := s.ListStatus(t.Context(), "pending")
	if err != nil || len(listed) != 1 || listed[0].ID != "op-000" || listed[0].Status != "pending" {
		t.Fatalf("pending operation hidden by newer history: %v, %v", listed, err)
	}
}
