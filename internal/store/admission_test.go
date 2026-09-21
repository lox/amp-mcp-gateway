package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestLedgerAdmissionRejectsOutstandingGrowth(t *testing.T) {
	s, _, _ := testStore(t)
	for i := range 16 {
		if _, err := s.Submit(t.Context(), operation(fmt.Sprintf("pending-%d", i), "pending")); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Submit(t.Context(), operation("excess", "pending")); err == nil {
		t.Fatal("admitted unbounded outstanding operations")
	}
	events, err := s.Events(t.Context())
	if err != nil || len(events) != 16 {
		t.Fatal("rejected admission appended an event")
	}
}

func TestLedgerAdmissionIncludesEventHistory(t *testing.T) {
	s, _, _ := testStore(t)
	if _, err := s.db.Exec(`WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<50000)
INSERT INTO events(operation,kind,actor,time) SELECT '', 'policy-proposed', 'fixture', 0 FROM n`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Submit(t.Context(), operation("excess", "denied")); err == nil {
		t.Fatal("operation ignored retained proposal history")
	}
}

func TestRetainedOperationAdmission(t *testing.T) {
	for _, status := range []string{"pending", "ready", "running", "denied", "expired", "succeeded", "unknown"} {
		t.Run(status, func(t *testing.T) {
			s, _, _ := testStore(t)
			s.limits.operations = 1
			o := operation("retained", status)
			if _, err := s.Submit(t.Context(), o); err != nil {
				t.Fatal(err)
			}
			for range 3 {
				if _, err := s.Submit(t.Context(), operation("excess", "denied")); !errors.Is(err, ErrCapacity) {
					t.Fatalf("retained %s ignored: %v", status, err)
				}
			}
			if got, err := s.Submit(t.Context(), o); err != nil || got.Status != status {
				t.Fatalf("replay failed at capacity: %v", err)
			}
			o.Digest = "different"
			if _, err := s.Submit(t.Context(), o); err == nil || errors.Is(err, ErrCapacity) {
				t.Fatal("capacity masked the ID conflict")
			}
			events, err := s.Events(t.Context())
			if err != nil || len(events) != 1 {
				t.Fatal("rejection or replay grew the audit log")
			}
		})
	}
}

func TestAdmissionByteBoundaryAndCompletion(t *testing.T) {
	s, _, _ := testStore(t)
	o := operation("exact", "pending")
	raw, err := json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	s.limits.bytes = int64(len(s.seal("operation:"+o.ID, raw)) + len(o.ID) + len(o.Status) + len(o.Subject))
	if _, err := s.Submit(t.Context(), o); err != nil {
		t.Fatalf("exact byte boundary rejected: %v", err)
	}
	if _, err := s.Submit(t.Context(), operation("excess", "denied")); !errors.Is(err, ErrCapacity) {
		t.Fatal("byte overflow admitted")
	}
	if err := s.Decide(t.Context(), o.ID, "owner", true); err != nil {
		t.Fatal(err)
	}
	claimed, err := s.Claim(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	result := json.RawMessage(`{"value":"` + strings.Repeat("x", 4096) + `"}`)
	if err := s.Finish(t.Context(), claimed, "succeeded", result); err != nil {
		t.Fatal("capacity lost a known outcome", err)
	}
	got, err := s.Submit(t.Context(), o)
	if err != nil || got.Status != "succeeded" || !bytes.Equal(got.Result, result) {
		t.Fatal("replay did not retain completed outcome", err)
	}
	if err := s.SaveToken(t.Context(), "fixture", []byte("rotated-fixture")); err != nil {
		t.Fatal("capacity blocked token rotation", err)
	}
	if err := s.SaveCatalogue(t.Context(), []byte(`{}`)); err != nil {
		t.Fatal("capacity blocked owner configuration", err)
	}
}

func TestEventAdmissionBytesAndDecisions(t *testing.T) {
	s, _, _ := testStore(t)
	e := Event{Kind: "policy-proposed", Actor: "雪 · fixture"}
	size := int64(len(e.Kind) + len(e.Actor))
	s.limits.bytes = size - 1
	if err := s.AdmitEvent(t.Context(), e); !errors.Is(err, ErrCapacity) {
		t.Fatal("oversized new event admitted")
	}
	s.limits.bytes = size
	if err := s.AdmitEvent(t.Context(), e); err != nil {
		t.Fatal("exact event byte boundary rejected", err)
	}
	s.limits.bytes = 2*size - 1
	if err := s.AdmitEvent(t.Context(), e); !errors.Is(err, ErrCapacity) {
		t.Fatal("retained Unicode bytes were undercounted")
	}
	s.limits.bytes = 2 * size
	if err := s.AdmitEvent(t.Context(), e); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordEvent(t.Context(), Event{Kind: "policy-discarded", Actor: "owner"}); err != nil {
		t.Fatal("capacity blocked a decision", err)
	}
	events, err := s.Events(t.Context())
	if err != nil || len(events) != 3 {
		t.Fatal("rejected event grew history")
	}
}

func TestConcurrentAdmission(t *testing.T) {
	s, _, _ := testStore(t)
	s.limits.operations, s.limits.outstanding = 8, 8
	var accepted atomic.Int32
	var workers sync.WaitGroup
	for i := range 32 {
		workers.Go(func() {
			_, err := s.Submit(t.Context(), operation(fmt.Sprintf("concurrent-%d", i), "pending"))
			if err == nil {
				accepted.Add(1)
			} else if !errors.Is(err, ErrCapacity) {
				t.Error(err)
			}
		})
	}
	workers.Wait()
	if accepted.Load() != 8 {
		t.Fatalf("accepted %d concurrent operations", accepted.Load())
	}
}

func TestOutstandingCapacityReleasesOnlyAfterTransition(t *testing.T) {
	s, _, _ := testStore(t)
	s.limits.outstanding = 1
	if _, err := s.Submit(t.Context(), operation("first", "pending")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Submit(t.Context(), operation("second", "ready")); !errors.Is(err, ErrCapacity) {
		t.Fatal("pending operation did not reserve capacity")
	}
	if err := s.Decide(t.Context(), "first", "owner", false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Submit(t.Context(), operation("second", "ready")); err != nil {
		t.Fatal("denial did not release outstanding capacity", err)
	}
	o, err := s.Claim(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Submit(t.Context(), operation("third", "pending")); !errors.Is(err, ErrCapacity) {
		t.Fatal("running operation did not reserve capacity")
	}
	if err := s.Finish(t.Context(), o, "succeeded", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Submit(t.Context(), operation("third", "pending")); err != nil {
		t.Fatal("completion did not release outstanding capacity", err)
	}
}

func TestReopenOverCapacityPreservesRecovery(t *testing.T) {
	s, path, key := testStore(t)
	o := operation("interrupted", "running")
	if _, err := s.Submit(t.Context(), o); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<50000)
INSERT INTO events(operation,kind,actor,time) SELECT '', 'legacy', 'fixture', 0 FROM n`); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path, key)
	if err != nil {
		t.Fatal("over-capacity legacy ledger could not reopen", err)
	}
	defer s.Close()
	got, err := s.Submit(t.Context(), o)
	if err != nil || got.Status != "unknown" {
		t.Fatal("capacity broke restart recovery or replay", err)
	}
	if err := s.AdmitEvent(t.Context(), Event{Kind: "policy-proposed"}); !errors.Is(err, ErrCapacity) {
		t.Fatal("new proposal ignored legacy capacity")
	}
}
