package store

import (
	"bytes"
	"fmt"
	"testing"
)

func TestAuditFiltersPaginationAndTimeline(t *testing.T) {
	s, _, _ := testStore(t)
	for i := range 60 {
		o := operation(fmt.Sprintf("request-%02d", i), "succeeded")
		if i == 57 {
			o.Status = "pending"
		}
		o.Created = 1000 + int64(i/2) // Exercise cursor ties.
		o.Connection, o.Account = "notes", "Notes account"
		if i%2 == 0 {
			o.Tool, o.Connection = "reference.echo", "reference"
		}
		if _, err := s.Submit(t.Context(), o); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Decide(t.Context(), "request-57", "human", false); err != nil {
		t.Fatal(err)
	}
	f := AuditFilter{Query: "NOTES.CREATE", Since: 1001, Until: 1029}
	first, more, err := s.Audit(t.Context(), f)
	if err != nil || !more || len(first) != 25 || first[0].Operation.ID != "request-59" || first[24].Operation.ID != "request-11" {
		t.Fatalf("first page: count=%d more=%v err=%v", len(first), more, err)
	}
	last := first[len(first)-1].Operation
	f.BeforeCreated, f.BeforeID = last.Created, last.ID
	second, more, err := s.Audit(t.Context(), f)
	if err != nil || more || len(second) != 4 || second[0].Operation.ID != "request-09" || second[3].Operation.ID != "request-03" {
		t.Fatalf("second page: %+v more=%v err=%v", second, more, err)
	}
	for _, tc := range []struct {
		filter AuditFilter
		want   string
	}{
		{AuditFilter{Outcome: "denied", Connection: "notes"}, "request-57"},
		{AuditFilter{Query: "request-57", Connection: "notes"}, "request-57"},
		{AuditFilter{Query: "request-57", Connection: "reference"}, ""},
		{AuditFilter{Outcome: "investigate"}, ""},
		{AuditFilter{Query: "%"}, ""},
	} {
		got, _, err := s.Audit(t.Context(), tc.filter)
		if err != nil {
			t.Fatal(err)
		}
		if tc.want == "" {
			if len(got) != 0 {
				t.Fatalf("unexpected matches for %+v", tc.filter)
			}
			continue
		}
		if len(got) != 1 || got[0].Operation.ID != tc.want || len(got[0].Events) != 2 || got[0].Events[0].Kind != "pending" || got[0].Events[1].Actor != "human" {
			t.Fatalf("filtered timeline: %+v", got)
		}
	}
	// Unfiltered pagination must not skip requests sharing a timestamp.
	all, more, err := s.Audit(t.Context(), AuditFilter{})
	if err != nil || !more || all[24].Operation.ID != "request-35" {
		t.Fatal("unexpected unfiltered first page", err)
	}
	next, _, err := s.Audit(t.Context(), AuditFilter{BeforeCreated: all[24].Operation.Created, BeforeID: all[24].Operation.ID})
	if err != nil || next[0].Operation.ID != "request-34" {
		t.Fatal("cursor skipped timestamp tie", err)
	}
}

func TestAuditSummaryUpgradeAndPayloadIsolation(t *testing.T) {
	s, _, _ := testStore(t)
	o := operation("legacy-summary", "ready")
	o.Connection, o.AmpUserID, o.ApprovalScope = "notes", "verified-user", "project"
	o.ApprovalGrantSource = "original-approval"
	if _, err := s.Submit(t.Context(), o); err != nil {
		t.Fatal(err)
	}
	var original []byte
	if err := s.db.QueryRow("SELECT payload FROM operations WHERE id=?", o.ID).Scan(&original); err != nil {
		t.Fatal(err)
	}
	// Recreate the first audit summary version, before grant-source metadata.
	old := s.seal("operation-summary:"+o.ID, []byte(`{"summary_version":1,"tool":"notes.create","account":"legacy"}`))
	if _, err := s.db.Exec("UPDATE operation_summaries SET payload=? WHERE id=?", old, o.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.backfillSummaries(); err != nil {
		t.Fatal(err)
	}
	var stored []byte
	if err := s.db.QueryRow("SELECT payload FROM operations WHERE id=?", o.ID).Scan(&stored); err != nil || !bytes.Equal(original, stored) {
		t.Fatal("summary upgrade altered operation ciphertext", err)
	}
	if _, err := s.db.Exec("UPDATE operations SET payload=? WHERE id=?", []byte("unreadable full payload"), o.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.backfillSummaries(); err != nil {
		t.Fatal("upgraded summary reread full payload", err)
	}
	rows, more, err := s.Audit(t.Context(), AuditFilter{Query: "notes.create", Connection: "notes"})
	if err != nil || more || len(rows) != 1 {
		t.Fatalf("audit read full payload: %v", err)
	}
	got := rows[0].Operation
	if got.Connection != "notes" || got.Subject != "owner" || got.AmpUserID != "verified-user" || got.ApprovalScope != "project" || got.ApprovalGrantSource != "original-approval" || got.Created != o.Created || got.Version != 2 {
		t.Fatalf("upgrade lost audit metadata: %+v", got)
	}
	if _, err := s.db.Exec("DELETE FROM operation_summaries WHERE id=?", o.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Audit(t.Context(), AuditFilter{}); err == nil {
		t.Fatal("audit silently omitted a missing summary")
	}
}

func TestAuditSummaryUpgradeRollsBack(t *testing.T) {
	s, _, _ := testStore(t)
	for _, id := range []string{"a", "z"} {
		if _, err := s.Submit(t.Context(), operation(id, "running")); err != nil {
			t.Fatal(err)
		}
		old := s.seal("operation-summary:"+id, []byte(`{"tool":"notes.create"}`))
		if _, err := s.db.Exec("UPDATE operation_summaries SET payload=? WHERE id=?", old, id); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.db.Exec("UPDATE operations SET payload=? WHERE id='z'", []byte("damaged")); err != nil {
		t.Fatal(err)
	}
	if err := s.backfillSummaries(); err == nil {
		t.Fatal("upgrade accepted damaged operation")
	}
	rows, _, err := s.Audit(t.Context(), AuditFilter{})
	if err != nil || len(rows) != 2 {
		t.Fatalf("failed upgrade committed partial changes: %+v %v", rows, err)
	}
	for _, row := range rows {
		if row.Operation.Version != 0 || row.Operation.Status != "running" {
			t.Fatal("upgrade did not roll back", row.Operation)
		}
	}
}
