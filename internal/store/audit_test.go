package store

import (
	"fmt"
	"testing"
)

func TestAuditFiltersPaginationAndTimeline(t *testing.T) {
	s, _, _ := testStore(t)
	for i := range 60 {
		o := operation(fmt.Sprintf("request-%02d", i), "succeeded")
		if i == 57 {
			o.Status = "pending"
		} else if i == 58 {
			o.Status = "running"
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
	active, _, err := s.Audit(t.Context(), AuditFilter{Outcome: "active", Query: "request-58"})
	if err != nil || len(active) != 1 || active[0].Operation.ID != "request-58" {
		t.Fatalf("active filter: %+v %v", active, err)
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
