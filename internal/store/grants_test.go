package store

import (
	"bytes"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

func ampOperation(id, thread, project, binding string) Operation {
	o := operation(id, "pending")
	o.Connection = "notes"
	o.Binding = binding
	o.AmpUserID = "user-owner"
	o.AmpWorkspaceID = "workspace-one"
	o.AmpProjectID = project
	o.AmpThreadID = thread
	o.Digest = id
	return o
}

func submitWithGrants(t *testing.T, s *Store, o Operation) Operation {
	t.Helper()
	got, err := s.Submit(t.Context(), o)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestApprovalGrantScopesAndRevocation(t *testing.T) {
	s, _, _ := testStore(t)
	first := submitWithGrants(t, s, ampOperation("thread-source", "thread-one", "project-one", "binding-one"))
	if err := s.Approve(t.Context(), first.ID, "owner", "thread"); err != nil {
		t.Fatal(err)
	}
	if got := submitWithGrants(t, s, ampOperation("same-thread", "thread-one", "project-one", "binding-one")); got.Status != "ready" || got.ApprovalScope != "thread" || got.ApprovalGrant == "" {
		t.Fatalf("thread grant did not apply or was not attributed: %+v", got)
	}
	for name, o := range map[string]Operation{
		"another thread":  ampOperation("another-thread", "thread-two", "project-one", "binding-one"),
		"another project": ampOperation("another-project", "thread-two", "project-two", "binding-one"),
		"another binding": ampOperation("another-binding", "thread-one", "project-one", "binding-two"),
	} {
		t.Run(name, func(t *testing.T) {
			if got := submitWithGrants(t, s, o); got.Status != "pending" {
				t.Fatalf("thread grant escaped scope: %s", got.Status)
			}
		})
	}

	projectSource, err := s.Get(t.Context(), "another-thread")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Approve(t.Context(), projectSource.ID, "owner", "project"); err != nil {
		t.Fatal(err)
	}
	if got := submitWithGrants(t, s, ampOperation("same-project", "thread-three", "project-one", "binding-one")); got.Status != "ready" || got.ApprovalScope != "project" || got.ApprovalGrant == "" {
		t.Fatalf("project grant did not apply across threads or was not attributed: %+v", got)
	}
	for name, mutate := range map[string]func(*Operation){
		"user":      func(o *Operation) { o.AmpUserID = "another-user" },
		"workspace": func(o *Operation) { o.AmpWorkspaceID = "workspace-two" },
		"project":   func(o *Operation) { o.AmpProjectID = "project-two" },
		"binding":   func(o *Operation) { o.Binding = "binding-two" },
	} {
		t.Run("project excludes "+name, func(t *testing.T) {
			o := ampOperation("excluded-"+name, "thread-four", "project-one", "binding-one")
			mutate(&o)
			if got := submitWithGrants(t, s, o); got.Status != "pending" {
				t.Fatalf("project grant escaped %s boundary: %s", name, got.Status)
			}
		})
	}

	grants, err := s.ApprovalGrants(t.Context())
	if err != nil || len(grants) != 2 {
		t.Fatalf("active grants: %+v, %v", grants, err)
	}
	var encrypted []byte
	if err := s.db.QueryRow("SELECT payload FROM approval_grants LIMIT 1").Scan(&encrypted); err != nil {
		t.Fatal(err)
	}
	for _, plaintext := range [][]byte{[]byte("workspace-one"), []byte("project-one"), []byte("thread-one"), []byte("notes.create")} {
		if bytes.Contains(encrypted, plaintext) {
			t.Fatalf("grant payload stored plaintext %q", plaintext)
		}
	}
	var projectGrant ApprovalGrant
	for _, grant := range grants {
		if grant.Scope == "project" {
			projectGrant = grant
		}
	}
	if err := s.RevokeApprovalGrant(t.Context(), projectGrant.ID, "owner"); err != nil {
		t.Fatal(err)
	}
	events, err := s.Events(t.Context())
	if err != nil || len(events) == 0 || events[0].Kind != "approval-revoked" || events[0].Actor != "owner" || events[0].Operation != projectGrant.OperationID {
		t.Fatalf("grant revocation was not audited: %+v, %v", events, err)
	}
	if err := s.RevokeApprovalGrant(t.Context(), projectGrant.ID, "owner"); err == nil {
		t.Fatal("revoked grant accepted twice")
	}
	if got := submitWithGrants(t, s, ampOperation("after-revoke", "thread-five", "project-one", "binding-one")); got.Status != "pending" {
		t.Fatalf("revoked project grant still applied: %s", got.Status)
	}
}

func TestApprovalGrantValidationAndAtomicity(t *testing.T) {
	t.Run("project identity required", func(t *testing.T) {
		s, _, _ := testStore(t)
		o := ampOperation("no-project", "thread-one", "", "binding")
		submitWithGrants(t, s, o)
		if err := s.Approve(t.Context(), o.ID, "owner", "project"); err == nil {
			t.Fatal("project grant accepted without project identity")
		}
		got, err := s.Get(t.Context(), o.ID)
		if err != nil || got.Status != "pending" {
			t.Fatalf("failed grant partially approved operation: %s, %v", got.Status, err)
		}
	})

	t.Run("grant persistence failure rolls back approval", func(t *testing.T) {
		s, _, _ := testStore(t)
		o := ampOperation("atomic-grant", "thread-one", "project-one", "binding")
		submitWithGrants(t, s, o)
		if _, err := s.db.Exec(`CREATE TRIGGER reject_grant BEFORE INSERT ON approval_grants BEGIN SELECT RAISE(ABORT, 'test failure'); END`); err != nil {
			t.Fatal(err)
		}
		if err := s.Approve(t.Context(), o.ID, "owner", "thread"); err == nil {
			t.Fatal("grant failure did not fail approval")
		}
		got, err := s.Get(t.Context(), o.ID)
		if err != nil || got.Status != "pending" {
			t.Fatalf("grant failure partially approved operation: %s, %v", got.Status, err)
		}
	})

	t.Run("single concurrent winner", func(t *testing.T) {
		s, _, _ := testStore(t)
		o := ampOperation("concurrent-grant", "thread-one", "project-one", "binding")
		submitWithGrants(t, s, o)
		var wins atomic.Int32
		var workers sync.WaitGroup
		for range 20 {
			workers.Go(func() {
				if err := s.Approve(t.Context(), o.ID, "owner", "thread"); err == nil {
					wins.Add(1)
				} else if errors.Is(err, ErrCapacity) {
					t.Error(err)
				}
			})
		}
		workers.Wait()
		grants, err := s.ApprovalGrants(t.Context())
		if err != nil || wins.Load() != 1 || len(grants) != 1 {
			t.Fatalf("wins=%d grants=%d err=%v", wins.Load(), len(grants), err)
		}
	})
}

func TestConfigurationAndOAuthChangesRevokeApprovalGrants(t *testing.T) {
	for name, revoke := range map[string]func(*Store) error{
		"catalogue": func(s *Store) error { return s.SaveCatalogue(t.Context(), []byte(`{}`)) },
		"OAuth":     func(s *Store) error { return s.Reauthorize(t.Context(), "notes:credential-hash", []byte(`{}`)) },
	} {
		t.Run(name, func(t *testing.T) {
			s, _, _ := testStore(t)
			o := ampOperation("revoke-source", "thread-one", "project-one", "binding")
			submitWithGrants(t, s, o)
			if err := s.Approve(t.Context(), o.ID, "owner", "project"); err != nil {
				t.Fatal(err)
			}
			if err := revoke(s); err != nil {
				t.Fatal(err)
			}
			grants, err := s.ApprovalGrants(t.Context())
			if err != nil || len(grants) != 0 {
				t.Fatalf("grant survived %s change: %+v, %v", name, grants, err)
			}
		})
	}
}
