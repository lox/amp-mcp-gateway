package store

import (
	"database/sql"
	"errors"
	"testing"
	"time"
)

func scopedOperation(id string) Operation {
	o := operation(id, "pending")
	o.AmpUserID, o.AmpThreadID = "amp-owner", "thread-a"
	o.AmpProjectID, o.AmpWorkspaceID = "project-a", "workspace-a"
	o.Connection, o.Binding = "notes", "reviewed-binding"
	return o
}

func grantFixture(t *testing.T, scope string) (*Store, Operation) {
	t.Helper()
	s, _, _ := testStore(t)
	o := scopedOperation("grant-source")
	if _, err := s.Submit(t.Context(), o); err != nil {
		t.Fatal(err)
	}
	if err := s.ApproveScope(t.Context(), o.ID, "owner", scope, o.Binding); err != nil {
		t.Fatal(err)
	}
	claimed, err := s.Claim(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if claimed.GrantID != "" {
		t.Fatal("direct human approval marked as grant use")
	}
	if err := s.Finish(t.Context(), claimed, "succeeded", nil); err != nil {
		t.Fatal(err)
	}
	return s, o
}

func TestGrantExactAuthority(t *testing.T) {
	for _, scope := range []string{"thread", "project"} {
		t.Run(scope, func(t *testing.T) {
			s, source := grantFixture(t, scope)
			for name, change := range map[string]func(*Operation){
				"same":            func(o *Operation) { o.Arguments = map[string]any{"text": "different arguments"} },
				"thread":          func(o *Operation) { o.AmpThreadID = "thread-b" },
				"owner":           func(o *Operation) { o.Subject = "other-owner" },
				"user":            func(o *Operation) { o.AmpUserID = "other-user" },
				"workspace":       func(o *Operation) { o.AmpWorkspaceID = "other-workspace" },
				"project":         func(o *Operation) { o.AmpProjectID = "other-project" },
				"missing project": func(o *Operation) { o.AmpProjectID = "" },
				"missing thread":  func(o *Operation) { o.AmpThreadID = "" },
				"tool":            func(o *Operation) { o.Tool = "notes.delete" },
				"connection":      func(o *Operation) { o.Connection = "other-notes" },
				"binding":         func(o *Operation) { o.Binding = "changed-policy-schema-or-identity" },
				"blocked":         func(o *Operation) { o.Status = "denied" },
			} {
				t.Run(name, func(t *testing.T) {
					o := scopedOperation("test-" + name)
					change(&o)
					got, err := s.Submit(t.Context(), o)
					if err != nil {
						t.Fatal(err)
					}
					want := "pending"
					if name == "same" || (scope == "project" && name == "thread") || (scope == "thread" && (name == "project" || name == "missing project")) {
						want = "ready"
					}
					if name == "blocked" {
						want = "denied"
					}
					if got.Status != want || (got.GrantID == source.ID) != (want == "ready") {
						t.Fatalf("got %s grant %q, want %s", got.Status, got.GrantID, want)
					}
				})
			}
			grants, err := s.Grants(t.Context(), "owner")
			if err != nil || len(grants) != 1 || time.Until(grants[0].Expires) > time.Hour || time.Until(grants[0].Expires) < 59*time.Minute {
				t.Fatalf("lifetime/list: %v %v", grants, err)
			}
			other, err := s.Grants(t.Context(), "other-owner")
			if err != nil || len(other) != 0 {
				t.Fatal("cross-owner grant list")
			}
		})
	}
}

func TestGrantInvalidationAtClaim(t *testing.T) {
	for _, action := range []string{"revoke", "expire", "catalogue", "reconnect"} {
		t.Run(action, func(t *testing.T) {
			s, source := grantFixture(t, "thread")
			if got, err := s.Submit(t.Context(), scopedOperation("queued")); err != nil || got.Status != "ready" {
				t.Fatalf("queue: %v %v", got, err)
			}
			var err error
			switch action {
			case "revoke":
				if s.RevokeGrant(t.Context(), source.ID, "wrong-owner") == nil {
					t.Fatal("other owner revoked grant")
				}
				err = s.RevokeGrant(t.Context(), source.ID, "owner")
			case "expire":
				_, err = s.db.Exec("UPDATE grants SET expires=?", time.Now().Unix())
			case "catalogue":
				err = s.SaveCatalogue(t.Context(), []byte(`{}`))
			case "reconnect":
				err = s.Reauthorize(t.Context(), "notes", []byte(`{}`))
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.Claim(t.Context()); !errors.Is(err, sql.ErrNoRows) {
				t.Fatalf("invalid grant claimed: %v", err)
			}
			got, err := s.Get(t.Context(), "queued")
			if err != nil || got.Status != "denied" {
				t.Fatalf("queue not denied: %v %v", got, err)
			}
			got, err = s.Submit(t.Context(), scopedOperation("later"))
			if err != nil || got.Status != "pending" || got.GrantID != "" {
				t.Fatalf("invalid grant reused: %v %v", got, err)
			}
		})
	}
}

func TestGrantCreationRollback(t *testing.T) {
	for _, name := range []string{"wrong owner", "stale binding", "expired", "denied", "missing identity", "missing project", "invalid scope"} {
		t.Run(name, func(t *testing.T) {
			s, _, _ := testStore(t)
			o := scopedOperation("source")
			actor, binding, scope := "owner", o.Binding, "project"
			switch name {
			case "wrong owner":
				actor = "stranger"
			case "stale binding":
				binding = "new-binding"
			case "expired":
				o.Expires = time.Now().Unix()
			case "denied":
				o.Status = "denied"
			case "missing identity":
				o.AmpUserID = ""
			case "missing project":
				o.AmpProjectID = ""
			case "invalid scope":
				scope = "owner"
			}
			if _, err := s.Submit(t.Context(), o); err != nil {
				t.Fatal(err)
			}
			if s.ApproveScope(t.Context(), o.ID, actor, scope, binding) == nil {
				t.Fatal("invalid grant created")
			}
			grants, err := s.Grants(t.Context(), "owner")
			if err != nil || len(grants) != 0 {
				t.Fatal("grant escaped rollback")
			}
			events, err := s.Events(t.Context())
			if err != nil || len(events) != 1 {
				t.Fatalf("audit escaped rollback: %v %v", events, err)
			}
		})
	}
}

func TestGrantRestartAuditAndSingleClaim(t *testing.T) {
	s, path, key := testStore(t)
	source := scopedOperation("source")
	if _, err := s.Submit(t.Context(), source); err != nil {
		t.Fatal(err)
	}
	if err := s.ApproveScope(t.Context(), source.ID, "owner", "thread", source.Binding); err != nil {
		t.Fatal(err)
	}
	if s.ApproveScope(t.Context(), source.ID, "owner", "project", source.Binding) == nil {
		t.Fatal("approval replay created grant")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	o, err := s.Submit(t.Context(), scopedOperation("later"))
	if err != nil || o.GrantID != source.ID {
		t.Fatalf("grant lost on restart: %v %v", o, err)
	}
	for range 2 {
		claimed, err := s.Claim(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Finish(t.Context(), claimed, "unknown", nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Submit(t.Context(), scopedOperation("later")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Claim(t.Context()); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("unknown operation retried")
	}
	events, err := s.Events(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	created, used := 0, 0
	for _, e := range events {
		if e.Kind == "grant-created:thread" && e.Actor == "owner" && e.Operation == source.ID {
			created++
		}
		if e.Kind == "grant-authorized" && e.Actor == "grant:"+source.ID && e.Operation == "later" {
			used++
		}
	}
	if created != 1 || used != 1 {
		t.Fatalf("wrong audit created=%d used=%d", created, used)
	}
}
