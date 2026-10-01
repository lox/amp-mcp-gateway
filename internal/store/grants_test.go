package store

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestApprovalGrantBreadth(t *testing.T) {
	t.Run("exact canonical arguments preserve numbers", func(t *testing.T) {
		s, _, _ := testStore(t)
		source := ampOperation("exact-source", "thread", "project", "tool-binding")
		source.ConnectionBinding = "connection-binding"
		source.Arguments = map[string]any{"left": json.Number("900719925474099312345"), "right": "different"}
		submitWithGrants(t, s, source)
		if err := s.ApproveWithOptions(t.Context(), source.ID, "owner", ApprovalOptions{"exact", "thread", "never"}); err != nil {
			t.Fatal(err)
		}
		matching := ampOperation("exact-match", "thread", "project", "tool-binding")
		matching.ConnectionBinding = "connection-binding"
		matching.Arguments = map[string]any{"right": "different", "left": json.Number("900719925474099312345")}
		if got := submitWithGrants(t, s, matching); got.Status != "ready" {
			t.Fatalf("canonical exact arguments did not match: %s", got.Status)
		}
		different := ampOperation("exact-different", "thread", "project", "tool-binding")
		different.ConnectionBinding = "connection-binding"
		different.Arguments = map[string]any{"left": json.Number("900719925474099312346"), "right": "different"}
		if got := submitWithGrants(t, s, different); got.Status != "pending" {
			t.Fatalf("asymmetric arguments matched exact grant: %s", got.Status)
		}
	})

	t.Run("connection crosses tools but not bindings", func(t *testing.T) {
		s, _, _ := testStore(t)
		source := ampOperation("connection-source", "thread", "project", "tool-one-binding")
		source.Tool, source.ConnectionBinding = "notes.create", "connection-binding"
		submitWithGrants(t, s, source)
		if err := s.ApproveWithOptions(t.Context(), source.ID, "owner", ApprovalOptions{"connection", "project", "24h"}); err != nil {
			t.Fatal(err)
		}
		otherTool := ampOperation("other-tool", "another-thread", "project", "tool-two-binding")
		otherTool.Tool, otherTool.ConnectionBinding = "notes.delete", "connection-binding"
		if got := submitWithGrants(t, s, otherTool); got.Status != "ready" {
			t.Fatalf("connection grant did not cross tools: %s", got.Status)
		}
		otherBinding := ampOperation("other-binding", "another-thread", "project", "tool-two-binding")
		otherBinding.Tool, otherBinding.ConnectionBinding = "notes.delete", "changed-connection-binding"
		if got := submitWithGrants(t, s, otherBinding); got.Status != "pending" {
			t.Fatalf("connection grant crossed configuration binding: %s", got.Status)
		}
	})
}

func TestApprovalGrantExplicitExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, _, _ := testStore(t)
		for _, tc := range []struct{ id, expiry string }{{"timed", "1h"}, {"day", "24h"}, {"lasting", "never"}} {
			o := ampOperation(tc.id, tc.id, "project", "binding")
			o.ConnectionBinding = "connection"
			submitWithGrants(t, s, o)
			if err := s.ApproveWithOptions(t.Context(), o.ID, "owner", ApprovalOptions{"tool", "thread", tc.expiry}); err != nil {
				t.Fatal(err)
			}
		}
		time.Sleep(time.Hour)
		for _, tc := range []struct{ id, thread, want string }{{"after-timed", "timed", "pending"}, {"before-day", "day", "ready"}, {"after-never", "lasting", "ready"}} {
			o := ampOperation(tc.id, tc.thread, "project", "binding")
			o.ConnectionBinding = "connection"
			if got := submitWithGrants(t, s, o); got.Status != tc.want {
				t.Fatalf("%s status = %s, want %s", tc.id, got.Status, tc.want)
			}
		}
		time.Sleep(23 * time.Hour)
		if got := submitWithGrants(t, s, ampOperation("after-day", "day", "project", "binding")); got.Status != "pending" {
			t.Fatal("24-hour grant did not expire at its boundary")
		}
		if got := submitWithGrants(t, s, ampOperation("still-lasting", "lasting", "project", "binding")); got.Status != "ready" {
			t.Fatal("indefinite grant expired")
		}
	})
}

func TestPersistedV1GrantRetainsExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, _, _ := testStore(t)
		o := ampOperation("legacy-source", "thread", "project", "binding")
		submitWithGrants(t, s, o)
		// Construct the old payload and key independently of today's grant builder.
		rawKey, _ := json.Marshal([]string{"approval-grant-v1", "thread", o.Tool, "notes", "binding", "user-owner", "workspace-one", "project", "thread"})
		hash := sha256.Sum256(rawKey)
		id := hex.EncodeToString(hash[:])
		payload, err := json.Marshal(map[string]any{"id": id, "scope": "thread", "tool": o.Tool, "connection": "notes", "binding": "binding", "amp_user_id": "user-owner", "amp_workspace_id": "workspace-one", "amp_project_id": "project", "amp_thread_id": "thread", "operation_id": o.ID, "created": time.Now().Unix()})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.db.Exec("INSERT INTO approval_grants(id,active,created,payload) VALUES(?,1,?,?)", id, time.Now().Unix(), s.seal("approval-grant:"+id, payload)); err != nil {
			t.Fatal(err)
		}
		if got := submitWithGrants(t, s, ampOperation("legacy-before", "thread", "project", "binding")); got.Status != "ready" {
			t.Fatal("legacy consent not recognized")
		}
		time.Sleep(time.Hour)
		if got := submitWithGrants(t, s, ampOperation("legacy-after", "thread", "project", "binding")); got.Status != "pending" {
			t.Fatal("legacy consent became permanent")
		}
	})
}

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

func TestApprovalGrantExpiresAtOneHour(t *testing.T) {
	for _, scope := range []string{"thread", "project"} {
		t.Run(scope, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s, path, key := testStore(t)
				source := submitWithGrants(t, s, ampOperation("source", "thread", "project", "binding"))
				if err := s.Approve(t.Context(), source.ID, "owner", scope); err != nil {
					t.Fatal(err)
				}
				claimed, err := s.Claim(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				if err := s.Finish(t.Context(), claimed, "succeeded", nil); err != nil {
					t.Fatal(err)
				}

				time.Sleep(59*time.Minute + 59*time.Second)
				queued := submitWithGrants(t, s, ampOperation("queued", "thread", "project", "binding"))
				if queued.Status != "ready" {
					t.Fatalf("grant expired early: %s", queued.Status)
				}
				if err := s.Close(); err != nil {
					t.Fatal(err)
				}
				s, err = Open(path, key)
				if err != nil {
					t.Fatal(err)
				}
				defer s.Close()
				grants, err := s.ApprovalGrants(t.Context())
				if err != nil || len(grants) != 1 {
					t.Fatalf("live grants: %v %v", grants, err)
				}
				time.Sleep(time.Second)
				later := submitWithGrants(t, s, ampOperation("later", "thread", "project", "binding"))
				if later.Status != "pending" {
					t.Fatalf("expired grant authorized submission: %s", later.Status)
				}
				grants, err = s.ApprovalGrants(t.Context())
				if err != nil || len(grants) != 0 {
					t.Fatalf("expired grant listed: %v %v", grants, err)
				}
				if _, err := s.Claim(t.Context()); !errors.Is(err, sql.ErrNoRows) {
					t.Fatalf("expired grant dispatched: %v", err)
				}
				got, err := s.Get(t.Context(), queued.ID)
				if err != nil || got.Status != "denied" {
					t.Fatalf("queued call not denied: %s %v", got.Status, err)
				}
				events, err := s.OperationEvents(t.Context(), queued.ID)
				if err != nil || events[0].Kind != "denied" || events[0].Actor != "approval-grant-unavailable" {
					t.Fatalf("missing denial audit: %v %v", events, err)
				}
			})
		})
	}
}

func TestLegacyGrantQueuedCallFailsClosed(t *testing.T) {
	s, path, key := testStore(t)
	source := submitWithGrants(t, s, ampOperation("source", "thread", "project", "binding"))
	if err := s.Approve(t.Context(), source.ID, "owner", "thread"); err != nil {
		t.Fatal(err)
	}
	claimed, err := s.Claim(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Finish(t.Context(), claimed, "succeeded", nil); err != nil {
		t.Fatal(err)
	}
	queued := submitWithGrants(t, s, ampOperation("queued", "thread", "project", "binding"))
	// The old writer persisted a grant ID but not its consent source.
	queued.ApprovalGrantSource = ""
	raw, err := encodeOperation(queued)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("UPDATE operations SET payload=? WHERE id=?", s.seal("operation:"+queued.ID, raw), queued.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Claim(t.Context()); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("legacy call dispatched: %v", err)
	}
	got, err := s.Get(t.Context(), queued.ID)
	if err != nil || got.Status != "denied" {
		t.Fatalf("legacy call not denied: %v %v", got, err)
	}
	fresh := submitWithGrants(t, s, ampOperation("fresh", "thread", "project", "binding"))
	if fresh.Status != "ready" || fresh.ApprovalGrantSource != source.ID {
		t.Fatal("live legacy grant did not authorize new call")
	}
	if _, err := s.Claim(t.Context()); err != nil {
		t.Fatalf("new call could not dispatch: %v", err)
	}
}

func TestApprovalGrantRevocationAtClaim(t *testing.T) {
	for _, replace := range []bool{false, true} {
		t.Run(map[bool]string{false: "revoked", true: "revoked then reapproved"}[replace], func(t *testing.T) {
			s, _, _ := testStore(t)
			// Two pending requests let a later human consent replace the same scope.
			source := submitWithGrants(t, s, ampOperation("source", "thread", "project", "binding"))
			renewal := submitWithGrants(t, s, ampOperation("renewal", "thread", "project", "binding"))
			if err := s.Approve(t.Context(), source.ID, "owner", "thread"); err != nil {
				t.Fatal(err)
			}
			claimed, err := s.Claim(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Finish(t.Context(), claimed, "succeeded", nil); err != nil {
				t.Fatal(err)
			}
			queuedInput := ampOperation("a-queued", "thread", "project", "binding")
			// Exercise setup crossing a second: creation time takes precedence over ID.
			queuedInput.Created = renewal.Created + 1
			queued := submitWithGrants(t, s, queuedInput)
			if queued.Status != "ready" {
				t.Fatal("grant did not authorize queued call")
			}
			if err := s.RevokeApprovalGrant(t.Context(), queued.ApprovalGrant, "owner"); err != nil {
				t.Fatal(err)
			}
			if replace {
				if err := s.Approve(t.Context(), renewal.ID, "owner", "thread"); err != nil {
					t.Fatal(err)
				}
				if claimed, err := s.Claim(t.Context()); err != nil || claimed.ID != renewal.ID {
					t.Fatalf("expected directly approved renewal, got %s: %v", claimed.ID, err)
				}
			}
			if _, err := s.Claim(t.Context()); !errors.Is(err, sql.ErrNoRows) {
				t.Fatalf("old consent dispatched: %v", err)
			}
			got, err := s.Get(t.Context(), queued.ID)
			if err != nil || got.Status != "denied" {
				t.Fatalf("queued call not denied: %v %v", got, err)
			}
			got = submitWithGrants(t, s, ampOperation(queued.ID, "thread", "project", "binding"))
			if got.Status != "denied" {
				t.Fatal("idempotent retry revived denied call")
			}
			if replace {
				fresh := submitWithGrants(t, s, ampOperation("fresh", "thread", "project", "binding"))
				if fresh.Status != "ready" {
					t.Fatal("new consent not usable")
				}
				if _, err := s.Claim(t.Context()); err != nil {
					t.Fatalf("new consent failed claim: %v", err)
				}
			}
		})
	}
}

func TestApprovalGrantRevocationDoesNotCancelDirectOrRunningCalls(t *testing.T) {
	s, _, _ := testStore(t)
	source := submitWithGrants(t, s, ampOperation("source", "thread", "project", "binding"))
	if err := s.Approve(t.Context(), source.ID, "owner", "thread"); err != nil {
		t.Fatal(err)
	}
	grants, err := s.ApprovalGrants(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeApprovalGrant(t.Context(), grants[0].ID, "owner"); err != nil {
		t.Fatal(err)
	}
	claimed, err := s.Claim(t.Context())
	if err != nil || claimed.ID != source.ID {
		t.Fatalf("revocation cancelled direct consent: %v %v", claimed, err)
	}
	if err := s.Finish(t.Context(), claimed, "succeeded", nil); err != nil {
		t.Fatal(err)
	}
	renewal := submitWithGrants(t, s, ampOperation("renewal", "thread", "project", "binding"))
	if err := s.Approve(t.Context(), renewal.ID, "owner", "thread"); err != nil {
		t.Fatal(err)
	}
	claimed, err = s.Claim(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Finish(t.Context(), claimed, "succeeded", nil); err != nil {
		t.Fatal(err)
	}
	running := submitWithGrants(t, s, ampOperation("running", "thread", "project", "binding"))
	claimed, err = s.Claim(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeApprovalGrant(t.Context(), running.ApprovalGrant, "owner"); err != nil {
		t.Fatal(err)
	}
	if err := s.Finish(t.Context(), claimed, "unknown", nil); err != nil {
		t.Fatal(err)
	}
	got := submitWithGrants(t, s, ampOperation("running", "thread", "project", "binding"))
	if got.Status != "unknown" {
		t.Fatal("running call outcome changed")
	}
	if _, err := s.Claim(t.Context()); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("unknown call retried")
	}
}
