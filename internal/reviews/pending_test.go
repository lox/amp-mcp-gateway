package reviews

import (
	"net/http"
	"testing"

	"golang.org/x/sync/semaphore"
)

func TestUnmappedRepositoriesAwaitApproval(t *testing.T) {
	_, gh := newGitHub(t)
	s, st, _, _ := fixtureService(t, "admin", &fakeAmp{}, gh, semaphore.NewWeighted(4))
	a := fixtureApp(t, "lox")
	a.Projects = map[string]string{} // The installation is approved; no repository is.
	if err := s.Save(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	p := fixturePull("lox/repo", 44)
	if code := deliver(t, s, a, p, "d1", "pull_request", "opened", nil); code != http.StatusForbidden || len(history(t, s)) != 0 {
		t.Fatalf("unmapped repository was accepted: %d", code)
	}
	// Unknown installations and repositories outside the installation's owner are not recorded.
	stranger := a
	stranger.InstallationID = 99
	deliver(t, s, stranger, fixturePull("lox/stranger", 45), "d2", "pull_request", "opened", nil)
	deliver(t, s, a, fixturePull("sporevm/repo", 46), "d3", "pull_request", "opened", nil)
	deliver(t, s, a, fixturePull("lox/ignored", 47), "d4", "pull_request", "opened", nil)
	pending := s.Pending("lox")
	if len(pending) != 2 || pending[0].Repository != "lox/ignored" || pending[1].Repository != "lox/repo" || pending[1].RepositoryID != 44 || pending[1].Number != p.Number || pending[1].InstallationID != 11 {
		t.Fatalf("pending: %+v", pending)
	}
	if err := s.IgnorePending(t.Context(), "lox", "lox/ignored"); err != nil {
		t.Fatal(err)
	}
	// Both lists are persisted; an ignored repository stays hidden on new deliveries.
	s, err := New(t.Context(), "admin", st, &fakeAmp{}, gh, semaphore.NewWeighted(4))
	if err != nil {
		t.Fatal(err)
	}
	deliver(t, s, a, fixturePull("lox/ignored", 47), "d5", "pull_request", "synchronize", nil)
	if pending := s.Pending("lox"); len(pending) != 1 || pending[0].Repository != "lox/repo" {
		t.Fatalf("ignored repository returned or state was lost: %+v", pending)
	}
	if err := s.ApprovePending(t.Context(), "lox", "lox/stranger", "", false); err == nil {
		t.Fatal("approved a repository that was never awaiting approval")
	}
	if err := s.ApprovePending(t.Context(), "lox", "lox/repo", "work/reviewed", false); err != nil {
		t.Fatal(err)
	}
	row := s.Configuration().Integrations["lox"].Installations[0].Repositories
	if len(row) != 1 || row[0].Name != "lox/repo" || row[0].Project != "work/reviewed" || !row[0].Enabled || row[0].ID != 44 || len(s.Pending("lox")) != 0 {
		t.Fatalf("approval did not save a verified enabled row: %+v", row)
	}
	if code := deliver(t, s, a, p, "d6", "pull_request", "synchronize", nil); code != http.StatusAccepted || len(history(t, s)) != 1 {
		t.Fatalf("approved repository did not enqueue: %d", code)
	}
}
