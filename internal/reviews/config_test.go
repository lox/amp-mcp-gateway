package reviews

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sync/semaphore"
)

func sharedIntegration(t *testing.T) (Integration, App) {
	t.Helper()
	a := fixtureApp(t, "lox")
	in := Integration{ID: a.ID, AppID: a.AppID, PrivateKey: a.PrivateKey, WebhookSecret: a.WebhookSecret, Enabled: true,
		Settings: Settings{FailOn: "critical", Visibility: "private", TimeoutMinutes: 17},
		Installations: []Installation{
			{ID: 11, Owner: "lox", ExecutionCredential: "bot", Repositories: []Repository{{Name: "lox/repo", Project: "work/personal", Enabled: true}}},
			{ID: 22, Owner: "sporevm", ExecutionCredential: "bot", Repositories: []Repository{{Name: "sporevm/repo", Project: "work/company", Settings: Settings{FailOn: "medium", TimeoutMinutes: 9}}}},
		}}
	return in, a
}

func TestSharedAppInstallationAuthorizationAndLifecycle(t *testing.T) {
	f, gh := newGitHub(t)
	f.sharedApp = true
	amp := &fakeAmp{execute: func(ctx context.Context, key string, j Job, onThread func(string) error) (string, error) {
		if key != "fake-service-account" || j.ExecutionCredential != "bot" || j.OwnerID != "admin" {
			t.Fatal("execution escaped its account or credential binding")
		}
		if j.Repository == "lox/repo" {
			if j.Project != "work/personal" || j.FailOn != "critical" || j.TimeoutMinutes != 17 {
				t.Fatal("wrong defaults")
			}
		} else if j.Project != "work/company" || j.FailOn != "medium" || j.TimeoutMinutes != 9 {
			t.Fatal("wrong installation or overrides")
		}
		if err := onThread(testThread); err != nil {
			return "", err
		}
		return `{"summary":"No issues","findings":[]}`, nil
	}}
	s, st, _, _ := fixtureService(t, "admin", amp, gh, semaphore.NewWeighted(4))
	in, signer := sharedIntegration(t)
	if err := s.SaveIntegration(t.Context(), in, map[string]string{"bot": "fake-service-account"}); err != nil {
		t.Fatal(err)
	}
	bad := in
	bad.AppID = 9
	if err := s.SaveIntegration(t.Context(), bad, nil); err == nil {
		t.Fatal("App identity was reassigned")
	}
	bad = in
	bad.Installations = []Installation{{ID: 99, Owner: "attacker", OwnerID: 999, ExecutionCredential: "bot"}}
	if err := s.SaveIntegration(t.Context(), bad, nil); err == nil {
		t.Fatal("unverified installation was accepted")
	}
	for _, tc := range []struct {
		name, repo               string
		installation, repository int64
		want                     int
	}{
		{"approved", "lox/repo", 11, 44, 202},
		{"disabled", "sporevm/repo", 22, 55, 403},
		{"unknown-installation", "lox/repo", 99, 44, 403},
		{"wrong-installation", "lox/repo", 22, 44, 403},
		{"replacement-repository", "lox/repo", 11, 99, 403},
		{"unknown-repository", "lox/new", 11, 66, 403},
		{"unknown-owner", "attacker/repo", 33, 77, 403},
	} {
		signer.InstallationID = tc.installation
		if code := deliver(t, s, signer, fixturePull(tc.repo, tc.repository), tc.name, "pull_request", "opened", nil); code != tc.want {
			t.Fatalf("%s: %d", tc.name, code)
		}
	}
	// Enabling the second installation must not invalidate work for the first.
	in.Installations[1].Repositories[0].Enabled = true
	if err := s.SaveIntegration(t.Context(), in, nil); err != nil {
		t.Fatal(err)
	}
	s.Reconcile(t.Context())
	if len(history(t, s)) != 2 {
		t.Fatal("reconciliation duplicated or missed an installation")
	}
	restarted, err := New(t.Context(), "admin", st, amp, gh, semaphore.NewWeighted(4))
	if err != nil {
		t.Fatal(err)
	}
	s = restarted
	for range 2 {
		if err := s.Step(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	jobs := history(t, s)
	for _, j := range jobs {
		if j.Status != "succeeded" {
			t.Fatalf("%s: %s", j.Repository, j.Status)
		}
	}
	visible := s.Configuration()
	raw, _ := json.Marshal(visible)
	if len(visible.Credentials) != 1 || strings.Contains(string(raw), "fake-service-account") || strings.Contains(string(raw), "PRIVATE KEY") || strings.Contains(string(raw), in.WebhookSecret) {
		t.Fatal("configuration duplicated or exposed keys")
	}
	if visible.Integrations[in.ID].Installations[1].OwnerID != 122 || visible.Integrations[in.ID].Installations[1].Repositories[0].ID != 55 {
		t.Fatal("identities were not verified")
	}
	// Switching one installation's payer must not silently reuse the shared key.
	in.Installations[1].ExecutionCredential = "company-bot"
	if err := s.SaveIntegration(t.Context(), in, map[string]string{"company-bot": "fake-company-key"}); err != nil {
		t.Fatal(err)
	}
	amp.execute = func(ctx context.Context, key string, j Job, onThread func(string) error) (string, error) {
		if key != "fake-company-key" || j.Repository != "sporevm/repo" || j.ExecutionCredential != "company-bot" {
			t.Fatal("rerun used the wrong installation's execution identity")
		}
		if err := onThread("T-00000000-0000-0000-0000-000000000456"); err != nil {
			return "", err
		}
		return `{"summary":"No issues","findings":[]}`, nil
	}
	for _, j := range jobs {
		if j.Repository == "sporevm/repo" {
			if err := s.Rerun(t.Context(), j.ID, "new-payer", false); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := s.Step(t.Context()); err != nil {
		t.Fatal(err)
	}
	// Removing an installation revokes intake and reruns, but not cleanup of its
	// already-owned threads. Cleanup uses the frozen credential, not current routing.
	in.Installations = in.Installations[:1]
	if err := s.SaveIntegration(t.Context(), in, nil); err != nil {
		t.Fatal(err)
	}
	signer.InstallationID = 22
	if deliver(t, s, signer, fixturePull("sporevm/repo", 55), "removed", "pull_request", "opened", nil) != 403 {
		t.Fatal("removed installation accepted")
	}
	for _, j := range jobs {
		if j.Repository == "sporevm/repo" && s.Rerun(t.Context(), j.ID, "removed-rerun", false) == nil {
			t.Fatal("removed installation reran")
		}
	}
	if err := s.Maintain(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(amp.keys) != 6 {
		t.Fatalf("cleanup lost removed installation: %v", amp.keys)
	}
	shared, company := 0, 0
	for _, key := range amp.keys {
		if strings.HasPrefix(key, "fake-service-account:") {
			shared++
		}
		if strings.HasPrefix(key, "fake-company-key:") {
			company++
		}
	}
	if shared != 4 || company != 2 {
		t.Fatal("cleanup borrowed a different payer's credential")
	}
}

func TestSharedCredentialRotationRevokesQueuedWork(t *testing.T) {
	f, gh := newGitHub(t)
	f.sharedApp = true
	calls := 0
	amp := &fakeAmp{execute: func(context.Context, string, Job, func(string) error) (string, error) { calls++; return "", nil }}
	s, _, _, _ := fixtureService(t, "admin", amp, gh, semaphore.NewWeighted(4))
	in, _ := sharedIntegration(t)
	in.Installations[1].Repositories[0].Enabled = true
	if err := s.SaveIntegration(t.Context(), in, map[string]string{"bot": "old-key"}); err != nil {
		t.Fatal(err)
	}
	s.Reconcile(t.Context())
	if len(history(t, s)) != 2 {
		t.Fatal("missing initial jobs")
	}
	if err := s.SaveIntegration(t.Context(), in, map[string]string{"bot": "new-key"}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := s.Step(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	for _, j := range history(t, s) {
		if j.Status != "cancelled" {
			t.Fatalf("old binding survived rotation: %s", j.Status)
		}
	}
	if calls != 0 {
		t.Fatal("launched queued work with replacement credentials")
	}
}

func TestLegacyConfigurationBecomesPausedVerifiedSetup(t *testing.T) {
	_, gh := newGitHub(t)
	s, st, _, _ := fixtureService(t, "admin", &fakeAmp{}, gh, semaphore.NewWeighted(4))
	a := fixtureApp(t, "lox")
	legacy := map[string]any{a.ID: map[string]any{"ID": a.ID, "AppID": a.AppID, "InstallationID": a.InstallationID, "Owner": a.Owner,
		"PrivateKey": a.PrivateKey, "WebhookSecret": a.WebhookSecret, "AmpKey": a.AmpKey, "Enabled": true, "FailOn": a.FailOn, "Visibility": a.Visibility, "TimeoutMinutes": a.TimeoutMinutes,
		"Repositories": []string{"lox/repo"}, "Projects": map[string]string{"lox/repo": "work/repo", "lox/unapproved": "work/unapproved"}}}
	raw, _ := json.Marshal(legacy)
	if err := st.SaveToken(t.Context(), configKey, raw); err != nil {
		t.Fatal(err)
	}
	s, err := New(t.Context(), "admin", st, &fakeAmp{}, gh, semaphore.NewWeighted(4))
	if err != nil {
		t.Fatal(err)
	}
	in := s.Configuration().Integrations[a.ID]
	if in.Enabled || len(in.Installations) != 1 || len(in.Installations[0].Repositories) != 1 || in.Installations[0].Repositories[0].ID != 0 {
		t.Fatal("legacy config granted new authority")
	}
	if deliver(t, s, a, fixturePull("lox/repo", 44), "before-verification", "pull_request", "opened", nil) != 403 {
		t.Fatal("migration enabled intake")
	}
	in.Enabled = true
	if err := s.SaveIntegration(t.Context(), in, nil); err != nil {
		t.Fatal(err)
	}
	if deliver(t, s, a, fixturePull("lox/repo", 44), "verified", "pull_request", "opened", nil) != 202 {
		t.Fatal("verified legacy setup cannot resume")
	}
}

func TestSlowInstallationVerificationCannotBlockOrOverwriteRevocation(t *testing.T) {
	f, gh := newGitHub(t)
	f.sharedApp = true
	s, _, _, _ := fixtureService(t, "admin", &fakeAmp{}, gh, semaphore.NewWeighted(4))
	in, _ := sharedIntegration(t)
	one := in
	one.Installations = one.Installations[:1]
	if err := s.SaveIntegration(t.Context(), one, map[string]string{"bot": "fake-service-account"}); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}, 1), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	transport := gh.Client.Transport
	gh.Client.Transport = reviewTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/app/installations/22" {
			select {
			case entered <- struct{}{}:
			default:
			}
			select {
			case <-release:
			case <-r.Context().Done():
				return nil, r.Context().Err()
			}
		}
		return transport.RoundTrip(r)
	})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.SaveIntegration(ctx, in, nil) }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("verification never started")
	}
	one.Enabled = false
	paused := make(chan error, 1)
	go func() { paused <- s.SaveIntegration(ctx, one, nil) }()
	select {
	case err := <-paused:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("GitHub verification blocked revocation")
	}
	// Even successful verification cannot overwrite the newer paused policy.
	unblock()
	if err := <-done; err == nil {
		t.Fatal("stale configuration overwrote revocation")
	}
	if ctx.Err() != nil {
		t.Fatal("save failed from timeout rather than stale policy")
	}
	stored := s.Configuration().Integrations[in.ID]
	if stored.Enabled || len(stored.Installations) != 1 {
		t.Fatal("revocation lost")
	}
}
