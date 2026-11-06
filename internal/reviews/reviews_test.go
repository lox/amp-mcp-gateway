package reviews

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"ampcode.com/lox/amp-mcp-gateway/internal/store"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/sync/semaphore"
)

const testThread = "T-00000000-0000-0000-0000-000000000123"

type fakeAmp struct {
	execute func(context.Context, string, Job, func(string) error) (string, error)
	keys    []string
}

func (f *fakeAmp) Execute(ctx context.Context, key string, j Job, onThread func(string) error) (string, error) {
	if f.execute != nil {
		return f.execute(ctx, key, j, onThread)
	}
	if err := onThread(testThread); err != nil {
		return "", err
	}
	return `{"summary":"Reviewed","findings":[{"severity":"high","title":"Wrong result","message":"This input returns the wrong value","suggestion":"Check the input","path":"main.go","startLine":3,"endLine":5},{"severity":"critical","title":"Unchanged","message":"Not in this diff","suggestion":"Ignore","path":"main.go","startLine":2}]}`, nil
}
func (f *fakeAmp) Archive(_ context.Context, key, id string) error {
	f.keys = append(f.keys, key+":"+id)
	return nil
}
func (f *fakeAmp) Usage(_ context.Context, key, id string) (*Usage, error) {
	f.keys = append(f.keys, key+":"+id)
	return &Usage{CostUSD: 0.23, InputTokens: 120, OutputTokens: 9, Requests: 2}, nil
}

type fakeGitHub struct {
	mu                          sync.Mutex
	checks                      map[int64]map[string]any
	pulls                       map[string]pull
	created, finished           int
	loseCreate, losePublish     bool
	rejectCreate, rejectPublish int
}

func fixturePull(repo string, id int64) pull {
	p := pull{Number: 7, State: "open", Title: "Frozen title", Body: "Description </pull-request-context>", UpdatedAt: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)}
	p.Base.SHA, p.Head.SHA = strings.Repeat("a", 40), strings.Repeat("b", 40)
	p.Base.Ref, p.Head.Ref = "main", "feature"
	p.Base.Repo.ID, p.Base.Repo.FullName = id, repo
	return p
}
func newGitHub(t *testing.T) (*fakeGitHub, *GitHub) {
	t.Helper()
	f := &fakeGitHub{checks: map[int64]map[string]any{}, pulls: map[string]pull{"lox/repo": fixturePull("lox/repo", 44), "sporevm/repo": fixturePull("sporevm/repo", 55)}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		write := func(v any) { w.Header().Set("Content-Type", "application/json"); _ = json.NewEncoder(w).Encode(v) }
		if strings.HasPrefix(r.URL.Path, "/app/installations/") {
			owner := "lox"
			appID, installation := int64(1), int64(11)
			if strings.Contains(r.URL.Path, "/22") {
				owner, appID, installation = "sporevm", 2, 22
			}
			if strings.HasSuffix(r.URL.Path, "/access_tokens") {
				var input struct{ Repositories []string }
				_ = json.NewDecoder(r.Body).Decode(&input)
				if !slices.Equal(input.Repositories, []string{"repo"}) {
					t.Error("installation token not repository scoped")
				}
				write(map[string]any{"token": "token-" + owner})
				return
			}
			write(map[string]any{"id": installation, "app_id": appID, "account": map[string]string{"login": owner}})
			return
		}
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/repos/"), "/")
		if len(parts) < 3 {
			http.NotFound(w, r)
			return
		}
		repo := parts[0] + "/" + parts[1]
		if r.Header.Get("Authorization") != "Bearer token-"+parts[0] {
			t.Error("cross-App installation credential")
			http.Error(w, "denied", 403)
			return
		}
		p := f.pulls[repo]
		switch {
		case parts[2] == "pulls":
			if len(parts) == 3 {
				write([]pull{p})
			} else {
				write(p)
			}
		case parts[2] == "compare":
			if parts[3] != strings.Repeat("a", 40)+"..."+strings.Repeat("b", 40) {
				t.Error("comparison not pinned")
			}
			write(map[string]any{"files": []any{map[string]string{"filename": "main.go", "patch": "@@ -2,3 +2,4 @@\n context\n-old\n+new\n+other\n context"}}})
		case parts[2] == "check-runs" && r.Method == "POST":
			var input map[string]any
			_ = json.NewDecoder(r.Body).Decode(&input)
			if f.rejectCreate != 0 {
				http.Error(w, "rejected", f.rejectCreate)
				return
			}
			f.created++
			id := int64(f.created + 100)
			input["id"] = id
			appID := 1
			if parts[0] == "sporevm" {
				appID = 2
			}
			input["app"] = map[string]int{"id": appID}
			f.checks[id] = input
			if f.loseCreate {
				http.Error(w, "lost after write", 502)
			} else {
				write(map[string]int64{"id": id})
			}
		case parts[2] == "check-runs":
			var id int64
			_, _ = fmt.Sscan(parts[3], &id)
			if r.Method == "GET" {
				write(f.checks[id])
				return
			}
			var input map[string]any
			_ = json.NewDecoder(r.Body).Decode(&input)
			if input["status"] == "completed" && f.rejectPublish != 0 {
				http.Error(w, "rejected", f.rejectPublish)
				return
			}
			for k, v := range input {
				f.checks[id][k] = v
			}
			if input["status"] == "completed" {
				f.finished++
				if f.losePublish {
					http.Error(w, "lost after write", 502)
					return
				}
			}
			write(f.checks[id])
		case parts[2] == "commits":
			checks := []map[string]any{}
			if r.URL.Query().Get("filter") == "all" {
				for _, c := range f.checks {
					checks = append(checks, c)
				}
			}
			write(map[string]any{"check_runs": checks})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return f, &GitHub{BaseURL: server.URL, Client: server.Client()}
}

func fixtureApp(t *testing.T, owner string) App {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	app, installation := int64(1), int64(11)
	if owner == "sporevm" {
		app, installation = 2, 22
	}
	return App{ID: owner, AppID: app, InstallationID: installation, Owner: owner, PrivateKey: string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), WebhookSecret: "fake-webhook-secret-" + owner, AmpKey: "fake-execution-" + owner, Repositories: []string{owner + "/repo"}, Projects: map[string]string{owner + "/repo": "workspace/" + owner}, Enabled: true, FailOn: "high", Visibility: "private", TimeoutMinutes: 5}
}

func fixtureService(t *testing.T, owner string, amp *fakeAmp, gh *GitHub, slots *semaphore.Weighted) (*Service, *store.Store, string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "account.db")
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	st, err := store.Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	s, err := New(t.Context(), owner, st, amp, gh, slots)
	if err != nil {
		t.Fatal(err)
	}
	return s, st, path, key
}

func deliver(t *testing.T, s *Service, a App, p pull, delivery, event, action string, mutate func(map[string]any)) int {
	t.Helper()
	payload := map[string]any{"action": action, "number": p.Number, "installation": map[string]int64{"id": a.InstallationID}, "repository": map[string]any{"id": p.Base.Repo.ID, "full_name": p.Base.Repo.FullName}, "pull_request": p}
	if mutate != nil {
		mutate(payload)
	}
	body, _ := json.Marshal(payload)
	mac := hmac.New(sha256.New, []byte(a.WebhookSecret))
	mac.Write(body)
	r := httptest.NewRequest("POST", "/webhooks/reviews/"+s.Route()+"/"+a.ID, strings.NewReader(string(body)))
	r.SetPathValue("owner", s.Route())
	r.SetPathValue("app", a.ID)
	r.Header.Set("X-GitHub-Event", event)
	r.Header.Set("X-GitHub-Delivery", delivery)
	r.Header.Set("X-Hub-Signature-256", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	w := httptest.NewRecorder()
	s.Webhook(w, r)
	return w.Code
}
func history(t *testing.T, s *Service) []Job {
	t.Helper()
	jobs, err := s.History(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return jobs
}

func TestGitHubAppJWT(t *testing.T) {
	a := fixtureApp(t, "lox")
	encoded, err := appJWT(a)
	if err != nil {
		t.Fatal(err)
	}
	token, err := jwt.ParseSigned(encoded, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatal(err)
	}
	key, err := privateKey(a.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	var claims jwt.Claims
	if err := token.Claims(&key.PublicKey, &claims); err != nil {
		t.Fatal(err)
	}
	if err := claims.Validate(jwt.Expected{Issuer: fmt.Sprint(a.AppID), Time: time.Now()}); err != nil {
		t.Fatal(err)
	}
}

func TestSignedLifecycleAndReruns(t *testing.T) {
	f, gh := newGitHub(t)
	amp := &fakeAmp{}
	s, _, path, _ := fixtureService(t, "user-one", amp, gh, semaphore.NewWeighted(4))
	a := fixtureApp(t, "lox")
	if err := s.Save(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	p := fixturePull("lox/repo", 44)
	for _, delivery := range []string{"delivery", "delivery", "another-delivery"} {
		if got := deliver(t, s, a, p, delivery, "pull_request", "opened", nil); got != 202 {
			t.Fatalf("intake %d", got)
		}
	}
	if len(history(t, s)) != 1 {
		t.Fatal("duplicate review")
	}
	// Advancing main does not replace the frozen review coordinates. The
	// comparison fixture still requires the original a...b pair.
	current := p
	current.Base.SHA = strings.Repeat("c", 40)
	f.pulls["lox/repo"] = current
	if err := s.Step(t.Context()); err != nil {
		t.Fatal(err)
	}
	j := history(t, s)[0]
	if j.Status != "succeeded" || j.Conclusion != "failure" || j.Omitted != 1 || len(j.Result.Findings) != 1 || j.Result.Findings[0].EndLine != 3 {
		t.Fatalf("wrong review: %+v", j)
	}
	f.mu.Lock()
	check := f.checks[j.CheckID]
	f.mu.Unlock()
	if check["conclusion"] != "failure" || check["details_url"] != "https://ampcode.com/threads/"+testThread {
		t.Fatalf("check: %+v", check)
	}
	if err := s.Maintain(t.Context()); err != nil {
		t.Fatal(err)
	}
	j = history(t, s)[0]
	if !j.Threads[0].Archived || j.Threads[0].Usage.CostUSD != 0.23 || j.Threads[0].Usage.ProviderEstimateUSD != nil {
		t.Fatal("cleanup or unknown estimate lost")
	}
	if !slices.Equal(amp.keys, []string{a.AmpKey + ":" + testThread, a.AmpKey + ":" + testThread}) {
		t.Fatal("wrong cleanup identity")
	}
	if err := s.Rerun(t.Context(), j.ID, "manual", false); err != nil {
		t.Fatal(err)
	}
	rerun := history(t, s)[0]
	if rerun.Context != j.Context || rerun.BaseSHA != j.BaseSHA || rerun.HeadSHA != j.HeadSHA || rerun.CheckID != 0 {
		t.Fatal("rerun changed frozen context")
	}
	for _, suffix := range []string{"", "-wal"} {
		raw, _ := os.ReadFile(path + suffix)
		for _, secret := range []string{a.AmpKey, a.WebhookSecret, a.PrivateKey, p.Body} {
			if strings.Contains(string(raw), secret) {
				t.Fatal("plaintext private data in database")
			}
		}
	}
}

func TestWebhookAuthorizationAcrossAppsAndAccounts(t *testing.T) {
	_, gh := newGitHub(t)
	slots := semaphore.NewWeighted(4)
	s, _, _, _ := fixtureService(t, "user-one", &fakeAmp{}, gh, slots)
	other, _, _, _ := fixtureService(t, "user-two", &fakeAmp{}, gh, slots)
	a, b := fixtureApp(t, "lox"), fixtureApp(t, "sporevm")
	for _, app := range []App{a, b} {
		if err := s.Save(t.Context(), app); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name   string
		app    App
		p      pull
		mutate func(map[string]any)
		want   int
	}{
		{"valid", a, fixturePull("lox/repo", 44), nil, 202},
		{"unapproved-owner", a, fixturePull("attacker/repo", 77), nil, 403},
		{"unmapped-repo", a, fixturePull("lox/other", 77), nil, 403},
		{"wrong-installation", a, fixturePull("lox/repo", 44), func(m map[string]any) { m["installation"] = map[string]int{"id": 22} }, 403},
		{"second-app", b, fixturePull("sporevm/repo", 55), nil, 202},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := deliver(t, s, tc.app, tc.p, tc.name, "pull_request", "opened", tc.mutate); got != tc.want {
				t.Fatalf("got %d want %d", got, tc.want)
			}
		})
	}
	bad := a
	bad.WebhookSecret = b.WebhookSecret
	if got := deliver(t, s, bad, fixturePull("lox/repo", 44), "bad-signature", "pull_request", "opened", nil); got != 401 {
		t.Fatal(got)
	}
	if len(history(t, s)) != 2 || len(history(t, other)) != 0 {
		t.Fatal("tenant history leaked")
	}
	if err := other.Rerun(t.Context(), history(t, s)[0].ID, "cross-owner", true); err == nil {
		t.Fatal("cross-owner rerun accepted")
	}
	if err := s.Step(t.Context()); err != nil {
		t.Fatal(err)
	}
	j := history(t, s)[1]
	got := deliver(t, s, b, fixturePull("sporevm/repo", 55), "foreign-check", "check_run", "rerequested", func(m map[string]any) {
		m["check_run"] = map[string]any{"id": j.CheckID, "external_id": j.ID, "app": map[string]int64{"id": b.AppID}}
	})
	if got != 403 {
		t.Fatalf("foreign check accepted: %d", got)
	}
}

func TestDraftCancellationAndConfigurationRevocation(t *testing.T) {
	f, gh := newGitHub(t)
	s, _, _, _ := fixtureService(t, "user", &fakeAmp{}, gh, semaphore.NewWeighted(4))
	a := fixtureApp(t, "lox")
	if err := s.Save(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	p := fixturePull("lox/repo", 44)
	p.Draft = true
	if got := deliver(t, s, a, p, "draft", "pull_request", "opened", nil); got != 202 || len(history(t, s)) != 0 {
		t.Fatal("draft queued")
	}
	p.Draft = false
	deliver(t, s, a, p, "ready", "pull_request", "ready_for_review", nil)
	deliver(t, s, a, p, "closed", "pull_request", "closed", nil)
	if history(t, s)[0].Status != "queued" {
		t.Fatal("stale close cancelled an open PR")
	}
	p.State = "closed"
	f.pulls["lox/repo"] = p
	if err := s.Step(t.Context()); err != nil {
		t.Fatal(err)
	}
	if history(t, s)[0].Status != "cancelled" {
		t.Fatal("close did not cancel")
	}
	deliver(t, s, a, p, "reopen", "pull_request", "reopened", nil)
	a.Enabled = false
	if err := s.Save(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	if err := s.Step(t.Context()); err != nil {
		t.Fatal(err)
	}
	if history(t, s)[0].Status != "cancelled" {
		t.Fatal("revoked job executed")
	}
}

func TestAmbiguousWritesRecoverWithoutReplay(t *testing.T) {
	for _, phase := range []string{"create", "publish", "published-checkpoint", "launch"} {
		t.Run(phase, func(t *testing.T) {
			f, gh := newGitHub(t)
			amp := &fakeAmp{}
			if phase == "launch" {
				amp.execute = func(context.Context, string, Job, func(string) error) (string, error) { return "", errAmbiguous }
			}
			s, st, _, _ := fixtureService(t, "user", amp, gh, semaphore.NewWeighted(4))
			a := fixtureApp(t, "lox")
			if err := s.Save(t.Context(), a); err != nil {
				t.Fatal(err)
			}
			f.loseCreate, f.losePublish = phase == "create", phase == "publish" || phase == "published-checkpoint"
			deliver(t, s, a, fixturePull("lox/repo", 44), "first", "pull_request", "opened", nil)
			if err := s.Step(t.Context()); err != nil {
				t.Fatal(err)
			}
			j := history(t, s)[0]
			if j.Status != "unknown" {
				t.Fatalf("expected unknown, got %s", j.Status)
			}
			if phase == "published-checkpoint" {
				// GitHub accepted publication, but the final success write failed.
				// The fallback can retain the completed phase with unknown status.
				j.Phase = "completed"
				if err := s.update(t.Context(), &j); err != nil {
					t.Fatal(err)
				}
			}
			restarted, err := New(t.Context(), "user", st, amp, gh, semaphore.NewWeighted(4))
			if err != nil {
				t.Fatal(err)
			}
			if err := restarted.Maintain(t.Context()); err != nil {
				t.Fatal(err)
			}
			j = history(t, restarted)[0]
			want := "unknown"
			if phase == "create" {
				want = "queued"
			}
			if phase == "publish" || phase == "published-checkpoint" {
				want = "succeeded"
			}
			if j.Status != want {
				t.Fatalf("recovery %s want %s", j.Status, want)
			}
			if phase == "create" {
				f.loseCreate = false
				if err := restarted.Step(t.Context()); err != nil {
					t.Fatal(err)
				}
			}
			if f.created != 1 {
				t.Fatal("ambiguous check creation replayed")
			}
			if (phase == "publish" || phase == "published-checkpoint") && f.finished != 1 {
				t.Fatal("annotations replayed")
			}
		})
	}
}

func TestDefiniteGitHubRejectionsDoNotBlockAccount(t *testing.T) {
	for _, phase := range []string{"create", "publish"} {
		for _, code := range []int{401, 403, 422, 408} {
			t.Run(fmt.Sprintf("%s/%d", phase, code), func(t *testing.T) {
				f, gh := newGitHub(t)
				s, _, _, _ := fixtureService(t, "user", &fakeAmp{}, gh, semaphore.NewWeighted(4))
				a := fixtureApp(t, "lox")
				if err := s.Save(t.Context(), a); err != nil {
					t.Fatal(err)
				}
				if phase == "create" {
					f.rejectCreate = code
				} else {
					f.rejectPublish = code
				}
				deliver(t, s, a, fixturePull("lox/repo", 44), "rejected", "pull_request", "opened", nil)
				if err := s.Step(t.Context()); err != nil {
					t.Fatal(err)
				}
				want := "failed"
				if code == 408 {
					want = "unknown" // A timeout is not a definite rejection.
				}
				if j := history(t, s)[0]; j.Status != want || f.finished != 0 {
					t.Fatalf("status %s, want %s; completed writes %d", j.Status, want, f.finished)
				}
			})
		}
	}
}

func TestReconciliationDoesNotRepeatKnownHeads(t *testing.T) {
	f, gh := newGitHub(t)
	s, _, _, _ := fixtureService(t, "user", &fakeAmp{}, gh, semaphore.NewWeighted(4))
	a := fixtureApp(t, "lox")
	if err := s.Save(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	s.Reconcile(t.Context())
	s.Reconcile(t.Context())
	if len(history(t, s)) != 1 {
		t.Fatal("reconciliation duplicate")
	}
	deliver(t, s, a, fixturePull("lox/repo", 44), "late", "pull_request", "synchronize", nil)
	if len(history(t, s)) != 1 {
		t.Fatal("late webhook duplicate")
	}
	if err := s.Step(t.Context()); err != nil {
		t.Fatal(err)
	}
	current := f.pulls["lox/repo"]
	current.Base.SHA = strings.Repeat("c", 40)
	f.pulls["lox/repo"] = current
	s.Reconcile(t.Context())
	if len(history(t, s)) != 1 {
		t.Fatal("completed head repeated after base advancement")
	}
}

func TestCancellationDuringExecution(t *testing.T) {
	_, gh := newGitHub(t)
	started := make(chan Job, 1)
	amp := &fakeAmp{execute: func(ctx context.Context, _ string, j Job, onThread func(string) error) (string, error) {
		if err := onThread(testThread); err != nil {
			return "", err
		}
		started <- j
		<-ctx.Done()
		return `{"summary":"late","findings":[]}`, nil
	}}
	s, _, _, _ := fixtureService(t, "user", amp, gh, semaphore.NewWeighted(4))
	a := fixtureApp(t, "lox")
	if err := s.Save(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	deliver(t, s, a, fixturePull("lox/repo", 44), "one", "pull_request", "opened", nil)
	done := make(chan error, 1)
	go func() { done <- s.Step(t.Context()) }()
	select {
	case j := <-started:
		if err := s.Cancel(t.Context(), j.ID, false); err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("did not start")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if history(t, s)[0].Status != "cancelled" {
		t.Fatal("late success after cancellation")
	}
}

func TestRecordRevisionFencesStaleWorker(t *testing.T) {
	_, gh := newGitHub(t)
	s, st, _, _ := fixtureService(t, "user", &fakeAmp{}, gh, semaphore.NewWeighted(4))
	a := fixtureApp(t, "lox")
	if err := s.Save(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	deliver(t, s, a, fixturePull("lox/repo", 44), "one", "pull_request", "opened", nil)
	j := history(t, s)[0]
	old := j.record()
	if err := s.Cancel(t.Context(), j.ID, false); err != nil {
		t.Fatal(err)
	}
	old.Status = "succeeded"
	if err := st.UpdateReview(t.Context(), old); !errors.Is(err, store.ErrReviewConflict) {
		t.Fatalf("stale worker: %v", err)
	}
}

func TestLegacyImportAndNumericCheckRerun(t *testing.T) {
	_, gh := newGitHub(t)
	s, _, _, _ := fixtureService(t, "user", &fakeAmp{}, gh, semaphore.NewWeighted(4))
	a := fixtureApp(t, "lox")
	a.Enabled = false
	if err := s.Save(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	p := fixturePull("lox/repo", 44)
	entry := map[string]any{
		"job":     map[string]any{"id": 17, "source_delivery_id": "old-delivery", "event_type": "pull_request.opened", "installation_id": 11, "repository_id": 44, "repository_full_name": "lox/repo", "pull_number": 7, "base_sha": p.Base.SHA, "head_sha": p.Head.SHA, "amp_project": "old/project", "pull_request_title": p.Title, "pull_request_body": p.Body, "base_ref": "main", "head_ref": "feature", "check_run_id": 101, "status": "succeeded", "created_at": "2026-10-01T01:02:03Z", "completed_at": "2026-10-01T01:03:03Z"},
		"threads": []any{map[string]any{"thread_id": testThread, "amp_usage_usd": 0.25, "estimated_provider_cost_at_list_price_usd": 1.5, "usage_details": map[string]any{"inputTokens": 123, "outputTokens": 45, "requests": 6}, "archived_at": "2026-10-01T01:03:04Z"}},
		"result":  map[string]any{"conclusion": "success", "fail_on": "high", "prompt_identifier": "legacy-prompt", "summary": "No issues", "findings": []any{}, "omitted_findings": 0},
	}
	raw, _ := json.Marshal(entry)
	for i, want := range []int{1, 0} {
		count, err := s.ImportLegacy(t.Context(), a.ID, strings.NewReader(string(raw)))
		if count != want || err != nil {
			t.Fatalf("import %d: %d %v", i, count, err)
		}
	}
	j := history(t, s)[0]
	if j.Project != "old/project" || j.Context != p.job("lox/repo", 44).Context || !j.Threads[0].Archived || j.Threads[0].Usage.InputTokens != 123 || *j.Threads[0].Usage.ProviderEstimateUSD != 1.5 {
		t.Fatal("historical data lost")
	}
	if err := s.Step(t.Context()); err != nil || history(t, s)[0].Status != "succeeded" {
		t.Fatal("import queued work")
	}
	a.Enabled = true
	if err := s.Save(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ImportLegacy(t.Context(), a.ID, strings.NewReader(string(raw))); err == nil {
		t.Fatal("import accepted for enabled App")
	}
	status := deliver(t, s, a, p, "legacy-rerun", "check_run", "rerequested", func(m map[string]any) {
		m["check_run"] = map[string]any{"id": 101, "external_id": "17", "app": map[string]int{"id": 1}}
	})
	if status != 202 {
		t.Fatalf("legacy rerun: %d", status)
	}
	if jobs := history(t, s); len(jobs) != 2 || jobs[0].Context != j.Context || jobs[0].Project != a.Projects["lox/repo"] {
		t.Fatal("rerun lost context or current project authorization")
	}
}

func TestAccountsShareCapacityWithoutMonopolizingExecution(t *testing.T) {
	_, gh := newGitHub(t)
	slots := semaphore.NewWeighted(2)
	started, release := make(chan string, 4), make(chan struct{})
	executor := &fakeAmp{execute: func(ctx context.Context, key string, _ Job, onThread func(string) error) (string, error) {
		if err := onThread(testThread); err != nil {
			return "", err
		}
		started <- key
		select {
		case <-release:
			return `{"summary":"ok","findings":[]}`, nil
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}}
	s, _, _, _ := fixtureService(t, "first", executor, gh, slots)
	other, _, _, _ := fixtureService(t, "second", executor, gh, slots)
	a, b := fixtureApp(t, "lox"), fixtureApp(t, "sporevm")
	if err := s.Save(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	if err := other.Save(t.Context(), b); err != nil {
		t.Fatal(err)
	}
	deliver(t, s, a, fixturePull("lox/repo", 44), "one", "pull_request", "opened", nil)
	deliver(t, other, b, fixturePull("sporevm/repo", 55), "two", "pull_request", "opened", nil)
	done := make(chan error, 2)
	go func() { done <- s.Step(t.Context()) }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("first did not start")
	}
	p := fixturePull("lox/repo", 44)
	p.Number = 8
	deliver(t, s, a, p, "another", "pull_request", "opened", nil)
	// Another worker for the same account cannot consume the spare slot.
	if err := s.Step(t.Context()); err != nil {
		t.Fatal(err)
	}
	go func() { done <- other.Step(t.Context()) }()
	select {
	case key := <-started:
		if key != b.AmpKey {
			t.Fatal("same account ran twice")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("second account starved")
	}
	close(release)
	for range 2 {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
}

func TestQueueCapacityAndUnknownHeadDoNotLaunchDuplicates(t *testing.T) {
	_, gh := newGitHub(t)
	s, _, _, _ := fixtureService(t, "user", &fakeAmp{execute: func(context.Context, string, Job, func(string) error) (string, error) { return "", errAmbiguous }}, gh, semaphore.NewWeighted(4))
	a := fixtureApp(t, "lox")
	if err := s.Save(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	p := fixturePull("lox/repo", 44)
	deliver(t, s, a, p, "initial", "pull_request", "opened", nil)
	if err := s.Step(t.Context()); err != nil {
		t.Fatal(err)
	}
	deliver(t, s, a, p, "late", "pull_request", "synchronize", nil)
	if len(history(t, s)) != 1 {
		t.Fatal("ambiguous launch repeated")
	}
	unknown := history(t, s)[0]
	for n := 1; n <= 101; n++ {
		p.Number = n + 100
		got := deliver(t, s, a, p, fmt.Sprint(n), "pull_request", "opened", nil)
		if n <= 100 && got != 202 || n == 101 && got != 409 {
			t.Fatalf("capacity at %d: %d", n, got)
		}
	}
	if err := s.Step(t.Context()); err != nil {
		t.Fatal(err)
	}
	if jobs, err := s.list(t.Context(), "queued", 100); err != nil || len(jobs) != 100 {
		t.Fatal("unknown execution did not pause the account")
	}
	if !slices.ContainsFunc(history(t, s), func(j Job) bool { return j.ID == unknown.ID }) {
		t.Fatal("queue hid unresolved review from owner")
	}
	if err := s.Cancel(t.Context(), unknown.ID, false); err == nil {
		t.Fatal("unknown resolved without acknowledgement")
	}
	if err := s.Cancel(t.Context(), unknown.ID, true); err != nil {
		t.Fatal(err)
	}
	if err := s.Step(t.Context()); err != nil {
		t.Fatal(err)
	}
	if jobs, err := s.list(t.Context(), "queued", 100); err != nil || len(jobs) != 99 {
		t.Fatal("resolved account did not resume")
	}
}
