// Package reviews runs tenant-bound GitHub App reviews in Amp orbs.
package reviews

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"ampcode.com/lox/amp-mcp-gateway/internal/store"
	"golang.org/x/sync/semaphore"
)

const configKey = "reviews/config/v1"

var (
	namePattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$`)
	shaPattern    = regexp.MustCompile(`^[0-9a-f]{40}$`)
	threadPattern = regexp.MustCompile(`^T-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// App is an ephemeral repository binding resolved from encrypted configuration.
type App struct {
	ID                                string
	AppID, InstallationID             int64
	GitHubOwnerID, RepositoryID       int64
	ExecutionCredential               string
	Owner                             string
	PrivateKey, WebhookSecret, AmpKey string
	Projects                          map[string]string
	Enabled                           bool
	FailOn, Visibility                string
	TimeoutMinutes                    int
}

func (a App) allows(repo string) bool {
	owner, _, ok := strings.Cut(strings.ToLower(repo), "/")
	return ok && owner == a.Owner && a.Projects[strings.ToLower(repo)] != ""
}

func (a App) binding() string { return hash(a) }

func hash(v any) string {
	b, _ := json.Marshal(v)
	d := sha256.Sum256(b)
	return hex.EncodeToString(d[:])
}

// Context is the PR description and refs frozen at intake, treated as untrusted.
type Context struct{ Title, Body, BaseRef, HeadRef string }

// Thread records each execution attempt, including cleanup and separate costs.
type Thread struct {
	ID         string
	Archived   bool
	Usage      *Usage
	UsageError string
}

// Usage separates billed Amp credits from an optional provider-price estimate.
type Usage struct {
	CostUSD                             float64
	ProviderEstimateUSD                 *float64
	InputTokens, OutputTokens, Requests int64
	SubscriptionUsed                    bool
}

// Job is a frozen review request with durable execution checkpoints.
type Job struct {
	ID, App, Binding, OwnerID             string
	InstallationID, RepositoryID          int64
	Repository                            string
	Number                                int
	BaseSHA, HeadSHA, Project             string
	Context                               Context
	Event, Delivery, Status, Phase, Error string
	CheckID                               int64
	Threads                               []Thread
	Attempts                              int
	Created, Completed, CleanupAt         int64
	Result                                *Result
	Conclusion                            string
	Omitted                               int
	FailOn, Visibility, PromptVersion     string
	TimeoutMinutes                        int
	// Cleanup never borrows a replacement execution identity's credential.
	ExecutionBinding    string
	ExecutionCredential string
	Revision            int64 `json:"-"`
}

func (j Job) headKey() string { return hash([]any{j.RepositoryID, j.Number, j.HeadSHA}) }
func (j Job) pullKey() string { return hash([]any{j.RepositoryID, j.Number}) }

func (j Job) record() store.ReviewRecord {
	b, _ := json.Marshal(j)
	pending := j.Status != "queued" && j.Status != "running" && slices.ContainsFunc(j.Threads, func(t Thread) bool { return !t.Archived || t.Usage == nil && t.UsageError == "" })
	return store.ReviewRecord{ID: j.ID, Scope: j.App, Delivery: j.Delivery, Head: j.headKey(), Pull: j.pullKey(), Status: j.Status, Created: j.Created, Revision: j.Revision, Payload: b, Cleanup: pending, MaintenanceAt: j.CleanupAt}
}

func decode(r store.ReviewRecord) (Job, error) {
	var j Job
	err := json.Unmarshal(r.Payload, &j)
	if err == nil && (j.ID != r.ID || j.App != r.Scope || j.headKey() != r.Head || j.pullKey() != r.Pull) {
		err = errors.New("review identity mismatch")
	}
	j.Status, j.Revision = r.Status, r.Revision
	return j, err
}

// Service is isolated to one immutable Amp user and encrypted account store.
// Each service can hold only one execution slot, regardless of its App count.
type Service struct {
	mu           sync.Mutex
	owner        string
	store        *store.Store
	config       Configuration
	amp          Executor
	github       *GitHub
	slots        *semaphore.Weighted
	activeID     string
	activeCancel context.CancelFunc
}

// New loads an account's configuration and fences interrupted workers. The
// shared FIFO semaphore bounds host execution without letting one account fill it.
func New(ctx context.Context, owner string, st *store.Store, amp Executor, github *GitHub, slots *semaphore.Weighted) (*Service, error) {
	if owner == "" || amp == nil || github == nil || slots == nil {
		return nil, errors.New("reviews requires an owner and execution backends")
	}
	s := &Service{owner: owner, store: st, amp: amp, github: github, slots: slots}
	if err := st.InitReviews(ctx); err != nil {
		return nil, err
	}
	b, err := st.LoadToken(ctx, configKey)
	if err != nil {
		return nil, err
	}
	s.config, err = readConfiguration(b)
	if err != nil {
		return nil, errors.New("invalid reviews configuration")
	}
	if err := st.RecoverReviews(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

// Route identifies this account in webhook URLs; it is a routing hint, not auth.
func (s *Service) Route() string { return hash(s.owner) }

func validRepository(repo string) bool {
	owner, name, ok := strings.Cut(repo, "/")
	return ok && namePattern.MatchString(owner) && namePattern.MatchString(name) && name != "." && name != ".."
}

func (s *Service) authorized(j Job) (App, bool) {
	a, ok := s.config.resolve(j.App, j.InstallationID, j.Repository)
	return a, ok && j.OwnerID == s.owner && a.Enabled && a.RepositoryID == j.RepositoryID && a.binding() == j.Binding
}

func (s *Service) update(ctx context.Context, j *Job) error {
	if err := s.store.UpdateReview(ctx, j.record()); err != nil {
		return err
	}
	j.Revision++
	return nil
}

// History returns recent records only from this account, with no credentials.
// Always include the next unresolved outcome, even behind a full queue.
func (s *Service) History(ctx context.Context) ([]Job, error) {
	jobs, err := s.list(ctx, "", 100)
	if err != nil {
		return nil, err
	}
	unknown, err := s.list(ctx, "unknown", 1)
	if len(unknown) > 0 && !slices.ContainsFunc(jobs, func(j Job) bool { return j.ID == unknown[0].ID }) {
		jobs = append(unknown, jobs...)
	}
	return jobs, err
}

func (s *Service) list(ctx context.Context, status string, limit int) ([]Job, error) {
	records, err := s.store.Reviews(ctx, status, 0, limit)
	if err != nil {
		return nil, err
	}
	var jobs []Job
	for _, r := range records {
		j, err := decode(r)
		if err != nil {
			return nil, err
		}
		if j.OwnerID != s.owner {
			return nil, errors.New("review owner mismatch")
		}
		jobs = append(jobs, j)
	}
	return jobs, nil
}

func (s *Service) get(ctx context.Context, id string) (Job, error) {
	r, err := s.store.Review(ctx, id)
	if err != nil {
		return Job{}, err
	}
	j, err := decode(r)
	if err == nil && j.OwnerID != s.owner {
		err = errors.New("review owner mismatch")
	}
	return j, err
}

func (s *Service) enqueue(ctx context.Context, a App, j Job, missing bool) error {
	j.ID, j.App, j.OwnerID, j.Binding = rand.Text(), a.ID, s.owner, a.binding()
	j.InstallationID, j.Project = a.InstallationID, a.Projects[strings.ToLower(j.Repository)]
	j.Status, j.Created, j.Revision = "queued", time.Now().UnixNano(), 1
	j.FailOn, j.Visibility, j.TimeoutMinutes = a.FailOn, a.Visibility, a.TimeoutMinutes
	j.ExecutionBinding = hash(a.AmpKey)
	j.ExecutionCredential = a.ExecutionCredential
	j.PromptVersion = "gateway-review-v1"
	return s.store.InsertReview(ctx, j.record(), missing)
}

func validJob(j Job) bool {
	return j.RepositoryID > 0 && j.Number > 0 && validRepository(j.Repository) && shaPattern.MatchString(j.BaseSHA) && shaPattern.MatchString(j.HeadSHA) && len(j.Context.Title) > 0 && len(j.Context.Title) <= 1024 && len(j.Context.Body) <= 65536 && len(j.Context.BaseRef) > 0 && len(j.Context.BaseRef) <= 1000 && len(j.Context.HeadRef) > 0 && len(j.Context.HeadRef) <= 1000
}

// Rerun creates a new check using the exact original coordinates and PR context.
// Unknown outcomes require explicit operator acknowledgement, never auto-replay.
func (s *Service) Rerun(ctx context.Context, id, delivery string, acknowledge bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rerun(ctx, id, delivery, acknowledge, 0, "")
}

func (s *Service) rerun(ctx context.Context, id, delivery string, ack bool, checkID int64, app string) error {
	j, err := s.get(ctx, id)
	if err != nil {
		return err
	}
	a, ok := s.config.resolve(j.App, j.InstallationID, j.Repository)
	if !ok || !a.Enabled || a.RepositoryID != j.RepositoryID || (app != "" && (app != j.App || checkID != j.CheckID)) {
		return errors.New("review not authorized")
	}
	if !validJob(j) {
		return errors.New("historical review lacks frozen PR context; request a new review from the current PR instead")
	}
	if j.Status == "queued" || j.Status == "running" || j.Status == "cancelling" || j.Status == "unknown" && !ack {
		return errors.New("review is active or its outcome needs operator acknowledgement")
	}
	if j.Status == "unknown" {
		j.Status, j.Error, j.Completed = "cancelled", "Owner acknowledged external outcome before rerun", time.Now().Unix()
		if err := s.update(ctx, &j); err != nil {
			return err
		}
	}
	j.ID, j.CheckID, j.Threads, j.Result, j.Attempts, j.Error, j.Phase, j.Conclusion, j.Completed, j.CleanupAt = "", 0, nil, nil, 0, "", "", "", 0, 0
	j.Delivery, j.Event = delivery, "check_run.rerequested"
	return s.enqueue(ctx, a, j, false)
}

func (j Job) String() string { return fmt.Sprintf("%s#%d", j.Repository, j.Number) }
