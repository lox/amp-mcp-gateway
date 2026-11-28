package reviews

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"
)

const pendingKey = "reviews/pending/v1"

// Pending is a repository on an approved installation that sent a signed pull
// request event but has no repository row. Recording it never creates a job;
// approval goes through the same verified save as any other row.
type Pending struct {
	Integration    string
	InstallationID int64
	Repository     string
	RepositoryID   int64
	Number         int
	Title          string
	Seen           int64
}

type ignoredRepository struct {
	Integration  string
	RepositoryID int64
}

type pendingState struct {
	Entries []Pending
	// Ignored is keyed by repository ID, so a recreated repository asks again.
	Ignored []ignoredRepository
}

const (
	maxPending = 50
	maxIgnored = 500
)

func readPending(raw []byte) (pendingState, error) {
	var p pendingState
	if len(raw) == 0 {
		return p, nil
	}
	return p, json.Unmarshal(raw, &p)
}

// configured reports whether the repository already has a row, enabled or not.
func (c Configuration) configured(integration, repo string) bool {
	for _, i := range c.Integrations[integration].Installations {
		for _, r := range i.Repositories {
			if r.Name == repo {
				return true
			}
		}
	}
	return false
}

// notePending records an unmapped repository from a signed webhook. Only
// installations already in the configuration are recorded, so strangers who
// install a public App cannot fill the list. Callers hold s.mu.
func (s *Service) notePending(ctx context.Context, in Integration, installation int64, repo string, repoID int64, number int, title string) error {
	repo = strings.ToLower(repo)
	owner, _, _ := strings.Cut(repo, "/")
	known := slices.ContainsFunc(in.Installations, func(i Installation) bool { return i.ID == installation && i.Owner == owner })
	if !known || repoID <= 0 || !validRepository(repo) || s.config.configured(in.ID, repo) ||
		slices.Contains(s.pending.Ignored, ignoredRepository{in.ID, repoID}) {
		return nil
	}
	if len(title) > 300 {
		title = strings.ToValidUTF8(title[:300], "")
	}
	next := pendingState{Ignored: s.pending.Ignored}
	entry := Pending{Integration: in.ID, InstallationID: installation, Repository: repo, RepositoryID: repoID, Number: number, Title: title, Seen: time.Now().Unix()}
	next.Entries = append(next.Entries, entry)
	for _, p := range s.pending.Entries {
		if !(p.Integration == in.ID && p.Repository == repo) && len(next.Entries) < maxPending {
			next.Entries = append(next.Entries, p)
		}
	}
	return s.savePending(ctx, next)
}

func (s *Service) savePending(ctx context.Context, next pendingState) error {
	b, err := json.Marshal(next)
	if err != nil {
		return err
	}
	if err := s.store.SaveToken(ctx, pendingKey, b); err != nil {
		return err
	}
	s.pending = next
	return nil
}

// Pending lists repositories awaiting approval for an integration, newest
// first, leaving out any that have since been added to the configuration.
func (s *Service) Pending(integration string) []Pending {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Pending
	for _, p := range s.pending.Entries {
		if p.Integration == integration && !s.config.configured(integration, p.Repository) {
			out = append(out, p)
		}
	}
	return out
}

func (s *Service) dropPending(ctx context.Context, integration, repo string, ignore bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := pendingState{Ignored: slices.Clone(s.pending.Ignored)}
	found := false
	for _, p := range s.pending.Entries {
		if p.Integration == integration && p.Repository == repo {
			found = true
			if ignore {
				next.Ignored = append(next.Ignored, ignoredRepository{integration, p.RepositoryID})
			}
			continue
		}
		next.Entries = append(next.Entries, p)
	}
	if !found {
		return errors.New("repository is not awaiting approval")
	}
	if len(next.Ignored) > maxIgnored {
		next.Ignored = next.Ignored[len(next.Ignored)-maxIgnored:]
	}
	return s.savePending(ctx, next)
}

// IgnorePending hides a repository until it is recreated with a new ID.
func (s *Service) IgnorePending(ctx context.Context, integration, repo string) error {
	return s.dropPending(ctx, integration, strings.ToLower(repo), true)
}

// ApprovePending adds an enabled row for a repository awaiting approval and
// saves it through the normal path, which verifies its ID with GitHub. Drafts
// (the demo) save unverified, like the configuration form.
func (s *Service) ApprovePending(ctx context.Context, integration, repo, project string, draft bool) error {
	repo = strings.ToLower(repo)
	s.mu.Lock()
	var entry *Pending
	for _, p := range s.pending.Entries {
		if p.Integration == integration && p.Repository == repo {
			entry = &p
			break
		}
	}
	// Copy the stored integration, keys included; json decoding into a fresh
	// value detaches it from the published configuration. The save is bound to
	// this snapshot so a concurrent save is never overwritten.
	raw, err := json.Marshal(s.config.Integrations[integration])
	base := hash(s.config)
	s.mu.Unlock()
	if entry == nil {
		return errors.New("repository is not awaiting approval")
	}
	if err != nil {
		return err
	}
	var in Integration
	if err := json.Unmarshal(raw, &in); err != nil {
		return err
	}
	n := slices.IndexFunc(in.Installations, func(i Installation) bool { return i.ID == entry.InstallationID })
	if n < 0 {
		return errors.New("the installation that sent this repository is no longer configured")
	}
	if project = strings.TrimSpace(project); project == "" {
		project = repo
	}
	in.Installations[n].Repositories = append(in.Installations[n].Repositories, Repository{Name: repo, Project: project, Enabled: true})
	if draft && in.Enabled {
		return errors.New("unverified drafts cannot enable reviews")
	}
	// Verification must find the repository that sent the pull request, not
	// a replacement created under the same name since.
	if err := s.saveIntegration(ctx, in, nil, !draft, &saveGuard{base: base, repository: repo, repositoryID: entry.RepositoryID}); err != nil {
		return err
	}
	// The row is saved; Pending already hides configured repositories, so a
	// failure to prune the entry here is harmless.
	_ = s.dropPending(ctx, integration, repo, false)
	return nil
}
