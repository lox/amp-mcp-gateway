package reviews

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"ampcode.com/lox/amp-mcp-gateway/internal/store"
	"golang.org/x/sync/errgroup"
)

// Run keeps execution and housekeeping independent, stopping both on shutdown.
func (s *Service) Run(ctx context.Context) error {
	group, ctx := errgroup.WithContext(ctx)
	group.Go(func() error {
		for ctx.Err() == nil {
			if err := s.Step(ctx); err != nil && !errors.Is(err, store.ErrReviewConflict) && ctx.Err() == nil {
				return err
			}
			if sleep(ctx, time.Second) != nil {
				break
			}
		}
		return nil
	})
	group.Go(func() error {
		lastReconcile := time.Time{}
		for ctx.Err() == nil {
			if err := s.Maintain(ctx); err != nil && !errors.Is(err, store.ErrReviewConflict) && ctx.Err() == nil {
				return err
			}
			if time.Since(lastReconcile) >= 5*time.Minute {
				s.Reconcile(ctx)
				lastReconcile = time.Now()
			}
			if sleep(ctx, time.Minute) != nil {
				break
			}
		}
		return nil
	})
	return group.Wait()
}

// Step claims the oldest queued review after obtaining a shared execution slot.
// It is also the synchronous integration-test entry point for a complete review.
func (s *Service) Step(ctx context.Context) error {
	jobs, err := s.list(ctx, "queued", 100)
	if err != nil {
		return err
	}
	if len(jobs) == 0 {
		return nil
	}
	if err := s.slots.Acquire(ctx, 1); err != nil {
		return err
	}
	defer s.slots.Release(1)
	s.mu.Lock()
	if s.activeID != "" {
		s.mu.Unlock()
		return nil
	}
	// An unknown launch may still be spending credits remotely. Do not let a
	// disconnected account accumulate orbs by moving on to other PRs.
	unknown, err := s.list(ctx, "unknown", 1)
	if err != nil || len(unknown) != 0 {
		s.mu.Unlock()
		return err
	}
	j, err := s.get(ctx, jobs[len(jobs)-1].ID)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	if j.Status != "queued" {
		s.mu.Unlock()
		return nil
	}
	a, ok := s.authorized(j)
	if !ok {
		j.Status, j.Error, j.Completed = "cancelled", "Review configuration changed or authorization revoked", time.Now().Unix()
		err = s.update(ctx, &j)
		s.mu.Unlock()
		return err
	}
	jobCtx, cancel := context.WithTimeout(ctx, time.Duration(j.TimeoutMinutes)*time.Minute)
	s.activeID, s.activeCancel = j.ID, cancel
	j.Status, j.Phase = "running", "preflight"
	j.Attempts++
	err = s.update(ctx, &j)
	s.mu.Unlock()
	defer func() { cancel(); s.mu.Lock(); s.activeID, s.activeCancel = "", nil; s.mu.Unlock() }()
	if err != nil {
		return err
	}
	s.review(jobCtx, a, &j)
	return nil
}

func (s *Service) checkpoint(ctx context.Context, j *Job, phase string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.authorized(*j); !ok {
		return errors.New("review authorization changed")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	j.Phase = phase
	return s.update(ctx, j)
}

func (s *Service) review(ctx context.Context, a App, j *Job) {
	status, message := "failed", "Review could not complete. Inspect its gateway history before rerunning."
	var gh *githubSession
	defer func() {
		finishCtx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		if j.Status == "succeeded" {
			return
		}
		if ctx.Err() != nil && status != "unknown" {
			status, message = "cancelled", "Review cancelled, superseded, timed out or configuration changed."
		}
		// If publishing might have succeeded, do not overwrite it or replay
		// annotations. Leave a visible unknown outcome for recovery/operator.
		if status != "unknown" && j.CheckID != 0 && gh != nil {
			conclusion := "failure"
			if status == "cancelled" {
				conclusion = "cancelled"
			}
			j.Phase = "finishing"
			if err := s.update(finishCtx, j); err != nil {
				return
			}
			if err := gh.finish(finishCtx, *j, conclusion, message); err != nil {
				status = "unknown"
			}
		}
		j.Status, j.Error, j.Completed = status, message, time.Now().Unix()
		// A failed write leaves the last durable checkpoint for restart recovery.
		_ = s.update(finishCtx, j)
	}()
	var err error
	gh, err = s.github.session(ctx, a, j.Repository)
	if err != nil {
		message = err.Error()
		return
	}
	current, err := gh.current(ctx, *j)
	if err != nil {
		message = err.Error()
		return
	}
	if !current {
		status, message = "cancelled", "PR is closed, draft, transferred or superseded."
		return
	}
	if j.CheckID == 0 {
		if err := s.checkpoint(ctx, j, "creating_check"); err != nil {
			return
		}
		j.CheckID, err = gh.createCheck(ctx, *j)
		if err != nil {
			status, message = "unknown", "GitHub check creation outcome unknown; no automatic retry."
			return
		}
	}
	if err := s.checkpoint(ctx, j, "starting_thread"); err != nil {
		status = "unknown"
		return
	}
	// Poll live state during long reviews, including missed close/draft events.
	pollCtx, stopPoll := context.WithCancel(ctx)
	pollDone := make(chan struct{})
	go func(snapshot Job) {
		defer close(pollDone)
		for sleep(pollCtx, 10*time.Second) == nil {
			current, err := gh.current(pollCtx, snapshot)
			if err == nil && !current {
				s.mu.Lock()
				if s.activeID == snapshot.ID && s.activeCancel != nil {
					s.activeCancel()
				}
				s.mu.Unlock()
				return
			}
		}
	}(*j)
	text, executeErr := s.amp.Execute(ctx, a.AmpKey, *j, func(id string) error {
		if !threadPattern.MatchString(id) {
			return errors.New("invalid Amp thread ID")
		}
		if !slices.ContainsFunc(j.Threads, func(t Thread) bool { return t.ID == id }) {
			j.Threads = append(j.Threads, Thread{ID: id})
		}
		// Persist the thread even if a simultaneous cancellation revokes work.
		saveCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.update(saveCtx, j); err != nil {
			return err
		}
		if err := s.checkpoint(ctx, j, "reviewing"); err != nil {
			return err
		}
		_ = gh.link(ctx, *j, id) // Link failure is non-critical and never retried.
		return nil
	})
	stopPoll()
	<-pollDone
	if executeErr != nil {
		if errors.Is(executeErr, errAmbiguous) {
			status = "unknown"
		}
		if errors.Is(executeErr, errCancelled) {
			status = "cancelled"
		}
		message = executeErr.Error()
		return
	}
	result, err := ParseResult(text)
	if err != nil {
		message = err.Error()
		return
	}
	changed, err := gh.changed(ctx, *j)
	if err != nil {
		message = err.Error()
		return
	}
	current, err = gh.current(ctx, *j)
	if err != nil {
		message = err.Error()
		return
	}
	if !current {
		status, message = "cancelled", "PR is closed, draft, transferred or superseded."
		return
	}
	result, j.Conclusion, j.Omitted = finalize(result, changed, j.FailOn)
	j.Result = &result
	if err := s.checkpoint(ctx, j, "publishing"); err != nil {
		return
	}
	if err := gh.finish(ctx, *j, j.Conclusion, result.Summary); err != nil {
		status, message = "unknown", "GitHub result publication outcome unknown; annotations will not be replayed."
		return
	}
	j.Status, j.Completed, j.Phase = "succeeded", time.Now().Unix(), "completed"
	if err := s.update(ctx, j); err != nil {
		j.Status = "unknown"
		status = "unknown"
	}
}

// Reconcile checks only explicitly mapped/approved repositories, with bounded
// pages and ten new jobs per pass. It never cancels work using a stale listing.
func (s *Service) Reconcile(ctx context.Context) {
	s.mu.Lock()
	apps := slices.Collect(maps.Values(s.apps))
	s.mu.Unlock()
	queued := 0
	for _, a := range apps {
		if !a.Enabled {
			continue
		}
		for repo := range a.Projects {
			if queued >= 10 || ctx.Err() != nil {
				return
			}
			if !a.allows(repo) {
				continue
			}
			gh, err := s.github.session(ctx, a, repo)
			if err != nil {
				continue
			}
			pulls, err := gh.openPulls(ctx)
			if err != nil {
				continue
			}
			for _, p := range pulls {
				updated, err := time.Parse(time.RFC3339, p.UpdatedAt)
				age := time.Since(updated)
				if err != nil || p.Draft || p.State != "open" || age < 5*time.Minute || age > 7*24*time.Hour {
					continue
				}
				j := p.job(repo, p.Base.Repo.ID)
				if !validJob(j) || !strings.EqualFold(p.Base.Repo.FullName, repo) {
					continue
				}
				j.Event, j.Delivery = "reconcile.missing_review", "reconcile:"+j.headKey()
				s.mu.Lock()
				current, ok := s.apps[a.ID]
				if ok && current.binding() == a.binding() {
					err = s.enqueue(ctx, a, j, true)
				} else {
					err = errors.New("configuration changed")
				}
				s.mu.Unlock()
				if err == nil {
					queued++
				}
				if queued >= 10 {
					return
				}
			}
		}
	}
}

// Maintain archives completed threads and records usage outside review slots.
// Unknown external writes stay unknown: recovery must not consume more credits.
func (s *Service) Maintain(ctx context.Context) error {
	jobs, err := s.list(ctx, "maintenance", 20)
	if err != nil {
		return err
	}
	count := 0
	for _, j := range jobs {
		if ctx.Err() != nil || count >= 20 {
			break
		}
		if j.Status == "queued" || j.Status == "running" {
			continue
		}
		j.CleanupAt = time.Now().Unix()
		count++
		if err := s.update(ctx, &j); err != nil {
			return err
		}
		s.mu.Lock()
		a, ok := s.apps[j.App]
		s.mu.Unlock()
		if !ok || j.OwnerID != s.owner || hash(a.AmpKey) != j.ExecutionBinding {
			continue
		}
		if j.Status == "unknown" {
			if err := s.recover(ctx, a, &j); err != nil {
				return err
			}
			if j.Status == "unknown" || j.Status == "queued" {
				continue
			}
		}
		for i := range j.Threads {
			t := &j.Threads[i]
			if !t.Archived {
				if err := s.amp.Archive(ctx, a.AmpKey, t.ID); err != nil {
					continue
				}
				t.Archived = true
				if err := s.update(ctx, &j); err != nil {
					return err
				}
			}
			if t.Usage == nil && t.UsageError == "" {
				usage, err := s.amp.Usage(ctx, a.AmpKey, t.ID)
				if err != nil {
					t.UsageError = "Usage unavailable"
				} else {
					t.Usage = usage
				}
				if err := s.update(ctx, &j); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// Cancel is an owner-only browser action; an active execution receives SIGTERM.
// Unknown work can only be resolved after the owner confirms the external state.
func (s *Service) Cancel(ctx context.Context, id string, acknowledge bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, err := s.get(ctx, id)
	if err != nil {
		return err
	}
	if j.Status != "queued" && j.Status != "running" && !(j.Status == "unknown" && acknowledge) {
		return fmt.Errorf("review is %s", j.Status)
	}
	if s.activeID == id && s.activeCancel != nil {
		s.activeCancel()
		return nil
	}
	j.Status, j.Completed, j.Error = "cancelled", time.Now().Unix(), "Cancelled by owner"
	if acknowledge {
		j.Error = "Owner acknowledged external outcome and stopped any old execution"
	}
	err = s.update(ctx, &j)
	if errors.Is(err, store.ErrReviewConflict) {
		return nil
	}
	return err
}
