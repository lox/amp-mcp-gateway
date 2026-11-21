package reviews

import (
	"context"
	"errors"
	"fmt"
	"time"
)

type checkRun struct {
	ID                 int64
	ExternalID         string `json:"external_id"`
	HeadSHA            string `json:"head_sha"`
	Status, Conclusion string
	App                struct{ ID int64 }
}

// Recovery reads external state; it never blindly replays a check creation,
// annotation append or Amp launch. Only pre-dispatch checkpoints requeue.
func (s *Service) recover(ctx context.Context, a App, key string, j *Job) error {
	s.mu.Lock()
	_, authorized := s.authorized(*j)
	s.mu.Unlock()
	if !authorized {
		return nil
	}
	if j.Phase == "preflight" {
		j.Status = "queued"
		if j.Attempts >= 3 {
			j.Status, j.Error, j.Completed = "failed", "Restart recovery attempts exhausted", time.Now().Unix()
		}
		return s.update(ctx, j)
	}
	gh, err := s.github.session(ctx, a, j.Repository)
	if err != nil {
		return nil
	}
	if j.CheckID == 0 && j.Phase == "creating_check" {
		for page := 1; page <= 10; page++ {
			var response struct {
				Checks []checkRun `json:"check_runs"`
			}
			if gh.request(ctx, "GET", fmt.Sprintf("/commits/%s/check-runs?filter=all&per_page=100&page=%d", j.HeadSHA, page), nil, &response) != nil {
				return nil
			}
			for _, check := range response.Checks {
				if check.ExternalID == j.ID && check.App.ID == a.AppID && check.HeadSHA == j.HeadSHA {
					j.CheckID = check.ID
					break
				}
			}
			if j.CheckID != 0 || len(response.Checks) < 100 {
				break
			}
		}
		if j.CheckID != 0 { // No Amp dispatch occurred before this checkpoint.
			j.Status = "queued"
			if j.Attempts >= 3 {
				j.Status = "unknown"
			}
			return s.update(ctx, j)
		}
	}
	if j.CheckID == 0 {
		return nil
	}
	var check checkRun
	if gh.request(ctx, "GET", fmt.Sprintf("/check-runs/%d", j.CheckID), nil, &check) != nil {
		return nil
	}
	if check.ID != j.CheckID || check.ExternalID != j.ID || check.HeadSHA != j.HeadSHA || check.App.ID != a.AppID {
		return nil
	}
	if check.Status != "completed" {
		// A PR merged or closed mid-review leaves an ambiguous execution
		// that would otherwise pause the account. Once the PR can no longer
		// use this review and Amp shows every thread stopped, nothing can
		// still spend credits or publish; close the check as cancelled.
		if j.Phase != "starting_thread" && j.Phase != "reviewing" || len(j.Threads) == 0 {
			return nil
		}
		if current, err := gh.current(ctx, *j); err != nil || current {
			return nil
		}
		for _, t := range j.Threads {
			if stopped, err := s.amp.Stopped(ctx, key, t.ID); err != nil || !stopped {
				return nil
			}
		}
		// Checkpoint first: a lost close is confirmed below on a later pass
		// rather than resent.
		j.Phase = "finishing"
		if err := s.update(ctx, j); err != nil {
			return err
		}
		message := "PR closed, draft or superseded during review; Amp thread confirmed stopped."
		closing := *j
		closing.Result = nil
		if err := gh.finish(ctx, closing, "cancelled", message); err != nil && !errors.Is(err, errGitHubRejected) {
			return nil
		}
		j.Status, j.Error, j.Completed = "cancelled", message, time.Now().Unix()
		return s.update(ctx, j)
	}
	if (j.Phase == "publishing" || j.Phase == "completed") && j.Result != nil && check.Conclusion == j.Conclusion {
		j.Status, j.Phase, j.Error, j.Completed = "succeeded", "completed", "", time.Now().Unix()
		return s.update(ctx, j)
	}
	if j.Phase == "finishing" && (check.Conclusion == "failure" || check.Conclusion == "cancelled") {
		j.Status = "failed"
		if check.Conclusion == "cancelled" {
			j.Status = "cancelled"
		}
		j.Completed = time.Now().Unix()
		return s.update(ctx, j)
	}
	return nil
}
