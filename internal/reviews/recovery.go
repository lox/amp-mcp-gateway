package reviews

import (
	"context"
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
func (s *Service) recover(ctx context.Context, a App, j *Job) error {
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
	if check.ID != j.CheckID || check.ExternalID != j.ID || check.HeadSHA != j.HeadSHA || check.App.ID != a.AppID || check.Status != "completed" {
		return nil
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
