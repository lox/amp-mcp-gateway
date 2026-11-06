package reviews

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"ampcode.com/lox/amp-mcp-gateway/internal/store"
)

type pull struct {
	Number    int    `json:"number"`
	State     string `json:"state"`
	Draft     bool   `json:"draft"`
	Title     string `json:"title"`
	Body      string `json:"body"`
	UpdatedAt string `json:"updated_at"`
	Base      struct {
		SHA, Ref string
		Repo     struct {
			ID       int64
			FullName string `json:"full_name"`
		}
	} `json:"base"`
	Head struct{ SHA, Ref string } `json:"head"`
}

func (p pull) job(repo string, id int64) Job {
	return Job{Repository: strings.ToLower(repo), RepositoryID: id, Number: p.Number, BaseSHA: p.Base.SHA, HeadSHA: p.Head.SHA, Context: Context{p.Title, p.Body, p.Base.Ref, p.Head.Ref}}
}

// Webhook authenticates one App, then separately authorizes installation and
// repository before recording anything. A signature alone never grants execution.
func (s *Service) Webhook(w http.ResponseWriter, r *http.Request) {
	if r.PathValue("owner") != s.Route() {
		http.NotFound(w, r)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "invalid webhook body", http.StatusRequestEntityTooLarge)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.apps[r.PathValue("app")]
	mac := hmac.New(sha256.New, []byte(a.WebhookSecret))
	mac.Write(body)
	signature, err := hex.DecodeString(strings.TrimPrefix(r.Header.Get("X-Hub-Signature-256"), "sha256="))
	if !ok || err != nil || !strings.HasPrefix(r.Header.Get("X-Hub-Signature-256"), "sha256=") || !hmac.Equal(signature, mac.Sum(nil)) {
		http.Error(w, "invalid webhook signature", http.StatusUnauthorized)
		return
	}
	delivery := r.Header.Get("X-GitHub-Delivery")
	if delivery == "" || len(delivery) > 200 {
		http.Error(w, "invalid delivery ID", 400)
		return
	}
	var event struct {
		Action       string             `json:"action"`
		Number       int                `json:"number"`
		Installation struct{ ID int64 } `json:"installation"`
		Repository   struct {
			ID       int64
			FullName string `json:"full_name"`
		} `json:"repository"`
		Pull  pull `json:"pull_request"`
		Check struct {
			ID         int64
			ExternalID string `json:"external_id"`
			App        struct{ ID int64 }
		} `json:"check_run"`
	}
	if json.Unmarshal(body, &event) != nil {
		http.Error(w, "invalid webhook JSON", 400)
		return
	}
	if r.Header.Get("X-GitHub-Event") == "ping" {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	if !a.Enabled || event.Installation.ID != a.InstallationID || !a.allows(event.Repository.FullName) || event.Repository.ID <= 0 {
		http.Error(w, "repository or installation not approved", 403)
		return
	}
	switch r.Header.Get("X-GitHub-Event") {
	case "pull_request":
		event.Pull.Number = event.Number
		j := event.Pull.job(event.Repository.FullName, event.Repository.ID)
		if !validJob(j) {
			http.Error(w, "invalid pull request", 400)
			return
		}
		if slices.Contains([]string{"opened", "reopened", "synchronize", "ready_for_review"}, event.Action) && !event.Pull.Draft {
			j.Event, j.Delivery = "pull_request."+event.Action, delivery
			err = s.enqueue(r.Context(), a, j, false)
		}
		// Closed/draft/superseded work is cancelled by the worker's live
		// state check (also while running). Delayed webhooks must not cancel
		// a subsequently reopened PR or a newer head based on arrival order.
	case "check_run":
		if event.Action == "rerequested" && event.Check.App.ID == a.AppID {
			old, getErr := s.get(r.Context(), event.Check.ExternalID)
			if getErr != nil {
				// The TypeScript service used numeric IDs. Prefix imported IDs
				// with this authenticated App, never search another tenant/App.
				if id, e := strconv.ParseInt(event.Check.ExternalID, 10, 64); e == nil && id > 0 {
					old, getErr = s.get(r.Context(), "legacy-"+a.ID+"-"+strconv.FormatInt(id, 10))
				}
			}
			if getErr != nil || old.RepositoryID != event.Repository.ID || old.Repository != strings.ToLower(event.Repository.FullName) {
				http.Error(w, "check is not owned by this integration", 403)
				return
			}
			err = s.rerun(r.Context(), old.ID, delivery, false, event.Check.ID, a.ID)
		}
	}
	if err != nil && !errors.Is(err, store.ErrReviewConflict) {
		http.Error(w, "review could not be accepted; inspect the integration", 409)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}
