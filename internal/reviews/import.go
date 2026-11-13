//go:build reviewimport

package reviews

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"ampcode.com/lox/amp-mcp-gateway/internal/store"
)

// ImportLegacy is an offline cutover tool, excluded from normal gateway builds.
// It reads the existing account identity/configuration and takes the same process
// lock as the gateway. It never starts workers or calls GitHub/Amp.
func ImportLegacy(ctx context.Context, database, key, app string, reader io.Reader) (int, error) {
	if info, err := os.Stat(database); err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
		return 0, errors.New("destination must be an existing gateway account database")
	}
	st, err := store.Open(database, key)
	if err != nil {
		return 0, err
	}
	defer st.Close()
	owner, err := st.LoadToken(ctx, "account-identity")
	if err != nil || len(owner) == 0 {
		return 0, errors.New("destination has no readable account identity")
	}
	raw, err := st.LoadToken(ctx, configKey)
	if err != nil {
		return 0, err
	}
	config, err := readConfiguration(raw)
	if err != nil {
		return 0, errors.New("destination has no valid reviews configuration")
	}
	in, ok := config.Integrations[app]
	if !ok || in.ID != app || in.Enabled {
		return 0, errors.New("configure and pause the destination App before importing")
	}
	if err := st.InitReviews(ctx); err != nil {
		return 0, err
	}
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), 2<<20)
	count, line := 0, 0
	for scanner.Scan() {
		line++
		var entry struct {
			Job struct {
				ID           int64
				Delivery     string `json:"source_delivery_id"`
				Event        string `json:"event_type"`
				Installation int64  `json:"installation_id"`
				RepositoryID int64  `json:"repository_id"`
				Repository   string `json:"repository_full_name"`
				Number       int    `json:"pull_number"`
				BaseSHA      string `json:"base_sha"`
				HeadSHA      string `json:"head_sha"`
				Project      string `json:"amp_project"`
				Title        string `json:"pull_request_title"`
				Body         string `json:"pull_request_body"`
				BaseRef      string `json:"base_ref"`
				HeadRef      string `json:"head_ref"`
				CheckID      int64  `json:"check_run_id"`
				Status       string
				Attempts     int
				Created      time.Time `json:"created_at"`
				Completed    time.Time `json:"completed_at"`
			}
			Threads []struct {
				ID         string     `json:"thread_id"`
				Archived   *time.Time `json:"archived_at"`
				Cost       *float64   `json:"amp_usage_usd"`
				Estimate   *float64   `json:"estimated_provider_cost_at_list_price_usd"`
				UsageError string     `json:"usage_error"`
				Usage      struct {
					InputTokens, OutputTokens, Requests int64
					SubscriptionUsed                    bool
				} `json:"usage_details"`
			}
			Result *struct {
				Conclusion string
				FailOn     string `json:"fail_on"`
				Prompt     string `json:"prompt_identifier"`
				Summary    string
				Findings   []Finding
				Omitted    int `json:"omitted_findings"`
			}
		}
		if json.Unmarshal(scanner.Bytes(), &entry) != nil {
			return count, fmt.Errorf("invalid JSON at import line %d", line)
		}
		old := entry.Job
		old.Repository = strings.ToLower(old.Repository)
		a, approved := config.resolve(app, old.Installation, old.Repository)
		if !approved || a.RepositoryID != old.RepositoryID || a.RepositoryID <= 0 {
			return count, fmt.Errorf("line %d is outside the verified repository configuration", line)
		}
		j := Job{ID: "legacy-" + a.ID + "-" + strconv.FormatInt(old.ID, 10), App: a.ID, OwnerID: string(owner), Binding: a.binding(), ExecutionBinding: hash(a.AmpKey), InstallationID: old.Installation, RepositoryID: old.RepositoryID, Repository: old.Repository, Number: old.Number, BaseSHA: old.BaseSHA, HeadSHA: old.HeadSHA, Project: old.Project, Context: Context{old.Title, old.Body, old.BaseRef, old.HeadRef}, Event: old.Event, Delivery: old.Delivery, Status: old.Status, Phase: "imported", CheckID: old.CheckID, Attempts: old.Attempts, Created: old.Created.UnixNano(), Completed: old.Completed.Unix(), Revision: 1, FailOn: a.FailOn, Visibility: a.Visibility, TimeoutMinutes: a.TimeoutMinutes, PromptVersion: "legacy"}
		j.ExecutionCredential = a.ExecutionCredential
		if old.ID <= 0 || old.Installation != a.InstallationID || !a.allows(old.Repository) || !shaPattern.MatchString(old.BaseSHA) || !shaPattern.MatchString(old.HeadSHA) || old.Number <= 0 || old.RepositoryID <= 0 || old.Created.IsZero() || (old.Status != "succeeded" && old.Status != "failed" && old.Status != "cancelled") {
			return count, fmt.Errorf("line %d is active, invalid or outside the approved installation/repositories; drain the source first", line)
		}
		for _, thread := range entry.Threads {
			if !threadPattern.MatchString(thread.ID) {
				return count, fmt.Errorf("invalid thread at line %d", line)
			}
			t := Thread{ID: thread.ID, Archived: thread.Archived != nil}
			if thread.Cost != nil {
				t.Usage = &Usage{CostUSD: *thread.Cost, ProviderEstimateUSD: thread.Estimate, InputTokens: thread.Usage.InputTokens, OutputTokens: thread.Usage.OutputTokens, Requests: thread.Usage.Requests, SubscriptionUsed: thread.Usage.SubscriptionUsed}
			} else if thread.UsageError != "" {
				t.UsageError = "Legacy usage unavailable"
			}
			j.Threads = append(j.Threads, t)
		}
		if entry.Result != nil {
			r := entry.Result
			raw, _ := json.Marshal(Result{Summary: r.Summary, Findings: r.Findings})
			result, err := ParseResult(string(raw))
			if err != nil || severityRank(r.FailOn) < 0 || (r.Conclusion != "success" && r.Conclusion != "neutral" && r.Conclusion != "failure") {
				return count, fmt.Errorf("invalid result at line %d", line)
			}
			j.Result, j.Conclusion, j.FailOn, j.PromptVersion, j.Omitted = &result, r.Conclusion, r.FailOn, r.Prompt, r.Omitted
		}
		err := st.InsertReview(ctx, j.record(), false)
		if errors.Is(err, store.ErrReviewConflict) {
			continue
		}
		if err != nil {
			return count, fmt.Errorf("could not persist import line %d", line)
		}
		count++
	}
	if scanner.Err() != nil {
		return count, errors.New("import could not be read or a record exceeds 2 MiB")
	}
	return count, nil
}
