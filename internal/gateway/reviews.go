package gateway

import (
	"crypto/rand"
	_ "embed"
	"encoding/json"
	"fmt"
	"html/template"
	"math"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"ampcode.com/lox/amp-mcp-gateway/internal/reviews"
)

//go:embed reviews.html
var reviewsHTML string

var reviewStatuses = []string{"queued", "running", "succeeded", "failed", "cancelled", "unknown"}

var reviewTemplateFuncs = template.FuncMap{
	"severities":  func() []string { return []string{"critical", "high", "medium", "low"} },
	"reviewTime":  func(nanos int64) string { return time.Unix(0, nanos).UTC().Format(time.RFC3339) },
	"reviewDate":  func(nanos int64) string { return time.Unix(0, nanos).UTC().Format("02 Jan · 15:04 UTC") },
	"reviewStats": reviewStats,
	"reviewUsage": reviewUsage,
	"reviewEstimate": func(cost *float64) string {
		if cost == nil {
			return "not reported"
		}
		return fmt.Sprintf("$%.4f", *cost)
	},
}

// Summaries describe the review outcome separately from successful execution.
// Costs include every attempt; missing usage must never look like a free review.
func reviewStats(j reviews.Job) any {
	v := struct {
		Outcome, Class, Elapsed, Queued, Credits, Estimate string
		Findings                                           []struct {
			Severity string
			Count    int
		}
	}{Outcome: j.Status, Class: j.Status, Elapsed: "—", Credits: "—", Estimate: "—"}
	if j.Status == "succeeded" {
		v.Outcome = "Completed"
		switch j.Conclusion {
		case "success":
			v.Outcome = "Passed"
		case "failure":
			v.Outcome, v.Class = "Blocking issues", "failed"
		case "neutral":
			v.Outcome, v.Class = "Advisory issues", "neutral"
		}
	} else if j.Status == "failed" {
		v.Outcome = "Review failed"
	}
	end := time.Unix(j.Completed, 0)
	if j.Status == "running" || j.Status == "queued" {
		end = time.Now()
	}
	if j.Created > 0 && (j.Completed > 0 || j.Status == "running" || j.Status == "queued") {
		elapsed := end.Sub(time.Unix(0, j.Created))
		if elapsed >= 0 {
			v.Elapsed = elapsed.Round(time.Second).String()
		}
		// Reviews recorded before Started existed show no split. The worker
		// polls every second, so a few seconds is pickup, not a wait.
		queuedUntil := time.Unix(0, j.Started)
		if j.Started == 0 && j.Status == "queued" {
			queuedUntil = end
		}
		if queued := queuedUntil.Sub(time.Unix(0, j.Created)).Round(time.Second); (j.Started > 0 || j.Status == "queued") && queued >= 5*time.Second && queued <= elapsed {
			v.Queued = queued.String()
		}
	}
	if j.Result != nil {
		for _, severity := range []string{"critical", "high", "medium", "low"} {
			count := 0
			for _, f := range j.Result.Findings {
				if f.Severity == severity {
					count++
				}
			}
			if count > 0 {
				v.Findings = append(v.Findings, struct {
					Severity string
					Count    int
				}{severity, count})
			}
		}
	}
	credits, estimate, known, estimates := 0.0, 0.0, 0, 0
	pending := j.Status == "queued" || j.Status == "running"
	for _, t := range j.Threads {
		if t.Usage == nil {
			pending = pending || t.UsageError == ""
			continue
		}
		known++
		credits += t.Usage.CostUSD
		if t.Usage.ProviderEstimateUSD != nil {
			estimates++
			estimate += *t.Usage.ProviderEstimateUSD
		}
	}
	if len(j.Threads) > 0 || pending {
		v.Credits, v.Estimate = "Unavailable", "Not reported"
		if pending {
			v.Credits, v.Estimate = "Pending", "Pending"
		}
		if known > 0 {
			v.Credits = fmt.Sprintf("$%.4f", credits)
			if pending || known < len(j.Threads) {
				v.Credits += " (partial)"
			}
		}
		if estimates > 0 {
			v.Estimate = fmt.Sprintf("$%.4f", estimate)
			if pending || estimates < len(j.Threads) {
				v.Estimate += " (partial)"
			}
		}
	}
	return v
}

func usageCost(value float64, known, threads int) string {
	if known == 0 {
		return "—"
	}
	text := fmt.Sprintf("$%.4f", value)
	if known < threads {
		text += " (partial)"
	}
	return text
}

func reviewUsage(days []reviews.DailyUsage) any {
	type day struct {
		Date, Credits, Estimate                   string
		Count, X, EstimateX                       int
		CreditHeight, EstimateHeight, CountHeight float64
		Partial                                   bool
	}
	v := struct {
		Days                                       []day
		Count, Threads, Known, Estimates, MaxCount int
		Credits, Estimate, From, To, MaxCost       string
	}{MaxCount: 1}
	credits, estimate, maxCost := 0.0, 0.0, 0.0
	for _, d := range days {
		v.Count += d.Reviews
		v.Threads += d.Threads
		v.Known += d.Known
		v.Estimates += d.Estimates
		credits += d.Credits
		estimate += d.ProviderEstimate
		maxCost = max(maxCost, d.Credits, d.ProviderEstimate)
		v.MaxCount = max(v.MaxCount, d.Reviews)
	}
	// Both cost series use the same zero-based USD scale.
	maxCost = max(.01, math.Ceil(maxCost*100)/100)
	v.MaxCost = fmt.Sprintf("$%.2f", maxCost)
	v.Credits = usageCost(credits, v.Known, v.Threads)
	v.Estimate = usageCost(estimate, v.Estimates, v.Threads)
	for i, d := range days {
		v.Days = append(v.Days, day{
			Date: d.Date.Format("02 Jan"), Credits: usageCost(d.Credits, d.Known, d.Threads), Estimate: usageCost(d.ProviderEstimate, d.Estimates, d.Threads),
			Count: d.Reviews, X: 48 + i*18, EstimateX: 56 + i*18,
			CreditHeight: 100 * d.Credits / maxCost, EstimateHeight: 100 * d.ProviderEstimate / maxCost, CountHeight: 100 * float64(d.Reviews) / float64(v.MaxCount),
			Partial: i == len(days)-1,
		})
	}
	if len(days) > 0 {
		v.From, v.To = days[0].Date.Format("02 Jan 2006"), days[len(days)-1].Date.Format("02 Jan 2006")
	}
	return v
}

func (g *Gateway) registerReviews(mux *http.ServeMux) {
	mux.HandleFunc("GET /integrations/reviews", g.reviewsPage)
	mux.HandleFunc("POST /integrations/reviews", g.saveReviews)
	mux.HandleFunc("GET /integrations/reviews/{id}/repositories", g.reviewInstallationRepositories)
	mux.HandleFunc("POST /integrations/reviews/{id}/{action}", func(w http.ResponseWriter, r *http.Request) {
		if g.Reviews == nil {
			http.Error(w, "Reviews unavailable", 503)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		if r.ParseForm() != nil {
			http.Error(w, "Invalid form", 400)
			return
		}
		var err error
		message := "Review action unavailable. Check its status, approved repository and frozen context; unknown outcomes require acknowledgement."
		switch r.PathValue("action") {
		case "cancel":
			err = g.Reviews.Cancel(r.Context(), r.PathValue("id"), r.PostForm.Get("acknowledge") == "on")
		case "close-check":
			err = g.Reviews.CloseCheck(r.Context(), r.PathValue("id"))
			message = "Could not close the GitHub check. It may already be closed or the repository is no longer approved; refresh to see its state."
		case "rerun":
			err = g.Reviews.Rerun(r.Context(), r.PathValue("id"), "browser:"+rand.Text(), r.PostForm.Get("acknowledge") == "on")
		default:
			http.NotFound(w, r)
			return
		}
		if err != nil {
			g.renderReviews(w, r, message, nil, nil)
			return
		}
		http.Redirect(w, r, "/integrations/reviews", http.StatusSeeOther)
	})
}

// reviewInstallationRepositories feeds the "Add from GitHub" picker. It only
// lists names; adding a row still needs an explicit save that verifies it.
func (g *Gateway) reviewInstallationRepositories(w http.ResponseWriter, r *http.Request) {
	if g.Reviews == nil {
		http.Error(w, "Reviews unavailable", 503)
		return
	}
	id := r.PathValue("id")
	var names []string
	var err error
	if g.cfg.Demo {
		// The demo never calls GitHub: offer fixed fake names per installation.
		in, ok := g.Reviews.Configuration().Integrations[id]
		if !ok {
			http.NotFound(w, r)
			return
		}
		for _, i := range in.Installations {
			for _, repo := range i.Repositories {
				names = append(names, repo.Name)
			}
			for _, name := range []string{"fly-mcp", "gh-review-bot", "pinned-models", "website"} {
				names = append(names, i.Owner+"/"+name)
			}
		}
		slices.Sort(names)
		names = slices.Compact(names)
	} else {
		names, err = g.Reviews.InstallationRepositories(r.Context(), id)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string][]string{"repositories": names})
}

func (g *Gateway) reviewsPage(w http.ResponseWriter, r *http.Request) {
	g.renderReviews(w, r, "", nil, nil)
}

type reviewInstallationView struct {
	Index string
	reviews.Installation
}

type reviewRepositoryView struct {
	Index string
	reviews.Repository
}

// Overrides summarises a row's non-default settings for its compact chip.
func (r reviewRepositoryView) Overrides() string {
	var parts []string
	if r.FailOn != "" {
		parts = append(parts, "fail on "+r.FailOn)
	}
	if r.Visibility != "" {
		parts = append(parts, r.Visibility)
	}
	if r.TimeoutMinutes != 0 {
		parts = append(parts, strconv.Itoa(r.TimeoutMinutes)+" min")
	}
	if len(parts) == 0 {
		return "Defaults"
	}
	return strings.Join(parts, " · ")
}

// renderReviews shows one repository list across installations. A rejected
// form passes its submitted rows, including any that matched no installation.
func (g *Gateway) renderReviews(w http.ResponseWriter, r *http.Request, message string, values *reviews.Integration, rows []reviews.Repository) {
	if g.Reviews == nil {
		http.Error(w, "Reviews unavailable", 503)
		return
	}
	config := g.Reviews.Configuration()
	selected := reviews.Integration{Settings: reviews.Settings{FailOn: "high", Visibility: "private", TimeoutMinutes: 30}}
	if a, ok := config.Integrations[r.URL.Query().Get("app")]; ok {
		selected = a
	}
	if values != nil {
		selected = *values
		selected.PrivateKey, selected.WebhookSecret = "", ""
	}
	_, existing := config.Integrations[selected.ID]
	editing := existing || values != nil || r.URL.Query().Get("new") == "1"
	var installations []reviewInstallationView
	for n, i := range selected.Installations {
		installations = append(installations, reviewInstallationView{Index: strconv.Itoa(n), Installation: i})
		if values == nil {
			rows = append(rows, i.Repositories...)
		}
	}
	if values == nil {
		slices.SortFunc(rows, func(a, b reviews.Repository) int { return strings.Compare(a.Name, b.Name) })
	}
	var repositories []reviewRepositoryView
	enabled := 0
	for n, repo := range rows {
		repositories = append(repositories, reviewRepositoryView{Index: strconv.Itoa(n), Repository: repo})
		if repo.Enabled {
			enabled++
		}
	}
	credentials := map[string]bool{}
	for id := range config.Credentials {
		credentials[id] = true
	}
	if values != nil {
		for _, id := range r.PostForm["credential_name"] {
			if _, exists := credentials[id]; !exists {
				credentials[id] = false
			}
		}
	}
	// Filter options come from configuration; unknown values are ignored.
	var filterRepositories []string
	for _, in := range config.Integrations {
		for _, i := range in.Installations {
			for _, repo := range i.Repositories {
				if name := strings.ToLower(repo.Name); !slices.Contains(filterRepositories, name) {
					filterRepositories = append(filterRepositories, name)
				}
			}
		}
	}
	slices.Sort(filterRepositories)
	query := r.URL.Query()
	var filter reviews.HistoryFilter
	if repo := strings.ToLower(query.Get("repo")); slices.Contains(filterRepositories, repo) {
		filter.Repository = repo
	}
	if n, err := strconv.Atoi(strings.TrimPrefix(strings.TrimSpace(query.Get("pr")), "#")); err == nil && n > 0 {
		filter.Number = n
	}
	if status := query.Get("status"); slices.Contains(reviewStatuses, status) {
		filter.Status = status
	}
	jobs, err := g.Reviews.History(r.Context(), filter)
	// Refresh keeps the accepted filters; Clear is the explicit reset.
	refresh := url.Values{}
	for key, value := range map[string]string{"repo": filter.Repository, "status": filter.Status} {
		if value != "" {
			refresh.Set(key, value)
		}
	}
	if filter.Number > 0 {
		refresh.Set("pr", strconv.Itoa(filter.Number))
	}
	refreshURL := "/integrations/reviews"
	if len(refresh) > 0 {
		refreshURL += "?" + refresh.Encode()
	}
	if err != nil {
		http.Error(w, "Review history unavailable", 503)
		return
	}
	var usage []reviews.DailyUsage
	if !editing {
		usage, err = g.Reviews.UsageSummary(r.Context(), time.Now())
		if err != nil {
			http.Error(w, "Review usage unavailable", 503)
			return
		}
	}
	if message != "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
	}
	g.render(w, r, map[string]any{"Section": "integrations", "ReviewsPage": true, "ReviewApps": config.Integrations, "ReviewApp": selected, "ReviewExisting": existing, "ReviewEditing": editing,
		"ReviewInstallations": installations, "ReviewRepositories": repositories, "ReviewEnabledRepositories": enabled, "ReviewCredentials": credentials,
		"ReviewInstallationTemplate": reviewInstallationView{Index: "__i__"}, "ReviewRepositoryTemplate": reviewRepositoryView{Index: "__r__", Repository: reviews.Repository{Name: "__name__"}},
		"ReviewJobs": jobs, "ReviewFilter": filter, "ReviewRefresh": template.URL(refreshURL), "ReviewFilterRepositories": filterRepositories, "ReviewStatuses": reviewStatuses, "ReviewUsage": usage, "ReviewWebhook": strings.TrimRight(g.cfg.BaseURL, "/") + "/webhooks/reviews/" + g.Reviews.Route() + "/", "Error": message, "Saved": r.URL.Query().Get("saved") == "1", "ReviewDemo": g.cfg.Demo})
}

func (g *Gateway) saveReviews(w http.ResponseWriter, r *http.Request) {
	if g.Reviews == nil {
		http.Error(w, "Reviews unavailable", 503)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 128<<10)
	if r.ParseForm() != nil {
		http.Error(w, "Invalid form", 400)
		return
	}
	f := r.PostForm
	a := reviews.Integration{ID: strings.TrimSpace(f.Get("id")), PrivateKey: f.Get("private_key"), WebhookSecret: f.Get("webhook_secret"), Enabled: f.Get("enabled") == "on", Settings: reviews.Settings{FailOn: f.Get("fail_on"), Visibility: f.Get("visibility")}}
	a.AppID, _ = strconv.ParseInt(f.Get("app_id"), 10, 64)
	a.TimeoutMinutes, _ = strconv.Atoi(f.Get("timeout"))
	if len(f["installation"]) > 20 || len(f["credential_name"]) > 20 || len(f["credential_name"]) != len(f["credential_key"]) {
		http.Error(w, "Invalid configuration size", 400)
		return
	}
	credentials := map[string]string{}
	for n, id := range f["credential_name"] {
		if _, duplicate := credentials[id]; duplicate {
			http.Error(w, "Duplicate credential name", 400)
			return
		}
		credentials[id] = f["credential_key"][n]
	}
	installations := map[string]int{}
	for _, token := range f["installation"] {
		prefix := "i." + token
		i := reviews.Installation{Owner: f.Get(prefix + ".owner"), ExecutionCredential: f.Get(prefix + ".credential")}
		i.ID, _ = strconv.ParseInt(f.Get(prefix+".id"), 10, 64)
		installations[strings.ToLower(strings.TrimSpace(i.Owner))] = len(a.Installations)
		a.Installations = append(a.Installations, i)
	}
	if len(f["repository"]) > 20*100 {
		http.Error(w, "Too many repositories", 400)
		return
	}
	var rows []reviews.Repository
	for _, row := range f["repository"] {
		p := "r." + row
		repo := reviews.Repository{Name: f.Get(p + ".name"), Project: f.Get(p + ".project"), Enabled: f.Get(p+".enabled") == "on",
			Settings: reviews.Settings{FailOn: f.Get(p + ".fail_on"), Visibility: f.Get(p + ".visibility")}}
		if raw := f.Get(p + ".timeout"); raw != "" {
			var err error
			repo.TimeoutMinutes, err = strconv.Atoi(raw)
			if err != nil || repo.TimeoutMinutes == 0 {
				repo.TimeoutMinutes = -1
			}
		}
		rows = append(rows, repo)
	}
	// The owner/ prefix assigns each row to its installation. Owners must be
	// distinct so the assignment is unambiguous; unmatched rows are never dropped.
	if len(installations) != len(a.Installations) {
		g.renderReviews(w, r, "each installation needs a distinct GitHub owner", &a, rows)
		return
	}
	for _, repo := range rows {
		owner, _, _ := strings.Cut(strings.ToLower(strings.TrimSpace(repo.Name)), "/")
		n, ok := installations[owner]
		if !ok {
			g.renderReviews(w, r, fmt.Sprintf("no installation for GitHub owner %q (repository %s); add the installation or remove the repository", owner, repo.Name), &a, rows)
			return
		}
		a.Installations[n].Repositories = append(a.Installations[n].Repositories, repo)
	}
	var err error
	if g.cfg.Demo {
		a.Enabled = false
		err = g.Reviews.SaveDraft(r.Context(), a, credentials)
	} else {
		err = g.Reviews.SaveIntegration(r.Context(), a, credentials)
	}
	if err != nil {
		g.renderReviews(w, r, err.Error(), &a, rows)
		return
	}
	http.Redirect(w, r, "/integrations/reviews?saved=1&app="+a.ID, http.StatusSeeOther)
}
