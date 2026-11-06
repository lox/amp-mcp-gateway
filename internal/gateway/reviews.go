package gateway

import (
	"crypto/rand"
	_ "embed"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"

	"ampcode.com/lox/amp-mcp-gateway/internal/reviews"
)

//go:embed reviews.html
var reviewsHTML string

var reviewTemplateFuncs = template.FuncMap{
	"severities": func() []string { return []string{"critical", "high", "medium", "low"} },
	"reviewTime": func(nanos int64) string { return time.Unix(0, nanos).UTC().Format(time.RFC3339) },
	"reviewEstimate": func(cost *float64) string {
		if cost == nil {
			return "not reported"
		}
		return fmt.Sprintf("$%.4f", *cost)
	},
}

func (g *Gateway) registerReviews(mux *http.ServeMux) {
	mux.HandleFunc("GET /integrations/reviews", g.reviewsPage)
	mux.HandleFunc("POST /integrations/reviews", g.saveReviews)
	mux.HandleFunc("POST /integrations/reviews/import", g.importReviews)
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
		switch r.PathValue("action") {
		case "cancel":
			err = g.Reviews.Cancel(r.Context(), r.PathValue("id"), r.PostForm.Get("acknowledge") == "on")
		case "rerun":
			err = g.Reviews.Rerun(r.Context(), r.PathValue("id"), "browser:"+rand.Text(), r.PostForm.Get("acknowledge") == "on")
		default:
			http.NotFound(w, r)
			return
		}
		if err != nil {
			g.renderReviews(w, r, "Review action unavailable. Check its status, approved repository and frozen context; unknown outcomes require acknowledgement.", nil)
			return
		}
		http.Redirect(w, r, "/integrations/reviews", http.StatusSeeOther)
	})
}

func (g *Gateway) reviewsPage(w http.ResponseWriter, r *http.Request) { g.renderReviews(w, r, "", nil) }

func (g *Gateway) importReviews(w http.ResponseWriter, r *http.Request) {
	if g.Reviews == nil {
		http.Error(w, "Reviews unavailable", 503)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32<<20)
	if r.ParseMultipartForm(1<<20) != nil {
		http.Error(w, "Invalid import (maximum 32 MiB)", 400)
		return
	}
	defer r.MultipartForm.RemoveAll()
	if r.PostForm.Get("confirmed") != "on" {
		http.Error(w, "Confirm the source is drained and execution identity matches", 400)
		return
	}
	file, _, err := r.FormFile("export")
	if err != nil {
		http.Error(w, "Choose a JSONL export", 400)
		return
	}
	defer file.Close()
	count, err := g.Reviews.ImportLegacy(r.Context(), r.PostForm.Get("app"), file)
	if err != nil {
		g.renderReviews(w, r, fmt.Sprintf("Imported %d records before stopping: %s. Re-import is safe.", count, err), nil)
		return
	}
	http.Redirect(w, r, "/integrations/reviews?imported="+strconv.Itoa(count), http.StatusSeeOther)
}

func (g *Gateway) renderReviews(w http.ResponseWriter, r *http.Request, message string, values *reviews.App) {
	if g.Reviews == nil {
		http.Error(w, "Reviews unavailable", 503)
		return
	}
	apps := g.Reviews.Apps()
	selected := reviews.App{FailOn: "high", Visibility: "private", TimeoutMinutes: 30, Projects: map[string]string{}}
	for _, a := range apps {
		if a.ID == r.URL.Query().Get("app") {
			selected = a
		}
	}
	if values != nil {
		selected = *values
		selected.PrivateKey, selected.WebhookSecret, selected.AmpKey = "", "", ""
	}
	existing := false
	for _, a := range apps {
		existing = existing || a.ID == selected.ID
	}
	imported, _ := strconv.Atoi(r.URL.Query().Get("imported"))
	projects, _ := json.MarshalIndent(selected.Projects, "", "  ")
	jobs, err := g.Reviews.History(r.Context())
	if err != nil {
		http.Error(w, "Review history unavailable", 503)
		return
	}
	if message != "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
	}
	g.render(w, r, map[string]any{"Section": "integrations", "ReviewsPage": true, "ReviewApps": apps, "ReviewApp": selected, "ReviewExisting": existing, "ReviewImported": imported, "ReviewProjects": string(projects), "ReviewRepositories": strings.Join(selected.Repositories, "\n"), "ReviewJobs": jobs, "ReviewWebhook": strings.TrimRight(g.cfg.BaseURL, "/") + "/webhooks/reviews/" + g.Reviews.Route() + "/", "Error": message, "Saved": r.URL.Query().Get("saved") == "1", "ReviewDemo": g.cfg.Demo})
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
	a := reviews.App{ID: strings.TrimSpace(f.Get("id")), Owner: f.Get("owner"), PrivateKey: f.Get("private_key"), WebhookSecret: f.Get("webhook_secret"), AmpKey: f.Get("amp_key"), Repositories: strings.Fields(f.Get("repositories")), OwnerApproved: f.Get("owner_approved") == "on", Enabled: f.Get("enabled") == "on", FailOn: f.Get("fail_on"), Visibility: f.Get("visibility")}
	a.AppID, _ = strconv.ParseInt(f.Get("app_id"), 10, 64)
	a.InstallationID, _ = strconv.ParseInt(f.Get("installation_id"), 10, 64)
	a.TimeoutMinutes, _ = strconv.Atoi(f.Get("timeout"))
	if json.Unmarshal([]byte(f.Get("projects")), &a.Projects) != nil {
		g.renderReviews(w, r, "Project mappings must be a JSON object of repository to Amp namespace/project.", &a)
		return
	}
	if g.cfg.Demo {
		a.Enabled = false
	}
	if err := g.Reviews.Save(r.Context(), a); err != nil {
		g.renderReviews(w, r, err.Error(), &a)
		return
	}
	http.Redirect(w, r, "/integrations/reviews?saved=1&app="+a.ID, http.StatusSeeOther)
}
