package gateway

import (
	"crypto/rand"
	_ "embed"
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

type reviewInstallationView struct {
	Index string
	reviews.Installation
	Repositories []reviewRepositoryView
}

type reviewRepositoryView struct {
	Prefix, Index string
	reviews.Repository
}

func (g *Gateway) renderReviews(w http.ResponseWriter, r *http.Request, message string, values *reviews.Integration) {
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
		v := reviewInstallationView{Index: strconv.Itoa(n), Installation: i}
		for k, repo := range i.Repositories {
			v.Repositories = append(v.Repositories, reviewRepositoryView{Prefix: "i." + v.Index, Index: strconv.Itoa(k), Repository: repo})
		}
		installations = append(installations, v)
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
	jobs, err := g.Reviews.History(r.Context())
	if err != nil {
		http.Error(w, "Review history unavailable", 503)
		return
	}
	if message != "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
	}
	g.render(w, r, map[string]any{"Section": "integrations", "ReviewsPage": true, "ReviewApps": config.Integrations, "ReviewApp": selected, "ReviewExisting": existing, "ReviewEditing": editing,
		"ReviewInstallations": installations, "ReviewCredentials": credentials,
		"ReviewInstallationTemplate": reviewInstallationView{Index: "__i__"}, "ReviewRepositoryTemplate": reviewRepositoryView{Prefix: "i.__i__", Index: "__r__"},
		"ReviewJobs": jobs, "ReviewWebhook": strings.TrimRight(g.cfg.BaseURL, "/") + "/webhooks/reviews/" + g.Reviews.Route() + "/", "Error": message, "Saved": r.URL.Query().Get("saved") == "1", "ReviewDemo": g.cfg.Demo})
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
	for _, token := range f["installation"] {
		prefix := "i." + token
		i := reviews.Installation{Owner: f.Get(prefix + ".owner"), ExecutionCredential: f.Get(prefix + ".credential")}
		i.ID, _ = strconv.ParseInt(f.Get(prefix+".id"), 10, 64)
		if len(f[prefix+".repository"]) > 100 {
			http.Error(w, "Too many repositories", 400)
			return
		}
		for _, row := range f[prefix+".repository"] {
			p := prefix + ".r." + row
			repo := reviews.Repository{Name: f.Get(p + ".name"), Project: f.Get(p + ".project"), Enabled: f.Get(p+".enabled") == "on",
				Settings: reviews.Settings{FailOn: f.Get(p + ".fail_on"), Visibility: f.Get(p + ".visibility")}}
			if raw := f.Get(p + ".timeout"); raw != "" {
				var err error
				repo.TimeoutMinutes, err = strconv.Atoi(raw)
				if err != nil || repo.TimeoutMinutes == 0 {
					repo.TimeoutMinutes = -1
				}
			}
			i.Repositories = append(i.Repositories, repo)
		}
		a.Installations = append(a.Installations, i)
	}
	var err error
	if g.cfg.Demo {
		a.Enabled = false
		err = g.Reviews.SaveDraft(r.Context(), a, credentials)
	} else {
		err = g.Reviews.SaveIntegration(r.Context(), a, credentials)
	}
	if err != nil {
		g.renderReviews(w, r, err.Error(), &a)
		return
	}
	http.Redirect(w, r, "/integrations/reviews?saved=1&app="+a.ID, http.StatusSeeOther)
}
