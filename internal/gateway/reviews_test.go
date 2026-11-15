package gateway

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"ampcode.com/lox/amp-mcp-gateway/internal/reviews"
	"ampcode.com/lox/amp-mcp-gateway/internal/upstream"
	"golang.org/x/sync/semaphore"
)

func TestReviewsBrowserAuthorizationAndSecretRetention(t *testing.T) {
	g, st, _ := fixture(t)
	var err error
	g.Reviews, err = reviews.New(t.Context(), g.cfg.AmpUserID, st, reviews.CLI{Binary: "/nonexistent"}, &reviews.GitHub{}, semaphore.NewWeighted(4))
	if err != nil {
		t.Fatal(err)
	}
	m, err := upstream.New(g.cfg.BaseURL, g.cfg.Connections, st)
	if err != nil {
		t.Fatal(err)
	}
	h, cookie := adminUI(t, g, m)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	private := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	values := url.Values{"id": {"lox"}, "app_id": {"1"}, "private_key": {private}, "webhook_secret": {"short"}, "credential_name": {"reviews-bot"}, "credential_key": {"fake-execution-key"}, "fail_on": {"high"}, "visibility": {"private"}, "timeout": {"30"}, "enabled": {"on"},
		"installation": {"0", "1"}, "i.0.owner": {"lox"}, "i.0.id": {"11"}, "i.0.credential": {"reviews-bot"}, "i.0.repository": {"0"}, "i.0.r.0.name": {"lox/repo"}, "i.0.r.0.project": {"lox/repo"}, "i.0.r.0.enabled": {"on"},
		"i.1.owner": {"sporevm"}, "i.1.id": {"22"}, "i.1.credential": {"reviews-bot"}, "i.1.repository": {"0"}, "i.1.r.0.name": {"sporevm/repo"}, "i.1.r.0.project": {"sporevm/repo"}}
	for _, path := range []string{"/integrations/reviews", "/integrations/reviews/unknown/rerun", "/integrations/reviews/unknown/cancel"} {
		if w := formRequest(h, nil, "POST", path, values); w.Code != http.StatusSeeOther {
			t.Fatalf("anonymous %s: %d", path, w.Code)
		}
		r := httptest.NewRequest("POST", path, strings.NewReader(values.Encode()))
		r.AddCookie(cookie)
		r.Header.Set("Origin", "https://attacker.example")
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Fatalf("CSRF %s: %d", path, w.Code)
		}
	}
	// An invalid new integration must remain editable and must not echo secrets.
	w := formRequest(h, cookie, "POST", "/integrations/reviews", values)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), `name="private_key"`) || strings.Contains(w.Body.String(), `name="id" value="lox" required pattern="[A-Za-z0-9][A-Za-z0-9_.-]{0,99}" readonly`) || strings.Contains(w.Body.String(), private) || strings.Contains(w.Body.String(), "fake-execution-key") {
		t.Fatal("invalid form leaked secrets or locked identity")
	}
	values.Set("webhook_secret", "long-enough-fake-hook-secret")
	values.Set("i.0.r.0.project", "invalid-project")
	w = formRequest(h, cookie, "POST", "/integrations/reviews", values)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), `value="invalid-project"`) {
		t.Fatal("invalid project mappings were lost instead of remaining editable")
	}
	values.Set("i.0.r.0.project", "lox/repo")
	values.Set("webhook_secret", "long-enough-fake-hook-secret")
	w = formRequest(h, cookie, "POST", "/integrations/reviews", values)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("save: %d %s", w.Code, w.Body.String())
	}
	if config := g.Reviews.Configuration(); len(config.Integrations) != 1 || config.Integrations["lox"].Enabled || len(config.Integrations["lox"].Installations) != 2 || len(config.Credentials) != 1 {
		t.Fatal("demo allowed execution")
	}
	values.Set("private_key", "")
	values.Set("webhook_secret", "")
	values.Set("credential_key", "")
	values.Set("fail_on", "critical")
	if w := formRequest(h, cookie, "POST", "/integrations/reviews", values); w.Code != http.StatusSeeOther {
		t.Fatal("blank secret fields did not retain credentials")
	}
	w = formRequest(h, cookie, "GET", "/integrations/reviews?app=lox", nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Configure lox") || strings.Contains(w.Body.String(), "Import amp-reviewbot history") || strings.Contains(w.Body.String(), "fake-execution-key") || strings.Contains(w.Body.String(), private) {
		t.Fatal("configured page lost state or leaked credentials")
	}
	if w := formRequest(h, cookie, "POST", "/integrations/reviews/import", nil); w.Code != http.StatusNotFound && w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("history import is still exposed over HTTP: %d", w.Code)
	}
	for _, tc := range []struct {
		path    string
		editing bool
	}{
		{"/integrations/reviews", false},
		{"/integrations/reviews?new=1", true},
		{"/integrations/reviews?app=lox", true},
	} {
		w := formRequest(h, cookie, "GET", tc.path, nil)
		body := w.Body.String()
		if w.Code != http.StatusOK || strings.Contains(body, `name="private_key"`) != tc.editing || strings.Contains(body, "Review history</h2>") == tc.editing {
			t.Fatalf("overview and setup mixed at %s", tc.path)
		}
		if !tc.editing && !strings.Contains(body, `href="/integrations/reviews?new=1"`) {
			t.Fatal("overview has no explicit add action")
		}
	}
}

func TestReviewHistoryCostsAndUnknownAcknowledgement(t *testing.T) {
	for _, estimate := range []*float64{nil, new(1.5)} {
		var body strings.Builder
		jobs := []reviews.Job{{ID: "job", Repository: "lox/repo", Status: "unknown", Threads: []reviews.Thread{{ID: "T-00000000-0000-0000-0000-000000000123", Usage: &reviews.Usage{CostUSD: 0.25, ProviderEstimateUSD: estimate}}}}}
		err := page.ExecuteTemplate(&body, "reviews", map[string]any{"ReviewApp": reviews.App{}, "ReviewJobs": jobs})
		if err != nil {
			t.Fatal(err)
		}
		want := "Provider estimate: not reported"
		if estimate != nil {
			want = "Provider estimate: $1.5000"
		}
		for _, text := range []string{"Amp credits: $0.2500", want, `name="acknowledge" required`, "Automatic replay is stopped", "https://ampcode.com/threads/T-00000000-0000-0000-0000-000000000123"} {
			if !strings.Contains(body.String(), text) {
				t.Fatalf("history missing %q", text)
			}
		}
	}
}

func TestReviewUsageOverview(t *testing.T) {
	for _, tc := range []struct {
		name  string
		usage reviews.DailyUsage
		want  []string
	}{
		{"empty", reviews.DailyUsage{}, []string{"No reviews requested in this period"}},
		{"missing", reviews.DailyUsage{Reviews: 2, Threads: 3}, []string{"No recorded costs yet", "Usage recorded for 0 / 3 attempts", "<strong>—</strong>"}},
		{"zero", reviews.DailyUsage{Reviews: 1, Threads: 1, Known: 1}, []string{"$0.0000", "Estimates for 0 / 1 attempts", "<strong>—</strong>"}},
		{"partial", reviews.DailyUsage{Reviews: 3, Threads: 4, Known: 2, Estimates: 1, Credits: .375, ProviderEstimate: 1.5}, []string{"$0.3750 (partial)", "$1.5000 (partial)", "Usage recorded for 2 / 4 attempts", "<strong>3</strong>"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			days := make([]reviews.DailyUsage, 30)
			days[4] = tc.usage
			for i := range days {
				days[i].Date = time.Date(2026, 10, 17+i, 0, 0, 0, 0, time.UTC)
			}
			var body strings.Builder
			if err := page.ExecuteTemplate(&body, "reviews", map[string]any{"ReviewUsage": days}); err != nil {
				t.Fatal(err)
			}
			for _, want := range append(tc.want, "17 Oct 2026", "15 Nov 2026") {
				if !strings.Contains(body.String(), want) {
					t.Fatalf("missing %q", want)
				}
			}
			if strings.Contains(body.String(), "NaN") || strings.Contains(body.String(), "ZgotmplZ") {
				t.Fatal("invalid chart coordinates")
			}
		})
	}
}

func TestReviewHistoryAtAGlance(t *testing.T) {
	created := time.Date(2026, 11, 15, 8, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name string
		job  reviews.Job
		want []string
	}{
		{"blocking, multiple attempts", reviews.Job{Status: "succeeded", Conclusion: "failure", Result: &reviews.Result{Findings: []reviews.Finding{{Severity: "high"}, {Severity: "medium"}, {Severity: "medium"}}}, Threads: []reviews.Thread{{Usage: &reviews.Usage{CostUSD: .125, ProviderEstimateUSD: new(1.5)}}, {Usage: &reviews.Usage{CostUSD: .375, ProviderEstimateUSD: new(2.25)}}}}, []string{"Blocking issues", "1 high", "2 medium", "$0.5000", "Est. $3.7500"}},
		{"advisory, partial usage", reviews.Job{Status: "succeeded", Conclusion: "neutral", Result: &reviews.Result{Findings: []reviews.Finding{{Severity: "low"}}}, Threads: []reviews.Thread{{Usage: &reviews.Usage{CostUSD: .25, ProviderEstimateUSD: new(1.5)}}, {}}}, []string{"Advisory issues", "1 low", "$0.2500 (partial)", "Est. $1.5000 (partial)"}},
		{"zero is known", reviews.Job{Status: "succeeded", Conclusion: "success", Result: &reviews.Result{}, Threads: []reviews.Thread{{Usage: &reviews.Usage{}}}}, []string{"Passed", "$0.0000", "Est. Not reported"}},
		{"pending is not zero", reviews.Job{Status: "unknown", Threads: []reviews.Thread{{}}}, []string{"unknown", "Pending", "Est. Pending", "review-findings\">—"}},
		{"failed usage is not zero", reviews.Job{Status: "failed", Threads: []reviews.Thread{{UsageError: "unavailable"}}}, []string{"Review failed", "Unavailable"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			j := tc.job
			j.Repository, j.Number, j.Context.Title = "example/repo", 42, "Fix <unsafe> lifecycle"
			j.Created, j.Completed = created.UnixNano(), created.Add(203*time.Second).Unix()
			var body strings.Builder
			if err := page.ExecuteTemplate(&body, "reviews", map[string]any{"ReviewJobs": []reviews.Job{j}}); err != nil {
				t.Fatal(err)
			}
			_, summary, _ := strings.Cut(body.String(), `<summary class="review-summary">`)
			summary, _, _ = strings.Cut(summary, "</summary>")
			for _, want := range append(tc.want, "3m23s", "Fix &lt;unsafe&gt; lifecycle", "example/repo#42", "15 Nov · 08:00 UTC") {
				if !strings.Contains(summary, want) {
					t.Fatalf("collapsed row missing %q: %s", want, summary)
				}
			}
			if tc.name != "zero is known" && strings.Contains(summary, "$0.0000") {
				t.Fatal("missing usage shown as zero")
			}
		})
	}
}
