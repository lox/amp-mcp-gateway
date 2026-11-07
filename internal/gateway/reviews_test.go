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
	values := url.Values{"id": {"lox"}, "owner": {"lox"}, "app_id": {"1"}, "installation_id": {"11"}, "private_key": {private}, "webhook_secret": {"short"}, "amp_key": {"fake-execution-key"}, "repositories": {"lox/repo"}, "projects": {`{"lox/repo":"lox/repo"}`}, "fail_on": {"high"}, "visibility": {"private"}, "timeout": {"30"}, "enabled": {"on"}}
	for _, path := range []string{"/integrations/reviews", "/integrations/reviews/import", "/integrations/reviews/unknown/rerun", "/integrations/reviews/unknown/cancel"} {
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
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), `name="private_key"`) || strings.Contains(w.Body.String(), "readonly") || strings.Contains(w.Body.String(), private) || strings.Contains(w.Body.String(), "fake-execution-key") {
		t.Fatal("invalid form leaked secrets or locked identity")
	}
	values.Set("projects", "not-json")
	w = formRequest(h, cookie, "POST", "/integrations/reviews", values)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), ">not-json</textarea>") {
		t.Fatal("invalid project mappings were lost instead of remaining editable")
	}
	values.Set("projects", `{"lox/repo":"lox/repo"}`)
	values.Set("webhook_secret", "long-enough-fake-hook-secret")
	w = formRequest(h, cookie, "POST", "/integrations/reviews", values)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("save: %d %s", w.Code, w.Body.String())
	}
	if apps := g.Reviews.Apps(); len(apps) != 1 || apps[0].Enabled {
		t.Fatal("demo allowed execution")
	}
	values.Set("private_key", "")
	values.Set("webhook_secret", "")
	values.Set("amp_key", "")
	values.Set("fail_on", "critical")
	if w := formRequest(h, cookie, "POST", "/integrations/reviews", values); w.Code != http.StatusSeeOther {
		t.Fatal("blank secret fields did not retain credentials")
	}
	w = formRequest(h, cookie, "GET", "/integrations/reviews?app=lox", nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Import amp-reviewbot history") || strings.Contains(w.Body.String(), "fake-execution-key") || strings.Contains(w.Body.String(), private) {
		t.Fatal("configured page lost state or leaked credentials")
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
