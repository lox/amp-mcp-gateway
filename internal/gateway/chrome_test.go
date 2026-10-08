package gateway

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"ampcode.com/lox/amp-mcp-gateway/internal/browserbridge"
	"ampcode.com/lox/amp-mcp-gateway/internal/upstream"
)

func TestConfigureChromeAddsCanonicalToolsAndPreservesPolicies(t *testing.T) {
	cfg := Config{
		Connections: []upstream.Connection{{ID: "notes", URL: "https://example.com/mcp", NoAuth: true}},
		Tools: []Tool{
			{ID: "notes.read", Connection: "notes", Name: "read", Policy: "allow", InputSchema: map[string]any{"type": "object"}},
			{ID: "browser.snapshot", Connection: chromeConnectionID, Name: "snapshot", Policy: "deny", Description: "stale", InputSchema: map[string]any{"type": "null"}},
			{ID: "browser.retired", Connection: chromeConnectionID, Name: "retired", Policy: "allow", InputSchema: map[string]any{"type": "object"}},
		},
	}
	if !ConfigureChrome(&cfg) {
		t.Fatal("Chrome integration was not configured")
	}
	if len(cfg.Connections) != 2 || cfg.Connections[1].ID != chromeConnectionID || !cfg.Connections[1].Browser {
		t.Fatalf("browser connection not configured: %#v", cfg.Connections)
	}
	if len(cfg.Tools) != 7 || cfg.Tools[1].ID != "browser.snapshot" || cfg.Tools[1].Policy != "deny" || cfg.Tools[1].Description == "stale" || cfg.Tools[6].ID != "browser.navigate" {
		t.Fatalf("canonical browser tools not configured: %#v", cfg.Tools)
	}
	if !ConfigureChrome(&cfg) || len(cfg.Connections) != 2 || len(cfg.Tools) != 7 {
		t.Fatalf("repeated configuration changed catalogue: connections=%d tools=%d", len(cfg.Connections), len(cfg.Tools))
	}
}

func TestConfigureChromePreservesNameConflicts(t *testing.T) {
	for _, cfg := range []Config{
		{Connections: []upstream.Connection{{ID: chromeConnectionID, URL: "https://example.com/mcp", NoAuth: true}}},
		{Connections: []upstream.Connection{{ID: "remote", URL: "https://example.com/mcp", NoAuth: true}}, Tools: []Tool{{ID: "browser.snapshot", Connection: "remote", Name: "snapshot", InputSchema: map[string]any{"type": "object"}}}},
	} {
		before := cfg
		before.Connections = append([]upstream.Connection(nil), cfg.Connections...)
		before.Tools = append([]Tool(nil), cfg.Tools...)
		if ConfigureChrome(&cfg) || !reflect.DeepEqual(cfg, before) {
			t.Fatalf("conflicting configuration changed: before=%#v after=%#v", before, cfg)
		}
	}
}

func TestChromePageReportsNamespaceConflict(t *testing.T) {
	g, s, _ := fixture(t)
	connections := []upstream.Connection{{ID: chromeConnectionID, Account: "Legacy browser", Browser: true}}
	m, err := upstream.New(g.cfg.BaseURL, connections, s)
	if err != nil {
		t.Fatal(err)
	}
	browser, err := browserbridge.New(t.Context(), connections, m, s)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	g.registerChrome(mux, browser, false)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/integrations/chrome", nil))
	body := w.Body.String()
	if w.Code != http.StatusOK || !strings.Contains(body, "Chrome setup unavailable") || strings.Contains(body, `/integrations/chrome/pair`) {
		t.Fatalf("namespace conflict page: status=%d body=%s", w.Code, body)
	}
	w = formRequest(mux, nil, http.MethodPost, "/integrations/chrome/pair", url.Values{"connection": {chromeConnectionID}})
	if w.Code != http.StatusConflict {
		t.Fatalf("namespace conflict pairing returned %d", w.Code)
	}
}

func TestChromeIntegrationPageAndPairingRoutes(t *testing.T) {
	g, s, _ := fixture(t)
	m, err := upstream.New(g.cfg.BaseURL, g.cfg.Connections, s)
	if err != nil {
		t.Fatal(err)
	}
	h, cookie := adminUI(t, g, m)
	if w := formRequest(h, nil, http.MethodGet, "/integrations/chrome", nil); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login" {
		t.Fatalf("unauthenticated Chrome page returned %d", w.Code)
	}
	w := formRequest(h, cookie, http.MethodGet, "/integrations/chrome", nil)
	body := w.Body.String()
	if w.Code != http.StatusOK || !strings.Contains(body, `action="/integrations/chrome/pair"`) || strings.Contains(body, "/integrations/chrome/enable") || !strings.Contains(body, `data-browser-state="not-paired"`) || !strings.Contains(body, `href="/integrations" aria-current="page"`) {
		t.Fatalf("incorrect Chrome integration page: status=%d body=%s", w.Code, body)
	}
	if !strings.Contains(body, `location.replace("/integrations/chrome")`) || strings.Contains(body, "location.reload()") || strings.Contains(body, "location.assign(") {
		t.Fatalf("Chrome state polling may replay the pairing POST: %s", body)
	}
	w = formRequest(h, cookie, http.MethodGet, "/integrations/chrome/status", nil)
	if w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "no-store" || strings.TrimSpace(w.Body.String()) != `[{"id":"browser","state":"not-paired"}]` {
		t.Fatalf("unexpected Chrome status: status=%d cache=%q body=%s", w.Code, w.Header().Get("Cache-Control"), w.Body.String())
	}
	crossOrigin := httptest.NewRequest(http.MethodPost, "/integrations/chrome/pair", strings.NewReader(url.Values{"connection": {chromeConnectionID}}.Encode()))
	crossOrigin.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	crossOrigin.Header.Set("Origin", "https://evil.example")
	crossOrigin.Header.Set("Sec-Fetch-Site", "cross-site")
	crossOrigin.AddCookie(cookie)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, crossOrigin)
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-origin browser pairing returned %d", w.Code)
	}
	w = formRequest(h, cookie, http.MethodPost, "/integrations/chrome/pair", url.Values{"connection": {chromeConnectionID}})
	match := regexp.MustCompile(`<code id="pairing-code">([^<]+)</code>`).FindStringSubmatch(w.Body.String())
	if w.Code != http.StatusOK || len(match) != 2 || !strings.Contains(w.Body.String(), `data-copy="pairing-code" aria-label="Copy pairing code"`) {
		t.Fatalf("pairing page did not render its code: status=%d body=%s", w.Code, w.Body.String())
	}
	if w := formRequest(h, cookie, http.MethodPost, "/integrations/chrome/pair", url.Values{"connection": {"missing"}}); w.Code != http.StatusBadRequest {
		t.Fatalf("unknown browser pairing returned %d", w.Code)
	}
	if w := formRequest(h, cookie, http.MethodPost, "/integrations/chrome/revoke", url.Values{"connection": {chromeConnectionID}}); w.Code != http.StatusSeeOther {
		t.Fatalf("browser revocation returned %d", w.Code)
	}
}
