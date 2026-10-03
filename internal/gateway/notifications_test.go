package gateway

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"ampcode.com/lox/amp-mcp-gateway/internal/store"
	"ampcode.com/lox/amp-mcp-gateway/internal/upstream"
)

func TestNotificationFeed(t *testing.T) {
	g, s, _ := fixture(t)
	for _, status := range []string{"pending", "ready", "running", "succeeded", "denied", "expired"} {
		_, err := s.Submit(t.Context(), store.Operation{
			ID: status + `-"<id>`, Status: status, Tool: "private-tool", Connection: "private-connection",
			Arguments: map[string]any{"text": "private-argument"},
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	m, err := upstream.New(g.cfg.BaseURL, g.cfg.Connections, s)
	if err != nil {
		t.Fatal(err)
	}
	h, cookie := adminUI(t, g, m)
	for _, authenticated := range []bool{false, true} {
		r := httptest.NewRequest("GET", "/notifications", nil)
		r.Header.Set("HX-Request", "true")
		if authenticated {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if !authenticated {
			if w.Header().Get("HX-Redirect") != "/login" || strings.Contains(w.Body.String(), "data-approval-id") {
				t.Fatal("notification feed must require the owner session")
			}
			continue
		}
		if w.Code != http.StatusOK || w.Body.String() != `<span data-approval-id="pending-&#34;&lt;id&gt;"></span>` {
			t.Fatalf("feed should contain only escaped pending IDs: %d %s", w.Code, w.Body.String())
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("notification feed must not be cached")
		}
	}
}
