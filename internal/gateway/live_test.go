package gateway

import (
	"net/http/httptest"
	"strings"
	"testing"

	"ampcode.com/lox/amp-mcp-gateway/internal/store"
	"ampcode.com/lox/amp-mcp-gateway/internal/upstream"
)

func TestLiveOperationStatus(t *testing.T) {
	for _, status := range []string{"pending", "ready", "running", "succeeded", "failed", "unknown", "denied", "expired"} {
		t.Run(status, func(t *testing.T) {
			g, s, _ := fixture(t)
			_, err := s.Submit(t.Context(), store.Operation{ID: "live", Tool: "notes.write", Connection: "notes", Status: status, Arguments: map[string]any{"text": "private-arguments"}})
			if err != nil {
				t.Fatal(err)
			}
			m, err := upstream.New(g.cfg.BaseURL, g.cfg.Connections, s)
			if err != nil {
				t.Fatal(err)
			}
			h, cookie := adminUI(t, g, m)
			for _, owner := range []bool{false, true} {
				r := httptest.NewRequest("GET", "/operations/live", nil)
				r.Header.Set("HX-Request", "true")
				if owner {
					r.AddCookie(cookie)
				}
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				if !owner {
					if w.Header().Get("HX-Redirect") != "/login" || strings.Contains(w.Body.String(), "operation-live") {
						t.Fatal("unauthenticated fragment request must navigate to login")
					}
					continue
				}
				body := w.Body.String()
				if w.Code != 200 || !strings.Contains(body, ">"+status+"</span>") || strings.Contains(body, "<html") || strings.Contains(body, "private-arguments") || strings.Contains(body, "<form") {
					t.Fatalf("incorrect status fragment: %d %s", w.Code, body)
				}
				if strings.Contains(body, `hx-trigger="every 2s"`) != (status == "ready" || status == "running") {
					t.Fatal("only active execution should poll")
				}
				if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Vary") != "HX-Request" {
					t.Fatal("fragment must not be cached or confused with the full page")
				}
			}
		})
	}
}
