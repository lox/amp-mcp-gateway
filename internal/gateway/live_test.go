package gateway

import (
	"encoding/json"
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
			o := store.Operation{ID: "live", Tool: "notes.write", Connection: "notes", Status: status, Arguments: map[string]any{"text": "private-arguments"}}
			if status == "succeeded" || status == "failed" {
				o.Result = json.RawMessage(`{"content":[{"type":"text","text":"<script>unsafe-result</script>"}]}`)
			}
			_, err := s.Submit(t.Context(), o)
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
				if strings.Contains(body, `data-live`) != (status == "ready" || status == "running") {
					t.Fatal("only active execution should subscribe to live updates")
				}
				if len(o.Result) > 0 && (!strings.Contains(body, "&lt;script&gt;unsafe-result&lt;/script&gt;") || strings.Contains(body, "<script>")) {
					t.Fatal("fragment must show the result as escaped text")
				}
				if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Vary") != "HX-Request" {
					t.Fatal("fragment must not be cached or confused with the full page")
				}
			}
		})
	}
}

func TestLiveOperationsList(t *testing.T) {
	g, s, _ := fixture(t)
	m, err := upstream.New(g.cfg.BaseURL, g.cfg.Connections, s)
	if err != nil {
		t.Fatal(err)
	}
	h, cookie := adminUI(t, g, m)
	for _, id := range []string{"waiting-request", "rejected-request"} {
		if _, err := g.submit(t.Context(), input(id, "private-argument")); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Decide(t.Context(), "rejected-request", "owner", false); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/approvals", nil)
	r.Header.Set("HX-Request", "true")
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	body := w.Body.String()
	if w.Code != 200 || !strings.Contains(body, "waiting") || strings.Contains(body, "rejected") || strings.Contains(body, "private-argument") || strings.Contains(body, "<html") {
		t.Fatalf("incorrect approvals fragment: %d %s", w.Code, body)
	}
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Vary") != "HX-Request" {
		t.Fatal("list fragment must not be cached")
	}
}

func TestLiveAuditList(t *testing.T) {
	g, s, _ := fixture(t)
	m, err := upstream.New(g.cfg.BaseURL, g.cfg.Connections, s)
	if err != nil {
		t.Fatal(err)
	}
	h, cookie := adminUI(t, g, m)
	if _, err := g.submit(t.Context(), input("audit-request", "private-argument")); err != nil {
		t.Fatal(err)
	}
	if err := s.Decide(t.Context(), "audit-request", "<script>actor</script>", false); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/audit?view=events", nil)
	r.Header.Set("HX-Request", "true")
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	body := w.Body.String()
	for _, want := range []string{"audit-request", "<td>denied</td>", "<td>pending</td>", "&lt;script&gt;actor&lt;/script&gt;"} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %s", want)
		}
	}
	if w.Code != 200 || strings.Contains(body, "<html") || strings.Contains(body, "<script>") || strings.Contains(body, "private-argument") || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Vary") != "HX-Request" {
		t.Fatalf("unsafe audit fragment: %d %s", w.Code, body)
	}
}
