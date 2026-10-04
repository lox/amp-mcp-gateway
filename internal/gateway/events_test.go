package gateway

import (
	"bufio"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ampcode.com/lox/amp-mcp-gateway/internal/upstream"
)

func TestLedgerEvents(t *testing.T) {
	g, s, _ := fixture(t)
	m, err := upstream.New(g.cfg.BaseURL, g.cfg.Connections, s)
	if err != nil {
		t.Fatal(err)
	}
	h, cookie := adminUI(t, g, m)
	if w := formRequest(h, nil, "GET", "/events", nil); w.Code != http.StatusSeeOther {
		t.Fatal("stream must require owner authentication")
	}
	unauthorized := httptest.NewRequest("GET", "/events", nil)
	unauthorized.Header.Set("Accept", "text/event-stream")
	rejected := httptest.NewRecorder()
	h.ServeHTTP(rejected, unauthorized)
	if rejected.Code != http.StatusUnauthorized || rejected.Header().Get("Location") != "" {
		t.Fatal("EventSource must not follow a login/OIDC redirect")
	}
	if w := formRequest(h, cookie, "HEAD", "/events", nil); w.Code != 200 || w.Body.Len() != 0 {
		t.Fatal("HEAD should return without streaming")
	}
	done := make(chan struct{})
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(done)
		g.streamLedgerEvents(w, r, 10*time.Millisecond)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	r, _ := http.NewRequestWithContext(t.Context(), "GET", server.URL+"/events", nil)
	r.AddCookie(cookie)
	client := server.Client()
	client.Timeout = 15 * time.Second
	response, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.ProtoMajor != 2 || response.StatusCode != 200 || response.Header.Get("Content-Type") != "text/event-stream" || response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("X-Accel-Buffering") != "no" {
		t.Fatalf("incorrect SSE response: %d %v", response.StatusCode, response.Header)
	}
	frames := make(chan string, 8)
	go func() {
		defer close(frames)
		scanner := bufio.NewScanner(response.Body)
		var frame []string
		for scanner.Scan() {
			if scanner.Text() == "" {
				frames <- strings.Join(frame, "\n")
				frame = nil
			} else {
				frame = append(frame, scanner.Text())
			}
		}
	}()
	next := func() {
		t.Helper()
		select {
		case frame := <-frames:
			if !strings.Contains(frame, "event: ledger\ndata: changed") || strings.Contains(frame, "private-value") || strings.Contains(frame, "event-request") {
				t.Fatalf("expected payload-free invalidation: %q", frame)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("committed change was not delivered")
		}
	}
	next() // Every connection refreshes current state, including after missed events.
	if _, err := g.submit(t.Context(), input("event-request", "private-value")); err != nil {
		t.Fatal(err)
	}
	next()
	if _, err := g.submit(t.Context(), input("event-request", "private-value")); err != nil {
		t.Fatal(err)
	}
	select {
	case frame := <-frames:
		t.Fatalf("unchanged ledger emitted a frame: %q", frame)
	case <-time.After(50 * time.Millisecond):
		// Outlast the per-write deadline: it must not terminate an idle HTTP/2 stream.
	}
	if err := s.Decide(t.Context(), "event-request", "owner", false); err != nil {
		t.Fatal(err)
	}
	next()
	response.Body.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("disconnected stream handler did not exit")
	}
}
