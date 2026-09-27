package gateway

import (
	"testing"

	"ampcode.com/lox/amp-mcp-gateway/internal/upstream"
)

func TestEnableChromePersistsAndPublishesNativeTools(t *testing.T) {
	g, s, backend := fixture(t)
	m, err := upstream.New(g.cfg.BaseURL, g.cfg.Connections, s)
	if err != nil {
		t.Fatal(err)
	}
	if err := g.EnableChrome(t.Context(), m); err != nil {
		t.Fatal(err)
	}
	if !backend.browser.Load() {
		t.Fatal("browser backend was not published")
	}
	if len(g.cfg.Connections) != 2 || g.cfg.Connections[1].ID != chromeConnectionID || !g.cfg.Connections[1].Browser {
		t.Fatalf("browser connection not enabled: %#v", g.cfg.Connections)
	}
	if len(g.cfg.Tools) != 7 || g.cfg.Tools[1].ID != "browser.snapshot" || g.cfg.Tools[6].ID != "browser.navigate" {
		t.Fatalf("browser tools not enabled: %#v", g.cfg.Tools)
	}
	var restored Config
	if err := LoadCatalogue(t.Context(), &restored, s); err != nil {
		t.Fatal(err)
	}
	if len(restored.Connections) != 2 || !restored.Connections[1].Browser || len(restored.Tools) != 7 {
		t.Fatalf("browser setup did not persist: connections=%#v tools=%#v", restored.Connections, restored.Tools)
	}
	events, err := s.Events(t.Context())
	if err != nil || len(events) != 1 || events[0].Kind != "integration-saved" {
		t.Fatalf("browser setup audit event = %#v, %v", events, err)
	}
	if err := g.EnableChrome(t.Context(), m); err != nil {
		t.Fatal(err)
	}
	if len(g.cfg.Connections) != 2 || len(g.cfg.Tools) != 7 {
		t.Fatal("repeated Chrome enable duplicated catalogue entries")
	}
}

func TestEnableChromeRejectsRemoteConnectionNameConflict(t *testing.T) {
	g, s, _ := fixture(t)
	g.cfg.Connections = append(g.cfg.Connections, upstream.Connection{ID: chromeConnectionID, URL: "https://example.com/mcp", NoAuth: true})
	m, err := upstream.New(g.cfg.BaseURL, g.cfg.Connections, s)
	if err != nil {
		t.Fatal(err)
	}
	if err := g.EnableChrome(t.Context(), m); err == nil {
		t.Fatal("remote connection using browser ID was replaced")
	}
}
