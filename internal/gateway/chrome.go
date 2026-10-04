package gateway

import (
	"context"
	"errors"

	"ampcode.com/lox/amp-mcp-gateway/internal/browserauth"
	"ampcode.com/lox/amp-mcp-gateway/internal/store"
	"ampcode.com/lox/amp-mcp-gateway/internal/upstream"
)

const chromeConnectionID = "browser"

// ChromeIntegration returns the native browser connection and its governed tools.
func ChromeIntegration() (upstream.Connection, []Tool) {
	targetProperties := map[string]any{
		"document_id":     map[string]any{"type": "string", "minLength": 1, "maxLength": 200},
		"backend_node_id": map[string]any{"type": "integer", "minimum": 1},
		"expected_url":    map[string]any{"type": "string", "maxLength": 16384},
		"expected_role":   map[string]any{"type": "string", "maxLength": 16384},
		"expected_name":   map[string]any{"type": "string", "maxLength": 16384},
	}
	targetSchema := map[string]any{"type": "object", "properties": targetProperties, "required": []any{"document_id", "backend_node_id", "expected_url", "expected_role", "expected_name"}, "additionalProperties": false}
	return upstream.Connection{ID: chromeConnectionID, Account: "Selected Chrome tab", Browser: true}, []Tool{
		{ID: "browser.snapshot", Connection: chromeConnectionID, Name: "snapshot", Description: "Read the selected Chrome tab's URL, title and accessibility tree", Policy: "allow", InputSchema: map[string]any{"type": "object", "additionalProperties": false}},
		{ID: "browser.screenshot", Connection: chromeConnectionID, Name: "screenshot", Description: "Capture the visible area of the selected Chrome tab", Policy: "allow", InputSchema: map[string]any{"type": "object", "additionalProperties": false}},
		{ID: "browser.click", Connection: chromeConnectionID, Name: "click", Description: "Click an accessibility-tree backend node in the selected Chrome tab", Policy: "require_approval", InputSchema: targetSchema},
		{ID: "browser.type", Connection: chromeConnectionID, Name: "type", Description: "Replace text in an accessibility-tree backend node in the selected Chrome tab", Policy: "require_approval", InputSchema: map[string]any{"type": "object", "properties": map[string]any{"document_id": targetProperties["document_id"], "backend_node_id": targetProperties["backend_node_id"], "expected_url": targetProperties["expected_url"], "expected_role": targetProperties["expected_role"], "expected_name": targetProperties["expected_name"], "text": map[string]any{"type": "string", "maxLength": 10000}, "submit": map[string]any{"type": "boolean"}}, "required": []any{"document_id", "backend_node_id", "expected_url", "expected_role", "expected_name", "text"}, "additionalProperties": false}},
		{ID: "browser.scroll", Connection: chromeConnectionID, Name: "scroll", Description: "Scroll the selected Chrome tab vertically", Policy: "allow", InputSchema: map[string]any{"type": "object", "properties": map[string]any{"delta_y": map[string]any{"type": "number", "minimum": -10000, "maximum": 10000}}, "required": []any{"delta_y"}, "additionalProperties": false}},
		{ID: "browser.navigate", Connection: chromeConnectionID, Name: "navigate", Description: "Navigate the selected Chrome tab to an HTTP(S) URL", Policy: "require_approval", InputSchema: map[string]any{"type": "object", "properties": map[string]any{"url": map[string]any{"type": "string", "pattern": "^https?://", "maxLength": 2000}}, "required": []any{"url"}, "additionalProperties": false}},
	}
}

type browserInstaller interface {
	InstallBrowser(upstream.Connection)
}

// EnableChrome persists and publishes the native browser connection and tools.
func (g *Gateway) EnableChrome(ctx context.Context, m *upstream.Manager) error {
	installer, ok := g.backend.(browserInstaller)
	if !ok {
		return errors.New("browser backend unavailable")
	}
	connection, tools := ChromeIntegration()
	g.mu.Lock()
	defer g.mu.Unlock()
	next := g.catalogue()
	configured := false
	for _, existing := range next.Connections {
		if existing.ID != connection.ID {
			continue
		}
		if !existing.Browser {
			return errors.New("the browser connection name is already in use")
		}
		configured = true
	}
	if !configured {
		next.Connections = append(next.Connections, connection)
	}
	existingTools := make(map[string]Tool, len(next.Tools))
	for _, tool := range next.Tools {
		existingTools[tool.ID] = tool
	}
	changed := !configured
	for _, tool := range tools {
		if existing, exists := existingTools[tool.ID]; exists {
			if existing.Connection != connection.ID || existing.Name != tool.Name {
				return errors.New("a Chrome tool name is already in use")
			}
			continue
		}
		next.Tools = append(next.Tools, tool)
		changed = true
	}
	if changed {
		if err := g.saveCatalogue(ctx, next, m, store.Event{Kind: "integration-saved", Actor: "amp:" + browserauth.Subject(ctx)}); err != nil {
			return err
		}
	}
	installer.InstallBrowser(connection)
	return nil
}
