package gateway

import (
	"encoding/json"
	"net/http"

	"ampcode.com/lox/amp-mcp-gateway/internal/browserbridge"
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

// ConfigureChrome adds the native browser connection and canonical tool
// definitions while preserving saved policies. It returns false and leaves a
// conflicting catalogue unchanged so an upgrade cannot take that account offline.
func ConfigureChrome(cfg *Config) bool {
	connection, tools := ChromeIntegration()
	canonical := make(map[string]Tool, len(tools))
	for _, tool := range tools {
		canonical[tool.ID] = tool
	}

	configured := -1
	for i, existing := range cfg.Connections {
		if existing.ID != connection.ID {
			continue
		}
		if configured >= 0 || !existing.Browser {
			return false
		}
		configured = i
	}

	existing := make(map[string]Tool, len(tools))
	retained := make([]Tool, 0, len(cfg.Tools)+len(tools))
	for _, tool := range cfg.Tools {
		definition, native := canonical[tool.ID]
		if native {
			if _, duplicate := existing[tool.ID]; duplicate || tool.Connection != definition.Connection || tool.Name != definition.Name {
				return false
			}
			existing[tool.ID] = tool
			continue
		}
		if tool.Connection == connection.ID {
			continue
		}
		retained = append(retained, tool)
	}
	if configured < 0 {
		cfg.Connections = append(cfg.Connections, connection)
	} else {
		cfg.Connections[configured] = connection
	}
	for _, tool := range tools {
		if saved, ok := existing[tool.ID]; ok {
			tool.Policy = saved.Policy
		}
		retained = append(retained, tool)
	}
	cfg.Tools = retained
	return true
}

func (g *Gateway) registerChrome(mux *http.ServeMux, browser *browserbridge.Manager, available bool) {
	mux.HandleFunc("GET /integrations/chrome", func(w http.ResponseWriter, r *http.Request) {
		g.chromePage(w, r, browser, available, nil)
	})
	mux.HandleFunc("GET /integrations/chrome/status", func(w http.ResponseWriter, _ *http.Request) {
		type status struct {
			ID    string `json:"id"`
			State string `json:"state"`
		}
		connections := browser.Statuses()
		result := make([]status, 0, len(connections))
		for _, connection := range connections {
			state := "not-paired"
			if connection.Connected {
				state = "connected"
			} else if connection.Paired {
				state = "offline"
			}
			result = append(result, status{ID: connection.ID, State: state})
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(result)
	})
	mux.HandleFunc("POST /integrations/chrome/pair", func(w http.ResponseWriter, r *http.Request) {
		if !available {
			http.Error(w, "Chrome setup unavailable", http.StatusConflict)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		if r.ParseForm() != nil {
			http.Error(w, "invalid pairing request", http.StatusBadRequest)
			return
		}
		connection := r.PostForm.Get("connection")
		code, found, err := browser.Pair(r.Context(), connection)
		if !found {
			http.Error(w, "unknown browser connection", http.StatusBadRequest)
			return
		}
		if err != nil {
			http.Error(w, "pairing unavailable", http.StatusServiceUnavailable)
			return
		}
		g.chromePage(w, r, browser, available, map[string]any{"PairingCode": code, "PairingConnection": connection})
	})
	mux.HandleFunc("POST /integrations/chrome/revoke", func(w http.ResponseWriter, r *http.Request) {
		if !available {
			http.Error(w, "Chrome setup unavailable", http.StatusConflict)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		if r.ParseForm() != nil {
			http.Error(w, "invalid revocation request", http.StatusBadRequest)
			return
		}
		found, err := browser.Revoke(r.Context(), r.PostForm.Get("connection"))
		if !found {
			http.Error(w, "unknown browser connection", http.StatusBadRequest)
			return
		}
		if err != nil {
			http.Error(w, "revocation unavailable", http.StatusServiceUnavailable)
			return
		}
		http.Redirect(w, r, "/integrations/chrome", http.StatusSeeOther)
	})
}

func (g *Gateway) chromePage(w http.ResponseWriter, r *http.Request, browser *browserbridge.Manager, available bool, extra map[string]any) {
	connections := browser.Statuses()
	data := map[string]any{
		"ChromeIntegration": true,
		"ChromeAvailable":   available,
		"Connections":       connections,
		"GatewayURL":        g.cfg.BaseURL,
	}
	for key, value := range extra {
		data[key] = value
	}
	g.render(w, r, data)
}
