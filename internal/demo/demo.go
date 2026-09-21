// Package demo supplies disposable, loopback-only MCP/OAuth fixtures. Never use real data here.
package demo

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"ampcode.com/lox/amp-mcp-gateway/internal/gateway"
	"ampcode.com/lox/amp-mcp-gateway/internal/upstream"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Secrets are generated locally and never checked in or printed.
type Secrets struct{ EncryptionKey, SessionKey, GatewayToken, FixtureToken string }

// LoadSecrets creates a private demo secret file once.
func LoadSecrets(path string) (Secrets, error) {
	var s Secrets
	b, err := os.ReadFile(path)
	if err == nil {
		err = json.Unmarshal(b, &s)
		return s, err
	}
	if !errors.Is(err, os.ErrNotExist) {
		return s, err
	}
	values := []*string{&s.EncryptionKey, &s.SessionKey, &s.GatewayToken, &s.FixtureToken}
	for _, v := range values {
		raw := make([]byte, 32)
		rand.Read(raw)
		*v = base64.StdEncoding.EncodeToString(raw)
	}
	b, err = json.Marshal(s)
	if err != nil {
		return s, err
	}
	return s, os.WriteFile(path, b, 0600)
}

// Start runs fixtures on a stable loopback address and returns the demo catalogue and consent handler.
func Start(ctx context.Context, baseURL, token string) (gateway.Config, http.Handler, error) {
	baseURL = strings.TrimRight(baseURL, "/")
	const addr = "127.0.0.1:8091"
	const endpoint = "http://" + addr
	if err := os.Setenv("GATEWAY_DEMO_UPSTREAM_TOKEN", token); err != nil {
		return gateway.Config{}, nil, err
	}
	schema := map[string]any{"type": "object", "properties": map[string]any{"text": map[string]any{"type": "string", "minLength": 1, "maxLength": 1000}}, "required": []any{"text"}, "additionalProperties": false}
	emptySchema := map[string]any{"type": "object", "additionalProperties": false}
	nodeSchema := map[string]any{"type": "object", "properties": map[string]any{"backend_node_id": map[string]any{"type": "integer", "minimum": 1}}, "required": []any{"backend_node_id"}, "additionalProperties": false}
	cfg := gateway.Config{OwnerSubject: "demo-owner", BaseURL: baseURL, Database: ".local/gateway.db", Connections: []upstream.Connection{
		{ID: "reference", URL: endpoint + "/read", Account: "Disposable reference account", TokenEnv: "GATEWAY_DEMO_UPSTREAM_TOKEN"},
		{ID: "notes", URL: endpoint + "/write", Account: "Disposable OAuth notes account", OAuth: &upstream.OAuthConfig{ClientID: "gateway-demo", AuthURL: baseURL + "/demo/authorize", TokenURL: endpoint + "/token", Scopes: []string{"notes:write"}}},
		{ID: "browser", Account: "Selected Chrome tab", Browser: true},
	}, Tools: []gateway.Tool{
		{ID: "reference.echo", Connection: "reference", Name: "echo", Description: "Read back reference text", Policy: "allow", InputSchema: schema},
		{ID: "notes.create", Connection: "notes", Name: "create_note", Description: "Create a disposable note", Policy: "require_approval", InputSchema: schema},
		{ID: "browser.snapshot", Connection: "browser", Name: "snapshot", Description: "Read the selected Chrome tab's URL, title and accessibility tree", Policy: "allow", InputSchema: emptySchema},
		{ID: "browser.screenshot", Connection: "browser", Name: "screenshot", Description: "Capture the visible area of the selected Chrome tab", Policy: "allow", InputSchema: emptySchema},
		{ID: "browser.click", Connection: "browser", Name: "click", Description: "Click an accessibility-tree backend node in the selected Chrome tab", Policy: "require_approval", InputSchema: nodeSchema},
		{ID: "browser.type", Connection: "browser", Name: "type", Description: "Replace text in an accessibility-tree backend node in the selected Chrome tab", Policy: "require_approval", InputSchema: map[string]any{"type": "object", "properties": map[string]any{"backend_node_id": map[string]any{"type": "integer", "minimum": 1}, "text": map[string]any{"type": "string", "maxLength": 10000}, "submit": map[string]any{"type": "boolean"}}, "required": []any{"backend_node_id", "text"}, "additionalProperties": false}},
		{ID: "browser.scroll", Connection: "browser", Name: "scroll", Description: "Scroll the selected Chrome tab vertically", Policy: "allow", InputSchema: map[string]any{"type": "object", "properties": map[string]any{"delta_y": map[string]any{"type": "number", "minimum": -10000, "maximum": 10000}}, "required": []any{"delta_y"}, "additionalProperties": false}},
		{ID: "browser.navigate", Connection: "browser", Name: "navigate", Description: "Navigate the selected Chrome tab to an HTTP(S) URL", Policy: "require_approval", InputSchema: map[string]any{"type": "object", "properties": map[string]any{"url": map[string]any{"type": "string", "pattern": "^https?://", "maxLength": 2000}}, "required": []any{"url"}, "additionalProperties": false}},
	}}
	mux := http.NewServeMux()
	for _, spec := range []struct{ path, name string }{{"/read", "echo"}, {"/write", "create_note"}} {
		s := mcp.NewServer(&mcp.Implementation{Name: "demo-fixture", Version: "1"}, nil)
		mcp.AddTool(s, &mcp.Tool{Name: spec.name, InputSchema: schema}, func(ctx context.Context, r *mcp.CallToolRequest, in struct {
			Text string `json:"text"`
		}) (*mcp.CallToolResult, map[string]any, error) {
			return nil, map[string]any{"text": in.Text, "fixture": true}, nil
		})
		h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
		mux.Handle(spec.path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer "+token {
				http.Error(w, "unauthorized", 401)
				return
			}
			h.ServeHTTP(w, r)
		}))
	}
	var mu sync.Mutex
	codes := map[string]string{}
	consent := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		redirect := baseURL + "/connections/notes/callback"
		if q.Get("redirect_uri") != redirect || q.Get("client_id") != "gateway-demo" || q.Get("code_challenge_method") != "S256" {
			http.Error(w, "invalid demo authorization", 400)
			return
		}
		code := rand.Text()
		mu.Lock()
		codes[code] = q.Get("code_challenge")
		mu.Unlock()
		u, _ := url.Parse(redirect)
		v := u.Query()
		v.Set("state", q.Get("state"))
		v.Set("code", code)
		u.RawQuery = v.Encode()
		http.Redirect(w, r, u.String(), 302)
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		if r.ParseForm() != nil {
			http.Error(w, "invalid", 400)
			return
		}
		switch r.Form.Get("grant_type") {
		case "authorization_code":
			mu.Lock()
			challenge, ok := codes[r.Form.Get("code")]
			delete(codes, r.Form.Get("code"))
			mu.Unlock()
			hash := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
			if !ok || challenge != base64.RawURLEncoding.EncodeToString(hash[:]) {
				http.Error(w, "invalid grant", 400)
				return
			}
		case "refresh_token":
			if !strings.HasPrefix(r.Form.Get("refresh_token"), token+".") {
				http.Error(w, "invalid grant", 400)
				return
			}
		default:
			http.Error(w, "invalid grant", 400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"access_token": token, "token_type": "Bearer", "refresh_token": token + "." + rand.Text(), "expires_in": 20})
	})
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return cfg, nil, err
	}
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { <-ctx.Done(); server.Close() }()
	go server.Serve(listener)
	return cfg, consent, nil
}
