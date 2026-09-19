// Package upstream connects the gateway to explicitly configured remote MCP servers.
package upstream

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/oauth2"
)

const (
	requestTimeout = 30 * time.Second
	stateLifetime  = 10 * time.Minute
)

// Connection describes one remote MCP endpoint and its authentication.
type Connection struct {
	ID       string
	URL      string
	Account  string
	TokenEnv string
	OAuth    *OAuthConfig
}

// OAuthConfig contains the pre-registered OAuth authorization-code endpoints.
type OAuthConfig struct {
	ClientID        string
	ClientSecretEnv string
	AuthURL         string
	TokenURL        string
	Scopes          []string
}

// TokenStore persists JSON-encoded oauth2.Token values. A missing token is nil, nil.
type TokenStore interface {
	LoadToken(context.Context, string) ([]byte, error)
	SaveToken(context.Context, string, []byte) error
}

// Manager owns the configured upstream connections and transient OAuth state.
type Manager struct {
	baseURL string
	store   TokenStore
	conns   map[string]*managedConnection
	states  map[string]pendingState
	stateMu sync.Mutex
}

type managedConnection struct {
	config Connection
	mu     sync.Mutex
}

type pendingState struct {
	connection string
	verifier   string
	expires    time.Time
}

// New validates configuration and creates a manager for explicit connections.
func New(baseURL string, connections []Connection, store TokenStore) (*Manager, error) {
	base, err := validatedURL(baseURL)
	if err != nil {
		return nil, fmt.Errorf("base URL: %w", err)
	}
	m := &Manager{baseURL: strings.TrimRight(base.String(), "/"), store: store, conns: make(map[string]*managedConnection, 2), states: make(map[string]pendingState)}
	for _, c := range connections {
		if c.ID == "" || strings.Trim(c.ID, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-") != "" {
			return nil, fmt.Errorf("connection ID must contain only letters, digits, underscores or hyphens")
		}
		if _, exists := m.conns[c.ID]; exists {
			return nil, fmt.Errorf("duplicate connection ID %q", c.ID)
		}
		if _, err := validatedURL(c.URL); err != nil {
			return nil, fmt.Errorf("connection %q URL: %w", c.ID, err)
		}
		if (c.TokenEnv == "") == (c.OAuth == nil) {
			return nil, fmt.Errorf("connection %q must configure exactly one authentication method", c.ID)
		}
		if c.OAuth != nil {
			if store == nil {
				return nil, fmt.Errorf("connection %q OAuth requires a token store", c.ID)
			}
			if c.OAuth.ClientID == "" {
				return nil, fmt.Errorf("connection %q OAuth client ID is required", c.ID)
			}
			if _, err := validatedURL(c.OAuth.AuthURL); err != nil {
				return nil, fmt.Errorf("connection %q authorization URL: %w", c.ID, err)
			}
			if _, err := validatedURL(c.OAuth.TokenURL); err != nil {
				return nil, fmt.Errorf("connection %q token URL: %w", c.ID, err)
			}
		}
		m.conns[c.ID] = &managedConnection{config: c}
	}
	return m, nil
}

// ListTools initializes a fresh MCP session and returns all pages of tools.
func (m *Manager) ListTools(ctx context.Context, connection string) ([]*mcp.Tool, error) {
	var tools []*mcp.Tool
	err := m.withSession(ctx, connection, func(session *mcp.ClientSession) error {
		cursor := ""
		for {
			result, err := session.ListTools(ctx, &mcp.ListToolsParams{Cursor: cursor})
			if err != nil {
				return err
			}
			tools = append(tools, result.Tools...)
			if result.NextCursor == "" {
				return nil
			}
			cursor = result.NextCursor
		}
	})
	return tools, err
}

// Call initializes a fresh MCP session and invokes one tool exactly once.
func (m *Manager) Call(ctx context.Context, connection, tool string, args map[string]any) (*mcp.CallToolResult, error) {
	var result *mcp.CallToolResult
	err := m.withSession(ctx, connection, func(session *mcp.ClientSession) error {
		var err error
		result, err = session.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: args})
		return err
	})
	return result, err
}

func (m *Manager) withSession(ctx context.Context, id string, fn func(*mcp.ClientSession) error) error {
	c, ok := m.conns[id]
	if !ok {
		return fmt.Errorf("unknown connection %q", id)
	}
	httpClient, err := m.httpClient(ctx, c)
	if err != nil {
		return err
	}
	transport := &mcp.StreamableClientTransport{Endpoint: c.config.URL, HTTPClient: httpClient, MaxRetries: -1, DisableStandaloneSSE: true}
	client := mcp.NewClient(&mcp.Implementation{Name: "mcp-gateway", Version: "1"}, nil)
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		return fmt.Errorf("connect upstream: %w", err)
	}
	defer session.Close()
	return fn(session)
}

func (m *Manager) httpClient(ctx context.Context, c *managedConnection) (*http.Client, error) {
	base := &http.Client{Timeout: requestTimeout, CheckRedirect: rejectRedirect}
	if c.config.TokenEnv != "" {
		token := os.Getenv(c.config.TokenEnv)
		if token == "" {
			return nil, fmt.Errorf("connection %q bearer token environment variable is empty", c.config.ID)
		}
		base.Transport = bearerTransport{token: token, base: http.DefaultTransport}
		return base, nil
	}
	token, err := m.loadToken(ctx, c)
	if err != nil {
		return nil, err
	}
	if token == nil {
		return nil, fmt.Errorf("connection %q is not authorized", c.config.ID)
	}
	source := &persistingTokenSource{manager: m, connection: c}
	base.Transport = &oauth2.Transport{Source: source, Base: http.DefaultTransport}
	return base, nil
}

type bearerTransport struct {
	token string
	base  http.RoundTripper
}

func (t bearerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.Header = req.Header.Clone()
	clone.Header.Set("Authorization", "Bearer "+t.token)
	return t.base.RoundTrip(clone)
}

func (m *Manager) loadToken(ctx context.Context, c *managedConnection) (*oauth2.Token, error) {
	raw, err := m.store.LoadToken(ctx, tokenKey(c.config))
	if err != nil {
		return nil, fmt.Errorf("load OAuth token: %w", err)
	}
	if raw == nil {
		return nil, nil
	}
	var token oauth2.Token
	if err := json.Unmarshal(raw, &token); err != nil {
		return nil, fmt.Errorf("decode OAuth token: %w", err)
	}
	return &token, nil
}

type persistingTokenSource struct {
	manager    *Manager
	connection *managedConnection
}

func (s *persistingTokenSource) Token() (*oauth2.Token, error) {
	c := s.connection
	c.mu.Lock()
	defer c.mu.Unlock()

	// Reload under the per-connection lock so concurrent requests share rotation.
	token, err := s.manager.loadToken(context.Background(), c)
	if err != nil {
		return nil, err
	}
	if token == nil {
		return nil, errors.New("connection is not authorized")
	}
	if token.Valid() {
		return token, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	ctx = context.WithValue(ctx, oauth2.HTTPClient, &http.Client{Timeout: requestTimeout, CheckRedirect: rejectRedirect})
	refreshed, err := s.manager.oauthConfig(c.config).TokenSource(ctx, token).Token()
	if err != nil {
		return nil, fmt.Errorf("refresh OAuth token: %w", err)
	}
	raw, err := json.Marshal(refreshed)
	if err != nil {
		return nil, fmt.Errorf("encode OAuth token: %w", err)
	}
	if err := s.manager.store.SaveToken(ctx, tokenKey(c.config), raw); err != nil {
		return nil, fmt.Errorf("save refreshed OAuth token: %w", err)
	}
	return refreshed, nil
}

func tokenKey(c Connection) string {
	// A configuration change must never forward an existing grant to a new endpoint.
	raw, _ := json.Marshal(c)
	hash := sha256.Sum256(raw)
	return c.ID + ":" + hex.EncodeToString(hash[:])
}

func rejectRedirect(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }

func validatedURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, errors.New("must be an absolute HTTP(S) URL without userinfo")
	}
	if u.Scheme == "http" {
		host := u.Hostname()
		if host != "localhost" && host != "127.0.0.1" && host != "::1" {
			return nil, errors.New("HTTP is allowed only for loopback URLs")
		}
	}
	return u, nil
}
