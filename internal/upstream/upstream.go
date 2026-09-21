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
	// Browser-managed configuration is encrypted at rest; never render these secrets.
	BearerToken string `json:",omitempty"`
	NoAuth      bool   `json:",omitempty"`
	PublicOnly  bool   `json:",omitempty"`
}

// OAuthConfig contains the pre-registered OAuth authorization-code endpoints.
type OAuthConfig struct {
	ClientID        string
	ClientSecretEnv string
	AuthURL         string
	TokenURL        string
	Scopes          []string
	ClientSecret    string           `json:",omitempty"`
	Resource        string           `json:",omitempty"`
	AuthStyle       oauth2.AuthStyle `json:",omitempty"`
}

// TokenStore persists JSON-encoded credentials. A missing token is nil, nil.
type TokenStore interface {
	LoadToken(context.Context, string) ([]byte, error)
	SaveToken(context.Context, string, []byte) error
}

// Manager owns the configured upstream connections and transient OAuth state.
type Manager struct {
	baseURL string
	store   TokenStore
	conns   map[string]*managedConnection
	connMu  sync.RWMutex
	states  map[string]pendingState
	stateMu sync.Mutex
}

type managedConnection struct {
	config Connection
	mu     sync.Mutex
	check  Health
	grant  uint64
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
		methods := 0
		for _, enabled := range []bool{c.TokenEnv != "", c.BearerToken != "", c.OAuth != nil, c.NoAuth} {
			if enabled {
				methods++
			}
		}
		if methods != 1 {
			return nil, fmt.Errorf("connection %q must configure exactly one authentication method", c.ID)
		}
		if c.PublicOnly {
			if err := ValidatePublicURL(c.URL); err != nil {
				return nil, err
			}
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
			if c.PublicOnly {
				for _, raw := range []string{c.OAuth.AuthURL, c.OAuth.TokenURL} {
					if err := ValidatePublicURL(raw); err != nil {
						return nil, err
					}
				}
			}
		}
		m.conns[c.ID] = &managedConnection{config: c}
	}
	return m, nil
}

// Install publishes a validated manager's connections, preserving existing token locks.
// Call only after the new configuration has been durably saved.
func (m *Manager) Install(next *Manager) {
	m.connMu.Lock()
	defer m.connMu.Unlock()
	for id, c := range next.conns {
		if old, ok := m.conns[id]; ok && tokenKey(old.config) == tokenKey(c.config) {
			next.conns[id] = old
		}
	}
	m.conns = next.conns
}

func (m *Manager) connection(id string) (*managedConnection, bool) {
	m.connMu.RLock()
	defer m.connMu.RUnlock()
	c, ok := m.conns[id]
	return c, ok
}

// ListTools initializes a fresh MCP session and returns all pages of tools.
func (m *Manager) ListTools(ctx context.Context, connection string) ([]*mcp.Tool, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	c, ok := m.connection(connection)
	if !ok {
		return nil, errors.New("unknown connection")
	}
	c.mu.Lock()
	grant := c.grant
	c.mu.Unlock()
	var tools []*mcp.Tool
	err := m.withSession(ctx, connection, func(session *mcp.ClientSession) error {
		cursor := ""
		seen := map[string]bool{}
		bytes := 0
		for {
			result, err := session.ListTools(ctx, &mcp.ListToolsParams{Cursor: cursor})
			if err != nil {
				return err
			}
			raw, err := json.Marshal(result.Tools)
			if err != nil {
				return err
			}
			bytes += len(raw) + len(result.NextCursor)
			if bytes > 2<<20 {
				return errors.New("tool catalogue exceeds 2 MiB")
			}
			tools = append(tools, result.Tools...)
			if len(tools) > 500 {
				return errors.New("server returned more than 500 tools")
			}
			if result.NextCursor == "" {
				return nil
			}
			cursor = result.NextCursor
			if seen[cursor] || len(seen) >= 50 {
				return errors.New("invalid or excessive tool pagination")
			}
			seen[cursor] = true
		}
	})
	c.mu.Lock()
	if c.grant == grant {
		c.check = Health{Status: "Healthy", Detail: "MCP initialization and tool listing succeeded. No tools were executed.", CheckedAt: time.Now().UTC()}
		if err != nil {
			c.check.Status, c.check.Detail = "Test failed", "Could not initialize MCP or list tools. Check the provider and try again."
			var f *Failure
			if errors.As(err, &f) && (f.HTTPStatus == 401 || f.HTTPStatus == 403) {
				c.check.Detail = "Provider rejected access. Check permissions and credentials; reconnect OAuth if authorization was revoked."
			}
		}
	}
	c.mu.Unlock()
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
	c, ok := m.connection(id)
	if !ok {
		return failure("credentials", fmt.Errorf("unknown connection %q", id), 0)
	}
	httpClient, err := m.httpClient(ctx, c)
	if err != nil {
		return failure("credentials", err, 0)
	}
	observed := &statusTransport{base: httpClient.Transport}
	httpClient.Transport = observed
	transport := &mcp.StreamableClientTransport{Endpoint: c.config.URL, HTTPClient: httpClient, MaxRetries: -1, DisableStandaloneSSE: true}
	client := mcp.NewClient(&mcp.Implementation{Name: "mcp-gateway", Version: "1"}, nil)
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		return failure("connect", err, int(observed.status.Load()))
	}
	defer session.Close()
	observed.status.Store(0)
	if err := fn(session); err != nil {
		return failure("request", err, int(observed.status.Load()))
	}
	return nil
}

func (m *Manager) httpClient(ctx context.Context, c *managedConnection) (*http.Client, error) {
	base := &http.Client{Timeout: requestTimeout, CheckRedirect: rejectRedirect}
	transport := http.DefaultTransport
	if c.config.PublicOnly {
		transport = publicTransport
	}
	base.Transport = transport
	if c.config.NoAuth {
		return base, nil
	}
	if c.config.TokenEnv != "" || c.config.BearerToken != "" {
		token := c.config.BearerToken
		if c.config.TokenEnv != "" {
			token = os.Getenv(c.config.TokenEnv)
		}
		if token == "" {
			return nil, fmt.Errorf("connection %q bearer token environment variable is empty", c.config.ID)
		}
		base.Transport = bearerTransport{token: token, base: transport}
		return base, nil
	}
	token, err := m.loadToken(ctx, c)
	if err != nil {
		return nil, err
	}
	if token == nil {
		return nil, fmt.Errorf("connection %q is not authorized", c.config.ID)
	}
	source := &persistingTokenSource{manager: m, connection: c, ctx: ctx}
	base.Transport = &oauth2.Transport{Source: source, Base: transport}
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

func (m *Manager) loadToken(ctx context.Context, c *managedConnection) (*credentials, error) {
	raw, err := m.store.LoadToken(ctx, tokenKey(c.config))
	if err != nil {
		return nil, fmt.Errorf("load OAuth token: %w", err)
	}
	if raw == nil {
		return nil, nil
	}
	var token credentials
	if err := json.Unmarshal(raw, &token); err != nil {
		return nil, fmt.Errorf("decode OAuth token: %w", err)
	}
	return &token, nil
}

type persistingTokenSource struct {
	manager    *Manager
	connection *managedConnection
	ctx        context.Context
}

func (s *persistingTokenSource) Token() (*oauth2.Token, error) {
	return s.manager.refresh(s.ctx, s.connection, false)
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
