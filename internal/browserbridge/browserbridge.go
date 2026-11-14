// Package browserbridge adapts a reverse-connected Chrome extension to the
// gateway's upstream tool boundary.
package browserbridge

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"ampcode.com/lox/amp-mcp-gateway/internal/upstream"
	"github.com/gorilla/websocket"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	maxHelloSize              = 32 << 10
	maxMessageSize            = 8 << 20
	maxUnauthenticatedSockets = 32
	pairingTTL                = 10 * time.Minute
)

type backend interface {
	Call(context.Context, string, string, string, map[string]any) (*mcp.CallToolResult, error)
}

type pairingStore interface {
	LoadBrowserPairings(context.Context) (map[string][]byte, error)
	SaveBrowserPairing(context.Context, string, []byte) error
	DeleteBrowserPairing(context.Context, string) error
}

// Manager owns persisted browser pairing state and active extension connections.
type Manager struct {
	fallback backend
	store    pairingStore

	mu              sync.Mutex
	connections     map[string]upstream.Connection
	pairings        map[string]pairing
	clients         map[string]*client
	unauthenticated chan struct{}
	now             func() time.Time
}

type pairing struct {
	hash     [32]byte
	created  time.Time
	target   string
	tabTitle string
	tabURL   string
	paired   bool
	name     string
	install  string // Empty for legacy tab-bound pairings.
}

type persistedPairing struct {
	Hash     []byte `json:"hash"`
	Created  int64  `json:"created"`
	Target   string `json:"target,omitempty"`
	TabTitle string `json:"tab_title,omitempty"`
	TabURL   string `json:"tab_url,omitempty"`
	Paired   bool   `json:"paired,omitempty"`
	Name     string `json:"name,omitempty"`
	Install  string `json:"install,omitempty"`
}

type client struct {
	manager    *Manager
	connection string
	binding    string
	sharing    bool
	ws         *websocket.Conn
	// Live tab metadata is protected by manager.mu, like the client registry.
	tabTitle string
	tabURL   string

	writeMu sync.Mutex
	mu      sync.Mutex
	pending map[string]chan response
	closed  chan struct{}
	once    sync.Once
}

type wireMessage struct {
	Type        string          `json:"type"`
	Version     int             `json:"version,omitempty"`
	BrowserName string          `json:"browser_name,omitempty"`
	PairingCode string          `json:"pairing_code,omitempty"`
	Reconnect   string          `json:"reconnect_code,omitempty"`
	InstallID   string          `json:"install_id,omitempty"`
	ShareID     string          `json:"share_id,omitempty"`
	TabID       int             `json:"tab_id,omitempty"`
	TabTitle    string          `json:"tab_title,omitempty"`
	TabURL      string          `json:"tab_url,omitempty"`
	ID          string          `json:"id,omitempty"`
	Tool        string          `json:"tool,omitempty"`
	Arguments   map[string]any  `json:"arguments,omitempty"`
	Result      json.RawMessage `json:"result,omitempty"`
	Error       string          `json:"error,omitempty"`
	BeforeInput bool            `json:"before_input,omitempty"`
}

type response struct {
	result       json.RawMessage
	err          string
	beforeInput  bool
	disconnected bool
}

type beforeDispatchError struct{ message string }

func (e *beforeDispatchError) Error() string { return e.message }

// OutcomeError reports a dispatched browser mutation whose effect is unknown.
// Message is bounded extension or bridge text, safe to store with the operation.
type OutcomeError struct{ Message string }

func (e *OutcomeError) Error() string { return "browser outcome unknown: " + e.Message }

// New creates a browser-aware backend and restores persisted reconnect
// authority. Non-browser connections are delegated to fallback.
func New(ctx context.Context, connections []upstream.Connection, fallback backend, store pairingStore) (*Manager, error) {
	if store == nil {
		return nil, errors.New("browser pairing store is required")
	}
	m := &Manager{
		fallback:        fallback,
		store:           store,
		connections:     make(map[string]upstream.Connection),
		pairings:        make(map[string]pairing),
		clients:         make(map[string]*client),
		unauthenticated: make(chan struct{}, maxUnauthenticatedSockets),
		now:             time.Now,
	}
	for _, c := range connections {
		if !c.Browser {
			continue
		}
		if _, exists := m.connections[c.ID]; exists {
			return nil, fmt.Errorf("duplicate browser connection %q", c.ID)
		}
		m.connections[c.ID] = c
	}
	stored, err := store.LoadBrowserPairings(ctx)
	if err != nil {
		return nil, fmt.Errorf("load browser pairings: %w", err)
	}
	for id, raw := range stored {
		if _, configured := m.connections[id]; !configured {
			continue
		}
		p, err := decodePairing(raw)
		if err != nil {
			return nil, fmt.Errorf("load browser pairing %q: %w", id, err)
		}
		m.pairings[id] = p
	}
	return m, nil
}

func decodePairing(raw []byte) (pairing, error) {
	var stored persistedPairing
	if err := json.Unmarshal(raw, &stored); err != nil || len(stored.Hash) != sha256.Size || stored.Created <= 0 || (stored.Paired && stored.Target == "") {
		return pairing{}, errors.New("invalid persisted pairing")
	}
	var hash [sha256.Size]byte
	copy(hash[:], stored.Hash)
	return pairing{hash: hash, created: time.Unix(stored.Created, 0), target: stored.Target, tabTitle: stored.TabTitle, tabURL: stored.TabURL, paired: stored.Paired, name: stored.Name, install: stored.Install}, nil
}

func (m *Manager) savePairing(ctx context.Context, id string, p pairing) error {
	raw, err := json.Marshal(persistedPairing{Hash: p.hash[:], Created: p.created.Unix(), Target: p.target, TabTitle: p.tabTitle, TabURL: p.tabURL, Paired: p.paired, Name: p.name, Install: p.install})
	if err != nil {
		return err
	}
	return m.store.SaveBrowserPairing(ctx, id, raw)
}

// Binding returns the current extension-and-tab identity included in durable
// operation authority. Re-pairing or sharing another tab changes it.
func (m *Manager) Binding(connection string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.binding(connection)
}

func (m *Manager) binding(connection string) string {
	if _, ok := m.connections[connection]; !ok {
		return ""
	}
	p, ok := m.pairings[connection]
	if !ok {
		return "unpaired"
	}
	return hex.EncodeToString(p.hash[:]) + ":" + p.target
}

// Call dispatches browser calls over the reverse connection and delegates all
// other configured connections to the regular upstream manager.
func (m *Manager) Call(ctx context.Context, connection, tool, expectedBinding string, args map[string]any) (*mcp.CallToolResult, error) {
	m.mu.Lock()
	_, browser := m.connections[connection]
	if browser && tool == "status" {
		status := m.status(connection)
		m.mu.Unlock()
		// Legacy migration details belong to the owner's dashboard, not agents.
		if !status.Connected {
			status.TabTitle, status.TabURL = "", ""
		}
		guidance := "Open the site in your local Chrome and choose Share this tab in the Amp MCP Gateway extension. Prefer your already-authenticated local browser over signing in again in an orb."
		if status.Connected {
			guidance = "Use the explicitly shared local tab. Sharing grants access, not permission to perform unrequested actions."
		} else if !status.Paired || status.Legacy {
			guidance = "Register this browser from /integrations/chrome, then choose Share this tab in the extension."
		}
		raw, err := json.Marshal(map[string]any{"registered": status.Paired && !status.Legacy, "browser_name": status.Account, "sharing": status.Connected, "tab_title": status.TabTitle, "tab_url": status.TabURL, "guidance": guidance})
		if err != nil {
			return nil, err
		}
		return resultToMCP(raw)
	}
	c := m.clients[connection]
	if browser && (m.binding(connection) != expectedBinding || c == nil || !c.sharing || c.binding != expectedBinding) {
		m.mu.Unlock()
		return toolError("Browser share changed or disconnected before dispatch. Open the site in your local Chrome and choose Share this tab in the Amp MCP Gateway extension."), nil
	}
	if !browser {
		m.mu.Unlock()
		return m.fallback.Call(ctx, connection, tool, expectedBinding, args)
	}
	id, pending, err := c.start(tool, args)
	m.mu.Unlock()
	if err != nil {
		if readOnlyTool(tool) {
			return toolError("Browser read failed before returning a result."), nil
		}
		var beforeDispatch *beforeDispatchError
		if errors.As(err, &beforeDispatch) {
			return toolError(beforeDispatch.Error()), nil
		}
		return nil, err
	}
	result, err := c.wait(ctx, id, tool, pending)
	if err != nil {
		if readOnlyTool(tool) {
			return toolError("Browser read failed before returning a result."), nil
		}
		return nil, err
	}
	if result.err != "" {
		return toolError(result.err), nil
	}
	return resultToMCP(result.result)
}

func readOnlyTool(tool string) bool { return tool == "snapshot" || tool == "screenshot" }

func toolError(message string) *mcp.CallToolResult {
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: message}}}
}

func resultToMCP(raw json.RawMessage) (*mcp.CallToolResult, error) {
	var structured any
	if err := json.Unmarshal(raw, &structured); err != nil {
		return nil, fmt.Errorf("decode extension result: %w", err)
	}
	content := []mcp.Content{}
	if object, ok := structured.(map[string]any); ok {
		data, hasData := object["screenshot_data"].(string)
		mime, hasMIME := object["mime_type"].(string)
		if hasData && hasMIME {
			decoded, err := base64.StdEncoding.DecodeString(data)
			if err != nil {
				return nil, errors.New("decode extension screenshot")
			}
			content = append(content, &mcp.ImageContent{Data: decoded, MIMEType: mime})
			delete(object, "screenshot_data")
		}
	}
	text, err := json.Marshal(structured)
	if err != nil {
		return nil, err
	}
	content = append([]mcp.Content{&mcp.TextContent{Text: string(text)}}, content...)
	return &mcp.CallToolResult{Content: content, StructuredContent: structured}, nil
}

// Socket accepts extension WebSockets. Authentication occurs in the first
// message so the pairing secret never appears in a URL or access log.
func (m *Manager) Socket() http.Handler {
	return socketRouter(func(string) *Manager { return m }, m.unauthenticated)
}

// SocketRouter selects an account from the first-message credential. Selection
// is not authentication: the selected manager verifies the entire credential.
func SocketRouter(selectManager func(string) *Manager) http.Handler {
	return socketRouter(selectManager, make(chan struct{}, maxUnauthenticatedSockets))
}

func socketRouter(selectManager func(string) *Manager, unauthenticated chan struct{}) http.Handler {
	upgrader := websocket.Upgrader{
		HandshakeTimeout: 10 * time.Second,
		CheckOrigin: func(r *http.Request) bool {
			return strings.HasPrefix(r.Header.Get("Origin"), "chrome-extension://")
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case unauthenticated <- struct{}{}:
		default:
			http.Error(w, "browser pairing busy", http.StatusServiceUnavailable)
			return
		}
		pendingAuthentication := true
		release := func() {
			if pendingAuthentication {
				<-unauthenticated
				pendingAuthentication = false
			}
		}
		defer release()
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		ws.SetReadLimit(maxHelloSize)
		_ = ws.SetReadDeadline(time.Now().Add(10 * time.Second))
		var hello wireMessage
		if err := ws.ReadJSON(&hello); err != nil || !validHello(hello) {
			ws.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "invalid hello"), time.Now().Add(time.Second))
			ws.Close()
			return
		}
		m := selectManager(hello.PairingCode)
		if m == nil {
			ws.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "pairing rejected"), time.Now().Add(time.Second))
			ws.Close()
			return
		}
		connection, binding, reconnect, ok, err := m.accept(r.Context(), hello)
		if err != nil {
			ws.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseInternalServerErr, "pairing unavailable"), time.Now().Add(time.Second))
			ws.Close()
			return
		}
		if !ok {
			ws.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "pairing rejected"), time.Now().Add(time.Second))
			ws.Close()
			return
		}
		ws.SetReadLimit(maxMessageSize)
		_ = ws.SetReadDeadline(time.Time{})
		release()
		c := &client{manager: m, connection: connection, binding: binding, sharing: hello.ShareID != "", tabTitle: truncate(hello.TabTitle, 200), tabURL: truncate(hello.TabURL, 2000), ws: ws, pending: make(map[string]chan response), closed: make(chan struct{})}
		if !m.install(c) {
			c.revoke()
			return
		}
		m.mu.Lock()
		name := m.pairings[connection].name
		m.mu.Unlock()
		if err := c.write(wireMessage{Type: "paired", Version: hello.Version, Reconnect: reconnect, BrowserName: name}); err != nil {
			c.close()
			return
		}
		c.readLoop()
	})
}

func validHello(h wireMessage) bool {
	if h.Type != "hello" || h.PairingCode == "" || len(h.PairingCode) > 200 || h.InstallID == "" || len(h.InstallID) > 200 || len(h.ShareID) > 200 || len(h.TabTitle) > 200 || len(h.TabURL) > 2000 {
		return false
	}
	if h.Version == 2 && h.ShareID == "" {
		return h.TabID == 0 && h.TabTitle == "" && h.TabURL == ""
	}
	return (h.Version == 0 || h.Version == 2) && h.ShareID != "" && h.TabID > 0
}

func (m *Manager) accept(ctx context.Context, hello wireMessage) (string, string, string, bool, error) {
	hash := sha256.Sum256([]byte(hello.PairingCode))
	targetIdentity, _ := json.Marshal([]any{hello.InstallID, hello.ShareID, hello.TabID})
	target := fmt.Sprintf("%x", sha256.Sum256(targetIdentity))
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, p := range m.pairings {
		if now.Sub(p.created) > pairingTTL && !p.paired {
			if err := m.store.DeleteBrowserPairing(ctx, id); err != nil {
				return "", "", "", false, err
			}
			delete(m.pairings, id)
			continue
		}
		if subtle.ConstantTimeCompare(p.hash[:], hash[:]) != 1 {
			continue
		}
		if p.paired {
			if p.install != "" {
				if hello.Version != 2 || p.install != hello.InstallID {
					return "", "", "", false, nil
				}
			} else if hello.Version != 0 || p.target != target {
				return "", "", "", false, nil
			}
		}
		reconnect := hello.PairingCode
		if !p.paired {
			// Browser registration is separate from granting access to a tab.
			if hello.Version == 2 {
				if hello.ShareID != "" {
					return "", "", "", false, nil
				}
				p.install = hello.InstallID
			}
			var err error
			reconnect, err = randomString(32)
			if err != nil {
				return "", "", "", false, err
			}
			p.hash = sha256.Sum256([]byte(reconnect))
		}
		p.paired = true
		p.target = target
		p.tabTitle = truncate(hello.TabTitle, 200)
		p.tabURL = truncate(hello.TabURL, 2000)
		if err := m.savePairing(ctx, id, p); err != nil {
			return "", "", "", false, err
		}
		m.pairings[id] = p
		return id, m.binding(id), reconnect, true, nil
	}
	return "", "", "", false, nil
}

// MatchesPairing selects the account owning an opaque pairing credential.
// The socket handshake still checks expiry and the paired browser target.
func (m *Manager) MatchesPairing(code string) bool {
	hash := sha256.Sum256([]byte(code))
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, p := range m.pairings {
		if subtle.ConstantTimeCompare(p.hash[:], hash[:]) == 1 {
			return true
		}
	}
	return false
}

func (m *Manager) install(c *client) bool {
	m.mu.Lock()
	if m.binding(c.connection) != c.binding {
		m.mu.Unlock()
		return false
	}
	old := m.clients[c.connection]
	m.clients[c.connection] = c
	m.mu.Unlock()
	if old != nil {
		old.revoke()
	}
	return true
}

func (c *client) revoke() {
	c.writeMu.Lock()
	_ = c.ws.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "pairing revoked"), time.Now().Add(time.Second))
	c.writeMu.Unlock()
	c.close()
}

func (c *client) start(tool string, args map[string]any) (string, <-chan response, error) {
	id, err := randomString(18)
	if err != nil {
		return "", nil, &beforeDispatchError{"Browser command could not be prepared before dispatch."}
	}
	result := make(chan response, 1)
	c.mu.Lock()
	select {
	case <-c.closed:
		c.mu.Unlock()
		return "", nil, &beforeDispatchError{"Browser disconnected before dispatch."}
	default:
	}
	c.pending[id] = result
	c.mu.Unlock()
	if err := c.write(wireMessage{Type: "command", ID: id, Tool: tool, Arguments: args}); err != nil {
		c.remove(id)
		return "", nil, err
	}
	return id, result, nil
}

func (c *client) wait(ctx context.Context, id, tool string, result <-chan response) (response, error) {
	select {
	case <-ctx.Done():
		if c.remove(id) {
			return response{}, ctx.Err()
		}
		return finishResponse(tool, <-result)
	case r := <-result:
		return finishResponse(tool, r)
	}
}

func finishResponse(tool string, r response) (response, error) {
	if r.disconnected {
		return response{}, &OutcomeError{"Browser disconnected before returning an outcome."}
	}
	// The extension sets beforeInput only when it stopped before sending any
	// click, key, focus, scroll or navigation input, so the failure is definite.
	if r.err != "" && !readOnlyTool(tool) && !r.beforeInput {
		return response{}, &OutcomeError{r.err}
	}
	return r, nil
}

func (c *client) write(message wireMessage) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := c.ws.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	return c.ws.WriteJSON(message)
}

func (c *client) readLoop() {
	defer c.close()
	for {
		var message wireMessage
		if err := c.ws.ReadJSON(&message); err != nil {
			return
		}
		if message.Type == "ping" {
			if c.write(wireMessage{Type: "pong"}) != nil {
				return
			}
			continue
		}
		if message.Type == "tab" {
			c.manager.mu.Lock()
			if c.sharing && c.manager.clients[c.connection] == c && c.binding == c.manager.binding(c.connection) {
				c.tabTitle, c.tabURL = truncate(message.TabTitle, 200), truncate(message.TabURL, 2000)
			}
			c.manager.mu.Unlock()
			continue
		}
		if message.Type != "result" || message.ID == "" {
			continue
		}
		c.mu.Lock()
		result := c.pending[message.ID]
		if result != nil {
			result <- response{result: message.Result, err: truncate(message.Error, 1000), beforeInput: message.BeforeInput}
		}
		delete(c.pending, message.ID)
		c.mu.Unlock()
	}
}

func (c *client) remove(id string) bool {
	c.mu.Lock()
	_, found := c.pending[id]
	delete(c.pending, id)
	c.mu.Unlock()
	return found
}

func (c *client) close() {
	c.once.Do(func() {
		c.ws.Close()
		c.mu.Lock()
		for id, result := range c.pending {
			result <- response{disconnected: true}
			delete(c.pending, id)
		}
		close(c.closed)
		c.mu.Unlock()
		c.manager.mu.Lock()
		if c.manager.clients[c.connection] == c {
			delete(c.manager.clients, c.connection)
		}
		c.manager.mu.Unlock()
	})
}

func randomString(bytes int) (string, error) {
	b := make([]byte, bytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func truncate(value string, max int) string {
	if len(value) > max {
		return value[:max]
	}
	return value
}

// Pair replaces any existing browser registration with a named, one-time code.
func (m *Manager) Pair(ctx context.Context, connection, name string) (string, bool, error) {
	m.mu.Lock()
	_, ok := m.connections[connection]
	m.mu.Unlock()
	if !ok {
		return "", false, nil
	}
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 80 {
		return "", true, errors.New("browser name must be between 1 and 80 bytes")
	}
	code, err := randomString(24)
	if err != nil {
		return "", true, err
	}
	hash := sha256.Sum256([]byte(code))
	p := pairing{hash: hash, created: m.now(), name: name}
	m.mu.Lock()
	if err := m.savePairing(ctx, connection, p); err != nil {
		m.mu.Unlock()
		return "", true, err
	}
	old := m.clients[connection]
	delete(m.clients, connection)
	m.pairings[connection] = p
	m.mu.Unlock()
	if old != nil {
		old.revoke()
	}
	return code, true, nil
}

// Revoke removes pairing and disconnects the selected tab.
func (m *Manager) Revoke(ctx context.Context, connection string) (bool, error) {
	m.mu.Lock()
	if _, ok := m.connections[connection]; !ok {
		m.mu.Unlock()
		return false, nil
	}
	if err := m.store.DeleteBrowserPairing(ctx, connection); err != nil {
		m.mu.Unlock()
		return true, err
	}
	old := m.clients[connection]
	delete(m.clients, connection)
	delete(m.pairings, connection)
	m.mu.Unlock()
	if old != nil {
		old.revoke()
	}
	return true, nil
}

// Status describes persisted and live state for one browser connection.
type Status struct {
	ID, Account, TabTitle, TabURL string
	Paired, Connected, Legacy     bool
}

func (m *Manager) status(id string) Status {
	p := m.pairings[id]
	s := Status{ID: id, Account: p.name, Paired: p.paired, Legacy: p.paired && p.install == ""}
	if s.Account == "" {
		s.Account = m.connections[id].Account
	}
	if c := m.clients[id]; c != nil && c.sharing && c.binding == m.binding(id) {
		s.Connected = true
		s.TabTitle, s.TabURL = c.tabTitle, c.tabURL
	} else if s.Legacy {
		s.TabTitle, s.TabURL = p.tabTitle, p.tabURL
	}
	return s
}

// Statuses returns browser connection state for presentation.
func (m *Manager) Statuses() []Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	statuses := make([]Status, 0, len(m.connections))
	for id := range m.connections {
		statuses = append(statuses, m.status(id))
	}
	sort.Slice(statuses, func(i, j int) bool { return statuses[i].ID < statuses[j].ID })
	return statuses
}
