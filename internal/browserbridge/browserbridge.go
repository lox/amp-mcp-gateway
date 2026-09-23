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
	"html/template"
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
	maxMessageSize = 8 << 20
	pairingTTL     = 10 * time.Minute
)

type backend interface {
	Call(context.Context, string, string, string, map[string]any) (*mcp.CallToolResult, error)
}

// Manager owns browser pairing state and active extension connections. Pairing
// credentials deliberately live only for this process in the first slice.
type Manager struct {
	fallback backend
	baseURL  string

	mu          sync.Mutex
	connections map[string]upstream.Connection
	pairings    map[string]pairing
	clients     map[string]*client
	now         func() time.Time
}

type pairing struct {
	hash     [32]byte
	created  time.Time
	target   string
	tabTitle string
	tabURL   string
	paired   bool
}

type client struct {
	manager    *Manager
	connection string
	binding    string
	ws         *websocket.Conn

	writeMu sync.Mutex
	mu      sync.Mutex
	pending map[string]chan response
	closed  chan struct{}
	once    sync.Once
}

type wireMessage struct {
	Type        string          `json:"type"`
	PairingCode string          `json:"pairing_code,omitempty"`
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
}

type response struct {
	result json.RawMessage
	err    string
}

type beforeDispatchError struct{ message string }

func (e *beforeDispatchError) Error() string { return e.message }

// New creates a browser-aware backend. Non-browser connections are delegated
// to fallback.
func New(baseURL string, connections []upstream.Connection, fallback backend) (*Manager, error) {
	m := &Manager{
		fallback:    fallback,
		baseURL:     strings.TrimRight(baseURL, "/"),
		connections: make(map[string]upstream.Connection),
		pairings:    make(map[string]pairing),
		clients:     make(map[string]*client),
		now:         time.Now,
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
	return m, nil
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
	c := m.clients[connection]
	if browser && (m.binding(connection) != expectedBinding || c == nil || c.binding != expectedBinding) {
		m.mu.Unlock()
		return toolError("Browser pairing changed or disconnected before dispatch."), nil
	}
	if !browser {
		m.mu.Unlock()
		return m.fallback.Call(ctx, connection, tool, "", args)
	}
	id, pending, err := c.start(tool, args)
	m.mu.Unlock()
	if err != nil {
		var beforeDispatch *beforeDispatchError
		if errors.As(err, &beforeDispatch) {
			return toolError(beforeDispatch.Error()), nil
		}
		return nil, err
	}
	result, err := c.wait(ctx, id, tool, pending)
	if err != nil {
		return nil, err
	}
	if result.err != "" {
		return toolError(result.err), nil
	}
	return resultToMCP(result.result)
}

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
	upgrader := websocket.Upgrader{
		HandshakeTimeout: 10 * time.Second,
		CheckOrigin: func(r *http.Request) bool {
			return strings.HasPrefix(r.Header.Get("Origin"), "chrome-extension://")
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		ws.SetReadLimit(maxMessageSize)
		_ = ws.SetReadDeadline(time.Now().Add(10 * time.Second))
		var hello wireMessage
		if err := ws.ReadJSON(&hello); err != nil || hello.Type != "hello" || hello.PairingCode == "" || hello.InstallID == "" || len(hello.InstallID) > 200 || hello.ShareID == "" || len(hello.ShareID) > 200 || hello.TabID <= 0 {
			ws.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "invalid hello"), time.Now().Add(time.Second))
			ws.Close()
			return
		}
		_ = ws.SetReadDeadline(time.Time{})
		connection, binding, ok := m.accept(hello)
		if !ok {
			ws.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "pairing rejected"), time.Now().Add(time.Second))
			ws.Close()
			return
		}
		c := &client{manager: m, connection: connection, binding: binding, ws: ws, pending: make(map[string]chan response), closed: make(chan struct{})}
		m.install(c)
		if err := c.write(wireMessage{Type: "paired"}); err != nil {
			c.close()
			return
		}
		c.readLoop()
	})
}

func (m *Manager) accept(hello wireMessage) (string, string, bool) {
	hash := sha256.Sum256([]byte(hello.PairingCode))
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, p := range m.pairings {
		if now.Sub(p.created) > pairingTTL && !p.paired {
			delete(m.pairings, id)
			continue
		}
		if subtle.ConstantTimeCompare(p.hash[:], hash[:]) != 1 {
			continue
		}
		p.paired = true
		p.target = fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%d", hello.InstallID, hello.ShareID, hello.TabID))))
		p.tabTitle = truncate(hello.TabTitle, 200)
		p.tabURL = truncate(hello.TabURL, 2000)
		m.pairings[id] = p
		return id, m.binding(id), true
	}
	return "", "", false
}

func (m *Manager) install(c *client) {
	m.mu.Lock()
	old := m.clients[c.connection]
	m.clients[c.connection] = c
	m.mu.Unlock()
	if old != nil {
		old.revoke()
	}
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
		c.remove(id)
		return response{}, ctx.Err()
	case <-c.closed:
		c.remove(id)
		return response{}, errors.New("browser disconnected before returning an outcome")
	case r := <-result:
		if r.err != "" && tool != "snapshot" && tool != "screenshot" {
			return response{}, fmt.Errorf("browser %s outcome unknown after extension error: %s", tool, r.err)
		}
		return r, nil
	}
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
		if message.Type != "result" || message.ID == "" {
			continue
		}
		c.mu.Lock()
		result := c.pending[message.ID]
		delete(c.pending, message.ID)
		c.mu.Unlock()
		if result != nil {
			result <- response{result: message.Result, err: truncate(message.Error, 1000)}
		}
	}
}

func (c *client) remove(id string) {
	c.mu.Lock()
	delete(c.pending, id)
	c.mu.Unlock()
}

func (c *client) close() {
	c.once.Do(func() {
		c.ws.Close()
		close(c.closed)
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

// UI serves owner-authenticated pairing and revocation controls. The caller
// supplies authentication and cross-origin protection middleware.
func (m *Manager) UI() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /browser", m.browserPage)
	mux.HandleFunc("POST /browser/pair", m.pair)
	mux.HandleFunc("POST /browser/revoke", m.revoke)
	return mux
}

func (m *Manager) browserPage(w http.ResponseWriter, r *http.Request) {
	m.render(w, browserPageData{Connections: m.statuses()})
}

func (m *Manager) pair(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid pairing request", http.StatusBadRequest)
		return
	}
	connection := r.PostForm.Get("connection")
	m.mu.Lock()
	_, ok := m.connections[connection]
	m.mu.Unlock()
	if !ok {
		http.Error(w, "unknown browser connection", http.StatusBadRequest)
		return
	}
	code, err := randomString(24)
	if err != nil {
		http.Error(w, "pairing unavailable", http.StatusInternalServerError)
		return
	}
	hash := sha256.Sum256([]byte(code))
	m.mu.Lock()
	old := m.clients[connection]
	delete(m.clients, connection)
	m.pairings[connection] = pairing{hash: hash, created: m.now()}
	m.mu.Unlock()
	if old != nil {
		old.revoke()
	}
	m.render(w, browserPageData{Connections: m.statuses(), PairingCode: code, GatewayURL: m.baseURL, PairingConnection: connection})
}

func (m *Manager) revoke(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid revocation request", http.StatusBadRequest)
		return
	}
	connection := r.PostForm.Get("connection")
	m.mu.Lock()
	old := m.clients[connection]
	delete(m.clients, connection)
	delete(m.pairings, connection)
	m.mu.Unlock()
	if old != nil {
		old.revoke()
	}
	http.Redirect(w, r, "/browser", http.StatusSeeOther)
}

type browserStatus struct {
	ID, Account, TabTitle, TabURL string
	Paired, Connected             bool
}

type browserPageData struct {
	Connections       []browserStatus
	PairingCode       string
	PairingConnection string
	GatewayURL        string
}

func (m *Manager) statuses() []browserStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	statuses := make([]browserStatus, 0, len(m.connections))
	for id, connection := range m.connections {
		p, paired := m.pairings[id]
		statuses = append(statuses, browserStatus{ID: id, Account: connection.Account, TabTitle: p.tabTitle, TabURL: p.tabURL, Paired: paired && p.paired, Connected: m.clients[id] != nil})
	}
	sort.Slice(statuses, func(i, j int) bool { return statuses[i].ID < statuses[j].ID })
	return statuses
}

func (m *Manager) render(w http.ResponseWriter, data browserPageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := browserPage.Execute(w, data); err != nil {
		http.Error(w, "render pairing page", http.StatusInternalServerError)
	}
}

var browserPage = template.Must(template.New("browser").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Amp MCP Gateway · Chrome</title><style>
:root{font-family:system-ui,sans-serif;color:#172b26;background:#f6f7f3}*{box-sizing:border-box}body{margin:0}header{background:#153e32;color:#fff;padding:22px max(24px,calc((100vw - 760px)/2))}header a{color:#fff;text-decoration:none;font-size:20px;font-weight:750}main{max-width:760px;margin:40px auto;padding:0 24px}h1{font-size:32px;letter-spacing:-1px;margin-bottom:8px}.sub{color:#586b62;line-height:1.6}.card{background:#fff;border:1px solid #dbe1d9;border-radius:12px;padding:24px;margin:18px 0}button{border:1px solid #216442;border-radius:6px;padding:10px 16px;background:#216442;color:#fff;font:inherit;cursor:pointer}.danger{background:#fff;color:#9f3535;border-color:#d9b7b7}.badge{font:12px ui-monospace,monospace;border-radius:5px;padding:5px 8px;background:#eaf0e8}.connected{background:#dff3e5;color:#175e37}code{font-family:ui-monospace,monospace;overflow-wrap:anywhere}.code{display:block;background:#f2f5ef;padding:16px;border-radius:8px;font-size:14px;margin:14px 0}.row{display:flex;align-items:center;justify-content:space-between;gap:16px}.url{overflow-wrap:anywhere;font-size:13px}form{margin:0}@media(max-width:600px){main{margin-top:24px}.card{padding:16px}.row{align-items:flex-start;flex-direction:column}}
</style></head><body><header><a href="/">Amp MCP Gateway</a></header><main><a href="/">← All activity</a><h1>Share Chrome with an orb.</h1><p class="sub">Pair one explicitly selected tab. The extension connects outbound and can be disconnected here at any time.</p>
{{if .PairingCode}}<div class="card"><strong>Gateway URL</strong><code class="code">{{.GatewayURL}}</code><strong>Pairing code for {{.PairingConnection}}</strong><code class="code">{{.PairingCode}}</code><p class="sub">Paste both values into the extension. The code expires in ten minutes if unused and is shown only on this page.</p></div>{{end}}
{{range .Connections}}<div class="card"><div class="row"><div><strong>{{.Account}}</strong><p><code>{{.ID}}</code> · {{if .Connected}}<span class="badge connected">connected</span>{{else if .Paired}}<span class="badge">offline</span>{{else}}<span class="badge">not paired</span>{{end}}</p>{{if .TabTitle}}<p class="sub">{{.TabTitle}}<br><span class="url">{{.TabURL}}</span></p>{{end}}</div>{{if or .Paired .Connected}}<form method="post" action="/browser/revoke"><input type="hidden" name="connection" value="{{.ID}}"><button class="danger">Disconnect</button></form>{{else}}<form method="post" action="/browser/pair"><input type="hidden" name="connection" value="{{.ID}}"><button>Create pairing code</button></form>{{end}}</div></div>{{else}}<div class="card"><p class="sub">No browser connection is configured.</p></div>{{end}}
</main></body></html>`))
