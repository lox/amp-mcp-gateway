package browserbridge

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"ampcode.com/lox/amp-mcp-gateway/internal/upstream"
	"github.com/gorilla/websocket"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type fallbackBackend struct{ calls int }

func (b *fallbackBackend) Call(_ context.Context, connection, tool, _ string, _ map[string]any) (*mcp.CallToolResult, error) {
	b.calls++
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: connection + "/" + tool}}}, nil
}

func browserManager(t *testing.T) (*Manager, *fallbackBackend) {
	t.Helper()
	fallback := &fallbackBackend{}
	m, err := New("https://gateway.example", []upstream.Connection{
		{ID: "browser", Account: "Selected tab", Browser: true},
		{ID: "remote", URL: "https://remote.example/mcp", Account: "Remote", TokenEnv: "TOKEN"},
	}, fallback)
	if err != nil {
		t.Fatal(err)
	}
	return m, fallback
}

func connectExtension(t *testing.T, m *Manager, code, install, share string, tab int) *websocket.Conn {
	t.Helper()
	hash := sha256.Sum256([]byte(code))
	m.mu.Lock()
	m.pairings["browser"] = pairing{hash: hash, created: time.Now()}
	m.mu.Unlock()
	server := httptest.NewServer(m.Socket())
	t.Cleanup(server.Close)
	header := http.Header{"Origin": []string{"chrome-extension://extension-id"}}
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	ws, _, err := websocket.DefaultDialer.Dial(wsURL, header)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ws.Close() })
	if err := ws.WriteJSON(wireMessage{Type: "hello", PairingCode: code, InstallID: install, ShareID: share, TabID: tab, TabTitle: "Example", TabURL: "https://example.com"}); err != nil {
		t.Fatal(err)
	}
	var paired wireMessage
	if err := ws.ReadJSON(&paired); err != nil || paired.Type != "paired" {
		t.Fatalf("pairing response %#v, %v", paired, err)
	}
	return ws
}

func TestRoutesBrowserCallsOverReverseConnection(t *testing.T) {
	m, fallback := browserManager(t)
	ws := connectExtension(t, m, "pairing-secret", "install-one", "share-one", 42)
	binding := m.Binding("browser")
	if binding == "" || binding == "unpaired" {
		t.Fatalf("missing paired binding %q", binding)
	}

	done := make(chan error, 1)
	go func() {
		var command wireMessage
		if err := ws.ReadJSON(&command); err != nil {
			done <- err
			return
		}
		if command.Type != "command" || command.Tool != "snapshot" || command.Arguments["full"] != true {
			done <- errors.New("unexpected command")
			return
		}
		done <- ws.WriteJSON(wireMessage{Type: "result", ID: command.ID, Result: json.RawMessage(`{"title":"Example","url":"https://example.com"}`)})
	}()

	result, err := m.Call(t.Context(), "browser", "snapshot", binding, map[string]any{"full": true})
	if err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if result.IsError || !strings.Contains(result.Content[0].(*mcp.TextContent).Text, "Example") {
		t.Fatalf("unexpected result %#v", result)
	}
	if fallback.calls != 0 {
		t.Fatal("browser call reached HTTP fallback")
	}

	remote, err := m.Call(t.Context(), "remote", "echo", "", nil)
	if err != nil || remote.Content[0].(*mcp.TextContent).Text != "remote/echo" || fallback.calls != 1 {
		t.Fatalf("fallback result %#v, %v", remote, err)
	}
}

func TestReadErrorIsDefiniteToolFailure(t *testing.T) {
	m, _ := browserManager(t)
	ws := connectExtension(t, m, "pairing-secret", "install-one", "share-one", 42)
	go func() {
		var command wireMessage
		_ = ws.ReadJSON(&command)
		_ = ws.WriteJSON(wireMessage{Type: "result", ID: command.ID, Error: "snapshot unavailable"})
	}()
	result, err := m.Call(t.Context(), "browser", "snapshot", m.Binding("browser"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError || result.Content[0].(*mcp.TextContent).Text != "snapshot unavailable" {
		t.Fatalf("unexpected result %#v", result)
	}
}

func TestMutationErrorHasUnknownOutcome(t *testing.T) {
	m, _ := browserManager(t)
	ws := connectExtension(t, m, "pairing-secret", "install-one", "share-one", 42)
	go func() {
		var command wireMessage
		_ = ws.ReadJSON(&command)
		_ = ws.WriteJSON(wireMessage{Type: "result", ID: command.ID, Error: "input command failed"})
	}()
	result, err := m.Call(t.Context(), "browser", "type", m.Binding("browser"), map[string]any{"backend_node_id": 7, "text": "changed"})
	if err == nil || result != nil || !strings.Contains(err.Error(), "outcome unknown") {
		t.Fatalf("ambiguous mutation returned %#v, %v", result, err)
	}
}

func TestDisconnectAfterDispatchHasUnknownOutcome(t *testing.T) {
	m, _ := browserManager(t)
	ws := connectExtension(t, m, "pairing-secret", "install-one", "share-one", 42)
	go func() {
		var command wireMessage
		_ = ws.ReadJSON(&command)
		ws.Close()
	}()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if result, err := m.Call(ctx, "browser", "click", m.Binding("browser"), map[string]any{"backend_node_id": 7}); err == nil || result != nil {
		t.Fatalf("ambiguous disconnect returned %#v, %v", result, err)
	}
}

func TestReadDisconnectIsDefiniteToolFailure(t *testing.T) {
	m, _ := browserManager(t)
	ws := connectExtension(t, m, "pairing-secret", "install-one", "share-one", 42)
	go func() {
		var command wireMessage
		_ = ws.ReadJSON(&command)
		ws.Close()
	}()
	result, err := m.Call(t.Context(), "browser", "snapshot", m.Binding("browser"), nil)
	if err != nil || result == nil || !result.IsError {
		t.Fatalf("interrupted read returned %#v, %v", result, err)
	}
}

func TestPairingIdentityChangesWithShareGeneration(t *testing.T) {
	m, _ := browserManager(t)
	first := connectExtension(t, m, "pairing-secret", "install-one", "share-one", 42)
	firstBinding := m.Binding("browser")
	first.Close()
	second := connectExtension(t, m, "pairing-secret", "install-one", "share-two", 42)
	if secondBinding := m.Binding("browser"); secondBinding == firstBinding {
		t.Fatal("new share generation did not change operation binding")
	}
	second.Close()
}

func TestUsedPairingCodeCannotReplaceTarget(t *testing.T) {
	m, _ := browserManager(t)
	hash := sha256.Sum256([]byte("pairing-secret"))
	m.pairings["browser"] = pairing{hash: hash, created: time.Now()}
	_, _, reconnect, ok := m.accept(wireMessage{PairingCode: "pairing-secret", InstallID: "install-one", ShareID: "share-one", TabID: 42})
	if !ok || reconnect == "" || reconnect == "pairing-secret" {
		t.Fatal("initial pairing rejected")
	}
	if _, _, _, ok := m.accept(wireMessage{PairingCode: "pairing-secret", InstallID: "install-one", ShareID: "share-one", TabID: 42}); ok {
		t.Fatal("initial pairing code was not consumed")
	}
	if _, _, _, ok := m.accept(wireMessage{PairingCode: reconnect, InstallID: "install-two", ShareID: "share-two", TabID: 84}); ok {
		t.Fatal("used pairing code replaced the paired target")
	}
	if _, _, next, ok := m.accept(wireMessage{PairingCode: reconnect, InstallID: "install-one", ShareID: "share-one", TabID: 42}); !ok || next != reconnect {
		t.Fatal("target-bound reconnect credential was rejected")
	}
}

func TestReceivedResultWinsOverImmediateClose(t *testing.T) {
	c := &client{closed: make(chan struct{})}
	result := make(chan response, 1)
	result <- response{result: json.RawMessage(`{"ok":true}`)}
	close(c.closed)
	for range 100 {
		got, err := c.wait(t.Context(), "command", "click", result)
		if err != nil || string(got.result) != `{"ok":true}` {
			t.Fatalf("received result lost to close: %s, %v", got.result, err)
		}
		result <- got
	}
}

func TestCallRejectsPairingChangedAfterValidation(t *testing.T) {
	m, _ := browserManager(t)
	first := connectExtension(t, m, "first-secret", "install-one", "share-one", 42)
	expected := m.Binding("browser")
	second := connectExtension(t, m, "second-secret", "install-two", "share-two", 84)

	result, err := m.Call(t.Context(), "browser", "click", expected, map[string]any{"backend_node_id": 7})
	if err != nil || result == nil || !result.IsError || !strings.Contains(result.Content[0].(*mcp.TextContent).Text, "before dispatch") {
		t.Fatalf("stale pairing returned %#v, %v", result, err)
	}
	if err := second.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	var command wireMessage
	if err := second.ReadJSON(&command); err == nil {
		t.Fatalf("stale approval dispatched to replacement browser: %#v", command)
	}
	first.Close()
	second.Close()
}

func TestDisconnectedBrowserIsDefinitePreDispatchFailure(t *testing.T) {
	m, _ := browserManager(t)
	hash := sha256.Sum256([]byte("pairing-secret"))
	m.mu.Lock()
	m.pairings["browser"] = pairing{hash: hash, created: time.Now(), paired: true, target: "selected-tab"}
	m.mu.Unlock()

	result, err := m.Call(t.Context(), "browser", "snapshot", m.Binding("browser"), nil)
	if err != nil || result == nil || !result.IsError || !strings.Contains(result.Content[0].(*mcp.TextContent).Text, "before dispatch") {
		t.Fatalf("offline browser returned %#v, %v", result, err)
	}
}

func TestScreenshotBecomesMCPImageContent(t *testing.T) {
	png := base64.StdEncoding.EncodeToString([]byte("fake-png"))
	result, err := resultToMCP(json.RawMessage(`{"mime_type":"image/png","screenshot_data":"` + png + `","url":"https://example.com"}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Content) != 2 || string(result.Content[1].(*mcp.ImageContent).Data) != "fake-png" {
		t.Fatalf("unexpected screenshot content %#v", result.Content)
	}
	if strings.Contains(result.Content[0].(*mcp.TextContent).Text, "screenshot_data") {
		t.Fatal("duplicated screenshot bytes in text content")
	}
}

func TestSocketRejectsWebPageOrigins(t *testing.T) {
	m, _ := browserManager(t)
	server := httptest.NewServer(m.Socket())
	defer server.Close()
	header := http.Header{"Origin": []string{"https://evil.example"}}
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	conn, response, err := websocket.DefaultDialer.Dial(wsURL, header)
	if conn != nil {
		conn.Close()
	}
	if err == nil || response == nil || response.StatusCode != http.StatusForbidden {
		t.Fatalf("web page origin accepted: response %#v, error %v", response, err)
	}
}

func TestRevokeSendsPolicyClose(t *testing.T) {
	m, _ := browserManager(t)
	ws := connectExtension(t, m, "pairing-secret", "install-one", "share-one", 42)
	form := url.Values{"connection": {"browser"}}
	r := httptest.NewRequest(http.MethodPost, "/browser/revoke", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	m.revoke(httptest.NewRecorder(), r)

	if err := ws.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var message wireMessage
	err := ws.ReadJSON(&message)
	var closeErr *websocket.CloseError
	if !errors.As(err, &closeErr) || closeErr.Code != websocket.ClosePolicyViolation {
		t.Fatalf("revocation close = %v, want policy violation", err)
	}
}
