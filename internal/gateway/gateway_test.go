package gateway

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"ampcode.com/lox/mcp-gateway/internal/browserauth"
	"ampcode.com/lox/mcp-gateway/internal/store"
	"ampcode.com/lox/mcp-gateway/internal/upstream"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type fixtureBackend struct {
	calls atomic.Int32
	fail  bool
}

func (b *fixtureBackend) Call(ctx context.Context, connection, tool string, args map[string]any) (*mcp.CallToolResult, error) {
	b.calls.Add(1)
	if b.fail {
		return nil, errors.New("lost response")
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: connection + "/" + tool + ":" + args["text"].(string)}}}, nil
}
func fixture(t *testing.T) (*Gateway, *store.Store, *fixtureBackend) {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "test.db"), base64.StdEncoding.EncodeToString(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	b := &fixtureBackend{}
	cfg := Config{OwnerSubject: "owner", BaseURL: "http://localhost", Connections: []upstream.Connection{{ID: "notes", URL: "http://localhost/mcp", Account: "test account", TokenEnv: "TEST_TOKEN"}}, Tools: []Tool{{ID: "notes.write", Connection: "notes", Name: "write", Policy: "require_approval", InputSchema: map[string]any{"type": "object", "properties": map[string]any{"text": map[string]any{"type": "string"}}, "required": []any{"text"}, "additionalProperties": false}}}}
	g, err := New(cfg, s, b)
	if err != nil {
		t.Fatal(err)
	}
	return g, s, b
}
func input(id, text string) callInput {
	var in callInput
	in.RequestID = id
	in.Calls = append(in.Calls, struct {
		ToolID    string         `json:"tool_id"`
		Arguments map[string]any `json:"arguments"`
	}{"notes.write", map[string]any{"text": text}})
	return in
}
func runWorker(t *testing.T, g *Gateway) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- g.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
}
func await(t *testing.T, s *store.Store, id, status string) store.Operation {
	t.Helper()
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		o, err := s.Get(t.Context(), id)
		if err != nil {
			t.Fatal(err)
		}
		if o.Status == status {
			return o
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("operation did not reach " + status)
	return store.Operation{}
}

func TestApprovalExecutesStoredArgumentsExactlyOnce(t *testing.T) {
	g, s, b := fixture(t)
	runWorker(t, g)
	in := input("request-123", "first value")
	o, err := g.submit(t.Context(), in)
	if err != nil || o.Status != "pending" {
		t.Fatalf("submit %v %v", o, err)
	}
	time.Sleep(300 * time.Millisecond)
	if b.calls.Load() != 0 {
		t.Fatal("executed without approval")
	}
	if _, err := g.submit(t.Context(), input("request-123", "substituted value")); err == nil {
		t.Fatal("argument substitution accepted")
	}
	if err := s.Decide(t.Context(), o.ID, "human", true); err != nil {
		t.Fatal(err)
	}
	done := await(t, s, o.ID, "succeeded")
	if !strings.Contains(string(done.Result), "first value") {
		t.Fatalf("wrong result %s", done.Result)
	}
	if _, err := g.submit(t.Context(), in); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	if b.calls.Load() != 1 {
		t.Fatalf("calls %d", b.calls.Load())
	}
	if err := s.Decide(t.Context(), o.ID, "human", true); err == nil {
		t.Fatal("approval replay accepted")
	}
}

func TestPolicyChangeAndUnknownOutcome(t *testing.T) {
	t.Run("changed account", func(t *testing.T) {
		g, s, b := fixture(t)
		o, err := g.submit(t.Context(), input("account-change", "private"))
		if err != nil {
			t.Fatal(err)
		}
		s.Decide(t.Context(), o.ID, "human", true)
		g.cfg.Connections[0].Account = "different account"
		next, err := New(g.cfg, s, b)
		if err != nil {
			t.Fatal(err)
		}
		runWorker(t, next)
		await(t, s, o.ID, "denied")
		if b.calls.Load() != 0 {
			t.Fatal("stale approval dispatched")
		}
	})
	t.Run("unknown not retried", func(t *testing.T) {
		g, s, b := fixture(t)
		b.fail = true
		in := input("unknown-call", "payload")
		o, err := g.submit(t.Context(), in)
		if err != nil {
			t.Fatal(err)
		}
		s.Decide(t.Context(), o.ID, "human", true)
		runWorker(t, g)
		await(t, s, o.ID, "unknown")
		g.submit(t.Context(), in)
		time.Sleep(300 * time.Millisecond)
		if b.calls.Load() != 1 {
			t.Fatal("unknown call retried")
		}
	})
}

type bearer struct{ token string }

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return http.DefaultTransport.RoundTrip(r)
}
func TestMCPProtocolAndApprovalUI(t *testing.T) {
	g, s, _ := fixture(t)
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	a, err := browserauth.New(t.Context(), browserauth.Config{BaseURL: "http://localhost", SessionKey: key, Demo: true, DemoPassword: "fixture", OwnerSubject: "owner"})
	if err != nil {
		t.Fatal(err)
	}
	m, err := upstream.New("http://localhost", g.cfg.Connections, s)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	a.Register(mux)
	mux.Handle("/mcp", g.MCP("gateway-test-token"))
	mux.Handle("/", g.UI(a, m))
	server := httptest.NewServer(mux)
	defer server.Close()
	r, err := http.Get(server.URL + "/mcp")
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != 401 {
		t.Fatal("MCP missing authentication")
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "integration-client", Version: "1"}, nil)
	session, err := client.Connect(t.Context(), &mcp.StreamableClientTransport{Endpoint: server.URL + "/mcp", HTTPClient: &http.Client{Transport: bearer{"gateway-test-token"}}, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	tools, err := session.ListTools(t.Context(), nil)
	if err != nil || len(tools.Tools) != 3 {
		t.Fatalf("tools %#v %v", tools, err)
	}
	found, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "find_tools", Arguments: map[string]any{"query": "notes"}})
	if err != nil || found.IsError {
		t.Fatalf("discovery %v %v", found, err)
	}
	result, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "call_tools", Arguments: input("protocol-test", "<script>alert(1)</script>")})
	if err != nil || result.IsError {
		t.Fatalf("submission %v %v", result, err)
	}
	bad, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "call_tools", Arguments: map[string]any{"request_id": "invalid-args", "calls": []any{map[string]any{"tool_id": "notes.write", "arguments": map[string]any{"text": 42}}}}})
	if err != nil || !bad.IsError {
		t.Fatal("invalid arguments accepted")
	}
	login := httptest.NewRecorder()
	request := httptest.NewRequest("POST", "/login", strings.NewReader("password=fixture"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	mux.ServeHTTP(login, request)
	cookie := login.Result().Cookies()[0]
	page := httptest.NewRecorder()
	request = httptest.NewRequest("GET", "/operations/protocol-test", nil)
	request.AddCookie(cookie)
	mux.ServeHTTP(page, request)
	if page.Code != 200 || !strings.Contains(page.Body.String(), "Approve once") || strings.Contains(page.Body.String(), "<script>alert") {
		t.Fatalf("unsafe/broken review page: %d", page.Code)
	}
	request = httptest.NewRequest("POST", "/operations/protocol-test/approve", nil)
	request.AddCookie(cookie)
	request.Header.Set("Origin", "https://evil.example")
	res := httptest.NewRecorder()
	mux.ServeHTTP(res, request)
	if res.Code != 403 {
		t.Fatal("cross-origin approval accepted")
	}
	o, _ := s.Get(t.Context(), "protocol-test")
	if o.Status != "pending" {
		t.Fatal(o.Status)
	}
	raw, _ := json.Marshal(found.StructuredContent)
	if !strings.Contains(string(raw), "InputSchema") {
		t.Fatal("missing schema")
	}
}
