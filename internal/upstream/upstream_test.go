package upstream

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/oauth2"
)

type memoryStore struct {
	mu    sync.Mutex
	data  map[string][]byte
	saves int
}

func (s *memoryStore) LoadToken(_ context.Context, key string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.data[key]...), nil
}
func (s *memoryStore) SaveToken(_ context.Context, key string, value []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[key] = append([]byte(nil), value...)
	s.saves++
	return nil
}

func TestOAuthStatus(t *testing.T) {
	c := Connection{ID: "oauth", URL: "https://mcp.example.com", OAuth: &OAuthConfig{ClientID: "client", AuthURL: "https://auth.example.com/authorize", TokenURL: "https://auth.example.com/token"}}
	for _, tc := range []struct{ name, raw, want string }{
		{"missing", "", "Not connected"},
		{"saved", `{"access_token":"private-canary"}`, "Connected"},
		{"expired", `{"access_token":"private-canary","expiry":"2000-01-01T00:00:00Z"}`, "Reconnect required"},
		{"refreshable", `{"access_token":"private-canary","refresh_token":"refresh-canary","expiry":"2000-01-01T00:00:00Z"}`, "Connected"},
		{"empty", `{}`, "Not connected"},
		{"corrupt", `invalid`, "Status unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &memoryStore{data: map[string][]byte{}}
			if tc.raw != "" {
				s.data[tokenKey(c)] = []byte(tc.raw)
			}
			m, err := New("https://gateway.example", []Connection{c}, s)
			if err != nil {
				t.Fatal(err)
			}
			if got := m.OAuthStatus(t.Context(), c.ID); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
			if s.saves != 0 {
				t.Fatal("status check changed credentials")
			}
		})
	}
}

func TestEmptyCatalogue(t *testing.T) {
	m, err := New("https://gateway.example", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Call(t.Context(), "unconfigured", "write", nil); err == nil {
		t.Fatal("unconfigured connection accepted")
	}
	mux := http.NewServeMux()
	m.Register(mux)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "/connections/unconfigured/connect", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("unconfigured OAuth route returned %d", w.Code)
	}
}

func TestBearerListAndCall(t *testing.T) {
	t.Setenv("UPSTREAM_TOKEN", "secret")
	type input struct {
		Name string `json:"name"`
	}
	server := mcp.NewServer(&mcp.Implementation{Name: "fixture", Version: "1"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "hello", Description: "greets"}, func(_ context.Context, _ *mcp.CallToolRequest, in input) (*mcp.CallToolResult, map[string]string, error) {
		return nil, map[string]string{"greeting": "hello " + in.Name}, nil
	})
	var badAuth bool
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{JSONResponse: true})
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret" {
			badAuth = true
		}
		handler.ServeHTTP(w, r)
	}))
	defer fixture.Close()
	m := newTestManager(t, fixture.URL, Connection{ID: "one", URL: fixture.URL, TokenEnv: "UPSTREAM_TOKEN"})
	tools, err := m.ListTools(t.Context(), "one")
	if err != nil || len(tools) != 1 || tools[0].Name != "hello" || tools[0].InputSchema == nil {
		t.Fatalf("ListTools() = %#v, %v", tools, err)
	}
	if _, err := m.Call(t.Context(), "one", "hello", map[string]any{"name": "world"}); err != nil {
		t.Fatalf("Call() error = %v", err)
	}
	if badAuth {
		t.Fatal("upstream request omitted bearer token")
	}
}

func TestOAuthRefreshSerializedAndPersisted(t *testing.T) {
	var mu sync.Mutex
	refreshes := 0
	tokens := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		refreshes++
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"fresh","refresh_token":"rotated","token_type":"Bearer","expires_in":3600}`))
	}))
	defer tokens.Close()
	store := &memoryStore{data: make(map[string][]byte)}
	expired, _ := json.Marshal(&oauth2.Token{AccessToken: "old", RefreshToken: "original", Expiry: time.Now().Add(-time.Hour)})
	oauthConn := Connection{ID: "one", URL: "http://localhost/mcp", Account: "acct", OAuth: &OAuthConfig{ClientID: "client", AuthURL: tokens.URL, TokenURL: tokens.URL}}
	store.data[tokenKey(oauthConn)] = expired
	m, err := New("http://localhost", []Connection{oauthConn, {ID: "two", URL: "http://localhost/other", TokenEnv: "UNUSED"}}, store)
	if err != nil {
		t.Fatal(err)
	}
	c := m.conns["one"]
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			source := &persistingTokenSource{manager: m, connection: c}
			token, err := source.Token()
			if err != nil || token.AccessToken != "fresh" {
				t.Errorf("Token() = %#v, %v", token, err)
			}
		}()
	}
	wg.Wait()
	mu.Lock()
	defer mu.Unlock()
	if refreshes != 1 || store.saves != 1 || !strings.Contains(string(store.data[tokenKey(oauthConn)]), "rotated") {
		t.Fatalf("refreshes=%d saves=%d", refreshes, store.saves)
	}
}

func TestChangedEndpointCannotReuseGrant(t *testing.T) {
	c := Connection{ID: "one", URL: "https://original.example/mcp", Account: "owner", OAuth: &OAuthConfig{ClientID: "client", AuthURL: "https://original.example/auth", TokenURL: "https://original.example/token"}}
	raw, err := json.Marshal(&oauth2.Token{AccessToken: "original-grant"})
	if err != nil {
		t.Fatal(err)
	}
	s := &memoryStore{data: map[string][]byte{tokenKey(c): raw}}
	c.URL = "https://replacement.example/mcp"
	m, err := New("https://gateway.example", []Connection{c}, s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.httpClient(t.Context(), m.conns[c.ID]); err == nil {
		t.Fatal("reused grant at changed endpoint")
	}
}

func TestOAuthStateTamperingAndMissingSecret(t *testing.T) {
	store := &memoryStore{data: make(map[string][]byte)}
	c := Connection{ID: "one", URL: "http://localhost/mcp", OAuth: &OAuthConfig{ClientID: "client", ClientSecretEnv: "MISSING_SECRET", AuthURL: "http://localhost/auth", TokenURL: "http://localhost/token"}}
	m, err := New("http://localhost", []Connection{c, {ID: "two", URL: "http://localhost/other", TokenEnv: "UNUSED"}}, store)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	m.Register(mux)
	r := httptest.NewRequest(http.MethodGet, "/connections/one/connect", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing secret status = %d", w.Code)
	}
	t.Setenv("MISSING_SECRET", "present")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	cookie := w.Result().Cookies()[0]
	location, _ := url.Parse(w.Header().Get("Location"))
	callback := httptest.NewRequest(http.MethodGet, "/connections/one/callback?state=tampered&code=x", nil)
	callback.AddCookie(cookie)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, callback)
	if w.Code != http.StatusBadRequest || location.Query().Get("code_challenge_method") != "S256" || store.saves != 0 {
		t.Fatalf("tampered callback status=%d challenge=%q saves=%d", w.Code, location.Query().Get("code_challenge_method"), store.saves)
	}
}

func TestDiscoveryLimits(t *testing.T) {
	for _, tc := range []struct {
		name        string
		count       int
		description int
		wantError   bool
	}{
		{"allowed count", 500, 0, false},
		{"too many tools", 501, 0, true},
		{"allowed size", 1, 1 << 20, false},
		{"oversized definitions", 1, 2 << 20, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := mcp.NewServer(&mcp.Implementation{Name: "fixture", Version: "1"}, nil)
			for i := 0; i < tc.count; i++ {
				server.AddTool(&mcp.Tool{Name: fmt.Sprintf("tool_%d", i), Description: strings.Repeat("x", tc.description), InputSchema: map[string]any{"type": "object"}}, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
					t.Error("discovery executed a tool")
					return &mcp.CallToolResult{}, nil
				})
			}
			fixture := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true}))
			defer fixture.Close()
			m := newTestManager(t, fixture.URL, Connection{ID: "one", URL: fixture.URL, NoAuth: true})
			tools, err := m.ListTools(t.Context(), "one")
			if (err != nil) != tc.wantError || (!tc.wantError && len(tools) != tc.count) {
				t.Fatalf("got %d tools, error %v", len(tools), err)
			}
		})
	}
}

func newTestManager(t *testing.T, endpoint string, first Connection) *Manager {
	t.Helper()
	m, err := New("http://localhost", []Connection{first, {ID: "two", URL: endpoint, TokenEnv: "UPSTREAM_TOKEN"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return m
}
