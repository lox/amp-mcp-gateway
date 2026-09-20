package upstream

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/oauth2"
)

func TestFailureRedactsProviderDetails(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		status int
		kind   string
		http   int
		rpc    int64
	}{
		{"arbitrary", errors.New("secret-canary"), 0, "other", 0, 0},
		{"timeout", fmt.Errorf("secret-canary: %w", context.DeadlineExceeded), 0, "timeout", 0, 0},
		{"cancelled", context.Canceled, 0, "cancelled", 0, 0},
		{"http", errors.New("secret-canary"), 403, "http", 403, 0},
		{"oauth", &oauth2.RetrieveError{Response: &http.Response{StatusCode: 401}, Body: []byte("secret-canary"), ErrorDescription: "secret-canary"}, 0, "oauth_token", 401, 0},
		{"rpc", &jsonrpc.Error{Code: -32602, Message: "secret-canary", Data: json.RawMessage(`"secret-canary"`)}, 0, "jsonrpc", 0, -32602},
		{"rpc zero", &jsonrpc.Error{Code: 0, Message: "secret-canary"}, 0, "jsonrpc", 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := failure("request", tc.err, tc.status)
			var f *Failure
			if !errors.As(err, &f) || f.Stage != "request" || f.Kind != tc.kind || f.HTTPStatus != tc.http {
				t.Fatalf("incorrect diagnostic: %#v", f)
			}
			raw, errJSON := json.Marshal(f)
			if errJSON != nil {
				t.Fatal(errJSON)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(raw, &fields); err != nil {
				t.Fatal(err)
			}
			code, present := fields["rpc_code"]
			if present != (tc.kind == "jsonrpc") || (present && string(code) != fmt.Sprint(tc.rpc)) {
				t.Fatalf("incorrect serialized RPC code: %s", raw)
			}
			if strings.Contains(string(raw)+err.Error(), "secret-canary") {
				t.Fatal("provider details leaked")
			}
			if !errors.Is(err, tc.err) {
				t.Fatal("original error not preserved internally")
			}
		})
	}
}

func TestSessionFailureStage(t *testing.T) {
	t.Run("connect HTTP", func(t *testing.T) {
		var calls atomic.Int32
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var request struct {
				Method string `json:"method"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Error(err)
			}
			if request.Method == "tools/call" {
				calls.Add(1)
			}
			http.Error(w, "secret-canary", http.StatusUnauthorized)
		}))
		defer s.Close()
		m := newTestManager(t, s.URL, Connection{ID: "one", URL: s.URL, NoAuth: true})
		_, err := m.Call(t.Context(), "one", "quota", map[string]any{})
		var f *Failure
		if !errors.As(err, &f) || f.Stage != "connect" || f.Kind != "http" || f.HTTPStatus != 401 {
			t.Fatalf("wrong failure: %#v", f)
		}
		if calls.Load() != 0 {
			t.Fatalf("dispatched %d tool calls after failed initialization", calls.Load())
		}
	})
	t.Run("request RPC", func(t *testing.T) {
		server := mcp.NewServer(&mcp.Implementation{Name: "fixture", Version: "1"}, nil)
		s := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{JSONResponse: true}))
		defer s.Close()
		m := newTestManager(t, s.URL, Connection{ID: "one", URL: s.URL, NoAuth: true})
		_, err := m.Call(t.Context(), "one", "secret-canary", map[string]any{})
		var f *Failure
		if !errors.As(err, &f) || f.Stage != "request" || f.Kind != "jsonrpc" || f.RPCCode == nil || *f.RPCCode != -32602 || f.HTTPStatus != 0 {
			t.Fatalf("wrong failure: %#v", f)
		}
	})
	t.Run("credentials", func(t *testing.T) {
		m := newTestManager(t, "http://localhost", Connection{ID: "one", URL: "http://localhost", TokenEnv: "MISSING_DIAGNOSTIC_TEST_TOKEN"})
		t.Setenv("MISSING_DIAGNOSTIC_TEST_TOKEN", "")
		_, err := m.Call(t.Context(), "one", "quota", nil)
		var f *Failure
		if !errors.As(err, &f) || f.Stage != "credentials" {
			t.Fatalf("wrong failure: %#v", f)
		}
	})
}
