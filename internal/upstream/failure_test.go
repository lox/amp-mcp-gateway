package upstream

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/oauth2"
)

type diagnosticTransportFunc func(*http.Request) (*http.Response, error)

func (f diagnosticTransportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type diagnosticTestBody struct {
	reader io.Reader
	read   int
	closed bool
}

func (b *diagnosticTestBody) Read(p []byte) (int, error) {
	n, err := b.reader.Read(p)
	b.read += n
	return n, err
}
func (b *diagnosticTestBody) Close() error { b.closed = true; return nil }

func TestHTTPDiagnosticBoundaries(t *testing.T) {
	const rejected = "invalid request: authentication provider rejected request"
	for _, tc := range []struct {
		name, body, contentType, reason string
	}{
		{"Dropbox", rejected + "\n", "text/plain; charset=utf-8", "authentication_rejected"},
		{"token", `{"error":"invalid_token","error_description":"secret-canary"}`, "application/json", "invalid_token"},
		{"scope", `{"error":"insufficient_scope","access_token":"secret-canary"}`, "application/json", "insufficient_scope"},
		{"unknown", "secret-canary", "text/plain", ""},
		{"HTML", rejected, "text/html", ""},
		{"untrusted suffix", rejected + " secret-canary", "text/plain", ""},
		{"nested error", `{"error":{"message":"secret-canary"}}`, "application/json", ""},
		{"limit", rejected + strings.Repeat(" ", 4096-len(rejected)), "text/plain", "authentication_rejected"},
		{"over limit", rejected + strings.Repeat(" ", 4097-len(rejected)), "text/plain", ""},
		{"large", strings.Repeat("secret-canary", 1000), "text/plain", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := &diagnosticTestBody{reader: strings.NewReader(tc.body)}
			calls := 0
			tr := &statusTransport{base: diagnosticTransportFunc(func(*http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: 400, Body: body, Header: http.Header{"Content-Type": {tc.contentType}, "X-Request-Id": {"secret-canary"}}}, nil
			})}
			req, _ := http.NewRequest("POST", "https://example.com/mcp", nil)
			res, err := tr.RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			if body.read > 4097 {
				t.Fatal("unbounded read")
			}
			f := tr.failure("request", errors.New("secret-canary"))
			if tc.reason == "" {
				if f.HTTP != nil {
					t.Fatalf("unexpected details: %+v", f.HTTP)
				}
			} else if f.HTTP == nil || f.HTTP.Reason != tc.reason || f.HTTP.Hint == "" {
				t.Fatalf("missing reason: %+v", f.HTTP)
			}
			raw, _ := json.Marshal(f)
			if strings.Contains(string(raw), "secret-canary") {
				t.Fatal("sensitive data leaked")
			}
			var replay bytes.Buffer
			if _, err := io.Copy(&replay, res.Body); err != nil || replay.String() != tc.body {
				t.Fatal("response changed")
			}
			res.Body.Close()
			if !body.closed || calls != 1 {
				t.Fatal("body not closed or request retried")
			}
			tr.reset()
			if f := tr.failure("request", errors.New("later")); f.HTTP != nil || f.HTTPStatus != 0 {
				t.Fatal("stale failure after reset")
			}
		})
	}
}

func TestHTTPDiagnosticRequestID(t *testing.T) {
	const id = "627206d2959f464d9c48ac656ab05b56"
	for _, tc := range []struct{ host, id, want string }{
		{"mcp.dropbox.com", id, id}, {"example.com", id, ""},
		{"mcp.dropbox.com", "secret-canary", ""}, {"mcp.dropbox.com", strings.Repeat("a", 33), ""},
	} {
		tr := &statusTransport{base: diagnosticTransportFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 500, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{"X-Dropbox-Request-Id": {tc.id}}}, nil
		})}
		req, _ := http.NewRequest("POST", "https://"+tc.host+"/mcp", nil)
		res, err := tr.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		f := tr.failure("request", errors.New("http failure"))
		got := ""
		if f.HTTP != nil {
			got = f.HTTP.RequestID
		}
		if got != tc.want {
			t.Fatalf("id=%q want=%q", got, tc.want)
		}
		if f := tr.failure("request", &oauth2.RetrieveError{}); f.HTTP != nil {
			t.Fatal("attached MCP response to token failure")
		}
	}
}

type diagnosticErrorReader struct{}

func (diagnosticErrorReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestHTTPDiagnosticPreservesReadError(t *testing.T) {
	body := &diagnosticTestBody{reader: io.MultiReader(strings.NewReader("prefix"), diagnosticErrorReader{})}
	tr := &statusTransport{base: diagnosticTransportFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 400, Body: body, Header: http.Header{"Content-Type": {"text/plain"}}}, nil
	})}
	req, _ := http.NewRequest("POST", "https://example.com/mcp", nil)
	res, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(res.Body)
	res.Body.Close()
	if string(data) != "prefix" || !errors.Is(err, io.ErrUnexpectedEOF) || !body.closed {
		t.Fatal("read failure not preserved")
	}
}

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
	t.Run("request HTTP diagnostic", func(t *testing.T) {
		server := mcp.NewServer(&mcp.Implementation{Name: "fixture", Version: "1"}, nil)
		handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{JSONResponse: true})
		var calls atomic.Int32
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				handler.ServeHTTP(w, r)
				return
			}
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Error(err)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			var request struct {
				Method string `json:"method"`
			}
			if err := json.Unmarshal(body, &request); err != nil {
				t.Error(err)
				return
			}
			if request.Method == "tools/call" {
				calls.Add(1)
				http.Error(w, "invalid request: authentication provider rejected request", http.StatusBadRequest)
				return
			}
			handler.ServeHTTP(w, r)
		}))
		defer s.Close()
		m := newTestManager(t, s.URL, Connection{ID: "one", URL: s.URL, NoAuth: true})
		_, err := m.Call(t.Context(), "one", "quota", "", map[string]any{})
		var f *Failure
		if !errors.As(err, &f) || f.Stage != "request" || f.HTTPStatus != 400 || f.HTTP == nil || f.HTTP.Reason != "authentication_rejected" || calls.Load() != 1 {
			t.Fatalf("missing diagnostic or repeated call: %+v, calls=%d", f, calls.Load())
		}
	})
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
		_, err := m.Call(t.Context(), "one", "quota", "", map[string]any{})
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
		_, err := m.Call(t.Context(), "one", "secret-canary", "", map[string]any{})
		var f *Failure
		if !errors.As(err, &f) || f.Stage != "request" || f.Kind != "jsonrpc" || f.RPCCode == nil || *f.RPCCode != -32602 || f.HTTPStatus != 0 {
			t.Fatalf("wrong failure: %#v", f)
		}
	})
	t.Run("credentials", func(t *testing.T) {
		m := newTestManager(t, "http://localhost", Connection{ID: "one", URL: "http://localhost", TokenEnv: "MISSING_DIAGNOSTIC_TEST_TOKEN"})
		t.Setenv("MISSING_DIAGNOSTIC_TEST_TOKEN", "")
		_, err := m.Call(t.Context(), "one", "quota", "", nil)
		var f *Failure
		if !errors.As(err, &f) || f.Stage != "credentials" {
			t.Fatalf("wrong failure: %#v", f)
		}
	})
}
