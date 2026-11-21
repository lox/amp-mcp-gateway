package upstream

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ampcode.com/lox/amp-mcp-gateway/internal/jsintegration"
	"ampcode.com/lox/amp-mcp-gateway/internal/store"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestJavaScriptHTTPAuthority(t *testing.T) {
	t.Setenv("JS_BROKER_TOKEN", "fake-broker-token")
	for _, tt := range []struct {
		name, request string
		allowed       bool
	}{
		{"granted", `{"method":"POST","path":"/allowed","body":{"x":3}}`, true},
		{"wrong method", `{"method":"DELETE","path":"/allowed"}`, false},
		{"wrong path", `{"method":"POST","path":"/other"}`, false},
		{"absolute URL", `{"method":"POST","path":"https://evil.example/allowed"}`, false},
		{"network path", `{"method":"POST","path":"//evil.example/allowed"}`, false},
		{"encoded traversal", `{"method":"POST","path":"/allowed/%2e%2e/private"}`, false},
		{"traversal", `{"method":"POST","path":"/allowed/../private"}`, false},
		{"query in path", `{"method":"POST","path":"/allowed?admin=1"}`, false},
		{"auth header", `{"method":"POST","path":"/allowed","headers":{"Authorization":"Bearer selected-by-js"}}`, false},
		{"host header", `{"method":"POST","path":"/allowed","headers":{"Host":"evil.example"}}`, false},
		{"cookies", `{"method":"POST","path":"/allowed","headers":{"cookie":"secret"}}`, false},
		{"account selector", `{"method":"POST","path":"/allowed","account":"other-owner"}`, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s, err := store.Open(filepath.Join(t.TempDir(), "ledger.db"), base64.StdEncoding.EncodeToString(make([]byte, 32)))
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			o := store.Operation{ID: "broker-test", Status: "running", Created: time.Now().Unix(), Expires: time.Now().Add(time.Minute).Unix()}
			if _, err := s.Submit(t.Context(), o); err != nil {
				t.Fatal(err)
			}
			definition := &jsintegration.Definition{Origin: "https://api.example.com", Source: `export async function run(a,ctx){await ctx.http.request(` + tt.request + `); return 7}`, Tools: []jsintegration.Tool{{Name: "run", Handler: "run", InputSchema: map[string]any{"type": "object"}, OutputSchema: map[string]any{"type": "integer"}, HTTP: []jsintegration.Grant{{Method: "POST", Path: "/allowed"}}}}}
			m, err := New("http://localhost", []Connection{{ID: "js", TokenEnv: "JS_BROKER_TOKEN", JavaScript: definition}}, s)
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			old := javascriptTransport
			javascriptTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.URL.String() != "https://api.example.com/allowed" || r.Header.Get("Authorization") != "Bearer fake-broker-token" {
					t.Errorf("wrong authenticated destination %s", r.URL)
				}
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{}`)), Request: r}, nil
			})
			defer func() { javascriptTransport = old }()
			result, err := m.Call(WithOperation(t.Context(), o.ID), "js", "run", definition.Binding("fake-broker-token"), map[string]any{})
			if err != nil || result == nil || result.IsError == tt.allowed {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			attempts, err := s.HTTPAttempts(t.Context(), o.ID)
			if err != nil {
				t.Fatal(err)
			}
			expected := 0
			if tt.allowed {
				expected = 1
			}
			if calls != expected || len(attempts) != expected {
				t.Fatalf("calls=%d journal=%d expected=%d", calls, len(attempts), expected)
			}
		})
	}
}

func TestJavaScriptHTTPNeverRedirectsOrReplays(t *testing.T) {
	t.Setenv("JS_BROKER_TOKEN", "fake-broker-token")
	for _, mode := range []string{"redirect", "lost", "oversized", "too many"} {
		t.Run(mode, func(t *testing.T) {
			s, err := store.Open(filepath.Join(t.TempDir(), "ledger.db"), base64.StdEncoding.EncodeToString(make([]byte, 32)))
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			o := store.Operation{ID: "broker-limits", Status: "running", Created: time.Now().Unix(), Expires: time.Now().Add(time.Minute).Unix()}
			if _, err := s.Submit(t.Context(), o); err != nil {
				t.Fatal(err)
			}
			definition := &jsintegration.Definition{Origin: "https://api.example.com", Source: `export async function run(a,ctx){for(let i=0;i<11;i++) await ctx.http.request({method:'GET',path:'/allowed'}); return 7}`, Tools: []jsintegration.Tool{{Name: "run", Handler: "run", InputSchema: map[string]any{"type": "object"}, OutputSchema: map[string]any{"type": "integer"}, HTTP: []jsintegration.Grant{{Method: "GET", Path: "/allowed"}}}}}
			if mode == "redirect" {
				definition.Source = `export async function run(a,ctx) {const r=await ctx.http.request({method:'GET',path:'/allowed'});return r.status}`
			}
			m, err := New("http://localhost", []Connection{{ID: "js", TokenEnv: "JS_BROKER_TOKEN", JavaScript: definition}}, s)
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			old := javascriptTransport
			javascriptTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				if mode == "lost" {
					return nil, errors.New("lost after possible write")
				}
				status := 200
				header := make(http.Header)
				body := `{}`
				if mode == "redirect" {
					status = 302
					header.Set("Location", "https://evil.example/steal")
				}
				if mode == "oversized" {
					body = `"` + strings.Repeat("x", 1<<20) + `"`
				}
				return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
			})
			defer func() { javascriptTransport = old }()
			result, err := m.Call(WithOperation(context.Background(), o.ID), "js", "run", definition.Binding("fake-broker-token"), map[string]any{})
			if mode == "redirect" {
				if err != nil || result == nil || result.IsError {
					t.Fatalf("redirect status not returned as data: %+v %v", result, err)
				}
			} else if err == nil || result != nil {
				t.Fatalf("possible dispatch did not remain unknown: %+v %v", result, err)
			}
			want := 1
			if mode == "too many" {
				want = 10
			}
			if calls != want {
				t.Fatalf("requests=%d expected=%d", calls, want)
			}
			attempts, err := s.HTTPAttempts(t.Context(), o.ID)
			if err != nil || len(attempts) != want {
				t.Fatalf("attempts=%d err=%v", len(attempts), err)
			}
		})
	}
}
