package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestEndpointValidation(t *testing.T) {
	for _, raw := range []string{
		"http://gateway.example/mcp", "https://user@gateway.example/mcp",
		"https://gateway.example/other", "https://gateway.example/mcp?q=1",
		"https://gateway.example/mcp#fragment",
	} {
		if _, err := parseEndpoint(raw, false); err == nil {
			t.Errorf("parseEndpoint(%q) succeeded", raw)
		}
	}
}

func TestAuthTransportMintFailureDoesNotSend(t *testing.T) {
	var sent atomic.Int32
	u, _ := parseEndpoint("https://gateway.example/mcp", false)
	transport := &authTransport{origin: u, base: roundTripFunc(func(*http.Request) (*http.Response, error) {
		sent.Add(1)
		return nil, errors.New("unexpected")
	}), mint: func(context.Context, string) (string, error) { return "", errors.New("no token") }}
	_, err := transport.RoundTrip(httptest.NewRequest("POST", u.String(), nil))
	if err == nil || sent.Load() != 0 {
		t.Fatalf("err=%v requests=%d", err, sent.Load())
	}
}

func TestAuthTransportRejectsCrossOrigin(t *testing.T) {
	var minted atomic.Int32
	u, _ := parseEndpoint("https://gateway.example/mcp", false)
	transport := &authTransport{origin: u, base: http.DefaultTransport, mint: func(context.Context, string) (string, error) {
		minted.Add(1)
		return "secret", nil
	}}
	_, err := transport.RoundTrip(httptest.NewRequest("GET", "https://evil.example/mcp", nil))
	if err == nil || minted.Load() != 0 {
		t.Fatalf("err=%v mints=%d", err, minted.Load())
	}
}

func TestRedirectRefused(t *testing.T) {
	destinationRequests := atomic.Int32{}
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { destinationRequests.Add(1) }))
	defer destination.Close()
	redirect := httptest.NewServer(http.RedirectHandler(destination.URL, http.StatusTemporaryRedirect))
	defer redirect.Close()
	u, _ := parseEndpoint(redirect.URL+"/mcp", true)
	client := &http.Client{Transport: &authTransport{origin: u, base: http.DefaultTransport, mint: func(context.Context, string) (string, error) { return "secret", nil }}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get(u.String())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusTemporaryRedirect || destinationRequests.Load() != 0 {
		t.Fatalf("status=%d destination requests=%d", resp.StatusCode, destinationRequests.Load())
	}
}

func TestBridgeListsAndCallsWithoutMutatingError(t *testing.T) {
	upstream := mcp.NewServer(&mcp.Implementation{Name: "fixture", Version: "1"}, nil)
	var calls atomic.Int32
	upstream.AddTool(&mcp.Tool{Name: "fail", Description: "fixture", InputSchema: map[string]any{"type": "object"}}, func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		calls.Add(1)
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(req.Params.Arguments)}}, IsError: true}, nil
	})
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return upstream }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	var mu sync.Mutex
	var auth []string
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		auth = append(auth, r.Header.Get("Authorization"))
		mu.Unlock()
		handler.ServeHTTP(w, r)
	}))
	defer httpServer.Close()
	var mint atomic.Int32
	bridge, remote, err := newBridge(t.Context(), httpServer.URL+"/mcp", http.DefaultTransport, func(context.Context, string) (string, error) {
		return "token-" + string(rune('0'+mint.Add(1))), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	go bridge.Run(t.Context(), serverTransport)
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	session, err := client.Connect(t.Context(), clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	tools, err := session.ListTools(t.Context(), nil)
	if err != nil || len(tools.Tools) != 1 || tools.Tools[0].Name != "fail" {
		t.Fatalf("tools=%#v err=%v", tools, err)
	}
	result, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "fail", Arguments: map[string]any{"value": "unchanged"}})
	if err != nil || !result.IsError || len(result.Content) != 1 || !strings.Contains(result.Content[0].(*mcp.TextContent).Text, "unchanged") {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	if calls.Load() != 1 {
		t.Fatalf("upstream tool called %d times", calls.Load())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(auth) < 3 || auth[0] == auth[len(auth)-1] || mint.Load() != int32(len(auth)) {
		t.Fatalf("auth=%v mints=%d", auth, mint.Load())
	}
}
