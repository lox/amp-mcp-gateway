// Command demo-client calls the local demo without printing its generated bearer token.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"ampcode.com/lox/mcp-gateway/internal/demo"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type bearer string

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+string(b))
	return http.DefaultTransport.RoundTrip(r)
}

func demoHTTPClient(token string) *http.Client {
	return &http.Client{
		Transport: bearer(token),
		// The transport injects credentials on every request, including redirects.
		// Never let a redirect forward the gateway token to another endpoint.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	endpoint := flag.String("url", "http://localhost:8080/mcp", "local demo MCP endpoint")
	tool := flag.String("tool", "find_tools", "gateway tool name")
	arguments := flag.String("args", `{"query":""}`, "tool arguments JSON")
	flag.Parse()
	raw, err := os.ReadFile(".local/demo-secrets.json")
	if err != nil {
		return err
	}
	var secrets demo.Secrets
	if err := json.Unmarshal(raw, &secrets); err != nil {
		return err
	}
	var args map[string]any
	if err := json.Unmarshal([]byte(*arguments), &args); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	client := mcp.NewClient(&mcp.Implementation{Name: "demo-client", Version: "1"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: *endpoint, HTTPClient: demoHTTPClient(secrets.GatewayToken), MaxRetries: -1, DisableStandaloneSSE: true}, nil)
	if err != nil {
		return err
	}
	defer session.Close()
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: *tool, Arguments: args})
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		return err
	}
	if result.IsError {
		return fmt.Errorf("tool reported an error")
	}
	return nil
}
