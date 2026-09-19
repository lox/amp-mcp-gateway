// Command amp-mcp exposes a remote MCP server over local stdio.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const mintTimeout = 10 * time.Second

type tokenMinter func(context.Context, string) (string, error)

type authTransport struct {
	origin *url.URL
	base   http.RoundTripper
	mint   tokenMinter
}

func (t *authTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != t.origin.Scheme || req.URL.Host != t.origin.Host {
		return nil, errors.New("refusing to send gateway credentials to a different origin")
	}
	token, err := t.mint(req.Context(), t.origin.Scheme+"://"+t.origin.Host)
	if err != nil {
		return nil, fmt.Errorf("mint gateway credential: %w", err)
	}
	clone := req.Clone(req.Context())
	clone.Header.Set("Authorization", "Bearer "+token)
	return t.base.RoundTrip(clone)
}

func mintToken(ctx context.Context, audience string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, mintTimeout)
	defer cancel()
	// Output deliberately excludes stderr so a failed command cannot disclose it.
	out, err := exec.CommandContext(ctx, "amp", "orb", "id-token", "--audience", audience, "--ttl-seconds", "600").Output()
	if err != nil {
		return "", errors.New("amp orb id-token failed")
	}
	token := strings.TrimSpace(string(out))
	if token == "" || strings.ContainsAny(token, "\r\n") {
		return "", errors.New("amp orb id-token returned an invalid token")
	}
	return token, nil
}

func parseEndpoint(raw string, allowHTTP bool) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "https" && !(allowHTTP && u.Scheme == "http")) {
		return nil, errors.New("gateway URL must be an absolute HTTPS URL")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "/mcp" {
		return nil, errors.New("gateway URL must contain only the origin and /mcp path")
	}
	return u, nil
}

func newBridge(ctx context.Context, rawURL string, base http.RoundTripper, minter tokenMinter) (*mcp.Server, *mcp.ClientSession, error) {
	u, err := parseEndpoint(rawURL, base != nil)
	if err != nil {
		return nil, nil, err
	}
	if base == nil {
		base = http.DefaultTransport
	}
	client := &http.Client{
		Transport: &authTransport{origin: u, base: base, mint: minter},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	remote := mcp.NewClient(&mcp.Implementation{Name: "amp-mcp", Version: "0.1.0"}, nil)
	session, err := remote.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: u.String(), HTTPClient: client, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("connect gateway: %w", err)
	}
	server := mcp.NewServer(&mcp.Implementation{Name: "amp-mcp", Version: "0.1.0"}, nil)
	var cursor string
	for {
		listed, err := session.ListTools(ctx, &mcp.ListToolsParams{Cursor: cursor})
		if err != nil {
			session.Close()
			return nil, nil, fmt.Errorf("discover gateway tools: %w", err)
		}
		for _, tool := range listed.Tools {
			tool := tool
			server.AddTool(tool, func(callCtx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				return session.CallTool(callCtx, &mcp.CallToolParams{
					Meta: req.Params.Meta, Name: tool.Name, Arguments: req.Params.Arguments,
					InputResponses: req.Params.InputResponses, RequestState: req.Params.RequestState,
				})
			})
		}
		cursor = listed.NextCursor
		if cursor == "" {
			break
		}
	}
	return server, session, nil
}

func run(ctx context.Context, rawURL string, transport mcp.Transport) error {
	server, remote, err := newBridge(ctx, rawURL, nil, mintToken)
	if err != nil {
		return err
	}
	defer remote.Close()
	return server.Run(ctx, transport)
}

func main() {
	rawURL := flag.String("url", "", "HTTPS gateway MCP endpoint")
	flag.Parse()
	if *rawURL == "" {
		fmt.Fprintln(os.Stderr, "amp-mcp: -url is required")
		os.Exit(2)
	}
	if err := run(context.Background(), *rawURL, &mcp.StdioTransport{}); err != nil {
		fmt.Fprintln(os.Stderr, "amp-mcp:", err)
		os.Exit(1)
	}
}
