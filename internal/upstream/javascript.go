package upstream

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"ampcode.com/lox/amp-mcp-gateway/internal/jsintegration"
	"ampcode.com/lox/amp-mcp-gateway/internal/jsruntime"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type operationKey struct{}

// WithOperation attaches the claimed ledger ID for broker journaling. Only the
// worker supplies this; neither arguments nor JavaScript can choose a parent.
func WithOperation(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, operationKey{}, id)
}

type attemptStore interface {
	BeginHTTPAttempt(context.Context, string, json.RawMessage) (int, error)
	CompleteHTTPAttempt(context.Context, string, int, json.RawMessage) error
}

var javascriptEngine = sync.OnceValues(func() (*jsruntime.Engine, error) { return jsruntime.New(context.Background()) })

// Fresh connections prevent net/http's transparent retry on a reused socket,
// even for GET. Do not add idempotency keys or replay bodies automatically.
var javascriptTransport http.RoundTripper = func() *http.Transport {
	t := publicTransport.(boundedPublicTransport).transport.(*http.Transport).Clone()
	t.DisableKeepAlives = true
	t.MaxResponseHeaderBytes = 16 << 10
	return t
}()

type httpRequest struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Query   map[string]string `json:"query,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    json.RawMessage   `json:"body,omitempty"`
}

func (m *Manager) callJavaScript(ctx context.Context, c *managedConnection, name, expectedBinding string, args map[string]any) (*mcp.CallToolResult, error) {
	dispatched := false
	result, err := m.runJavaScript(ctx, c, name, expectedBinding, args, &dispatched)
	if err == nil {
		return result, nil
	}
	if dispatched {
		return nil, errors.New("JavaScript operation has no reliable final outcome")
	}
	// Known local failures are failed, not ambiguous upstream effects. Guest and
	// provider diagnostics are deliberately not surfaced through ordinary logs.
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "JavaScript operation failed before HTTP dispatch."}}}, nil
}

func (m *Manager) runJavaScript(ctx context.Context, c *managedConnection, name, expectedBinding string, args map[string]any, dispatched *bool) (*mcp.CallToolResult, error) {
	definition := c.config.JavaScript
	var tool *jsintegration.Tool
	for _, t := range definition.Tools {
		if t.Name == name {
			tool = &t
			break
		}
	}
	if tool == nil {
		return nil, errors.New("unknown JavaScript tool")
	}
	token := os.Getenv(c.config.TokenEnv)
	if token == "" || len(token) > 16<<10 || strings.ContainsAny(token, "\r\n") {
		return nil, errors.New("invalid JavaScript credential")
	}
	binding := definition.Binding(token)
	if binding != expectedBinding {
		return nil, errors.New("JavaScript authority changed")
	}
	journal, ok := m.store.(attemptStore)
	if !ok {
		return nil, errors.New("HTTP journal unavailable")
	}
	parent, _ := ctx.Value(operationKey{}).(string)
	if parent == "" {
		return nil, errors.New("claimed operation required")
	}
	input, err := json.Marshal(args)
	if err != nil || len(input) > jsruntime.MaxInput {
		return nil, errors.New("invalid JavaScript arguments")
	}
	schema, err := jsintegration.CompileSchema(tool.InputSchema)
	if err != nil {
		return nil, err
	}
	if err := schema.Validate(args); err != nil {
		return nil, err
	}
	outputSchema, err := jsintegration.CompileSchema(tool.OutputSchema)
	if err != nil {
		return nil, err
	}
	engine, err := javascriptEngine()
	if err != nil {
		return nil, err
	}
	calls, total := 0, 0
	output, err := engine.Run(ctx, definition.Source, tool.Handler, input, func(ctx context.Context, raw json.RawMessage) (json.RawMessage, error) {
		current, ok := m.connection(c.config.ID)
		if !ok || current != c || definition.Binding(os.Getenv(c.config.TokenEnv)) != binding {
			return nil, errors.New("JavaScript authority changed")
		}
		var request httpRequest
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&request); err != nil {
			return nil, errors.New("invalid HTTP request")
		}
		if !jsintegration.ValidPath(request.Path) {
			return nil, errors.New("invalid HTTP path")
		}
		allowed := false
		for _, grant := range tool.HTTP {
			if grant.Method == request.Method && grant.Path == request.Path {
				allowed = true
			}
		}
		if !allowed || calls >= 10 {
			return nil, errors.New("HTTP capability denied")
		}
		query := url.Values{}
		for k, v := range request.Query {
			query.Set(k, v)
		}
		endpoint := definition.Origin + request.Path
		if len(query) > 0 {
			endpoint += "?" + query.Encode()
		}
		callCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(callCtx, request.Method, endpoint, bytes.NewReader(request.Body))
		if err != nil {
			return nil, err
		}
		for k, v := range request.Headers {
			switch strings.ToLower(k) {
			case "accept", "content-type":
			default:
				return nil, errors.New("HTTP header denied")
			}
			if strings.ContainsAny(v, "\r\n") {
				return nil, errors.New("invalid HTTP header")
			}
			req.Header.Set(k, v)
		}
		if req.Header.Get("Content-Type") == "" && len(request.Body) > 0 {
			req.Header.Set("Content-Type", "application/json")
		}
		sanitized, err := json.Marshal(request)
		if err != nil || len(sanitized) > jsruntime.MaxInput {
			return nil, errors.New("HTTP request exceeds limit")
		}
		total += len(sanitized)
		if total > 4<<20 {
			return nil, errors.New("aggregate HTTP limit exceeded")
		}
		seq, err := journal.BeginHTTPAttempt(ctx, parent, sanitized)
		if err != nil {
			return nil, err
		}
		calls++
		*dispatched = true
		req.Header.Set("Authorization", "Bearer "+token)
		client := http.Client{Transport: javascriptTransport, CheckRedirect: rejectRedirect}
		response, err := client.Do(req)
		if err != nil {
			if response != nil && response.Body != nil {
				response.Body.Close()
			}
			return nil, errors.New("HTTP transport outcome uncertain")
		}
		defer response.Body.Close()
		b, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
		if err != nil || len(b) > 1<<20 {
			return nil, errors.New("invalid or oversized HTTP response")
		}
		total += len(b)
		if total > 4<<20 {
			return nil, errors.New("aggregate HTTP limit exceeded")
		}
		var body any
		if len(b) > 0 {
			if err := json.Unmarshal(b, &body); err != nil {
				return nil, errors.New("HTTP response is not JSON")
			}
		}
		envelope, err := json.Marshal(struct {
			Status int `json:"status"`
			Body   any `json:"body"`
		}{response.StatusCode, body})
		if err != nil {
			return nil, err
		}
		if err := journal.CompleteHTTPAttempt(ctx, parent, seq, envelope); err != nil {
			return nil, err
		}
		return envelope, nil
	})
	if err != nil {
		return nil, err
	}
	var value any
	if err := json.Unmarshal(output, &value); err != nil {
		return nil, err
	}
	if err := outputSchema.Validate(value); err != nil {
		return nil, errors.New("JavaScript output schema mismatch")
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(output)}}}, nil
}
