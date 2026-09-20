// Package gateway provides the policy-controlled MCP endpoint and approval UI.
package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"ampcode.com/lox/mcp-gateway/internal/browserauth"
	"ampcode.com/lox/mcp-gateway/internal/store"
	"ampcode.com/lox/mcp-gateway/internal/upstream"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// Tool pins a reviewed definition. An empty Policy inherits its connection default.
type Tool struct {
	ID, Connection, Name, Description, Policy string
	InputSchema                               map[string]any
}

// Config holds non-secret configuration. Secrets are supplied by environment variables.
type Config struct {
	Listen, BaseURL, Database, OwnerSubject, Issuer, ClientID string
	AmpUserID, HostedDomain                                   string
	Connections                                               []upstream.Connection
	Tools                                                     []Tool
	ToolDefaults                                              map[string]string `json:",omitempty"`
}

// Backend is the upstream transport boundary.
type Backend interface {
	Call(context.Context, string, string, map[string]any) (*mcp.CallToolResult, error)
}

// Gateway owns validated tools and execution policy.
type Gateway struct {
	mu        sync.RWMutex // catalogue publication, submission and discovery snapshots
	cfg       Config
	store     *store.Store
	backend   Backend
	tools     map[string]Tool
	schemas   map[string]*jsonschema.Schema
	bindings  map[string]string
	drafts    map[string]toolDraft
	proposals map[string]policyProposal
}

// New validates and compiles the pinned tool catalogue.
func New(cfg Config, s *store.Store, b Backend) (*Gateway, error) {
	g := &Gateway{cfg: cfg, store: s, backend: b, tools: map[string]Tool{}, schemas: map[string]*jsonschema.Schema{}, bindings: map[string]string{}}
	for _, policy := range cfg.ToolDefaults {
		if !validPolicy(policy) {
			return nil, errors.New("invalid connection default")
		}
	}
	for _, t := range cfg.Tools {
		if t.ID == "" || t.Name == "" || t.InputSchema == nil {
			return nil, errors.New("tool ID, name and input schema required")
		}
		if _, ok := g.tools[t.ID]; ok {
			return nil, errors.New("duplicate tool ID")
		}
		if t.Policy == "" {
			t.Policy = cfg.defaultPolicy(t.Connection)
		}
		if !validPolicy(t.Policy) {
			return nil, fmt.Errorf("invalid policy for %s", t.ID)
		}
		var connection *upstream.Connection
		for _, c := range cfg.Connections {
			if c.ID == t.Connection {
				connection = &c
				break
			}
		}
		if connection == nil {
			return nil, fmt.Errorf("unknown connection for %s", t.ID)
		}
		compiler := jsonschema.NewCompiler()
		// Upstream schemas are untrusted: only references within this document are allowed.
		compiler.UseLoader(jsonschema.SchemeURLLoader{})
		if err := compiler.AddResource("schema.json", t.InputSchema); err != nil {
			return nil, err
		}
		schema, err := compiler.Compile("schema.json")
		if err != nil {
			return nil, err
		}
		g.schemas[t.ID] = schema
		g.tools[t.ID] = t
		g.bindings[t.ID] = digest([]any{t, connection, cfg.OwnerSubject, cfg.Issuer, cfg.ClientID, cfg.AmpUserID, cfg.HostedDomain, os.Getenv(connection.TokenEnv)})
	}
	return g, nil
}

func digest(v any) string {
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

type findInput struct {
	Query string `json:"query"`
}
type callInput struct {
	RequestID string `json:"request_id" jsonschema:"Unique idempotency key. Reuse only for the exact same request."`
	Calls     []struct {
		ToolID    string         `json:"tool_id"`
		Arguments map[string]any `json:"arguments"`
	} `json:"calls" jsonschema:"Exactly one call is supported in this first version."`
	ModelReported string `json:"model_reported,omitempty" jsonschema:"Optional unverified model label. Never used for authorization."`
}
type getInput struct {
	ID string `json:"id"`
}
type operationResult struct {
	ID          string          `json:"id"`
	Status      string          `json:"status"`
	ApprovalURL string          `json:"approval_url"`
	Result      json.RawMessage `json:"result,omitempty"`
}

func (g *Gateway) result(o store.Operation) operationResult {
	return operationResult{ID: o.ID, Status: o.Status, ApprovalURL: g.cfg.BaseURL + "/operations/" + o.ID, Result: o.Result}
}

// MCP serves execution and policy proposal tools behind a revocable owner bearer token.
func (g *Gateway) MCP(token string) http.Handler {
	h := g.mcpHandler()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if g.cfg.AmpUserID != "" || token == "" || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+token)) != 1 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "unauthorized", 401)
			return
		}
		h.ServeHTTP(w, r)
	})
}

func (g *Gateway) mcpHandler() http.Handler {
	s := mcp.NewServer(&mcp.Implementation{Name: "mcp-gateway", Version: "0.1.0"}, nil)
	mcp.AddTool(s, &mcp.Tool{Name: "propose_policy_changes", Description: "Prepare an immutable batch of connection default and tool exception changes for human browser review. Never applies policies. Use exact saved tool IDs; omitted settings stay unchanged. Policies: allow, require_approval, deny; tool exceptions also accept inherit. Review expires in ten minutes."}, func(ctx context.Context, r *mcp.CallToolRequest, in policyInput) (*mcp.CallToolResult, any, error) {
		out, err := g.proposePolicies(ctx, in)
		return nil, out, err
	})
	mcp.AddTool(s, &mcp.Tool{Name: "find_tools", Description: "Search the permitted pinned tool catalogue. Returns schemas and approval policies."}, func(ctx context.Context, r *mcp.CallToolRequest, in findInput) (*mcp.CallToolResult, any, error) {
		g.mu.RLock()
		defer g.mu.RUnlock()
		out := []Tool{}
		words := strings.Fields(strings.ToLower(in.Query))
		for _, t := range g.tools {
			if t.Policy == "deny" {
				continue
			}
			hay := strings.ToLower(t.ID + " " + t.Description)
			match := true
			for _, w := range words {
				if !strings.Contains(hay, w) {
					match = false
				}
			}
			if match {
				out = append(out, t)
			}
		}
		sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
		return nil, map[string]any{"tools": out}, nil
	})
	mcp.AddTool(s, &mcp.Tool{Name: "call_tools", Description: "Submit exactly one operation. Never resubmit with a new request_id after an ambiguous response. Pending writes need browser approval; poll get_operation."}, func(ctx context.Context, r *mcp.CallToolRequest, in callInput) (*mcp.CallToolResult, any, error) {
		o, err := g.submit(ctx, in)
		if err != nil {
			return nil, nil, err
		}
		return nil, g.result(o), nil
	})
	mcp.AddTool(s, &mcp.Tool{Name: "get_operation", Description: "Read durable status and upstream result by operation ID. Unknown means do not automatically retry."}, func(ctx context.Context, r *mcp.CallToolRequest, in getInput) (*mcp.CallToolResult, any, error) {
		o, err := g.store.Get(ctx, in.ID)
		if err != nil {
			return nil, nil, errors.New("operation unavailable")
		}
		return nil, g.result(o), nil
	})
	return mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true, MaxRequestBodyBytes: 1 << 20})
}

var requestID = regexp.MustCompile(`^[a-zA-Z0-9_-]{8,100}$`)

func (g *Gateway) submit(ctx context.Context, in callInput) (store.Operation, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	identity, _ := ctx.Value(ampIdentityKey{}).(ampIdentity)
	if g.cfg.AmpUserID != "" && (identity.UserID != g.cfg.AmpUserID || !ampThreadID.MatchString(identity.ThreadID)) {
		return store.Operation{}, errors.New("verified Amp identity required")
	}
	if !requestID.MatchString(in.RequestID) || len(in.Calls) != 1 || len(in.ModelReported) > 200 {
		return store.Operation{}, errors.New("supply an 8–100 character request_id and exactly one call")
	}
	c := in.Calls[0]
	t, ok := g.tools[c.ToolID]
	if !ok {
		return store.Operation{}, errors.New("unknown tool")
	}
	if c.Arguments == nil {
		c.Arguments = map[string]any{}
	}
	if err := g.schemas[t.ID].Validate(c.Arguments); err != nil {
		return store.Operation{}, errors.New("arguments do not match pinned tool schema")
	}
	status := "ready"
	if t.Policy == "require_approval" {
		status = "pending"
	}
	if t.Policy == "deny" {
		status = "denied"
	}
	account := ""
	for _, conn := range g.cfg.Connections {
		if conn.ID == t.Connection {
			account = conn.Account
		}
	}
	o := store.Operation{ID: in.RequestID, Tool: t.ID, Connection: t.Connection, Account: account, Subject: g.cfg.OwnerSubject, Model: in.ModelReported, Arguments: c.Arguments, Binding: g.bindings[t.ID], Status: status, Created: time.Now().Unix(), Expires: time.Now().Add(10 * time.Minute).Unix()}
	o.AmpUserID, o.AmpThreadID = identity.UserID, identity.ThreadID
	o.Digest = digest([]any{o.Tool, o.Arguments, o.Binding, o.Model, o.AmpUserID, o.AmpThreadID})
	return g.store.Submit(ctx, o)
}

// Run executes persisted requests serially until ctx is cancelled. It never retries dispatch.
func (g *Gateway) Run(ctx context.Context) error {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			o, err := g.store.Claim(ctx)
			if errors.Is(err, sql.ErrNoRows) {
				continue
			}
			if err != nil {
				return fmt.Errorf("claim operation: %w", err)
			}
			g.mu.RLock()
			t, ok := g.tools[o.Tool]
			valid := ok && t.Policy != "deny" && g.bindings[o.Tool] == o.Binding
			g.mu.RUnlock()
			if !valid {
				if err := g.store.Finish(ctx, o, "denied", nil); err != nil {
					return err
				}
				continue
			}
			callCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
			result, callErr := g.backend.Call(callCtx, t.Connection, t.Name, o.Arguments)
			cancel()
			status := "succeeded"
			var raw json.RawMessage
			if callErr != nil {
				status = "unknown"
				var diagnostic *upstream.Failure
				errors.As(callErr, &diagnostic)
				raw, err = json.Marshal(struct {
					Message    string            `json:"message"`
					Diagnostic *upstream.Failure `json:"diagnostic,omitempty"`
				}{"No reliable upstream outcome. Inspect the upstream before retrying.", diagnostic})
				if err != nil {
					return err
				}
			} else {
				raw, err = json.Marshal(result)
				if err != nil {
					return err
				}
				if result.IsError {
					status = "failed"
				}
			}
			persistCtx, done := context.WithTimeout(context.Background(), 5*time.Second)
			err = g.store.Finish(persistCtx, o, status, raw)
			done()
			if err != nil {
				return fmt.Errorf("persist outcome: %w", err)
			}
		}
	}
}

// UI returns the owner-authenticated server-rendered review and audit interface.
func (g *Gateway) UI(auth *browserauth.Auth, m *upstream.Manager) http.Handler {
	mux := http.NewServeMux()
	m.Register(mux)
	g.registerConnections(mux, m)
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) { g.dashboard(w, r, m) })
	mux.HandleFunc("GET /operations/{id}", g.operation)
	mux.HandleFunc("POST /operations/{id}/{decision}", func(w http.ResponseWriter, r *http.Request) {
		decision := r.PathValue("decision")
		if decision != "approve" && decision != "deny" {
			http.NotFound(w, r)
			return
		}
		if err := g.store.Decide(r.Context(), r.PathValue("id"), browserauth.Subject(r.Context()), decision == "approve"); err != nil {
			http.Error(w, "Operation expired or already decided.", 409)
			return
		}
		http.Redirect(w, r, "/operations/"+r.PathValue("id"), 303)
	})
	return auth.Require(http.NewCrossOriginProtection().Handler(mux))
}

func (g *Gateway) dashboard(w http.ResponseWriter, r *http.Request, m *upstream.Manager) {
	ops, err := g.store.List(r.Context())
	if err != nil {
		http.Error(w, "ledger unavailable", 503)
		return
	}
	events, err := g.store.Events(r.Context())
	if err != nil {
		http.Error(w, "audit unavailable", 503)
		return
	}
	g.mu.RLock()
	connections := make([]map[string]any, 0, len(g.cfg.Connections))
	for _, c := range g.cfg.Connections {
		connections = append(connections, map[string]any{"ID": c.ID, "Account": c.Account, "OAuth": c.OAuth != nil})
	}
	g.mu.RUnlock()
	for _, c := range connections {
		c["Health"] = m.Health(r.Context(), c["ID"].(string))
	}
	g.render(w, map[string]any{"Operations": ops, "Events": events, "Connections": connections, "Owner": g.cfg.OwnerSubject})
}
func (g *Gateway) operation(w http.ResponseWriter, r *http.Request) {
	o, err := g.store.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	args, _ := json.MarshalIndent(o.Arguments, "", "  ")
	var result struct {
		Content    []json.RawMessage `json:"content"`
		Structured json.RawMessage   `json:"structuredContent"`
	}
	var blocks []string
	if json.Unmarshal(o.Result, &result) == nil {
		if len(result.Structured) > 0 {
			blocks = append(blocks, prettyJSON(result.Structured))
		}
		for _, raw := range result.Content {
			var block struct {
				Type string `json:"type"`
				Text string `json:"text"`
			}
			if json.Unmarshal(raw, &block) == nil && block.Type == "text" {
				text := prettyJSON([]byte(block.Text))
				if len(result.Structured) == 0 || text != prettyJSON(result.Structured) {
					blocks = append(blocks, text)
				}
			} else {
				blocks = append(blocks, prettyJSON(raw))
			}
		}
	}
	if len(blocks) == 0 && len(o.Result) > 0 {
		blocks = append(blocks, prettyJSON(o.Result))
	}
	name := strings.TrimPrefix(o.Tool, o.Connection+".")
	name = strings.ReplaceAll(name, "_", " ")
	g.render(w, map[string]any{"Operation": o, "Title": name, "ResultBlocks": blocks, "RawResult": prettyJSON(o.Result), "Arguments": string(args), "Owner": g.cfg.OwnerSubject})
}

// Indent without decoding numbers through float64 or dropping unknown fields.
func prettyJSON(raw []byte) string {
	var out bytes.Buffer
	if json.Indent(&out, raw, "", "  ") == nil {
		return out.String()
	}
	return string(raw)
}

func (g *Gateway) render(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := page.Execute(w, data); err != nil {
		slog.Error("render page", "error", err)
	}
}
