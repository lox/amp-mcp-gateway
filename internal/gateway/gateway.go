// Package gateway provides the policy-controlled MCP endpoint and approval UI.
package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"ampcode.com/lox/amp-mcp-gateway/internal/browserauth"
	"ampcode.com/lox/amp-mcp-gateway/internal/fly"
	"ampcode.com/lox/amp-mcp-gateway/internal/policy"
	"ampcode.com/lox/amp-mcp-gateway/internal/store"
	"ampcode.com/lox/amp-mcp-gateway/internal/upstream"
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
	Listen, BaseURL, Database string
	AmpUserID                 string
	AccountPage               bool `json:"-"`
	Demo                      bool `json:"-"`
	Connections               []upstream.Connection
	Integrations              []Integration `json:",omitempty"`
	Tools                     []Tool
	ToolDefaults              map[string]string `json:",omitempty"`
	PrivateConnections        map[string]bool   `json:",omitempty"`
}

// Backend is the upstream transport boundary.
type Backend interface {
	Call(context.Context, string, string, string, map[string]any) (*mcp.CallToolResult, error)
	Binding(string) string
}

// Gateway owns validated tools and execution policy.
type Gateway struct {
	// ProjectNames optionally enriches browser pages. Set before serving.
	ProjectNames func(context.Context) browserauth.ProjectNames
	mu           sync.RWMutex // catalogue publication, submission and discovery snapshots
	cfg          Config
	store        *store.Store
	backend      Backend
	tools        map[string]Tool
	schemas      map[string]*jsonschema.Schema
	bindings     map[string]string
	drafts       map[string]toolDraft
	proposals    map[string]policyProposal
	policyClient policy.Client
}

// New validates and compiles the pinned tool catalogue.
func New(cfg Config, s *store.Store, b Backend) (*Gateway, error) {
	if cfg.AmpUserID == "" {
		return nil, errors.New("AmpUserID is required")
	}
	cfg.Integrations = slices.Clone(cfg.Integrations)
	cfg.Tools = slices.Clone(cfg.Tools)
	cfg.ToolDefaults = maps.Clone(cfg.ToolDefaults)
	integrations := make(map[string]Integration, len(cfg.Integrations))
	for i, integration := range cfg.Integrations {
		if integration.ID != flyIntegrationID || integration.Provider != "fly" {
			return nil, errors.New("unsupported integration configuration")
		}
		if _, exists := integrations[integration.ID]; exists {
			return nil, errors.New("duplicate integration ID")
		}
		for _, connection := range cfg.Connections {
			if connection.ID == integration.ID {
				return nil, errors.New("connection and integration IDs must be unique")
			}
		}
		if err := fly.ValidateToken(integration.Credential); err != nil {
			return nil, errors.New("invalid Fly.io integration credential")
		}
		if integration.Policy == "" {
			integration.Policy = cfg.defaultPolicy(integration.ID)
		}
		if !validPolicy(integration.Policy) {
			return nil, errors.New("invalid integration policy")
		}
		cfg.Integrations[i] = integration
		integrations[integration.ID] = integration
	}
	if cfg.ToolDefaults == nil {
		cfg.ToolDefaults = map[string]string{}
	}
	for _, integration := range cfg.Integrations {
		cfg.Tools = slices.DeleteFunc(cfg.Tools, func(tool Tool) bool {
			return tool.ID == flyIntegrationID+"."+flyRequestToken && tool.Connection == flyIntegrationID && tool.Name == flyRequestToken
		})
		cfg.ToolDefaults[integration.ID] = integration.Policy
		cfg.Tools = append(cfg.Tools, flyTool(""))
	}
	g := &Gateway{cfg: cfg, store: s, backend: b, tools: map[string]Tool{}, schemas: map[string]*jsonschema.Schema{}, bindings: map[string]string{}}
	g.policyClient = policy.Client{Key: os.Getenv("TYPESAFE_API_KEY")}
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
		integration, native := integrations[t.Connection]
		if connection == nil && !native {
			return nil, fmt.Errorf("unknown connection for %s", t.ID)
		}
		if native && (t.ID != flyIntegrationID+"."+flyRequestToken || t.Name != flyRequestToken) {
			return nil, errors.New("invalid Fly.io integration tool")
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
		if native {
			g.bindings[t.ID] = digest([]any{t, integration, cfg.AmpUserID})
		} else {
			g.bindings[t.ID] = digest([]any{t, connection, cfg.privateConnection(t.Connection), cfg.AmpUserID, os.Getenv(connection.TokenEnv)})
		}
	}
	return g, nil
}

func digest(v any) string {
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func (g *Gateway) binding(tool Tool) string {
	return g.bindingWith(tool, g.backend.Binding(tool.Connection))
}

func (g *Gateway) bindingWith(tool Tool, binding string) string {
	if binding == "" {
		return g.bindings[tool.ID]
	}
	return g.bindings[tool.ID] + ":" + binding
}

func (g *Gateway) connectionBindingWith(connection, binding string) string {
	// Reuse the tool bindings, which already cover schema, policy, account,
	// credentials and owner configuration. Adding or changing a tool changes
	// the connection-wide authority, including across a restart.
	bindings := map[string]string{}
	for id, tool := range g.tools {
		if tool.Connection == connection {
			bindings[id] = g.bindings[id]
		}
	}
	return digest([]any{bindings, binding})
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
	ArtifactURL string          `json:"artifact_url,omitempty"`
	Result      json.RawMessage `json:"result,omitempty"`
}

func (g *Gateway) result(o store.Operation) operationResult {
	out := operationResult{ID: o.ID, Status: o.Status, ApprovalURL: g.cfg.BaseURL + "/operations/" + o.ID, Result: o.Result}
	if _, mimeType, ok := firstImageContent(o.Result); ok && o.Status == "succeeded" && safeImageMIME(mimeType) {
		out.ArtifactURL = g.cfg.BaseURL + "/operations/" + o.ID + "/image"
	}
	return out
}

func firstImageContent(result json.RawMessage) ([]byte, string, bool) {
	var upstreamResult mcp.CallToolResult
	if json.Unmarshal(result, &upstreamResult) != nil {
		return nil, "", false
	}
	for _, block := range upstreamResult.Content {
		image, ok := block.(*mcp.ImageContent)
		if ok {
			return image.Data, image.MIMEType, true
		}
	}
	return nil, "", false
}

func safeImageMIME(mimeType string) bool {
	return mimeType == "image/jpeg" || mimeType == "image/png" || mimeType == "image/webp"
}

func (g *Gateway) resultWithContent(o store.Operation) (*mcp.CallToolResult, operationResult) {
	out := g.result(o)
	if len(o.Result) == 0 {
		return nil, out
	}
	var stored map[string]json.RawMessage
	if err := json.Unmarshal(o.Result, &stored); err != nil {
		return nil, out
	}
	var content []json.RawMessage
	if err := json.Unmarshal(stored["content"], &content); err != nil {
		return nil, out
	}
	retained := make([]json.RawMessage, 0, len(content))
	hasImage := false
	for _, block := range content {
		var kind struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(block, &kind) == nil && kind.Type == "image" {
			hasImage = true
			continue
		}
		retained = append(retained, block)
	}
	if !hasImage {
		return nil, out
	}
	var upstreamResult mcp.CallToolResult
	if err := json.Unmarshal(o.Result, &upstreamResult); err != nil {
		return nil, out
	}
	promoted := make([]mcp.Content, 0, len(upstreamResult.Content))
	for _, block := range upstreamResult.Content {
		if _, ok := block.(*mcp.ImageContent); ok {
			promoted = append(promoted, block)
		}
	}
	retainedContent, err := json.Marshal(retained)
	if err != nil {
		return nil, out
	}
	stored["content"] = retainedContent
	out.Result, err = json.Marshal(stored)
	if err != nil {
		return nil, g.result(o)
	}
	return &mcp.CallToolResult{Content: promoted}, out
}

func (g *Gateway) mcpHandler() http.Handler {
	s := mcp.NewServer(&mcp.Implementation{Name: "amp-mcp-gateway", Version: "0.1.0"}, nil)
	mcp.AddTool(s, &mcp.Tool{Name: "propose_policy_changes", Description: "Prepare an immutable batch of provider privacy, default policy, and tool exception changes for human browser review. Providers include remote MCP connections and native integrations. Never applies policies. Use exact saved tool IDs; omitted settings stay unchanged. Policies: allow, require_approval, deny; tool exceptions also accept inherit. Set private to restrict a remote connection to the owner's private, non-multiplayer Amp threads. Review expires in ten minutes."}, func(ctx context.Context, r *mcp.CallToolRequest, in policyInput) (*mcp.CallToolResult, any, error) {
		out, err := g.proposePolicies(ctx, in)
		return nil, out, err
	})
	mcp.AddTool(s, &mcp.Tool{Name: "find_tools", Description: "Search the permitted pinned tool catalogue. Returns schemas and approval policies."}, func(ctx context.Context, r *mcp.CallToolRequest, in findInput) (*mcp.CallToolResult, any, error) {
		words, err := searchTerms(in.Query)
		if err != nil {
			return nil, nil, err
		}
		g.mu.RLock()
		defer g.mu.RUnlock()
		identity, _ := ctx.Value(ampIdentityKey{}).(ampIdentity)
		out := []Tool{}
		for _, t := range g.tools {
			if t.Policy == "deny" || !identity.allows(g.cfg.privateConnection(t.Connection)) {
				continue
			}
			hay := strings.ToLower(t.ID + " " + t.Description)
			match := true
			for _, w := range words {
				if !strings.Contains(hay, w) {
					match = false
					break
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
		// The SDK's generic decoding uses float64. Decode the original request
		// again so exact approvals and upstream calls retain JSON number precision.
		decoder := json.NewDecoder(bytes.NewReader(r.Params.Arguments))
		decoder.UseNumber()
		if err := decoder.Decode(&in); err != nil {
			return nil, nil, err
		}
		o, err := g.submit(ctx, in)
		if err != nil {
			return nil, nil, err
		}
		return nil, g.result(o), nil
	})
	mcp.AddTool(s, &mcp.Tool{Name: "get_operation", Description: "Read durable status and upstream result by operation ID. Unknown means do not automatically retry."}, func(ctx context.Context, r *mcp.CallToolRequest, in getInput) (*mcp.CallToolResult, any, error) {
		o, err := g.getOperation(ctx, in.ID)
		if err != nil {
			return nil, nil, errors.New("operation unavailable")
		}
		result, out := g.resultWithContent(o)
		return result, out, nil
	})
	return mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true, MaxRequestBodyBytes: 1 << 20})
}

var requestID = regexp.MustCompile(`^[a-zA-Z0-9_-]{8,100}$`)

func (g *Gateway) submit(ctx context.Context, in callInput) (store.Operation, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	identity, _ := ctx.Value(ampIdentityKey{}).(ampIdentity)
	if g.cfg.Demo && identity.UserID == "" {
		identity = demoIdentity(g.cfg.AmpUserID)
	}
	if identity.UserID != g.cfg.AmpUserID || !ampThreadID.MatchString(identity.ThreadID) {
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
	if !identity.allows(g.cfg.privateConnection(t.Connection)) {
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
	for _, integration := range g.cfg.Integrations {
		if integration.ID == t.Connection {
			account = integration.Account
		}
	}
	dynamicBinding := g.backend.Binding(t.Connection)
	o := store.Operation{ID: in.RequestID, Tool: t.ID, Connection: t.Connection, Account: account, Model: in.ModelReported, Arguments: c.Arguments, Binding: g.bindingWith(t, dynamicBinding), ConnectionBinding: g.connectionBindingWith(t.Connection, dynamicBinding), Private: g.cfg.privateConnection(t.Connection), Status: status, Created: time.Now().Unix(), Expires: time.Now().Add(10 * time.Minute).Unix()}
	o.AmpSubject, o.AmpUserID = identity.Subject, identity.UserID
	o.AmpWorkspaceID, o.AmpProjectID, o.AmpThreadID = identity.WorkspaceID, identity.ProjectID, identity.ThreadID
	o.AmpThreadVisibility, o.AmpThreadContext = identity.ThreadVisibility, identity.hasThreadContext()
	if identity.ThreadMultiplayer != nil {
		o.AmpThreadMultiplayer = *identity.ThreadMultiplayer
	}
	if identity.ThreadNonOwnerCanInfluence != nil {
		o.AmpThreadNonOwnerCanInfluence = *identity.ThreadNonOwnerCanInfluence
	}
	o.Digest = digest([]any{o.Tool, o.Arguments, o.Binding, o.Model, o.AmpSubject, o.AmpUserID, o.AmpWorkspaceID, o.AmpProjectID, o.AmpThreadID})
	stored, err := g.store.Submit(ctx, o)
	if err != nil {
		return stored, err
	}
	// An idempotent retry can return an operation made private after its original
	// submission, even when the connection is no longer private.
	if stored.Private && !identity.privateThread() {
		return store.Operation{}, errors.New("unknown tool")
	}
	return stored, nil
}

func (g *Gateway) getOperation(ctx context.Context, id string) (store.Operation, error) {
	o, err := g.store.Get(ctx, id)
	if err != nil {
		return o, err
	}
	identity, _ := ctx.Value(ampIdentityKey{}).(ampIdentity)
	g.mu.RLock()
	private := o.Private || g.cfg.privateConnection(o.Connection)
	g.mu.RUnlock()
	if private && !identity.privateThread() {
		return store.Operation{}, errors.New("private operation unavailable in this Amp thread")
	}
	return o, nil
}

// Run executes persisted requests serially until ctx is cancelled. It never retries dispatch.
func (g *Gateway) Run(ctx context.Context) error {
	timer := time.NewTimer(0) // Drain persisted ready work on startup.
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-g.store.Ready():
			timer.Reset(0)
		case <-timer.C:
			// Retain expiration/recovery checks without polling idle accounts at 5 Hz.
			timer.Reset(time.Minute)
			o, err := g.store.Claim(ctx)
			if errors.Is(err, sql.ErrNoRows) {
				continue
			}
			if err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return fmt.Errorf("claim operation: %w", err)
			}
			timer.Reset(0) // Continue draining after this operation, including denials.
			g.mu.RLock()
			t, ok := g.tools[o.Tool]
			expectedBinding := ""
			valid := false
			integration, native := g.integration(t.Connection)
			if ok && t.Policy != "deny" && !native {
				expectedBinding = g.backend.Binding(t.Connection)
				valid = g.bindingWith(t, expectedBinding) == o.Binding
			} else if ok && t.Policy != "deny" {
				valid = g.bindingWith(t, "") == o.Binding
			}
			if valid && o.ConnectionBinding != "" {
				valid = g.connectionBindingWith(t.Connection, expectedBinding) == o.ConnectionBinding
			}
			g.mu.RUnlock()
			if !valid {
				if err := g.store.Finish(ctx, o, "denied", nil); err != nil {
					return err
				}
				continue
			}
			callCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
			var result *mcp.CallToolResult
			var callErr error
			if native {
				result, callErr = g.callIntegration(operationContext{Context: callCtx, Operation: o}, integration, t.Name, o.Arguments)
			} else {
				result, callErr = g.backend.Call(callCtx, t.Connection, t.Name, expectedBinding, o.Arguments)
			}
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
	mux.Handle("GET /assets/", http.FileServerFS(assets))
	mux.HandleFunc("GET /events", g.ledgerEvents)
	mux.HandleFunc("GET /notifications", g.notifications)
	m.Register(mux)
	g.registerConnections(mux, m)
	g.registerIntegrations(mux, m)
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/approvals", http.StatusSeeOther) })
	mux.HandleFunc("GET /audit", g.audit)
	mux.HandleFunc("GET /operations", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("view") == "all" {
			http.Redirect(w, r, "/audit", http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/approvals", http.StatusSeeOther)
	})
	for _, path := range []string{"/approvals", "/connections", "/integrations", "/approval-grants"} {
		mux.HandleFunc("GET "+path, func(w http.ResponseWriter, r *http.Request) { g.dashboard(w, r, m) })
	}
	mux.HandleFunc("GET /connections/{id}/settings", func(w http.ResponseWriter, r *http.Request) {
		g.connectionSettings(w, r, m)
	})
	mux.HandleFunc("GET /operations/{id}", g.operation)
	mux.HandleFunc("GET /operations/{id}/image", g.operationImage)
	mux.HandleFunc("POST /operations/{id}/{decision}", func(w http.ResponseWriter, r *http.Request) {
		decision := r.PathValue("decision")
		if decision != "approve" && decision != "deny" {
			http.NotFound(w, r)
			return
		}
		actor := browserActor(r)
		var err error
		if decision == "approve" {
			r.Body = http.MaxBytesReader(w, r.Body, 4096)
			if parseErr := r.ParseForm(); parseErr != nil {
				http.Error(w, "Invalid approval.", 400)
				return
			}
			if r.Form.Get("remember") != "on" {
				err = g.store.Decide(r.Context(), r.PathValue("id"), actor, true)
			} else {
				options := store.ApprovalOptions{Breadth: r.Form.Get("breadth"), Scope: r.Form.Get("scope"), Expiry: r.Form.Get("expiry")}
				if !slices.Contains([]string{"exact", "tool", "connection"}, options.Breadth) || !slices.Contains([]string{"thread", "project"}, options.Scope) || !slices.Contains([]string{"never", "1h", "24h"}, options.Expiry) {
					http.Error(w, "Invalid approval.", http.StatusBadRequest)
					return
				}
				err = g.store.ApproveWithOptions(r.Context(), r.PathValue("id"), actor, options)
			}
		} else {
			err = g.store.Decide(r.Context(), r.PathValue("id"), actor, false)
		}
		if err != nil {
			http.Error(w, "Operation expired or already decided.", 409)
			return
		}
		http.Redirect(w, r, "/operations/"+r.PathValue("id"), 303)
	})
	mux.HandleFunc("POST /approval-grants/{id}/revoke", func(w http.ResponseWriter, r *http.Request) {
		if err := g.store.RevokeApprovalGrant(r.Context(), r.PathValue("id"), browserActor(r)); err != nil {
			http.Error(w, "Approval unavailable or already revoked.", 409)
			return
		}
		http.Redirect(w, r, "/approval-grants", 303)
	})
	return auth.Require(http.NewCrossOriginProtection().Handler(mux))
}

func (g *Gateway) dashboard(w http.ResponseWriter, r *http.Request, m *upstream.Manager) {
	data := map[string]any{"Section": strings.TrimPrefix(r.URL.Path, "/")}
	var err error
	switch r.URL.Path {
	case "/approvals":
		data["Operations"], err = g.store.ListStatus(r.Context(), "pending")
	case "/approval-grants":
		data["ApprovalGrants"], err = g.store.ApprovalGrants(r.Context())
	case "/connections":
		g.mu.RLock()
		connections := make([]map[string]any, 0, len(g.cfg.Connections))
		for _, c := range g.cfg.Connections {
			if c.Browser {
				continue
			}
			connections = append(connections, map[string]any{"ID": c.ID, "Account": c.Account, "OAuth": c.OAuth != nil})
		}
		g.mu.RUnlock()
		for _, c := range connections {
			c["Health"] = m.Health(r.Context(), c["ID"].(string))
		}
		data["Connections"] = connections
	case "/integrations":
		g.mu.RLock()
		_, configured := g.integration(flyIntegrationID)
		g.mu.RUnlock()
		data["FlyConfigured"] = configured
	}
	if err != nil {
		http.Error(w, "page data unavailable", http.StatusServiceUnavailable)
		return
	}
	if r.URL.Path == "/approvals" {
		w.Header().Set("Vary", "HX-Request")
		w.Header().Set("Cache-Control", "no-store")
		if r.Header.Get("HX-Request") == "true" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			if err := page.ExecuteTemplate(w, "operations-list", data); err != nil {
				slog.Error("render live list", "error", err)
			}
			return
		}
	}
	g.render(w, r, data)
}
func (g *Gateway) operation(w http.ResponseWriter, r *http.Request) {
	o, err := g.store.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	args, _ := json.Marshal(o.Arguments)
	var result struct {
		Content    []json.RawMessage `json:"content"`
		Structured json.RawMessage   `json:"structuredContent"`
	}
	var blocks []string
	if json.Unmarshal(o.Result, &result) == nil {
		structured := prettyJSON(result.Structured)
		if len(result.Structured) > 0 {
			blocks = append(blocks, structured)
		}
		for _, raw := range result.Content {
			var block struct {
				Type string `json:"type"`
				Text string `json:"text"`
			}
			if json.Unmarshal(raw, &block) == nil && block.Type == "text" {
				text := prettyJSON([]byte(block.Text))
				if len(result.Structured) == 0 || text != structured {
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
	events, err := g.store.OperationEvents(r.Context(), o.ID)
	if err != nil {
		http.Error(w, "audit unavailable", http.StatusServiceUnavailable)
		return
	}
	next := ""
	if o.Status != "pending" {
		pending, err := g.store.ListStatus(r.Context(), "pending")
		if err != nil {
			http.Error(w, "ledger unavailable", http.StatusServiceUnavailable)
			return
		}
		if len(pending) > 0 {
			next = pending[0].ID
		}
	}
	data := map[string]any{"Operation": o, "Title": name, "ResultBlocks": blocks, "RawResult": prettyJSON(o.Result), "Arguments": prettyJSON(args), "Events": events, "Next": next}
	data["ActorNames"] = g.actorNames(r)
	w.Header().Set("Vary", "HX-Request")
	w.Header().Set("Cache-Control", "no-store")
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := page.ExecuteTemplate(w, "operation-status", data); err != nil {
			slog.Error("render operation status", "error", err)
		}
		return
	}
	g.render(w, r, data)
}

func (g *Gateway) operationImage(w http.ResponseWriter, r *http.Request) {
	o, err := g.store.Get(r.Context(), r.PathValue("id"))
	if err != nil || o.Status != "succeeded" {
		http.NotFound(w, r)
		return
	}
	data, mimeType, ok := firstImageContent(o.Result)
	if !ok || !safeImageMIME(mimeType) {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("Content-Disposition", "inline")
	w.Header().Set("Content-Type", mimeType)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(data)
}

func (g *Gateway) render(w http.ResponseWriter, r *http.Request, data map[string]any) {
	data["AccountPage"] = g.cfg.AccountPage
	data["User"] = browserauth.User(r.Context())
	data["ActorNames"] = g.actorNames(r)
	data["AmpNames"] = browserauth.ProjectNames{}
	op, _ := data["Operation"].(store.Operation)
	needsProjects := op.Status == "pending" && op.AmpProjectID != ""
	grants, _ := data["ApprovalGrants"].([]store.ApprovalGrant)
	for _, grant := range grants {
		needsProjects = needsProjects || grant.Scope == "project"
	}
	if g.ProjectNames != nil && needsProjects {
		data["AmpNames"] = g.ProjectNames(r.Context())
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := page.Execute(w, data); err != nil {
		slog.Error("render page", "error", err)
	}
}
