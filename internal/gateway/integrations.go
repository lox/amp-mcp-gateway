package gateway

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"ampcode.com/lox/amp-mcp-gateway/internal/browserauth"
	"ampcode.com/lox/amp-mcp-gateway/internal/fly"
	"ampcode.com/lox/amp-mcp-gateway/internal/store"
	"ampcode.com/lox/amp-mcp-gateway/internal/upstream"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	flyIntegrationID = "fly"
	flyRequestToken  = "request_token"
	secretProvider   = "secret"
	secretRequest    = "request_secret"
	maxSecretBytes   = 64 << 10
	maxFlyTokenTTL   = 15 * time.Minute
	leaseClaimTTL    = 5 * time.Minute
)

// Integration is a browser-managed native capability provider. Credential is
// encrypted inside the catalogue and never reaches presentation data.
type Integration struct {
	ID, Provider, Account, Credential, Policy string
}

func flyTool(policy string) Tool {
	return Tool{
		ID: flyIntegrationID + "." + flyRequestToken, Connection: flyIntegrationID, Name: flyRequestToken,
		Description: "Request a one-time URL for a short-lived Fly.io token derived from the stored scoped token. The token retains the parent token's restrictions and expires after at most 15 minutes.",
		Policy:      policy,
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"duration_seconds": map[string]any{"type": "integer", "minimum": 60, "maximum": int(maxFlyTokenTTL.Seconds()), "description": "Lifetime of the redeemed Fly.io token."},
				"purpose":          map[string]any{"type": "string", "minLength": 1, "maxLength": 300, "description": "Why broad flyctl access is needed. Shown during approval."},
			},
			"required":             []any{"duration_seconds", "purpose"},
			"additionalProperties": false,
		},
	}
}

func secretTool(integration Integration, policy string) Tool {
	return Tool{
		ID: integration.ID + "." + secretRequest, Connection: integration.ID, Name: secretRequest,
		Description: "Request a caller-bound, single-use URL for the stored secret “" + integration.Account + "”. The secret is returned only by authenticated redemption and never in MCP results.",
		Policy:      policy,
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"purpose": map[string]any{"type": "string", "minLength": 1, "maxLength": 300, "description": "Why this secret is needed. Shown during approval."},
			},
			"required":             []any{"purpose"},
			"additionalProperties": false,
		},
	}
}

func integrationTool(integration Integration, policy string) Tool {
	if integration.Provider == secretProvider {
		return secretTool(integration, policy)
	}
	return flyTool(policy)
}

func (g *Gateway) integration(id string) (Integration, bool) {
	for _, integration := range g.cfg.Integrations {
		if integration.ID == id {
			return integration, true
		}
	}
	return Integration{}, false
}

func (g *Gateway) registerIntegrations(mux *http.ServeMux, m *upstream.Manager) {
	mux.HandleFunc("GET /integrations/fly", g.flyIntegrationPage)
	mux.HandleFunc("POST /integrations/fly", func(w http.ResponseWriter, r *http.Request) { g.saveFlyIntegration(w, r, m) })
	mux.HandleFunc("POST /integrations/fly/remove", func(w http.ResponseWriter, r *http.Request) { g.removeFlyIntegration(w, r, m) })
	mux.HandleFunc("GET /secrets", g.secretsPage)
	mux.HandleFunc("POST /secrets", func(w http.ResponseWriter, r *http.Request) { g.saveSecret(w, r, m) })
	mux.HandleFunc("POST /secrets/{id}/remove", func(w http.ResponseWriter, r *http.Request) { g.removeSecret(w, r, m) })
}

func (g *Gateway) secretIntegrations() []Integration {
	secrets := []Integration{}
	for _, integration := range g.cfg.Integrations {
		if integration.Provider == secretProvider {
			secrets = append(secrets, integration)
		}
	}
	slices.SortFunc(secrets, func(a, b Integration) int { return strings.Compare(a.ID, b.ID) })
	return secrets
}

func (g *Gateway) secretsPage(w http.ResponseWriter, r *http.Request) {
	g.mu.RLock()
	secrets := g.secretIntegrations()
	views := make([]map[string]string, 0, len(secrets))
	for _, secret := range secrets {
		views = append(views, map[string]string{"ID": secret.ID, "Name": secret.Account, "Policy": secret.Policy})
	}
	g.mu.RUnlock()
	g.render(w, r, map[string]any{"SecretsPage": true, "Secrets": views, "Saved": r.URL.Query().Get("saved") == "1"})
}

func (g *Gateway) saveSecret(w http.ResponseWriter, r *http.Request, m *upstream.Manager) {
	r.Body = http.MaxBytesReader(w, r.Body, 3*maxSecretBytes+(8<<10))
	if r.ParseForm() != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	id := strings.TrimSpace(r.PostForm.Get("id"))
	name := strings.TrimSpace(r.PostForm.Get("name"))
	credential := r.PostForm.Get("value")
	if r.PostForm.Has("value_base64") {
		decoded, err := base64.StdEncoding.DecodeString(r.PostForm.Get("value_base64"))
		if err != nil {
			http.Error(w, "invalid secret value", http.StatusBadRequest)
			return
		}
		credential = string(decoded)
	}
	policy := r.PostForm.Get("policy")
	fail := func(message string) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		g.mu.RLock()
		secrets := g.secretIntegrations()
		views := make([]map[string]string, 0, len(secrets))
		for _, secret := range secrets {
			views = append(views, map[string]string{"ID": secret.ID, "Name": secret.Account, "Policy": secret.Policy})
		}
		g.mu.RUnlock()
		g.render(w, r, map[string]any{"SecretsPage": true, "Secrets": views, "Values": map[string]string{"ID": id, "Name": name, "Policy": policy}, "Error": message})
	}
	if !connectionID.MatchString(id) || id == flyIntegrationID {
		fail("Use 1–60 letters, numbers, dashes or underscores for a non-reserved secret ID.")
		return
	}
	if name == "" || len(name) > 200 {
		fail("Secret name must be 1–200 characters.")
		return
	}
	if !validPolicy(policy) {
		fail("Choose a permission for secret access.")
		return
	}
	if len(credential) > maxSecretBytes {
		fail("Secret value must be 64 KiB or smaller.")
		return
	}
	g.mu.Lock()
	existing, configured := g.integration(id)
	if configured && existing.Provider != secretProvider {
		g.mu.Unlock()
		fail("That ID is already used by another integration.")
		return
	}
	for _, connection := range g.cfg.Connections {
		if connection.ID == id {
			g.mu.Unlock()
			fail("That ID is already used by a connection.")
			return
		}
	}
	if credential == "" && configured {
		credential = existing.Credential
	}
	if credential == "" {
		g.mu.Unlock()
		fail("Enter a secret value.")
		return
	}
	next := g.catalogue()
	next.Integrations = slices.DeleteFunc(next.Integrations, func(i Integration) bool { return i.ID == id })
	next.Integrations = append(next.Integrations, Integration{ID: id, Provider: secretProvider, Account: name, Credential: credential, Policy: policy})
	err := g.saveCatalogue(r.Context(), next, m, store.Event{Kind: "secret-saved", Actor: browserActor(r)})
	g.mu.Unlock()
	if err != nil {
		fail(err.Error())
		return
	}
	http.Redirect(w, r, "/secrets?saved=1", http.StatusSeeOther)
}

func (g *Gateway) removeSecret(w http.ResponseWriter, r *http.Request, m *upstream.Manager) {
	id := r.PathValue("id")
	g.mu.Lock()
	integration, configured := g.integration(id)
	if !configured || integration.Provider != secretProvider {
		g.mu.Unlock()
		http.Error(w, "Secret is no longer configured", http.StatusConflict)
		return
	}
	next := g.catalogue()
	next.Integrations = slices.DeleteFunc(next.Integrations, func(i Integration) bool { return i.ID == id })
	err := g.saveCatalogue(r.Context(), next, m, store.Event{Kind: "secret-removed", Actor: browserActor(r)})
	g.mu.Unlock()
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	http.Redirect(w, r, "/secrets", http.StatusSeeOther)
}

func (g *Gateway) flyIntegrationPage(w http.ResponseWriter, r *http.Request) {
	g.mu.RLock()
	integration, configured := g.integration(flyIntegrationID)
	policy := "require_approval"
	if tool, ok := g.tools[flyIntegrationID+"."+flyRequestToken]; ok {
		policy = tool.Policy
	}
	g.mu.RUnlock()
	g.render(w, r, map[string]any{
		"FlyIntegration": true, "Configured": configured, "Account": integration.Account,
		"Policy": policy, "Saved": r.URL.Query().Get("saved") == "1",
	})
}

func (g *Gateway) saveFlyIntegration(w http.ResponseWriter, r *http.Request, m *upstream.Manager) {
	r.Body = http.MaxBytesReader(w, r.Body, 24<<10)
	if r.ParseForm() != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	account := strings.TrimSpace(r.PostForm.Get("account"))
	credential := strings.TrimSpace(r.PostForm.Get("token"))
	policy := r.PostForm.Get("policy")
	g.mu.RLock()
	_, configured := g.integration(flyIntegrationID)
	g.mu.RUnlock()
	fail := func(message string) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		g.render(w, r, map[string]any{"FlyIntegration": true, "Configured": configured, "Account": account, "Policy": policy, "Error": message})
	}
	if len(account) > 200 {
		fail("Account label must be 200 characters or fewer.")
		return
	}
	if !validPolicy(policy) {
		fail("Choose a permission for token requests.")
		return
	}
	g.mu.Lock()
	existing, configuredNow := g.integration(flyIntegrationID)
	configured = configuredNow
	if credential == "" && configured {
		credential = existing.Credential
	}
	if err := fly.ValidateToken(credential); err != nil {
		g.mu.Unlock()
		fail(err.Error() + ".")
		return
	}
	next := g.catalogue()
	next.Integrations = slices.DeleteFunc(next.Integrations, func(i Integration) bool { return i.ID == flyIntegrationID })
	next.Integrations = append(next.Integrations, Integration{ID: flyIntegrationID, Provider: "fly", Account: account, Credential: credential, Policy: policy})
	err := g.saveCatalogue(r.Context(), next, m, store.Event{Kind: "integration-saved", Actor: browserActor(r)})
	g.mu.Unlock()
	if err != nil {
		fail(err.Error())
		return
	}
	http.Redirect(w, r, "/integrations/fly?saved=1", http.StatusSeeOther)
}

func (g *Gateway) removeFlyIntegration(w http.ResponseWriter, r *http.Request, m *upstream.Manager) {
	g.mu.Lock()
	if _, configured := g.integration(flyIntegrationID); !configured {
		g.mu.Unlock()
		http.Error(w, "Fly.io integration is no longer configured", http.StatusConflict)
		return
	}
	next := g.catalogue()
	next.Integrations = slices.DeleteFunc(next.Integrations, func(i Integration) bool { return i.ID == flyIntegrationID })
	err := g.saveCatalogue(r.Context(), next, m, store.Event{Kind: "integration-removed", Actor: browserActor(r)})
	g.mu.Unlock()
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	http.Redirect(w, r, "/integrations", http.StatusSeeOther)
}

func browserActor(r *http.Request) string {
	return "amp:" + browserauth.Subject(r.Context())
}

func (g *Gateway) callIntegration(ctx operationContext, integration Integration, tool string, args map[string]any) (*mcp.CallToolResult, error) {
	if integration.Provider != "fly" && integration.Provider != secretProvider {
		return nil, errors.New("unknown integration tool")
	}
	var input struct {
		DurationSeconds int64  `json:"duration_seconds"`
		Purpose         string `json:"purpose"`
	}
	raw, err := json.Marshal(args)
	if err != nil || json.Unmarshal(raw, &input) != nil || input.Purpose == "" {
		return nil, errors.New("invalid integration credential request")
	}
	if integration.Provider == "fly" && (tool != flyRequestToken || input.DurationSeconds < 60 || input.DurationSeconds > int64(maxFlyTokenTTL.Seconds())) {
		return nil, errors.New("invalid Fly.io token request")
	}
	if integration.Provider == secretProvider && tool != secretRequest {
		return nil, errors.New("invalid secret request")
	}
	audience := ""
	if !g.cfg.Demo {
		audience, err = CanonicalOrigin(g.cfg.BaseURL)
		if err != nil {
			return nil, err
		}
	}
	now := time.Now()
	lease := store.CredentialLease{
		ID: rand.Text(), OperationID: ctx.Operation.ID, Integration: integration.ID,
		CredentialDigest: digest(integration.Credential), LifetimeSeconds: input.DurationSeconds,
		AmpSubject: ctx.Operation.AmpSubject, AmpUserID: ctx.Operation.AmpUserID,
		AmpWorkspaceID: ctx.Operation.AmpWorkspaceID, AmpProjectID: ctx.Operation.AmpProjectID, AmpThreadID: ctx.Operation.AmpThreadID,
		Expires: now.Add(leaseClaimTTL).Unix(),
	}
	if err := g.store.CreateCredentialLease(ctx, lease); err != nil {
		if errors.Is(err, store.ErrCredentialLeaseCapacity) {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Too many unredeemed credential URLs. Redeem one or wait for it to expire, then submit a new request."}}}, nil
		}
		return nil, err
	}
	redemptionURL := strings.TrimRight(g.cfg.BaseURL, "/") + "/leases/" + lease.ID
	content := map[string]any{
		"redemption_url": redemptionURL,
		"redeem_by":      time.Unix(lease.Expires, 0).UTC().Format(time.RFC3339),
		"usage":          "POST the URL once with the same authenticated caller identity. Capture the response directly into a protected file or environment variable; do not print it.",
	}
	if integration.Provider == "fly" {
		content["token_lifetime_seconds"] = input.DurationSeconds
	}
	if audience != "" {
		content["workload_identity_audience"] = audience
		content["authentication"] = "Mint a thread identity with amp orb id-token --audience \"$WORKLOAD_IDENTITY_AUDIENCE\"; use it as the redemption Bearer token."
	}
	return &mcp.CallToolResult{StructuredContent: content}, nil
}

type operationContext struct {
	context.Context
	Operation store.Operation
}

func (g *Gateway) redeemLease(w http.ResponseWriter, r *http.Request) {
	identity, _ := r.Context().Value(ampIdentityKey{}).(ampIdentity)
	caller := store.CredentialLease{
		AmpSubject: identity.Subject, AmpUserID: identity.UserID, AmpWorkspaceID: identity.WorkspaceID,
		AmpProjectID: identity.ProjectID, AmpThreadID: identity.ThreadID,
	}
	g.mu.RLock()
	authorities := make(map[string]string, len(g.cfg.Integrations))
	for _, integration := range g.cfg.Integrations {
		authorities[integration.ID] = digest(integration.Credential)
	}
	lease, err := g.store.RedeemCredentialLeaseForIntegrations(r.Context(), r.PathValue("id"), caller, authorities)
	if err != nil {
		g.mu.RUnlock()
		http.Error(w, "credential lease unavailable or expired", http.StatusGone)
		return
	}
	integration, ok := g.integration(lease.Integration)
	if !ok {
		g.mu.RUnlock()
		http.Error(w, "credential lease invalidated by integration changes", http.StatusGone)
		return
	}
	if integration.Provider == secretProvider {
		credential := integration.Credential
		g.mu.RUnlock()
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", "attachment; filename="+integration.ID+".secret")
		_, _ = w.Write([]byte(credential))
		return
	}
	token, err := fly.Attenuate(integration.Credential, time.Now(), time.Duration(lease.LifetimeSeconds)*time.Second)
	g.mu.RUnlock()
	if err != nil {
		http.Error(w, "credential lease could not be issued", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=fly-token.txt")
	w.Write([]byte(token))
}
