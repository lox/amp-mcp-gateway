package gateway

import (
	"context"
	"crypto/rand"
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
}

func (g *Gateway) flyIntegrationPage(w http.ResponseWriter, r *http.Request) {
	g.mu.RLock()
	integration, configured := g.integration(flyIntegrationID)
	policy := "require_approval"
	if tool, ok := g.tools[flyIntegrationID+"."+flyRequestToken]; ok {
		policy = tool.Policy
	}
	g.mu.RUnlock()
	g.render(w, map[string]any{
		"FlyIntegration": true, "Configured": configured, "Account": integration.Account,
		"Policy": policy, "Saved": r.URL.Query().Get("saved") == "1", "Owner": g.cfg.OwnerSubject,
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
		g.render(w, map[string]any{"FlyIntegration": true, "Configured": configured, "Account": account, "Policy": policy, "Error": message, "Owner": g.cfg.OwnerSubject})
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
	return browserauth.Subject(r.Context())
}

func (g *Gateway) callIntegration(ctx operationContext, integration Integration, tool string, args map[string]any) (*mcp.CallToolResult, error) {
	if integration.Provider != "fly" || tool != flyRequestToken {
		return nil, errors.New("unknown integration tool")
	}
	var input struct {
		DurationSeconds int64  `json:"duration_seconds"`
		Purpose         string `json:"purpose"`
	}
	raw, err := json.Marshal(args)
	if err != nil || json.Unmarshal(raw, &input) != nil || input.DurationSeconds < 60 || input.DurationSeconds > int64(maxFlyTokenTTL.Seconds()) {
		return nil, errors.New("invalid Fly.io token request")
	}
	var audience string
	if g.cfg.AmpUserID != "" {
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
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Too many unredeemed Fly.io token URLs. Redeem one or wait for it to expire, then submit a new request."}}}, nil
		}
		return nil, err
	}
	redemptionURL := strings.TrimRight(g.cfg.BaseURL, "/") + "/leases/" + lease.ID
	content := map[string]any{
		"redemption_url":         redemptionURL,
		"redeem_by":              time.Unix(lease.Expires, 0).UTC().Format(time.RFC3339),
		"token_lifetime_seconds": input.DurationSeconds,
		"usage":                  "POST the URL once with the same authenticated caller identity. Capture the response directly into FLY_ACCESS_TOKEN; do not print it.",
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
	integration, ok := g.integration(flyIntegrationID)
	if ok {
		caller.Integration = integration.ID
		caller.CredentialDigest = digest(integration.Credential)
	}
	lease, err := g.store.RedeemCredentialLease(r.Context(), r.PathValue("id"), caller)
	if err != nil {
		g.mu.RUnlock()
		http.Error(w, "credential lease unavailable or expired", http.StatusGone)
		return
	}
	if !ok || integration.ID != lease.Integration {
		g.mu.RUnlock()
		http.Error(w, "credential lease invalidated by integration changes", http.StatusGone)
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
