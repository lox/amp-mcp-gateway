package main

import (
	"context"
	"encoding/json"
	"time"

	"ampcode.com/lox/amp-mcp-gateway/internal/browserauth"
	"golang.org/x/oauth2"
)

// projectNames is optional page enrichment, never part of approval decisions.
// The account lock also covers login so refresh cannot overwrite reauthentication.
func (a *accountRuntime) projectNames(ctx context.Context, auth *browserauth.Auth) browserauth.ProjectNames {
	a.tokenMu.Lock()
	defer a.tokenMu.Unlock()
	if time.Now().Before(a.namesUntil) {
		return a.names
	}
	a.names = browserauth.ProjectNames{}
	a.namesUntil = time.Now().Add(30 * time.Second) // Back off failures too.
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	raw, err := a.store.LoadToken(ctx, "amp-api-oauth/v1")
	var token oauth2.Token
	if err != nil || len(raw) == 0 || json.Unmarshal(raw, &token) != nil {
		return a.names
	}
	if !token.Valid() {
		if token.RefreshToken == "" {
			return a.names
		}
		// Retire before dispatch: a crash, timeout or failed persistence must
		// never replay an ambiguously rotated refresh token. Sign in to recover.
		retired := token
		retired.RefreshToken = ""
		raw, err = json.Marshal(&retired)
		if err != nil || a.store.SaveToken(ctx, "amp-api-oauth/v1", raw) != nil {
			return a.names
		}
		updated, err := auth.RefreshToken(ctx, &token)
		if err != nil {
			return a.names
		}
		raw, err = json.Marshal(updated)
		if err != nil || a.store.SaveToken(ctx, "amp-api-oauth/v1", raw) != nil {
			return a.names
		}
		token = *updated
	}
	names, err := auth.ProjectNames(ctx, &token)
	if err == nil {
		a.names = names
		a.namesUntil = time.Now().Add(5 * time.Minute)
	}
	return a.names
}
