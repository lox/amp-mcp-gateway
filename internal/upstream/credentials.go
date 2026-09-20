package upstream

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/oauth2"
)

// Additional fields share the encrypted token record. Old oauth2.Token records
// still decode, and the connection's credential binding does not change.
type credentials struct {
	oauth2.Token
	RefreshState string           `json:"refresh_state,omitempty"`
	Attempts     int              `json:"refresh_attempts,omitempty"`
	RetryAt      time.Time        `json:"retry_at,omitzero"`
	RefreshedAt  time.Time        `json:"refreshed_at,omitzero"`
	AuthStyle    oauth2.AuthStyle `json:"auth_style,omitempty"`
}

// Health contains presentation-safe facts, never provider messages or credentials.
type Health struct {
	Status, Detail, Refresh                    string
	CheckedAt, RefreshedAt, ExpiresAt, RetryAt time.Time
}

// Health reads local state only. Check results are observations since process start,
// not a promise that access remains valid. Refresh state survives restarts.
func (m *Manager) Health(ctx context.Context, id string) Health {
	c, ok := m.connection(id)
	if !ok {
		return Health{Status: "Not connected"}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	h := c.check
	if h.Status == "" {
		h.Status, h.Detail = "Not tested", "Test the connection to verify MCP access."
	}
	if c.config.OAuth == nil {
		return h
	}
	token, err := m.loadToken(ctx, c)
	if err != nil {
		h.Status, h.Detail = "Status unavailable", "Could not read saved credentials. Try again before reconnecting."
		return h
	}
	if token == nil || token.AccessToken == "" {
		h.Status, h.Detail = "Not connected", "Connect your provider account to enable access."
		return h
	}
	h.ExpiresAt, h.RefreshedAt, h.RetryAt = token.Expiry.UTC(), token.RefreshedAt.UTC(), token.RetryAt.UTC()
	if token.RefreshToken == "" {
		h.Refresh = "No refresh token issued. Reconnect will be needed when access expires."
		if !token.Valid() {
			h.Status, h.Detail = "Reconnect required", "The access token expired and the provider did not issue a refresh token."
		}
	} else {
		h.Refresh = "Automatic refresh enabled, including while idle."
		if token.Expiry.IsZero() {
			h.Refresh = "Refresh token saved, but no access-token expiry was supplied; proactive refresh cannot be scheduled."
		}
	}
	switch token.RefreshState {
	case "refreshing", "unknown":
		h.Status, h.Detail = "Refresh uncertain", "A refresh may have rotated credentials without saving its result. Automatic refresh is stopped; reconnect to restore it safely."
	case "reconnect":
		h.Status, h.Detail = "Reconnect required", "The provider rejected the refresh grant. Reconnect to authorize access again."
	case "retry":
		h.Status, h.Detail = "Refresh delayed", "Refresh failed before connecting or was safely rejected. A bounded automatic retry is scheduled."
	case "paused":
		h.Status, h.Detail = "Refresh paused", "Temporary refresh failures exhausted automatic retries. Test connection to retry safely."
	case "configuration":
		h.Status, h.Detail = "Refresh blocked", "The provider rejected the OAuth client or refresh request. Check provider configuration before reconnecting."
	}
	if token.RefreshState != "" {
		h.Refresh = "Automatic refresh is paused."
		if token.RefreshState == "retry" {
			h.Refresh = "Automatic retry scheduled."
		}
	}
	return h
}

// RunRefresh maintains idle grants without executing tools. It stops with the
// process context and picks up newly installed connections on every sweep.
func (m *Manager) RunRefresh(ctx context.Context) error {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		m.refreshDue(ctx)
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (m *Manager) refreshDue(ctx context.Context) {
	m.connMu.RLock()
	connections := make([]*managedConnection, 0, len(m.conns))
	for _, c := range m.conns {
		if c.config.OAuth != nil {
			connections = append(connections, c)
		}
	}
	m.connMu.RUnlock()
	for _, c := range connections {
		if ctx.Err() != nil {
			return
		}
		// Errors remain visible in the encrypted refresh record, not logs that
		// might contain an OAuth response body or credentials.
		_, _ = m.refresh(ctx, c, true)
	}
}

func (m *Manager) saveCredentials(ctx context.Context, c *managedConnection, token *credentials) error {
	raw, err := json.Marshal(token)
	if err != nil {
		return err
	}
	return m.store.SaveToken(ctx, tokenKey(c.config), raw)
}

func (m *Manager) refresh(ctx context.Context, c *managedConnection, proactive bool) (*oauth2.Token, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	token, err := m.loadToken(ctx, c)
	if err != nil {
		return nil, err
	}
	if token == nil {
		return nil, errors.New("connection is not authorized")
	}
	now := time.Now()
	// Very short-lived tokens refresh on the next sweep, never in a tight loop.
	due := !token.Expiry.IsZero() && token.Expiry.Before(now.Add(2*time.Minute)) && now.Sub(token.RefreshedAt) >= time.Minute
	if token.Valid() && (!proactive || !due || token.RefreshToken == "") {
		return &token.Token, nil
	}
	if token.RefreshToken == "" {
		return nil, errors.New("reconnect required: no refresh token")
	}
	if token.RefreshState != "" && token.RefreshState != "retry" {
		return nil, errors.New("automatic refresh is paused")
	}
	if now.Before(token.RetryAt) {
		return nil, errors.New("refresh retry is scheduled")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Claim durably before contacting the provider. A crash or lost response
	// must never cause replay of a possibly consumed rotating refresh token.
	token.RefreshState = "refreshing"
	token.Attempts++
	if err := m.saveCredentials(ctx, c, token); err != nil {
		return nil, errors.New("could not persist refresh attempt")
	}
	config := m.oauthConfig(c.config)
	legacyStyle := token.AuthStyle == 0 && config.Endpoint.AuthStyle == 0 && config.ClientSecret != ""
	if token.AuthStyle != 0 {
		config.Endpoint.AuthStyle = token.AuthStyle
	}
	if config.Endpoint.AuthStyle == 0 {
		// Legacy records did not retain the exchange's auth method. Use the
		// OAuth default, never the library's retrying auto-detection on refresh.
		config.Endpoint.AuthStyle = oauth2.AuthStyleInHeader
		if config.ClientSecret == "" {
			config.Endpoint.AuthStyle = oauth2.AuthStyleInParams
		}
	}
	h := oauthHTTPClient(c.config)
	observed := &tokenTransport{base: h.Transport, resource: c.config.OAuth.Resource}
	h.Transport = observed
	refreshCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	refreshCtx = context.WithValue(refreshCtx, oauth2.HTTPClient, h)
	force := token.Token
	force.Expiry = now.Add(-time.Hour)
	refreshed, refreshErr := config.TokenSource(refreshCtx, &force).Token()
	if refreshErr == nil {
		token = &credentials{Token: *refreshed, RefreshedAt: time.Now().UTC(), AuthStyle: config.Endpoint.AuthStyle}
	} else {
		token.RefreshState, token.RetryAt = "unknown", time.Time{}
		var rejected *oauth2.RetrieveError
		var networkError net.Error
		retryable := !observed.connected.Load() && errors.As(refreshErr, &networkError)
		if errors.As(refreshErr, &rejected) && rejected.Response != nil && rejected.Response.StatusCode >= 400 {
			switch rejected.ErrorCode {
			case "invalid_grant":
				token.RefreshState = "reconnect"
			case "invalid_client":
				token.RefreshState = "configuration"
				// Migrate old confidential grants without requiring consent again.
				// Only an explicit authentication rejection permits trying form auth.
				if legacyStyle && (rejected.Response.StatusCode == 400 || rejected.Response.StatusCode == 401) {
					token.AuthStyle, retryable = oauth2.AuthStyleInParams, true
				}
			case "unauthorized_client", "invalid_scope", "invalid_request", "unsupported_grant_type":
				token.RefreshState = "configuration"
			case "temporarily_unavailable", "server_error":
				retryable = true
			}
		}
		if retryable {
			token.RefreshState = "paused"
			if token.Attempts < 3 {
				token.RefreshState = "retry"
				token.RetryAt = time.Now().Add(time.Duration(token.Attempts) * time.Minute).UTC()
			}
		}
	}
	// Finish persistence even if the caller disconnected after the response.
	saveCtx, saveCancel := context.WithTimeout(context.Background(), requestTimeout)
	defer saveCancel()
	if err := m.saveCredentials(saveCtx, c, token); err != nil {
		return nil, errors.New("could not save refreshed credentials; refresh outcome uncertain")
	}
	if refreshErr != nil {
		return nil, failure("credentials", refreshErr, 0)
	}
	return &token.Token, nil
}

// tokenTransport adds the bound resource to refresh requests and records the
// successful exchange's client authentication style for subsequent refreshes.
type tokenTransport struct {
	base      http.RoundTripper
	resource  string
	style     oauth2.AuthStyle
	connected atomic.Bool
}

func (t *tokenTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(httptrace.WithClientTrace(r.Context(), &httptrace.ClientTrace{GotConn: func(httptrace.GotConnInfo) { t.connected.Store(true) }}))
	if t.resource != "" {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		r.Body.Close()
		form, err := url.ParseQuery(string(body))
		if err != nil {
			return nil, err
		}
		form.Set("resource", t.resource)
		r = r.Clone(r.Context())
		r.Body = io.NopCloser(strings.NewReader(form.Encode()))
		r.ContentLength = int64(len(form.Encode()))
		r.GetBody = nil
	}
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	res, err := base.RoundTrip(r)
	if err == nil && res.StatusCode >= 200 && res.StatusCode < 300 {
		t.style = oauth2.AuthStyleInParams
		if _, _, ok := r.BasicAuth(); ok {
			t.style = oauth2.AuthStyleInHeader
		}
	}
	return res, err
}

// TestConnection checks MCP access without executing tools or changing policies.
// Only explicit temporary rejections can be retried by this action.
func (m *Manager) TestConnection(ctx context.Context, id string) error {
	c, ok := m.connection(id)
	if !ok {
		return errors.New("unknown connection")
	}
	if c.config.OAuth != nil {
		c.mu.Lock()
		token, err := m.loadToken(ctx, c)
		if err == nil && token != nil && token.RefreshState == "paused" {
			token.RefreshState, token.Attempts = "", 0
			err = m.saveCredentials(ctx, c, token)
		}
		c.mu.Unlock()
		if err != nil {
			return err
		}
	}
	_, err := m.ListTools(ctx, id)
	return err
}
