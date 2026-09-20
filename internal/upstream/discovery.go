package upstream

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
	"golang.org/x/oauth2"
)

// DiscoverOAuth uses MCP metadata and optionally registers a public OAuth client.
// User-supplied credentials are sent only to the discovered authorization server.
func DiscoverOAuth(ctx context.Context, endpoint, callback, clientID, secret string) (*OAuthConfig, error) {
	if err := ValidatePublicURL(endpoint); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	h := oauthHTTPClient(Connection{PublicOnly: true})
	return discoverOAuth(ctx, endpoint, callback, clientID, secret, h)
}

func discoverOAuth(ctx context.Context, endpoint, callback, clientID, secret string, h *http.Client) (*OAuthConfig, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, errors.New("invalid MCP URL")
	}
	origin := u.Scheme + "://" + u.Host
	type metadataCandidate struct {
		url, resource string
	}
	metadataURLs := []metadataCandidate{}
	advertised := false
	scopes := []string{}
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json, text/event-stream")
	res, err := h.Do(req)
	if err == nil {
		res.Body.Close()
		challenges, _ := oauthex.ParseWWWAuthenticate(res.Header.Values("WWW-Authenticate"))
		for _, c := range challenges {
			if c.Scheme == "bearer" {
				if raw := c.Params["resource_metadata"]; raw != "" {
					metadataURLs = append(metadataURLs, metadataCandidate{raw, endpoint})
					advertised = true
				}
				scopes = strings.Fields(c.Params["scope"])
				break
			}
		}
	}
	// Preserve endpoint-scoped metadata at the root, then try origin-scoped
	// metadata. Each candidate still requires an exact resource match.
	metadataURLs = append(metadataURLs,
		metadataCandidate{origin + "/.well-known/oauth-protected-resource" + u.EscapedPath(), endpoint},
		metadataCandidate{origin + "/.well-known/oauth-protected-resource", endpoint},
		metadataCandidate{origin + "/.well-known/oauth-protected-resource", origin},
	)
	var prm *oauthex.ProtectedResourceMetadata
	for _, candidate := range metadataURLs {
		prm, err = oauthex.GetProtectedResourceMetadata(ctx, candidate.url, candidate.resource, h)
		if err == nil && prm != nil {
			break
		}
		if advertised {
			return nil, errors.New("advertised OAuth resource metadata is invalid or unavailable")
		}
	}
	issuer, resource := origin, endpoint
	if prm != nil {
		if len(prm.AuthorizationServers) == 0 {
			return nil, errors.New("MCP metadata lists no authorization server")
		}
		issuer, resource = prm.AuthorizationServers[0], prm.Resource
		if len(scopes) == 0 {
			scopes = prm.ScopesSupported
		}
	}
	meta, err := auth.GetAuthServerMetadata(ctx, issuer, h)
	if err != nil || meta == nil {
		return nil, errors.New("OAuth metadata unavailable; use a bearer token or ask the provider for MCP OAuth support")
	}
	if !slices.Contains(meta.CodeChallengeMethodsSupported, "S256") {
		return nil, errors.New("OAuth server must support PKCE S256")
	}
	// The owner reviews the authorization URL before connecting. Do not send
	// codes, PKCE verifiers or client secrets to a different, hidden origin.
	authorization, authErr := url.Parse(meta.AuthorizationEndpoint)
	token, tokenErr := url.Parse(meta.TokenEndpoint)
	if authErr != nil || tokenErr != nil || authorization.Host == "" || authorization.Scheme != token.Scheme || !strings.EqualFold(authorization.Host, token.Host) {
		return nil, errors.New("OAuth authorization and token endpoints must share an origin; split-origin providers are not supported yet")
	}
	if len(scopes) == 0 {
		scopes = meta.ScopesSupported
	}
	o := &OAuthConfig{ClientID: clientID, ClientSecret: secret, AuthURL: meta.AuthorizationEndpoint, TokenURL: meta.TokenEndpoint, Scopes: scopes, Resource: resource}
	if clientID == "" {
		if meta.RegistrationEndpoint == "" {
			return nil, errors.New("this provider requires an existing OAuth client ID; register the callback URL shown below")
		}
		registered, err := oauthex.RegisterClient(ctx, meta.RegistrationEndpoint, &oauthex.ClientRegistrationMetadata{
			RedirectURIs: []string{callback}, ClientName: "mcp-gateway", TokenEndpointAuthMethod: "none",
			GrantTypes: []string{"authorization_code", "refresh_token"}, ResponseTypes: []string{"code"}, Scope: strings.Join(scopes, " "),
		}, h)
		if err != nil {
			return nil, errors.New("OAuth client registration failed; try an existing client ID")
		}
		if registered.ClientSecret != "" && !registered.ClientSecretExpiresAt.IsZero() {
			return nil, errors.New("expiring OAuth client secrets are not supported; use a non-expiring registered client")
		}
		o.ClientID, o.ClientSecret = registered.ClientID, registered.ClientSecret
		switch registered.TokenEndpointAuthMethod {
		case "none", "client_secret_post":
			o.AuthStyle = oauth2.AuthStyleInParams
		case "", "client_secret_basic":
			o.AuthStyle = oauth2.AuthStyleInHeader
		default:
			return nil, errors.New("OAuth client authentication method is unsupported")
		}
	} else if secret == "" {
		o.AuthStyle = oauth2.AuthStyleInParams
	}
	if o.ClientID == "" {
		return nil, errors.New("OAuth registration returned no client ID")
	}
	return o, nil
}
