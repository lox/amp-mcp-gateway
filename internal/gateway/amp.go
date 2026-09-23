package gateway

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

const ampIssuer = "https://ampcode.com/api/workload-identity"

var ampThreadID = regexp.MustCompile(`^T-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type ampIdentity struct {
	UserID   string `json:"user_id"`
	ThreadID string `json:"thread_id"`
	TokenUse string `json:"token_use"`
}
type ampIdentityKey struct{}

func withAmpIdentity(ctx context.Context, identity ampIdentity) context.Context {
	return context.WithValue(ctx, ampIdentityKey{}, identity)
}

// AmpMCP authenticates each HTTP request using Amp's signed workload identity.
// All threads created by the configured Amp user share this owner's authority.
func (g *Gateway) AmpMCP(ctx context.Context) (http.Handler, error) {
	if g.cfg.AmpUserID == "" {
		return nil, errors.New("AmpUserID is required for workload authentication")
	}
	audience, err := ampAudience(g.cfg.BaseURL)
	if err != nil {
		return nil, err
	}
	ctx = oidc.ClientContext(ctx, &http.Client{Timeout: 10 * time.Second})
	provider, err := oidc.NewProvider(ctx, ampIssuer)
	if err != nil {
		return nil, err
	}
	return g.ampMCP(provider.Verifier(&oidc.Config{ClientID: audience, SupportedSigningAlgs: []string{"RS256"}})), nil
}

func ampAudience(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("Amp workload identity requires an HTTPS origin BaseURL")
	}
	host := strings.ToLower(u.Hostname())
	if port := u.Port(); port != "" && port != "443" {
		host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return "https://" + host, nil
}

func (g *Gateway) ampMCP(verifier *oidc.IDTokenVerifier) http.Handler {
	next := g.mcpHandler()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if ok && len(raw) <= 16384 {
			ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
			defer cancel()
			token, err := verifier.Verify(ctx, raw)
			var identity ampIdentity
			if err == nil && token.Subject != "" && token.Claims(&identity) == nil &&
				identity.UserID != "" && identity.UserID == g.cfg.AmpUserID &&
				identity.TokenUse == "mcp" && ampThreadID.MatchString(identity.ThreadID) {
				next.ServeHTTP(w, r.WithContext(withAmpIdentity(r.Context(), identity)))
				return
			}
		}
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})
}
