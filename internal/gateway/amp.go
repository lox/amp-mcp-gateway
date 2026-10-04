package gateway

import (
	"context"
	"crypto/subtle"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/net/idna"
)

const ampIssuer = "https://ampcode.com/api/workload-identity"

var ampThreadID = regexp.MustCompile(`^T-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type ampIdentity struct {
	Subject                    string `json:"sub"`
	UserID                     string `json:"user_id"`
	WorkspaceID                string `json:"workspace_id"`
	ProjectID                  string `json:"project_id"`
	ThreadID                   string `json:"thread_id"`
	ThreadVisibility           string `json:"thread_visibility"`
	ThreadMultiplayer          *bool  `json:"thread_multiplayer"`
	ThreadNonOwnerCanInfluence *bool  `json:"thread_non_owner_can_influence"`
	TokenUse                   string `json:"token_use"`
}
type ampIdentityKey struct{}

const demoThreadID = "T-00000000-0000-0000-0000-000000000001"

func demoIdentity(userID string) ampIdentity {
	return ampIdentity{
		Subject: "demo-fixture-workload", UserID: userID,
		WorkspaceID: "demo-fixture-workspace", ProjectID: "demo-fixture-project",
		ThreadID: demoThreadID, ThreadVisibility: "private",
		ThreadMultiplayer: new(bool), ThreadNonOwnerCanInfluence: new(bool),
	}
}

func withAmpIdentity(ctx context.Context, identity ampIdentity) context.Context {
	return context.WithValue(ctx, ampIdentityKey{}, identity)
}

func (identity ampIdentity) privateThread() bool {
	return identity.UserID != "" && ampThreadID.MatchString(identity.ThreadID) &&
		identity.ThreadVisibility == "private" &&
		identity.ThreadMultiplayer != nil && !*identity.ThreadMultiplayer &&
		identity.ThreadNonOwnerCanInfluence != nil && !*identity.ThreadNonOwnerCanInfluence
}

func (identity ampIdentity) hasThreadContext() bool {
	switch identity.ThreadVisibility {
	case "private", "thread_group_shared", "thread_workspace_shared", "public_unlisted":
		return identity.ThreadMultiplayer != nil && identity.ThreadNonOwnerCanInfluence != nil
	default:
		return false
	}
}

func (identity ampIdentity) allows(private bool) bool {
	return !private || identity.privateThread()
}

// AmpMCP authenticates each HTTP request using Amp's signed workload identity.
// All threads created by the configured Amp user share this owner's authority.
func (g *Gateway) AmpMCP(ctx context.Context) (http.Handler, error) {
	mcpHandler, _, err := g.AmpHandlers(ctx)
	return mcpHandler, err
}

// AmpHandlers authenticates MCP and credential-redemption requests with one verifier.
func (g *Gateway) AmpHandlers(ctx context.Context) (http.Handler, http.Handler, error) {
	if g.cfg.AmpUserID == "" {
		return nil, nil, errors.New("AmpUserID is required for workload authentication")
	}
	v, err := NewAmpVerifier(ctx, g.cfg.BaseURL)
	if err != nil {
		return nil, nil, err
	}
	return v.Handlers(g)
}

// DemoHandlers exposes fake-fixture handlers only when demo mode was explicitly
// configured. It must never be mounted by a production command.
func (g *Gateway) DemoHandlers(token string) (http.Handler, http.Handler) {
	wrap := func(next http.Handler, tokenUse string) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !g.cfg.Demo || token == "" || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+token)) != 1 {
				w.Header().Set("WWW-Authenticate", "Bearer")
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			identity := demoIdentity(g.cfg.AmpUserID)
			identity.TokenUse = tokenUse
			next.ServeHTTP(w, r.WithContext(withAmpIdentity(r.Context(), identity)))
		})
	}
	return wrap(g.mcpHandler(), "mcp"), wrap(http.HandlerFunc(g.redeemLease), "exchanged")
}

// AmpVerifier shares discovery and JWKS caching across accounts on one origin.
type AmpVerifier struct {
	audience string
	verifier *oidc.IDTokenVerifier
}

// NewAmpVerifier discovers Amp once for a deployment. Account identity checks
// remain in each handler; the shared verifier only authenticates the token.
func NewAmpVerifier(ctx context.Context, baseURL string) (*AmpVerifier, error) {
	audience, err := CanonicalOrigin(baseURL)
	if err != nil {
		return nil, err
	}
	ctx = oidc.ClientContext(ctx, &http.Client{Timeout: 10 * time.Second})
	provider, err := oidc.NewProvider(ctx, ampIssuer)
	if err != nil {
		return nil, err
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: audience, SupportedSigningAlgs: []string{"RS256"}})
	return &AmpVerifier{audience: audience, verifier: verifier}, nil
}

// Handlers builds account-specific MCP and lease handlers for this origin.
func (v *AmpVerifier) Handlers(g *Gateway) (http.Handler, http.Handler, error) {
	audience, err := CanonicalOrigin(g.cfg.BaseURL)
	if err != nil || audience != v.audience || g.cfg.AmpUserID == "" {
		return nil, nil, errors.New("workload handlers require the verifier's origin and an AmpUserID")
	}
	return g.ampAuthenticated(v.verifier, g.mcpHandler(), false), g.ampAuthenticated(v.verifier, http.HandlerFunc(g.redeemLease), true), nil
}

// CanonicalOrigin returns the HTTPS origin used for Amp audiences and account routing.
func CanonicalOrigin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("Amp workload identity requires an HTTPS origin BaseURL")
	}
	host := u.Hostname()
	addr, addrErr := netip.ParseAddr(host)
	if addrErr == nil {
		if addr.Zone() != "" {
			return "", errors.New("Amp workload identity BaseURL cannot contain an IPv6 zone")
		}
		host = addr.String()
	} else {
		if strings.IndexFunc(host, func(r rune) bool { return r != '.' && (r < '0' || r > '9') }) == -1 {
			return "", errors.New("Amp workload identity BaseURL contains a noncanonical IP address")
		}
		host, err = idna.Lookup.ToASCII(host)
		if err != nil || host == "" {
			return "", errors.New("Amp workload identity BaseURL contains an invalid hostname")
		}
		host = strings.ToLower(host)
	}
	port := u.Port()
	if port != "" {
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil {
			return "", errors.New("Amp workload identity BaseURL contains an invalid port")
		}
		port = strconv.FormatUint(n, 10)
	}
	if port != "" && port != "443" {
		host = net.JoinHostPort(host, port)
	} else if addrErr == nil && addr.Is6() {
		host = "[" + host + "]"
	}
	return "https://" + host, nil
}

func (g *Gateway) ampMCP(verifier *oidc.IDTokenVerifier) http.Handler {
	return g.ampAuthenticated(verifier, g.mcpHandler(), false)
}

func (g *Gateway) ampAuthenticated(verifier *oidc.IDTokenVerifier, next http.Handler, allowExchanged bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if ok && len(raw) <= 16384 {
			ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
			defer cancel()
			token, err := verifier.Verify(ctx, raw)
			var identity ampIdentity
			if err == nil && token.Subject != "" && token.Claims(&identity) == nil &&
				identity.Subject == token.Subject &&
				identity.UserID != "" && identity.UserID == g.cfg.AmpUserID &&
				(identity.TokenUse == "mcp" || allowExchanged && identity.TokenUse == "exchanged") &&
				ampThreadID.MatchString(identity.ThreadID) {
				next.ServeHTTP(w, r.WithContext(withAmpIdentity(r.Context(), identity)))
				return
			}
		}
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})
}
