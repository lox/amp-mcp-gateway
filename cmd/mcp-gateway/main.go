// Command mcp-gateway runs isolated owner accounts on one MCP gateway process.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"ampcode.com/lox/amp-mcp-gateway/internal/browserauth"
	"ampcode.com/lox/amp-mcp-gateway/internal/browserbridge"
	"ampcode.com/lox/amp-mcp-gateway/internal/demo"
	"ampcode.com/lox/amp-mcp-gateway/internal/gateway"
	"ampcode.com/lox/amp-mcp-gateway/internal/store"
	"ampcode.com/lox/amp-mcp-gateway/internal/upstream"
	"golang.org/x/oauth2"
	"golang.org/x/sync/errgroup"
)

func main() {
	if err := run(); err != nil {
		slog.Error("gateway stopped", "error", err)
		os.Exit(1)
	}
}
func run() error {
	demoMode := flag.Bool("demo", false, "use disposable local upstreams and demo-only browser password")
	portalAuth := flag.Bool("orb-portal-auth", false, "development only: trust owner identity from the local Amp portal proxy (requires loopback listen)")
	configPath := flag.String("config", "gateway.json", "production configuration file")
	listen := flag.String("listen", "127.0.0.1:8080", "HTTP listen address")
	base := flag.String("base-url", "http://localhost:8080", "canonical browser origin")
	clientIPHeader := flag.String("trusted-client-ip-header", "", "client IP header overwritten by trusted ingress; listener must not be directly reachable")
	migrateFrom := flag.String("migrate-from", "", "configuration file for the offline legacy dataset")
	migrationDir := flag.String("migration-dir", "", "destination directory for migrated account databases")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *migrateFrom != "" || *migrationDir != "" {
		if *migrateFrom == "" || *migrationDir == "" {
			return errors.New("-migrate-from and -migration-dir must be supplied together")
		}
		return migrateAccounts(ctx, *migrateFrom, *migrationDir, os.Getenv("GATEWAY_ENCRYPTION_KEY"))
	}
	var err error
	var cfg gateway.Config
	var deployment deploymentConfig
	var consent http.Handler
	secrets := demo.Secrets{EncryptionKey: os.Getenv("GATEWAY_ENCRYPTION_KEY"), SessionKey: os.Getenv("GATEWAY_SESSION_KEY")}
	if *demoMode {
		if err := os.MkdirAll(".local", 0700); err != nil {
			return err
		}
		var err error
		secrets, err = demo.LoadSecrets(".local/demo-secrets.json")
		if err != nil {
			return err
		}
		cfg, consent, err = demo.Start(ctx, *base, secrets.FixtureToken)
		if err != nil {
			return err
		}
	} else {
		f, err := os.Open(*configPath)
		if err != nil {
			return err
		}
		defer f.Close()
		d := json.NewDecoder(f)
		d.DisallowUnknownFields()
		if err := d.Decode(&deployment); err != nil {
			return err
		}
		cfg = deployment.Config
		if cfg.AmpUserID == "" || cfg.BaseURL == "" || cfg.Database == "" {
			return errors.New("AmpUserID, BaseURL and Database are required")
		}
		u, err := url.Parse(cfg.BaseURL)
		if err != nil || u.Scheme != "https" {
			return errors.New("production BaseURL must use HTTPS behind your trusted TLS proxy")
		}
	}
	if cfg.Listen != "" {
		*listen = cfg.Listen
	}
	shared := !*demoMode && !*portalAuth
	if shared && (deployment.AmpLoginClientID == "" || deployment.AmpWorkspaceID == "" || cfg.AmpUserID == "") {
		return errors.New("production requires AmpLoginClientID, AmpWorkspaceID and the primary AmpUserID")
	}
	if *portalAuth {
		if err := validatePortalAuth(cfg, *listen, *demoMode); err != nil {
			return err
		}
	}
	var registry *accountRegistry
	authCfg := browserauth.Config{BaseURL: cfg.BaseURL, AmpUserID: cfg.AmpUserID, SessionKey: secrets.SessionKey, Demo: *demoMode}
	if shared {
		authCfg.ClientID = deployment.AmpLoginClientID
		authCfg.ClientSecret = os.Getenv("GATEWAY_AMP_OIDC_SECRET")
		authCfg.WorkspaceID = deployment.AmpWorkspaceID
		authCfg.APIBaseURL = deployment.AmpAPIBaseURL
		authCfg.Login = func(ctx context.Context, id string, token *oauth2.Token) error {
			return registry.login(ctx, id, token)
		}
		identity, _ := json.Marshal([]string{"amp-login/v2", deployment.AmpLoginClientID, deployment.AmpWorkspaceID})
		var err error
		authCfg.SessionKey, err = accountKey(secrets.SessionKey, "browser-session", identity)
		if err != nil {
			return err
		}
	}
	authCfg.TrustedClientIPHeader = *clientIPHeader
	if authCfg.TrustedClientIPHeader == "" && os.Getenv("FLY_APP_NAME") != "" {
		authCfg.TrustedClientIPHeader = "Fly-Client-IP"
	}
	if *portalAuth {
		authCfg.PortalUserID = cfg.AmpUserID
		authCfg.ClientSecret = ""
	}
	if *demoMode {
		authCfg.DemoPassword = "demo-only"
	}
	group, ctx := errgroup.WithContext(ctx)
	var sharedAuth *browserauth.Auth
	if shared {
		sharedAuth, err = browserauth.New(ctx, authCfg)
		if err != nil {
			return err
		}
	}
	primaryConfig := accountConfig{Config: cfg, Secrets: secrets}
	if shared {
		primaryConfig.Config.AccountPage = true
		primaryConfig.auth = sharedAuth
		primaryConfig.verifier, err = gateway.NewAmpVerifier(ctx, cfg.BaseURL)
		if err != nil {
			return err
		}
	}
	primary, err := newAccount(ctx, primaryConfig, authCfg, consent)
	if err != nil {
		return err
	}
	defer primary.store.Close()
	accounts := []*accountRuntime{primary}
	handler := primary.handler
	if shared {
		registry, err = newRegistry(ctx, primary, primaryConfig, func(config accountConfig) (*accountRuntime, error) {
			return newAccount(ctx, config, authCfg, nil)
		})
		if err != nil {
			return err
		}
		defer registry.close()
		accounts = nil
		handler = sharedAccountHandler(sharedAuth, registry)
	}
	if shared {
		host, err := accountHost(cfg.BaseURL)
		if err != nil {
			return err
		}
		handler = accountRouter(host, handler)
	}
	server := &http.Server{Addr: *listen, Handler: http.NewCrossOriginProtection().Handler(handler), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16384}
	startAccount := func(account *accountRuntime) {
		group.Go(func() error { return account.gateway.Run(ctx) })
		group.Go(func() error { return account.upstream.RunRefresh(ctx) })
	}
	for _, account := range accounts {
		startAccount(account)
	}
	if registry != nil {
		registry.start = startAccount
		registry.mu.RLock()
		for _, account := range registry.users {
			startAccount(account)
		}
		registry.mu.RUnlock()
	}
	group.Go(func() error {
		slog.Info("gateway listening", "address", *listen, "demo", *demoMode, "account_linking", shared)
		err := server.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	})
	group.Go(func() error {
		<-ctx.Done()
		if registry != nil {
			// Finish any provisioning that can add workers before Wait returns.
			registry.provisionMu.Lock()
			registry.provisionMu.Unlock()
		}
		shutdown, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		return server.Shutdown(shutdown)
	})
	return group.Wait()
}

type accountRuntime struct {
	handler    http.Handler
	store      *store.Store
	gateway    *gateway.Gateway
	upstream   *upstream.Manager
	browser    *browserbridge.Manager
	tokenMu    sync.Mutex // OAuth writes and project cache, isolated per account.
	names      browserauth.ProjectNames
	namesUntil time.Time
}

func newAccount(ctx context.Context, config accountConfig, authCfg browserauth.Config, consent http.Handler) (_ *accountRuntime, err error) {
	cfg := config.Config
	secrets := config.Secrets
	s, err := store.Open(cfg.Database, secrets.EncryptionKey)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			s.Close()
		}
	}()
	if err := bindAccountIdentity(ctx, s, cfg); err != nil {
		return nil, err
	}
	if err := gateway.LoadCatalogue(ctx, &cfg, s); err != nil {
		return nil, fmt.Errorf("load saved catalogue: %w", err)
	}
	m, err := upstream.New(cfg.BaseURL, cfg.Connections, s)
	if err != nil {
		return nil, err
	}
	browser, err := browserbridge.New(cfg.BaseURL, cfg.Connections, m)
	if err != nil {
		return nil, err
	}
	browser.AccountPage = cfg.AccountPage
	g, err := gateway.New(cfg, s, browser)
	if err != nil {
		return nil, err
	}
	auth := config.auth
	if auth == nil {
		authCfg.BaseURL, authCfg.AmpUserID, authCfg.SessionKey = cfg.BaseURL, cfg.AmpUserID, secrets.SessionKey
		auth, err = browserauth.New(ctx, authCfg)
		if err != nil {
			return nil, err
		}
	}
	routingID := sha256.Sum256([]byte(cfg.AmpUserID))
	browser.RoutingID = fmt.Sprintf("%x", routingID[:12])
	mux := http.NewServeMux()
	auth.Register(mux)
	var mcpHandler, leaseHandler http.Handler
	if !cfg.Demo {
		if config.verifier != nil {
			mcpHandler, leaseHandler, err = config.verifier.Handlers(g)
		} else {
			mcpHandler, leaseHandler, err = g.AmpHandlers(ctx)
		}
		if err != nil {
			return nil, err
		}
	} else {
		mcpHandler, leaseHandler = g.DemoHandlers(secrets.GatewayToken)
	}
	mux.Handle("/mcp", mcpHandler)
	mux.Handle("POST /leases/{id}", leaseHandler)
	mux.Handle("/browser/connect", browser.Socket())
	browserUI := auth.Require(http.NewCrossOriginProtection().Handler(browser.UI(func(ctx context.Context) error {
		return g.EnableChrome(ctx, m)
	})))
	mux.Handle("/integrations/chrome", browserUI)
	mux.Handle("/integrations/chrome/", browserUI)
	mux.Handle("/", g.UI(auth, m))
	if consent != nil {
		mux.Handle("GET /demo/authorize", auth.Require(consent))
	}
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { fmt.Fprintln(w, "ok") })
	account := &accountRuntime{handler: securityHeaders(mux), store: s, gateway: g, upstream: m, browser: browser}
	if cfg.AccountPage {
		g.ProjectNames = func(ctx context.Context) browserauth.ProjectNames { return account.projectNames(ctx, auth) }
	}
	return account, nil
}

func sharedAccountHandler(auth *browserauth.Auth, registry *accountRegistry) http.Handler {
	mux := http.NewServeMux()
	auth.Register(mux)
	mux.Handle("GET /account", auth.Require(http.HandlerFunc(registry.account)))
	mux.Handle("/mcp", http.HandlerFunc(registry.workload))
	mux.Handle("POST /leases/{id}", http.HandlerFunc(registry.workload))
	mux.Handle("/browser/connect", browserbridge.SocketRouter(registry.browserManager))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprintln(w, "ok") })
	mux.Handle("/", auth.Require(http.HandlerFunc(registry.browser)))
	return securityHeaders(mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

func validatePortalAuth(cfg gateway.Config, listen string, demo bool) error {
	address, err := netip.ParseAddrPort(listen)
	if err != nil || !address.Addr().IsLoopback() || os.Getenv("AMP_ORB") != "1" || os.Getenv("PUBLIC_URL") == "" || strings.TrimSuffix(os.Getenv("PUBLIC_URL"), "/") != cfg.BaseURL || demo || cfg.AmpUserID == "" {
		return errors.New("orb portal auth requires AMP_ORB=1, BaseURL matching PUBLIC_URL, literal loopback listen, AmpUserID, and no demo configuration")
	}
	return nil
}
