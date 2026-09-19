// Command mcp-gateway runs the single-owner MCP gateway.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"ampcode.com/lox/mcp-gateway/internal/browserauth"
	"ampcode.com/lox/mcp-gateway/internal/demo"
	"ampcode.com/lox/mcp-gateway/internal/gateway"
	"ampcode.com/lox/mcp-gateway/internal/store"
	"ampcode.com/lox/mcp-gateway/internal/upstream"
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
	configPath := flag.String("config", "gateway.json", "production configuration file")
	listen := flag.String("listen", "127.0.0.1:8080", "HTTP listen address")
	base := flag.String("base-url", "http://localhost:8080", "canonical browser origin")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var cfg gateway.Config
	var consent http.Handler
	secrets := demo.Secrets{EncryptionKey: os.Getenv("GATEWAY_ENCRYPTION_KEY"), SessionKey: os.Getenv("GATEWAY_SESSION_KEY"), GatewayToken: os.Getenv("GATEWAY_TOKEN")}
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
		if err := d.Decode(&cfg); err != nil {
			return err
		}
		if cfg.OwnerSubject == "" || cfg.BaseURL == "" || cfg.Database == "" {
			return errors.New("OwnerSubject, BaseURL and Database are required")
		}
		u, err := url.Parse(cfg.BaseURL)
		if err != nil || u.Scheme != "https" {
			return errors.New("production BaseURL must use HTTPS behind your trusted TLS proxy")
		}
	}
	if cfg.AmpUserID == "" && len(secrets.GatewayToken) < 32 {
		return errors.New("GATEWAY_TOKEN must be at least 32 characters")
	}
	if cfg.Listen != "" {
		*listen = cfg.Listen
	}
	s, err := store.Open(cfg.Database, secrets.EncryptionKey)
	if err != nil {
		return err
	}
	defer s.Close()
	m, err := upstream.New(cfg.BaseURL, cfg.Connections, s)
	if err != nil {
		return err
	}
	g, err := gateway.New(cfg, s, m)
	if err != nil {
		return err
	}
	authCfg := browserauth.Config{BaseURL: cfg.BaseURL, Issuer: cfg.Issuer, ClientID: cfg.ClientID, ClientSecret: os.Getenv("GATEWAY_OIDC_SECRET"), OwnerSubject: cfg.OwnerSubject, HostedDomain: cfg.HostedDomain, SessionKey: secrets.SessionKey, Demo: *demoMode}
	if *demoMode {
		authCfg.DemoPassword = "demo-only"
	}
	auth, err := browserauth.New(ctx, authCfg)
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	auth.Register(mux)
	var mcpHandler http.Handler
	if cfg.AmpUserID != "" {
		mcpHandler, err = g.AmpMCP(ctx)
		if err != nil {
			return err
		}
	} else {
		mcpHandler = g.MCP(secrets.GatewayToken)
	}
	mux.Handle("/mcp", mcpHandler)
	mux.Handle("/", g.UI(auth, m))
	if consent != nil {
		mux.Handle("GET /demo/authorize", auth.Require(consent))
	}
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { fmt.Fprintln(w, "ok") })
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		w.Header().Set("X-Frame-Options", "DENY")
		mux.ServeHTTP(w, r)
	})
	server := &http.Server{Addr: *listen, Handler: http.NewCrossOriginProtection().Handler(handler), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16384}
	group, ctx := errgroup.WithContext(ctx)
	group.Go(func() error { return g.Run(ctx) })
	group.Go(func() error {
		slog.Info("gateway listening", "address", *listen, "demo", *demoMode)
		err := server.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	})
	group.Go(func() error {
		<-ctx.Done()
		shutdown, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		return server.Shutdown(shutdown)
	})
	return group.Wait()
}
