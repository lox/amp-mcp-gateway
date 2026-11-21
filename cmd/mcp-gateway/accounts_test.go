package main

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ampcode.com/lox/amp-mcp-gateway/internal/browserauth"
	"ampcode.com/lox/amp-mcp-gateway/internal/demo"
	"ampcode.com/lox/amp-mcp-gateway/internal/gateway"
	"ampcode.com/lox/amp-mcp-gateway/internal/store"
	"ampcode.com/lox/amp-mcp-gateway/internal/upstream"
)

func accountSecrets() demo.Secrets {
	return demo.Secrets{EncryptionKey: base64.StdEncoding.EncodeToString(make([]byte, 32)), SessionKey: base64.StdEncoding.EncodeToString(make([]byte, 32))}
}

func TestCanonicalHostGate(t *testing.T) {
	h := accountRouter("gateway.example", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	for _, tc := range []struct {
		host, path string
		status     int
	}{
		{"GATEWAY.example:443", "/account", 204},
		{"foreign.example", "/account", 404},
		{"foreign.example", "/healthz", 200},
	} {
		req := httptest.NewRequest("GET", "https://"+tc.host+tc.path, nil)
		req.Header.Set("X-Forwarded-Host", "gateway.example")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != tc.status {
			t.Fatalf("%s%s: got %d, want %d", tc.host, tc.path, w.Code, tc.status)
		}
	}
}

func TestRegistryDerivesIsolatedStableAccountState(t *testing.T) {
	secrets := accountSecrets()
	db := filepath.Join(t.TempDir(), "gateway.db")
	s, err := store.Open(db, secrets.EncryptionKey)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	primary := &accountRuntime{store: s}
	base := accountConfig{Config: gateway.Config{BaseURL: "https://gateway.example", Database: db, AmpUserID: "amp-primary"}, Secrets: secrets}
	var opened []accountConfig
	r, err := newRegistry(t.Context(), primary, base, func(c accountConfig) (*accountRuntime, error) {
		opened = append(opened, c)
		child, err := store.Open(c.Config.Database, c.Secrets.EncryptionKey)
		return &accountRuntime{store: child}, err
	})
	if err != nil {
		t.Fatal(err)
	}
	defer r.close()
	if err := r.provision(t.Context(), "amp-bob"); err != nil {
		t.Fatal(err)
	}
	if len(opened) != 1 {
		t.Fatalf("opened %d accounts", len(opened))
	}
	child := opened[0]
	if child.Config.Database == db || child.Secrets.EncryptionKey == secrets.EncryptionKey || child.Config.AmpUserID != "amp-bob" {
		t.Fatalf("linked account was not isolated: %#v", child.Config)
	}
	if child.Secrets.SessionKey != secrets.SessionKey || child.auth != base.auth {
		t.Fatal("linked account did not retain the shared browser authentication boundary")
	}
	childStore := r.users["amp-bob"].store
	_, err = childStore.Submit(t.Context(), store.Operation{ID: "bob-operation", Status: "pending", Digest: "bob-only", Created: 1})
	if err != nil {
		t.Fatal(err)
	}
	r.close()

	opened = nil
	restarted, err := newRegistry(t.Context(), primary, base, func(c accountConfig) (*accountRuntime, error) {
		opened = append(opened, c)
		child, openErr := store.Open(c.Config.Database, c.Secrets.EncryptionKey)
		return &accountRuntime{store: child}, openErr
	})
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.close()
	if len(opened) != 1 || restarted.current("amp-bob") != "amp-bob" {
		t.Fatalf("restart did not restore unique linkage: opened=%d current=%q", len(opened), restarted.current("amp-bob"))
	}
	op, err := restarted.users["amp-bob"].store.Get(t.Context(), "bob-operation")
	if err != nil || op.Digest != "bob-only" {
		t.Fatalf("restart lost child state: operation=%#v err=%v", op, err)
	}
	if _, err := primary.store.Get(t.Context(), "bob-operation"); err == nil {
		t.Fatal("child operation leaked into primary store")
	}
	restarted.close()
	if err := os.Remove(child.Config.Database); err != nil {
		t.Fatal(err)
	}
	restored, err := newRegistry(t.Context(), primary, base, r.open)
	if restored != nil {
		restored.close()
	}
	if !errors.Is(err, os.ErrNotExist) || !strings.Contains(err.Error(), "restore") {
		t.Fatalf("missing linked database did not require recovery: %v", err)
	}
	if _, err := os.Stat(child.Config.Database); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing linked database was recreated: %v", err)
	}
}

func TestWorkloadRejectsMissingMalformedAndUnknownRoutingHints(t *testing.T) {
	r := &accountRegistry{users: map[string]*accountRuntime{}}
	for _, token := range []string{"", "not-a-jwt", "e30.e30.", "e30.eyJ1c2VyX2lkIjoiZm9yZWlnbiJ9."} {
		req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		r.workload(w, req)
		if w.Code != http.StatusUnauthorized || w.Header().Get("WWW-Authenticate") != "Bearer" {
			t.Fatalf("token %q: status=%d challenge=%q", token, w.Code, w.Header().Get("WWW-Authenticate"))
		}
	}
}

func TestRegistryStopsLinkingAfterShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := &accountRegistry{ctx: ctx}
	if err := r.provision(context.Background(), "user"); err == nil {
		t.Fatal("link accepted during shutdown")
	}
}

func TestSlowLinkDoesNotBlockExistingAccountRouting(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	s, err := store.Open(filepath.Join(t.TempDir(), "primary.db"), accountSecrets().EncryptionKey)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	r := &accountRegistry{
		ctx: t.Context(), config: accountConfig{Secrets: accountSecrets()},
		primary: &accountRuntime{store: s},
		users:   map[string]*accountRuntime{"existing": {}},
		open: func(accountConfig) (*accountRuntime, error) {
			close(entered)
			<-release
			return nil, errors.New("discovery unavailable")
		},
	}
	done := make(chan error, 1)
	go func() { done <- r.provision(t.Context(), "amp-new") }()
	<-entered
	defer func() {
		close(release)
		if err := <-done; err == nil {
			t.Error("failed discovery published an account")
		}
	}()
	routed := make(chan string, 1)
	go func() { routed <- r.current("existing") }()
	select {
	case got := <-routed:
		if got != "existing" {
			t.Fatal("existing link lost")
		}
	case <-time.After(time.Second):
		t.Fatal("slow runtime creation blocked existing account lookup")
	}
}

func TestBoundPrimaryDatabaseRejectsIdentityReassignment(t *testing.T) {
	secrets := accountSecrets()
	cfg := gateway.Config{Database: filepath.Join(t.TempDir(), "primary.db"), AmpUserID: "original-amp", AccountPage: true}
	s, err := store.Open(cfg.Database, secrets.EncryptionKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := bindAccountIdentity(t.Context(), s, cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveToken(t.Context(), "private-provider", []byte("original-credential")); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	for _, linking := range []bool{true, false} {
		changed := cfg
		changed.AmpUserID, changed.AccountPage = "new-amp", linking
		_, err := newAccount(t.Context(), accountConfig{Config: changed, Secrets: secrets}, browserauth.Config{}, nil)
		if err == nil || !strings.Contains(err.Error(), "identity cannot be reassigned") {
			t.Fatalf("reassigned existing data (linking=%v): %v", linking, err)
		}
	}
	s, err = store.Open(cfg.Database, secrets.EncryptionKey)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := bindAccountIdentity(t.Context(), s, cfg); err != nil {
		t.Fatal(err)
	}
	if raw, err := s.LoadToken(t.Context(), "private-provider"); err != nil || string(raw) != "original-credential" {
		t.Fatal("rejected reassignment changed existing credentials")
	}
}

func TestAccountRetiresNativeBrowserIntegration(t *testing.T) {
	for _, tc := range []struct {
		name   string
		remote string // What owns the browser ID after the upgrade, if anything.
	}{{"native browser from a saved catalogue", ""}, {"remote connection named browser", "connection"}, {"secret named browser", "secret"}} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := gateway.Config{BaseURL: "https://gateway.example", Database: filepath.Join(t.TempDir(), "gateway.db"), AmpUserID: "owner", Demo: true}
			secrets := accountSecrets()
			s, err := store.Open(cfg.Database, secrets.EncryptionKey)
			if err != nil {
				t.Fatal(err)
			}
			switch tc.remote {
			case "connection":
				cfg.Connections = []upstream.Connection{{ID: "browser", URL: "https://example.com/mcp", NoAuth: true}}
				cfg.Tools = []gateway.Tool{{ID: "browser.click", Connection: "browser", Name: "click", Policy: "require_approval", InputSchema: map[string]any{"type": "object"}}}
			case "secret":
				cfg.Integrations = []gateway.Integration{{ID: "browser", Provider: "secret", Account: "Browser API key", Credential: "fixture-secret", Policy: "require_approval"}}
			default:
				// The shape the previous release saved after any catalogue change.
				saved := `{"Connections":[{"ID":"browser","URL":"","Account":"Local Chrome browser","TokenEnv":"","Browser":true,"OAuth":null}],"Tools":[{"ID":"browser.click","Connection":"browser","Name":"click","Description":"","Policy":"require_approval","InputSchema":{"type":"object"}}],"PrivateConnections":{"browser":true}}`
				if err := s.SaveCatalogue(t.Context(), []byte(saved)); err != nil {
					t.Fatal(err)
				}
			}
			now := time.Now()
			submit := func(id, connection string) {
				o := store.Operation{ID: id, Tool: connection + ".click", Connection: connection, Binding: "binding", AmpUserID: "owner", AmpThreadID: "thread", Status: "pending", Digest: id, Created: now.Unix(), Expires: now.Add(time.Hour).Unix()}
				if _, err := s.Submit(t.Context(), o); err != nil {
					t.Fatal(err)
				}
			}
			submit("browser-granted", "browser")
			if err := s.ApproveWithOptions(t.Context(), "browser-granted", "amp:owner", store.ApprovalOptions{Breadth: "tool", Scope: "thread", Expiry: "never"}); err != nil {
				t.Fatal(err)
			}
			submit("browser-pending", "browser")
			submit("notes-pending", "notes")
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}

			account, err := newAccount(t.Context(), accountConfig{Config: cfg, Secrets: secrets}, browserauth.Config{Demo: true, DemoPassword: "fixture-password"}, nil)
			if err != nil {
				t.Fatalf("startup failed: %v", err)
			}
			defer account.store.Close()
			want := map[string]string{"browser-granted": "denied", "browser-pending": "denied", "notes-pending": "pending"}
			if tc.remote != "" {
				want["browser-granted"], want["browser-pending"] = "ready", "ready" // the second matched the standing approval
			}
			for id, status := range want {
				o, err := account.store.Get(t.Context(), id)
				if err != nil || o.Status != status {
					t.Fatalf("%s = %q, %v; want %q", id, o.Status, err, status)
				}
				events, err := account.store.OperationEvents(t.Context(), id)
				if err != nil {
					t.Fatal(err)
				}
				last := events[0] // newest first
				if retired := last.Kind == "denied" && last.Actor == "browser-integration-removed"; retired != (status == "denied") {
					t.Fatalf("%s audit history = %+v", id, events)
				}
			}
			grants, err := account.store.ApprovalGrants(t.Context())
			if err != nil || len(grants) != map[bool]int{false: 0, true: 1}[tc.remote != ""] {
				t.Fatalf("standing approvals = %+v, %v", grants, err)
			}
		})
	}
}
