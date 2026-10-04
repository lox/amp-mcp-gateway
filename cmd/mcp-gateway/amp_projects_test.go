package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ampcode.com/lox/amp-mcp-gateway/internal/browserauth"
	"ampcode.com/lox/amp-mcp-gateway/internal/store"
	"golang.org/x/oauth2"
)

func TestAccountProjectNamesRefresh(t *testing.T) {
	for _, failure := range []bool{false, true} {
		t.Run(map[bool]string{false: "rotated", true: "ambiguous failure"}[failure], func(t *testing.T) {
			s, err := store.Open(filepath.Join(t.TempDir(), "account.db"), accountSecrets().EncryptionKey)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			a := &accountRuntime{store: s}
			raw, _ := json.Marshal(&oauth2.Token{AccessToken: "old", RefreshToken: "refresh-old", Expiry: time.Now().Add(-time.Hour)})
			if err := s.SaveToken(t.Context(), "amp-api-oauth/v1", raw); err != nil {
				t.Fatal(err)
			}
			var issuer string
			var refreshes, reads atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/.well-known/openid-configuration":
					_ = json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}})
				case "/token":
					refreshes.Add(1)
					_ = r.ParseForm()
					if r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("refresh_token") != "refresh-old" || r.Form.Get("client_id") != "client" || r.Form.Get("client_secret") != "fixture-secret" {
						t.Error("incorrect refresh request")
					}
					var persisted oauth2.Token
					raw, err := s.LoadToken(r.Context(), "amp-api-oauth/v1")
					if err != nil || json.Unmarshal(raw, &persisted) != nil || persisted.RefreshToken != "" {
						t.Error("refresh dispatched before old token retired")
					}
					if failure {
						http.Error(w, "provider failure", 500)
						return
					}
					_, _ = w.Write([]byte(`{"access_token":"new","refresh_token":"refresh-new","token_type":"Bearer","expires_in":3600}`))
				case "/workspace/projects":
					reads.Add(1)
					if r.Header.Get("Authorization") != "Bearer new" {
						t.Error("lookup did not use refreshed token")
					}
					_, _ = w.Write([]byte(`{"projects":[{"id":"project","namespace":"team","name":"Gateway","owner":{"id":"workspace","name":"Team","type":"workspace"}}]}`))
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			issuer = server.URL
			auth, err := browserauth.New(t.Context(), browserauth.Config{BaseURL: "https://gateway.example", Issuer: issuer, ActorURL: issuer + "/actor", ClientID: "client", ClientSecret: "fixture-secret", WorkspaceID: "workspace", SessionKey: accountSecrets().SessionKey, Login: func(context.Context, string, *oauth2.Token) error { return nil }})
			if err != nil {
				t.Fatal(err)
			}
			var wg sync.WaitGroup
			for range 8 {
				wg.Go(func() {
					names := a.projectNames(t.Context(), auth)
					want := "team/Gateway"
					if failure {
						want = ""
					}
					if names.Project("workspace", "project") != want {
						t.Error("unexpected project label")
					}
				})
			}
			wg.Wait()
			if refreshes.Load() != 1 || (!failure && reads.Load() != 1) || (failure && reads.Load() != 0) {
				t.Fatalf("refreshes=%d reads=%d", refreshes.Load(), reads.Load())
			}
			// A fresh runtime must use the persisted rotation, or refuse to retry
			// an ambiguous refresh even after the in-memory failure cache expires.
			restarted := &accountRuntime{store: s}
			restarted.projectNames(t.Context(), auth)
			if refreshes.Load() != 1 {
				t.Fatal("restart replayed refresh")
			}
			other, err := store.Open(filepath.Join(t.TempDir(), "other.db"), accountSecrets().EncryptionKey)
			if err != nil {
				t.Fatal(err)
			}
			defer other.Close()
			if names := (&accountRuntime{store: other}).projectNames(t.Context(), auth); names.Project("workspace", "project") != "" {
				t.Fatal("project cache crossed account boundary")
			}
		})
	}
}
