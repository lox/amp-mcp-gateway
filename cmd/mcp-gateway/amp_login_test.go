package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"ampcode.com/lox/amp-mcp-gateway/internal/gateway"
	"ampcode.com/lox/amp-mcp-gateway/internal/store"
	"golang.org/x/oauth2"
)

func TestLoginRetainsCredentialsInTheCanonicalAccount(t *testing.T) {
	base := accountConfig{Config: gateway.Config{Database: filepath.Join(t.TempDir(), "gateway.db"), AmpUserID: "user_owner"}, Secrets: accountSecrets()}
	s, err := store.Open(base.Config.Database, base.Secrets.EncryptionKey)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	r, err := newRegistry(t.Context(), &accountRuntime{store: s}, base, func(c accountConfig) (*accountRuntime, error) {
		child, err := store.Open(c.Config.Database, c.Secrets.EncryptionKey)
		return &accountRuntime{store: child}, err
	})
	if err != nil {
		t.Fatal(err)
	}
	defer r.close()
	for _, id := range []string{"user_owner", "user_child"} {
		if err := r.login(t.Context(), id, &oauth2.Token{AccessToken: "first-" + id, RefreshToken: "refresh-" + id}); err != nil {
			t.Fatal(err)
		}
		if err := r.login(t.Context(), id, &oauth2.Token{AccessToken: "second-" + id}); err != nil {
			t.Fatal(err)
		}
	}
	if len(r.users) != 2 {
		t.Fatal("login created duplicate accounts")
	}
	for id, account := range r.users {
		raw, err := account.store.LoadToken(t.Context(), "amp-api-oauth/v1")
		if err != nil {
			t.Fatal(err)
		}
		var token oauth2.Token
		if json.Unmarshal(raw, &token) != nil || token.AccessToken != "second-"+id || token.RefreshToken != "refresh-"+id {
			t.Fatal("login lost refresh credentials or crossed account boundaries")
		}
	}
}

func TestAccountProvisioningRecoversInterruptedCreation(t *testing.T) {
	for _, createFile := range []bool{false, true} {
		t.Run(fmt.Sprintf("database-created-%t", createFile), func(t *testing.T) {
			ctx := t.Context()
			base := accountConfig{Config: gateway.Config{Database: filepath.Join(t.TempDir(), "gateway.db"), AmpUserID: "amp-primary", AccountPage: true}, Secrets: accountSecrets()}
			s, err := store.Open(base.Config.Database, base.Secrets.EncryptionKey)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			primary := &accountRuntime{store: s}
			open := func(c accountConfig) (*accountRuntime, error) {
				child, err := store.Open(c.Config.Database, c.Secrets.EncryptionKey)
				if err != nil {
					return nil, err
				}
				if err := bindAccountIdentity(ctx, child, c.Config); err != nil {
					child.Close()
					return nil, err
				}
				return &accountRuntime{store: child}, nil
			}
			r, err := newRegistry(ctx, primary, base, func(c accountConfig) (*accountRuntime, error) {
				marker, err := s.LoadToken(ctx, provisioningKey)
				if err != nil || string(marker) != "child" {
					t.Fatal("database creation preceded durable provisioning intent")
				}
				if createFile {
					child, err := open(c)
					if err != nil {
						t.Fatal(err)
					}
					if err := child.store.SaveToken(ctx, "sentinel", []byte("preserved")); err != nil {
						t.Fatal(err)
					}
					child.store.Close()
				}
				return nil, errors.New("simulated interruption")
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := r.provision(ctx, "child"); err == nil {
				t.Fatal("ignored provisioning failure")
			}
			if err := r.provision(ctx, "other"); err == nil {
				t.Fatal("overwrote pending provisioning intent")
			}
			r.close()
			r, err = newRegistry(ctx, primary, base, open)
			if err != nil {
				t.Fatal(err)
			}
			if r.current("child") != "child" {
				t.Fatal("restart did not finish provisioning")
			}
			if createFile {
				if raw, err := r.users["child"].store.LoadToken(ctx, "sentinel"); err != nil || string(raw) != "preserved" {
					t.Fatal("recovery replaced existing database")
				}
			}
			if raw, err := s.LoadToken(ctx, provisioningKey); err != nil || len(raw) != 0 {
				t.Fatal("recovery left provisioning pending")
			}
			r.close()
			// A crash after registry publication but before marker cleanup must
			// not allow recreation of a now-committed missing database.
			if err := s.SaveToken(ctx, provisioningKey, []byte("child")); err != nil {
				t.Fatal(err)
			}
			r, err = newRegistry(ctx, primary, base, open)
			if err != nil {
				t.Fatal(err)
			}
			cfg, err := r.userConfig("child")
			if err != nil {
				t.Fatal(err)
			}
			r.close()
			if err := s.SaveToken(ctx, provisioningKey, []byte("child")); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(cfg.Config.Database); err != nil {
				t.Fatal(err)
			}
			if bad, err := newRegistry(ctx, primary, base, open); err == nil {
				bad.close()
				t.Fatal("provisioning marker allowed replacement of a committed database")
			}
		})
	}
}
