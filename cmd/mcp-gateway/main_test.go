package main

import (
	"testing"

	"ampcode.com/lox/mcp-gateway/internal/gateway"
)

func TestPortalStartupGuard(t *testing.T) {
	for _, tc := range []struct {
		name, orb, public, listen, user, owner, issuer string
		demo, wantOK                                   bool
	}{
		{"orb", "1", "https://debug.onamp.dev", "127.0.0.1:8082", "user_owner", "amp-portal:user_owner", "", false, true},
		{"IPv6", "1", "https://debug.onamp.dev", "[::1]:8082", "user_owner", "amp-portal:user_owner", "", false, true},
		{"outside orb", "", "https://debug.onamp.dev", "127.0.0.1:8082", "user_owner", "amp-portal:user_owner", "", false, false},
		{"public listener", "1", "https://debug.onamp.dev", "0.0.0.0:8082", "user_owner", "amp-portal:user_owner", "", false, false},
		{"unspecified IPv6", "1", "https://debug.onamp.dev", "[::]:8082", "user_owner", "amp-portal:user_owner", "", false, false},
		{"different portal", "1", "https://other.onamp.dev", "127.0.0.1:8082", "user_owner", "amp-portal:user_owner", "", false, false},
		{"missing owner", "1", "https://debug.onamp.dev", "127.0.0.1:8082", "", "amp-portal:", "", false, false},
		{"Google owner", "1", "https://debug.onamp.dev", "127.0.0.1:8082", "user_owner", "google-subject", "", false, false},
		{"OIDC", "1", "https://debug.onamp.dev", "127.0.0.1:8082", "user_owner", "amp-portal:user_owner", "https://accounts.google.com", false, false},
		{"demo", "1", "https://debug.onamp.dev", "127.0.0.1:8082", "user_owner", "amp-portal:user_owner", "", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("AMP_ORB", tc.orb)
			t.Setenv("PUBLIC_URL", tc.public)
			cfg := gateway.Config{BaseURL: "https://debug.onamp.dev", AmpUserID: tc.user, OwnerSubject: tc.owner, Issuer: tc.issuer}
			if err := validatePortalAuth(cfg, tc.listen, tc.demo); (err == nil) != tc.wantOK {
				t.Fatalf("error=%v", err)
			}
		})
	}
}
