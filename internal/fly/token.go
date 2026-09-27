// Package fly derives short-lived Fly.io credentials from an existing scoped token.
package fly

import (
	"errors"
	"strings"
	"time"

	"github.com/superfly/macaroon"
	"github.com/superfly/macaroon/flyio"
)

// ValidateToken verifies that raw is a syntactically valid Fly permission token.
// Only Fly.io can verify its signature and current revocation state.
func ValidateToken(raw string) error {
	if raw == "" || strings.ContainsAny(raw, "\r\n") || len(raw) > 16<<10 {
		return errors.New("enter one Fly.io access token without line breaks")
	}
	permission, _, err := flyio.ParsePermissionAndDischargeTokens(raw)
	if err != nil {
		return errors.New("enter a FlyV1 app or organization access token")
	}
	if _, err := macaroon.Decode(permission); err != nil {
		return errors.New("enter a valid Fly.io access token")
	}
	return nil
}

// Attenuate adds a validity window without widening any authority in parent.
func Attenuate(parent string, now time.Time, lifetime time.Duration) (string, error) {
	if lifetime <= 0 {
		return "", errors.New("token lifetime must be positive")
	}
	permission, discharges, err := flyio.ParsePermissionAndDischargeTokens(parent)
	if err != nil {
		return "", errors.New("parse Fly.io access token")
	}
	m, err := macaroon.Decode(permission)
	if err != nil {
		return "", errors.New("decode Fly.io access token")
	}
	if err := m.Add(&macaroon.ValidityWindow{NotBefore: now.Unix(), NotAfter: now.Add(lifetime).Unix()}); err != nil {
		return "", errors.New("attenuate Fly.io access token")
	}
	permission, err = m.Encode()
	if err != nil {
		return "", errors.New("encode Fly.io access token")
	}
	return macaroon.ToAuthorizationHeader(append([][]byte{permission}, discharges...)...), nil
}
