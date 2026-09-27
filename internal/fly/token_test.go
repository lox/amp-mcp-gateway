package fly

import (
	"testing"
	"time"

	"github.com/superfly/macaroon"
	"github.com/superfly/macaroon/flyio"
)

func fixtureToken(t *testing.T) string {
	t.Helper()
	m, err := macaroon.New([]byte("fixture"), flyio.LocationPermission, macaroon.SigningKey(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := m.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return macaroon.ToAuthorizationHeader(raw)
}

func TestAttenuateAddsRequestedWindow(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	parent := fixtureToken(t)
	child, err := Attenuate(parent, now, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if child == parent {
		t.Fatal("token was not attenuated")
	}
	permission, _, err := flyio.ParsePermissionAndDischargeTokens(child)
	if err != nil {
		t.Fatal(err)
	}
	m, err := macaroon.Decode(permission)
	if err != nil {
		t.Fatal(err)
	}
	windows := macaroon.GetCaveats[*macaroon.ValidityWindow](&m.UnsafeCaveats)
	if len(windows) != 1 || windows[0].NotBefore != now.Add(-clockSkewAllowance).Unix() || windows[0].NotAfter != now.Add(10*time.Minute).Unix() {
		t.Fatalf("unexpected validity windows: %#v", windows)
	}
}

func TestValidateTokenRejectsUnsafeInput(t *testing.T) {
	if err := ValidateToken(fixtureToken(t)); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"", "not-a-token", fixtureToken(t) + "\nsecond"} {
		if ValidateToken(raw) == nil {
			t.Fatalf("accepted %q", raw)
		}
	}
}
