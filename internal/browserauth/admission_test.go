package browserauth

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOIDCSourceAdmissionAndBrowserRetry(t *testing.T) {
	a := demoAuth(t)
	a.demo = false
	a.oauth.Endpoint.AuthURL = "https://issuer.example/authorize"
	mux := http.NewServeMux()
	a.Register(mux)
	login := func(source string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/login", nil)
		r.RemoteAddr = source
		// Forwarding headers are not trusted on a directly exposed listener.
		r.Header.Set("X-Forwarded-For", fmt.Sprintf("203.0.113.%d", len(a.states)))
		r.Header.Set("Fly-Client-IP", fmt.Sprintf("203.0.113.%d", len(a.states)))
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	first := login("192.0.2.1:1", nil)
	for i := 1; i < 8; i++ {
		if w := login(fmt.Sprintf("192.0.2.1:%d", i+1), nil); w.Code != 303 {
			t.Fatalf("admission %d: %d", i, w.Code)
		}
	}
	for range 128 {
		if w := login("192.0.2.1:9999", nil); w.Code != 429 || len(w.Result().Cookies()) != 0 {
			t.Fatal("one source exhausted the global pool")
		}
	}
	if len(a.states) != 8 {
		t.Fatalf("one source retained %d logins", len(a.states))
	}
	if w := login("192.0.2.2:1", nil); w.Code != 303 {
		t.Fatalf("attacker blocked a different source: %d", w.Code)
	}
	for range 128 {
		w := login("192.0.2.1:1", first.Result().Cookies()[0])
		if w.Code != 303 || w.Header().Get("Location") != first.Header().Get("Location") {
			t.Fatal("signed browser retry changed its pending login")
		}
	}
	if len(a.states) != 9 {
		t.Fatal("signed browser retries allocated extra states")
	}
}

func TestLoginSourceNormalizationAndTrustedIngress(t *testing.T) {
	for _, tc := range []struct {
		name, peer, header string
		trusted            bool
		want               string
	}{
		{"direct", "192.0.2.1:1234", "203.0.113.1", false, "192.0.2.1/32"},
		{"mapped IPv4", "[::ffff:192.0.2.1]:1234", "", false, "192.0.2.1/32"},
		{"IPv6 prefix", "[2001:db8:1:2::abcd]:1234", "", false, "2001:db8:1:2::/64"},
		{"trusted proxy", "[fdaa::1]:1234", "203.0.113.1", true, "203.0.113.1/32"},
		{"trusted IPv6", "[fdaa::1]:1234", "2001:db8:1:2::ffff", true, "2001:db8:1:2::/64"},
		{"missing header", "[fdaa::1]:1234", "", true, ""},
		{"header list", "[fdaa::1]:1234", "203.0.113.1, 203.0.113.2", true, ""},
		{"malformed peer", "unknown", "203.0.113.1", false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := demoAuth(t)
			if tc.trusted {
				a.clientIPHeader = "Fly-Client-IP"
			}
			r := httptest.NewRequest("GET", "/login", nil)
			r.RemoteAddr = tc.peer
			if tc.header != "" {
				r.Header.Set("Fly-Client-IP", tc.header)
			}
			source, err := a.loginSource(r)
			if tc.want == "" {
				if err == nil {
					t.Fatal("invalid source accepted")
				}
			} else if err != nil || source.String() != tc.want {
				t.Fatalf("source=%s err=%v", source, err)
			}
		})
	}
}
