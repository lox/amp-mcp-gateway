package browserauth

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPortalOwnerAuthentication(t *testing.T) {
	a, err := New(t.Context(), Config{BaseURL: "https://debug.onamp.dev", SessionKey: base64.StdEncoding.EncodeToString(make([]byte, 32)), OwnerSubject: "amp-portal:user_owner", PortalUserID: "user_owner"})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, peer, host, user, authenticated string
		want                                  int
	}{
		{"owner", "127.0.0.1:5000", "debug.onamp.dev", "user_owner", "amp-user=yes, collaborator=yes", 200},
		{"IPv6", "[::1]:5000", "debug.onamp.dev", "user_owner", "amp-user=yes, workspace-member=yes", 200},
		{"anonymous", "127.0.0.1:5000", "debug.onamp.dev", "", "amp-user=no", 403},
		{"other member", "127.0.0.1:5000", "debug.onamp.dev", "user_other", "amp-user=yes, workspace-member=yes", 403},
		{"forged remote", "192.0.2.5:5000", "debug.onamp.dev", "user_owner", "amp-user=yes", 403},
		{"wrong host", "127.0.0.1:5000", "other.onamp.dev", "user_owner", "amp-user=yes", 403},
		{"missing attestation", "127.0.0.1:5000", "debug.onamp.dev", "user_owner", "", 403},
		{"contradictory", "127.0.0.1:5000", "debug.onamp.dev", "user_owner", "amp-user=no, amp-user=yes", 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "https://"+tc.host+"/", nil)
			r.RemoteAddr = tc.peer
			r.Header.Set("X-Amp-User-ID", tc.user)
			r.Header.Set("X-Amp-Authenticated", tc.authenticated)
			w := httptest.NewRecorder()
			a.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if Subject(r.Context()) != "amp-portal:user_owner" {
					t.Error("incorrect audit actor")
				}
				w.WriteHeader(200)
			})).ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("got %d want %d", w.Code, tc.want)
			}
		})
	}
	// Cookies must never bypass the per-request portal identity check.
	w := httptest.NewRecorder()
	a.setSignedCookie(w, sessionCookie, cookieValue{Subject: a.owner, Expires: a.now().Add(sessionTTL).Unix()}, sessionTTL)
	r := httptest.NewRequest("GET", "https://debug.onamp.dev/", nil)
	r.RemoteAddr = "127.0.0.1:5000"
	r.AddCookie(w.Result().Cookies()[0])
	result := httptest.NewRecorder()
	a.Require(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("cookie bypass") })).ServeHTTP(result, r)
	if result.Code != 403 {
		t.Fatal(result.Code)
	}
	for _, header := range []string{"X-Amp-User-ID", "X-Amp-Authenticated"} {
		r := httptest.NewRequest("GET", "https://debug.onamp.dev/", nil)
		r.RemoteAddr = "127.0.0.1:5000"
		r.Header.Set("X-Amp-User-ID", "user_owner")
		r.Header.Set("X-Amp-Authenticated", "amp-user=yes")
		r.Header.Add(header, r.Header.Get(header))
		if a.portalOwner(r) {
			t.Errorf("accepted duplicate %s", header)
		}
	}
	mux := http.NewServeMux()
	a.Register(mux)
	callback := httptest.NewRecorder()
	mux.ServeHTTP(callback, httptest.NewRequest("GET", "/auth/callback", nil))
	if callback.Code != 404 {
		t.Fatal("OIDC callback enabled")
	}
	r = httptest.NewRequest("POST", "https://debug.onamp.dev/logout", nil)
	r.RemoteAddr = "127.0.0.1:5000"
	r.Header.Set("X-Amp-User-ID", "user_owner")
	r.Header.Set("X-Amp-Authenticated", "amp-user=yes")
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	result = httptest.NewRecorder()
	mux.ServeHTTP(result, r)
	if result.Code != 403 {
		t.Fatal("cross-site logout accepted")
	}
}

func TestPortalHeadersDoNotEnableOtherModes(t *testing.T) {
	a := demoAuth(t)
	r := httptest.NewRequest("GET", "https://gateway.example/", nil)
	r.RemoteAddr = "127.0.0.1:5000"
	r.Header.Set("X-Amp-User-ID", "user_owner")
	r.Header.Set("X-Amp-Authenticated", "amp-user=yes")
	w := httptest.NewRecorder()
	a.Require(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("portal bypass outside explicit mode") })).ServeHTTP(w, r)
	if w.Code != 303 {
		t.Fatal(w.Code)
	}
}
