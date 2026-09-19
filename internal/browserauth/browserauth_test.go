package browserauth

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func demoAuth(t *testing.T) *Auth {
	t.Helper()
	a, err := New(context.Background(), Config{
		BaseURL:    "https://gateway.example",
		SessionKey: base64.StdEncoding.EncodeToString(make([]byte, 32)),
		Demo:       true, DemoPassword: "correct horse", OwnerSubject: "owner",
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestDemoLoginRequireTamperAndLogout(t *testing.T) {
	a := demoAuth(t)
	mux := http.NewServeMux()
	a.Register(mux)
	mux.Handle("GET /private", a.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(Subject(r.Context())))
	})))

	unauthorized := httptest.NewRecorder()
	mux.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/private", nil))
	if unauthorized.Code != http.StatusSeeOther || unauthorized.Header().Get("Location") != "/login" {
		t.Fatalf("unauthorized: %d %q", unauthorized.Code, unauthorized.Header().Get("Location"))
	}

	bad := httptest.NewRecorder()
	mux.ServeHTTP(bad, formRequest("/login", "wrong"))
	if bad.Code != http.StatusUnauthorized {
		t.Fatalf("bad password status = %d", bad.Code)
	}

	login := httptest.NewRecorder()
	mux.ServeHTTP(login, formRequest("/login", "correct horse"))
	if login.Code != http.StatusSeeOther {
		t.Fatalf("login status = %d", login.Code)
	}
	cookie := login.Result().Cookies()[0]
	if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("weak cookie: %#v", cookie)
	}

	private := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	req.AddCookie(cookie)
	mux.ServeHTTP(private, req)
	if private.Code != http.StatusOK || private.Body.String() != "owner" {
		t.Fatalf("private: %d %q", private.Code, private.Body.String())
	}

	tampered := *cookie
	tampered.Value += "x"
	tamperResult := httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/private", nil)
	req.AddCookie(&tampered)
	mux.ServeHTTP(tamperResult, req)
	if tamperResult.Code != http.StatusSeeOther {
		t.Fatalf("tamper status = %d", tamperResult.Code)
	}

	logout := httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.AddCookie(cookie)
	mux.ServeHTTP(logout, req)
	if logout.Code != http.StatusSeeOther || logout.Result().Cookies()[0].MaxAge >= 0 {
		t.Fatalf("logout response: %#v", logout.Result())
	}
}

func TestDemoLoginPageAndCrossOriginProtection(t *testing.T) {
	a := demoAuth(t)
	mux := http.NewServeMux()
	a.Register(mux)
	page := httptest.NewRecorder()
	mux.ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/login", nil))
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "DEMO MODE") || !strings.Contains(page.Body.String(), `type="password"`) {
		t.Fatalf("unexpected page: %d %q", page.Code, page.Body.String())
	}

	cross := formRequest("/login", "correct horse")
	cross.Header.Set("Origin", "https://evil.example")
	cross.Header.Set("Sec-Fetch-Site", "cross-site")
	result := httptest.NewRecorder()
	mux.ServeHTTP(result, cross)
	if result.Code != http.StatusForbidden {
		t.Fatalf("cross-origin status = %d", result.Code)
	}

	getLogout := httptest.NewRecorder()
	mux.ServeHTTP(getLogout, httptest.NewRequest(http.MethodGet, "/logout", nil))
	if getLogout.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET logout status = %d", getLogout.Code)
	}
}

func TestNewRejectsInvalidAndMixedConfiguration(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	tests := []Config{
		{BaseURL: "", SessionKey: key, Demo: true, DemoPassword: "x"},
		{BaseURL: "https://example.com", SessionKey: "bad", Demo: true, DemoPassword: "x"},
		{BaseURL: "https://example.com", SessionKey: key, Demo: true},
		{BaseURL: "https://example.com", SessionKey: key},
		{BaseURL: "https://example.com", SessionKey: key, DemoPassword: "x", Issuer: "i", ClientID: "c", ClientSecret: "s", OwnerSubject: "o"},
		{BaseURL: "https://example.com", SessionKey: key, Demo: true, DemoPassword: "x", Issuer: "i"},
	}
	for i, cfg := range tests {
		if _, err := New(context.Background(), cfg); err == nil {
			t.Errorf("case %d unexpectedly succeeded", i)
		}
	}
}

func formRequest(path, password string) *http.Request {
	form := url.Values{"password": {password}}
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}
