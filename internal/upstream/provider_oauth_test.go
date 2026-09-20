package upstream

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

type oauthMetadataTransport struct {
	issuer, authorize, token string
	resource, scope          string
	t                        *testing.T
}

func (m oauthMetadataTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	m.t.Helper()
	if r.Method != "GET" {
		m.t.Fatalf("discovery sent unexpected %s request", r.Method)
	}
	status, body := 404, `{}`
	if strings.Contains(r.URL.Path, "/.well-known/oauth-protected-resource") {
		status = 200
		raw, _ := json.Marshal(map[string]any{"resource": m.resource, "authorization_servers": []string{m.issuer}, "scopes_supported": []string{m.scope}})
		body = string(raw)
	} else if strings.Contains(r.URL.Path, "/.well-known/") {
		status = 200
		raw, _ := json.Marshal(map[string]any{"issuer": strings.TrimSuffix(m.issuer, "/"), "authorization_endpoint": m.authorize, "token_endpoint": m.token, "response_types_supported": []string{"code"}, "code_challenge_methods_supported": []string{"S256"}})
		body = string(raw)
	}
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
}

func TestGoogleOAuthDiscovery(t *testing.T) {
	for _, tc := range []struct {
		name, issuer, authorize, token string
		wantOK                         bool
	}{
		{"Google", "https://accounts.google.com/", "https://accounts.google.com/o/oauth2/v2/auth", "https://oauth2.googleapis.com/token", true},
		{"wrong issuer", "https://attacker.example", "https://accounts.google.com/o/oauth2/v2/auth", "https://oauth2.googleapis.com/token", false},
		{"wrong token host", "https://accounts.google.com/", "https://accounts.google.com/o/oauth2/v2/auth", "https://oauth2.googleapis.com.attacker.example/token", false},
		{"wrong token path", "https://accounts.google.com/", "https://accounts.google.com/o/oauth2/v2/auth", "https://oauth2.googleapis.com/other", false},
		{"HTTP token", "https://accounts.google.com/", "https://accounts.google.com/o/oauth2/v2/auth", "http://oauth2.googleapis.com/token", false},
		{"wrong authorization", "https://accounts.google.com/", "https://attacker.example/auth", "https://oauth2.googleapis.com/token", false},
		{"authorization query", "https://accounts.google.com/", "https://accounts.google.com/o/oauth2/v2/auth?redirect_uri=https://attacker.example", "https://oauth2.googleapis.com/token", false},
		{"token userinfo", "https://accounts.google.com/", "https://accounts.google.com/o/oauth2/v2/auth", "https://attacker@oauth2.googleapis.com/token", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &http.Client{Transport: oauthMetadataTransport{tc.issuer, tc.authorize, tc.token, "https://sheetsmcp.googleapis.com/mcp/v1", "https://www.googleapis.com/auth/spreadsheets.readonly", t}}
			o, err := discoverOAuth(t.Context(), "https://sheetsmcp.googleapis.com/mcp/v1", "https://gateway.example/connections/sheets/callback", "existing-client", "fixture-secret", h)
			if (err == nil) != tc.wantOK {
				t.Fatalf("success=%v, error=%v", err == nil, err)
			}
			if !tc.wantOK {
				return
			}
			if o.AuthStyle != oauth2.AuthStyleInParams || o.Resource != "https://sheetsmcp.googleapis.com/mcp/v1" || len(o.Scopes) != 1 {
				t.Fatalf("incorrect config: auth style=%v resource=%q scopes=%v", o.AuthStyle, o.Resource, o.Scopes)
			}
			m, err := New("https://gateway.example", []Connection{{ID: "sheets", URL: o.Resource, OAuth: o}}, &memoryStore{data: map[string][]byte{}})
			if err != nil {
				t.Fatal(err)
			}
			mux := http.NewServeMux()
			m.Register(mux)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/connections/sheets/connect", nil))
			location := authorizationLocation(t, w)
			q := location.Query()
			for key, want := range map[string]string{"access_type": "offline", "prompt": "consent", "token_access_type": "", "code_challenge_method": "S256", "client_id": "existing-client", "redirect_uri": "https://gateway.example/connections/sheets/callback", "scope": "https://www.googleapis.com/auth/spreadsheets.readonly"} {
				if q.Get(key) != want {
					t.Errorf("%s=%q, want %q", key, q.Get(key), want)
				}
			}
			if q.Get("state") == "" || q.Get("code_challenge") == "" || q.Has("client_secret") {
				t.Fatal("unsafe authorization URL")
			}
		})
	}
}

func TestDropboxOAuthDiscovery(t *testing.T) {
	for _, tc := range []struct {
		name, issuer, authorize, token string
		wantOK                         bool
	}{
		{"Dropbox", "https://www.dropbox.com", "https://www.dropbox.com/oauth2/authorize", "https://api.dropboxapi.com/oauth2/token", true},
		{"wrong issuer", "https://attacker.example", "https://www.dropbox.com/oauth2/authorize", "https://api.dropboxapi.com/oauth2/token", false},
		{"lookalike host", "https://www.dropbox.com", "https://www.dropbox.com/oauth2/authorize", "https://api.dropboxapi.com.attacker.example/oauth2/token", false},
		{"wrong token path", "https://www.dropbox.com", "https://www.dropbox.com/oauth2/authorize", "https://api.dropboxapi.com/other", false},
		{"HTTP token", "https://www.dropbox.com", "https://www.dropbox.com/oauth2/authorize", "http://api.dropboxapi.com/oauth2/token", false},
		{"authorization query", "https://www.dropbox.com", "https://www.dropbox.com/oauth2/authorize?redirect_uri=https://attacker.example", "https://api.dropboxapi.com/oauth2/token", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &http.Client{Transport: oauthMetadataTransport{tc.issuer, tc.authorize, tc.token, "https://mcp.dropbox.com/mcp", "files.metadata.read", t}}
			o, err := discoverOAuth(t.Context(), "https://mcp.dropbox.com/mcp", "https://gateway.example/connections/dropbox/callback", "existing-client", "fixture-secret", h)
			if (err == nil) != tc.wantOK {
				t.Fatalf("success=%v, error=%v", err == nil, err)
			}
			if !tc.wantOK {
				return
			}
			m, err := New("https://gateway.example", []Connection{{ID: "dropbox", URL: o.Resource, OAuth: o}}, &memoryStore{data: map[string][]byte{}})
			if err != nil {
				t.Fatal(err)
			}
			mux := http.NewServeMux()
			m.Register(mux)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, httptest.NewRequest("GET", "/connections/dropbox/connect", nil))
			location, err := url.Parse(w.Header().Get("Location"))
			if err != nil {
				t.Fatal(err)
			}
			q := location.Query()
			for key, want := range map[string]string{"token_access_type": "offline", "access_type": "", "prompt": "", "code_challenge_method": "S256", "client_id": "existing-client", "redirect_uri": "https://gateway.example/connections/dropbox/callback", "scope": "files.metadata.read", "resource": "https://mcp.dropbox.com/mcp"} {
				if q.Get(key) != want {
					t.Errorf("%s=%q, want %q", key, q.Get(key), want)
				}
			}
			if q.Get("state") == "" || q.Get("code_challenge") == "" || q.Has("client_secret") {
				t.Fatal("unsafe authorization URL")
			}
		})
	}
}
