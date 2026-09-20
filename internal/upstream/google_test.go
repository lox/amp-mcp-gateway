package upstream

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

type googleMetadataTransport struct {
	issuer, authorize, token string
	t                        *testing.T
}

func (m googleMetadataTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	m.t.Helper()
	if r.Method != "GET" {
		m.t.Fatalf("discovery sent unexpected %s request", r.Method)
	}
	status, body := 404, `{}`
	if strings.Contains(r.URL.Path, "/.well-known/oauth-protected-resource") {
		status = 200
		raw, _ := json.Marshal(map[string]any{"resource": "https://sheetsmcp.googleapis.com/mcp/v1", "authorization_servers": []string{m.issuer}, "scopes_supported": []string{"https://www.googleapis.com/auth/spreadsheets.readonly"}})
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
			h := &http.Client{Transport: googleMetadataTransport{tc.issuer, tc.authorize, tc.token, t}}
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
			mux.ServeHTTP(w, httptest.NewRequest("GET", "/connections/sheets/connect", nil))
			location, err := url.Parse(w.Header().Get("Location"))
			if err != nil {
				t.Fatal(err)
			}
			q := location.Query()
			for key, want := range map[string]string{"access_type": "offline", "prompt": "consent", "code_challenge_method": "S256", "client_id": "existing-client", "redirect_uri": "https://gateway.example/connections/sheets/callback", "scope": "https://www.googleapis.com/auth/spreadsheets.readonly"} {
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
