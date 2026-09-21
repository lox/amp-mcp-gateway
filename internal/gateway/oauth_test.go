package gateway

import (
	"net/http/httptest"
	"strings"
	"testing"

	"ampcode.com/lox/amp-mcp-gateway/internal/upstream"
)

func TestOAuthConnectRequiresOwnerPost(t *testing.T) {
	g, s, _ := fixture(t)
	g.cfg.Connections[0].TokenEnv = ""
	g.cfg.Connections[0].OAuth = &upstream.OAuthConfig{ClientID: "fixture", AuthURL: "https://provider.example/authorize", TokenURL: "https://provider.example/token"}
	m, err := upstream.New(g.cfg.BaseURL, g.cfg.Connections, s)
	if err != nil {
		t.Fatal(err)
	}
	h, cookie := adminUI(t, g, m)
	for _, tc := range []struct {
		name, method, site, origin string
		owner                      bool
		want                       int
	}{
		{"GET", "GET", "cross-site", "", true, 405},
		{"HEAD", "HEAD", "cross-site", "", true, 405},
		{"cross-site POST", "POST", "cross-site", "", true, 403},
		{"same-site POST", "POST", "same-site", "", true, 403},
		{"foreign origin", "POST", "", "https://attacker.example", true, 403},
		{"no owner", "POST", "same-origin", "", false, 303},
		{"owner POST", "POST", "same-origin", "", true, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, "/connections/notes/connect", nil)
			r.Header.Set("Sec-Fetch-Site", tc.site)
			r.Header.Set("Origin", tc.origin)
			if tc.owner {
				r.AddCookie(cookie)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("status=%d, want %d", w.Code, tc.want)
			}
			if tc.want != 200 {
				if len(w.Result().Cookies()) != 0 || strings.Contains(w.Body.String(), "provider.example") {
					t.Fatal("rejected initiation produced OAuth state or handoff")
				}
				return
			}
			if w.Header().Get("Location") != "" || !strings.Contains(w.Body.String(), "https://provider.example/authorize?") || len(w.Result().Cookies()) != 1 {
				t.Fatal("owner POST did not render provider navigation")
			}
			if w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("authorization handoff may be cached")
			}
		})
	}
}
