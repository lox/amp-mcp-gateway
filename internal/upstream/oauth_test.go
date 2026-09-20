package upstream

import (
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"testing"
)

func authorizationLocation(t *testing.T, w *httptest.ResponseRecorder) *url.URL {
	t.Helper()
	if w.Code != http.StatusOK || w.Header().Get("Location") != "" {
		t.Fatalf("authorization handoff status=%d", w.Code)
	}
	link := regexp.MustCompile(`<a href="([^"]+)">`).FindStringSubmatch(w.Body.String())
	if len(link) != 2 {
		t.Fatal("missing authorization link")
	}
	u, err := url.Parse(html.UnescapeString(link[1]))
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestOAuthConnectMethods(t *testing.T) {
	c := Connection{ID: "one", URL: "http://localhost/mcp", OAuth: &OAuthConfig{ClientID: "fixture", AuthURL: "http://localhost/authorize", TokenURL: "http://localhost/token"}}
	m, err := New("http://localhost", []Connection{c}, &memoryStore{data: map[string][]byte{}})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	m.Register(mux)
	for _, method := range []string{"GET", "HEAD"} {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(method, "/connections/one/connect", nil))
		if w.Code != 405 || len(m.states) != 0 || len(w.Result().Cookies()) != 0 {
			t.Fatalf("%s changed authorization state", method)
		}
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("POST", "/connections/one/connect", nil))
	location := authorizationLocation(t, w)
	if len(m.states) != 1 || location.Query().Get("state") == "" {
		t.Fatal("POST did not start authorization")
	}
}
