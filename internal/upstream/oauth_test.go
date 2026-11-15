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

func TestRemovalDuringOAuthExchangeSavesNoToken(t *testing.T) {
	exchanging, release := make(chan struct{}), make(chan struct{})
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(exchanging)
		<-release
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":"late-canary","token_type":"Bearer"}`))
	}))
	defer provider.Close()
	store := &memoryStore{data: map[string][]byte{}}
	c := Connection{ID: "notes", URL: "http://localhost/mcp", OAuth: &OAuthConfig{ClientID: "client", AuthURL: provider.URL + "/authorize", TokenURL: provider.URL + "/token"}}
	m, err := New("http://localhost", []Connection{c}, store)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	m.Register(mux)
	login := httptest.NewRecorder()
	mux.ServeHTTP(login, httptest.NewRequest(http.MethodPost, "/connections/notes/connect", nil))
	location := authorizationLocation(t, login)
	callback := httptest.NewRequest(http.MethodGet, "/connections/notes/callback?code=fixture&state="+url.QueryEscape(location.Query().Get("state")), nil)
	callback.AddCookie(login.Result().Cookies()[0])
	done := make(chan *httptest.ResponseRecorder)
	go func() {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, callback)
		done <- w
	}()
	<-exchanging
	next, err := New("http://localhost", nil, store)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Remove("notes", next, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	close(release)
	if w := <-done; w.Code == http.StatusSeeOther || store.saves != 0 {
		t.Fatalf("callback after removal saved a token: status=%d saves=%d", w.Code, store.saves)
	}
}
