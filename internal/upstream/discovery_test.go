package upstream

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

func TestDiscoverOAuthRegistrationAndResource(t *testing.T) {
	var origin string
	registrations := 0
	mux := http.NewServeMux()
	mux.HandleFunc("GET /mcp", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+origin+`/metadata", scope="notes:read"`)
		w.WriteHeader(401)
	})
	mux.HandleFunc("GET /metadata", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"resource": origin + "/mcp", "authorization_servers": []string{origin}, "scopes_supported": []string{"too:broad"}})
	})
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"issuer": origin, "authorization_endpoint": origin + "/authorize", "token_endpoint": origin + "/token", "registration_endpoint": origin + "/register", "response_types_supported": []string{"code"}, "code_challenge_methods_supported": []string{"S256"}})
	})
	mux.HandleFunc("POST /register", func(w http.ResponseWriter, r *http.Request) {
		registrations++
		var v map[string]any
		if json.NewDecoder(r.Body).Decode(&v) != nil || v["scope"] != "notes:read" || v["token_endpoint_auth_method"] != "none" {
			t.Error("incorrect registration")
		}
		uris, ok := v["redirect_uris"].([]any)
		if !ok || len(uris) != 1 || uris[0] != "https://gateway.example/connections/notes/callback" {
			t.Error("wrong callback registered")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]any{"client_id": "registered-id", "token_endpoint_auth_method": "none"})
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.Form.Get("resource") != origin+"/mcp" || r.Form.Get("code_verifier") == "" || r.Form.Get("client_id") != "registered-id" {
			t.Error("missing resource, PKCE or client ID")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":"fixture-access","token_type":"Bearer"}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	origin = server.URL
	o, err := discoverOAuth(t.Context(), origin+"/mcp", "https://gateway.example/connections/notes/callback", "", "", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if o.Resource != origin+"/mcp" || strings.Join(o.Scopes, " ") != "notes:read" || o.ClientID != "registered-id" || o.AuthStyle != oauth2.AuthStyleInParams {
		t.Fatalf("incorrect discovery: %#v", o)
	}
	if _, err := discoverOAuth(t.Context(), origin+"/mcp", "https://gateway.example/connections/notes/callback", "existing", "secret", server.Client()); err != nil || registrations != 1 {
		t.Fatal("pre-registered client tried DCR", err)
	}
	m, err := New("https://gateway.example", []Connection{{ID: "notes", URL: origin + "/mcp", OAuth: o}}, &memoryStore{data: map[string][]byte{}})
	if err != nil {
		t.Fatal(err)
	}
	app := http.NewServeMux()
	m.Register(app)
	login := httptest.NewRecorder()
	app.ServeHTTP(login, httptest.NewRequest("GET", "/connections/notes/connect", nil))
	location, _ := url.Parse(login.Header().Get("Location"))
	if location.Query().Get("resource") != origin+"/mcp" || location.Query().Get("code_challenge_method") != "S256" {
		t.Fatal("authorization missing resource or PKCE")
	}
	r := httptest.NewRequest("GET", "/connections/notes/callback?code=fixture&state="+url.QueryEscape(location.Query().Get("state")), nil)
	r.AddCookie(login.Result().Cookies()[0])
	w := httptest.NewRecorder()
	app.ServeHTTP(w, r)
	if w.Code != 303 || w.Header().Get("Location") != "/connections/notes/tools" {
		t.Fatalf("callback: %d %s", w.Code, w.Body.String())
	}
}

func TestAdvertisedMetadataFailureDoesNotFallBack(t *testing.T) {
	var origin string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/mcp":
			w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+origin+`/broken"`)
			w.WriteHeader(401)
		case "/broken":
			w.WriteHeader(503)
		default:
			t.Errorf("unexpected discovery fallback: %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	origin = server.URL
	if _, err := discoverOAuth(t.Context(), origin+"/mcp", "https://gateway.example/callback", "client", "", server.Client()); err == nil || !strings.Contains(err.Error(), "advertised") {
		t.Fatalf("expected advertised metadata rejection, got %v", err)
	}
}

func TestPublicDestinationBoundary(t *testing.T) {
	for _, raw := range []string{"http://public.example/mcp", "https://localhost/mcp", "https://127.0.0.1/mcp", "https://[::ffff:127.0.0.1]/mcp", "https://10.1.2.3/mcp", "https://169.254.169.254/latest", "https://100.100.100.200/", "https://[fd00::1]/", "https://public.example:8443/mcp", "https://user:pass@public.example/mcp"} {
		if ValidatePublicURL(raw) == nil {
			t.Errorf("accepted %s", raw)
		}
	}
	for _, ip := range []string{"127.0.0.1", "10.20.30.40", "169.254.1.2", "100.64.0.1", "::1", "fd00::1", "::ffff:192.168.1.1", "2002:7f00:1::", "64:ff9b::7f00:1"} {
		if publicIP(netip.MustParseAddr(ip)) {
			t.Errorf("public IP accepted %s", ip)
		}
	}
	for _, ip := range []string{"8.8.8.8", "2606:4700:4700::1111"} {
		if !publicIP(netip.MustParseAddr(ip)) {
			t.Errorf("public IP blocked %s", ip)
		}
	}
	if err := ValidatePublicURL("https://mcp.example.com/mcp"); err != nil {
		t.Fatal(err)
	}
	// This hostname is not an IP literal. Its loopback DNS result must still be
	// rejected by the actual transport, not merely by the form validator.
	if _, err := oauthHTTPClient(Connection{PublicOnly: true}).Get("https://localhost.localdomain/mcp"); err == nil {
		t.Fatal("private DNS destination reached")
	}
}

func TestNewFieldsPreserveLegacyTokenKey(t *testing.T) {
	c := Connection{ID: "legacy", URL: "https://mcp.example.com", OAuth: &OAuthConfig{ClientID: "client", AuthURL: "https://auth.example.com/authorize", TokenURL: "https://auth.example.com/token"}}
	raw, _ := json.Marshal(c)
	for _, field := range []string{"BearerToken", "PublicOnly", "NoAuth", "ClientSecret\"", "Resource", "AuthStyle"} {
		if strings.Contains(string(raw), field) {
			t.Fatalf("new empty field changes existing credential binding: %s", field)
		}
	}
}
