package upstream

import (
	"encoding/json"
	"net"
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
	o, err := discoverOAuth(t.Context(), origin+"/mcp", "https://gateway.example/connections/notes/callback", "", "", server.Client(), false)
	if err != nil {
		t.Fatal(err)
	}
	if o.Resource != origin+"/mcp" || strings.Join(o.Scopes, " ") != "notes:read" || o.ClientID != "registered-id" || o.AuthStyle != oauth2.AuthStyleInParams {
		t.Fatalf("incorrect discovery: %#v", o)
	}
	if _, err := discoverOAuth(t.Context(), origin+"/mcp", "https://gateway.example/connections/notes/callback", "existing", "secret", server.Client(), false); err != nil || registrations != 1 {
		t.Fatal("pre-registered client tried DCR", err)
	}
	m, err := New("https://gateway.example", []Connection{{ID: "notes", URL: origin + "/mcp", OAuth: o}}, &memoryStore{data: map[string][]byte{}})
	if err != nil {
		t.Fatal(err)
	}
	app := http.NewServeMux()
	m.Register(app)
	login := httptest.NewRecorder()
	app.ServeHTTP(login, httptest.NewRequest(http.MethodPost, "/connections/notes/connect", nil))
	location := authorizationLocation(t, login)
	if location.Query().Get("resource") != origin+"/mcp" || location.Query().Get("code_challenge_method") != "S256" {
		t.Fatal("authorization missing resource or PKCE")
	}
	if location.Query().Has("access_type") || location.Query().Has("prompt") || location.Query().Has("token_access_type") {
		t.Fatal("provider-specific consent parameters leaked to another provider")
	}
	r := httptest.NewRequest("GET", "/connections/notes/callback?code=fixture&state="+url.QueryEscape(location.Query().Get("state")), nil)
	r.AddCookie(login.Result().Cookies()[0])
	w := httptest.NewRecorder()
	app.ServeHTTP(w, r)
	if w.Code != 303 || w.Header().Get("Location") != "/connections/notes/tools" {
		t.Fatalf("callback: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	app.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatal("callback state replay accepted")
	}
}

func TestDiscoveryCanonicalizesRootResource(t *testing.T) {
	for _, tc := range []struct {
		name, endpointPath string
		wantSuccess        bool
	}{
		{name: "root slash", endpointPath: "/", wantSuccess: true},
		{name: "path remains exact", endpointPath: "/mcp"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var origin string
			authorizationRequests := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case tc.endpointPath:
					w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+origin+`/metadata"`)
					w.WriteHeader(http.StatusUnauthorized)
				case "/metadata":
					json.NewEncoder(w).Encode(map[string]any{"resource": origin, "authorization_servers": []string{origin}, "scopes_supported": []string{"stock-market-data"}})
				case "/.well-known/oauth-authorization-server":
					authorizationRequests++
					json.NewEncoder(w).Encode(map[string]any{"issuer": origin, "authorization_endpoint": origin + "/authorize", "token_endpoint": origin + "/token", "response_types_supported": []string{"code"}, "code_challenge_methods_supported": []string{"S256"}})
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()
			origin = server.URL

			o, err := discoverOAuth(t.Context(), origin+tc.endpointPath, "https://gateway.example/callback", "existing-client", "", server.Client(), false)
			if !tc.wantSuccess {
				if err == nil || o != nil || authorizationRequests != 0 {
					t.Fatalf("accepted mismatched path resource: config=%v, error=%v, authorization requests=%d", o, err, authorizationRequests)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if o.Resource != origin || strings.Join(o.Scopes, " ") != "stock-market-data" || authorizationRequests != 1 {
				t.Fatalf("incorrect root discovery: config=%#v, authorization requests=%d", o, authorizationRequests)
			}
		})
	}
}

func TestDiscoveryRootResourceFallback(t *testing.T) {
	for _, tc := range []struct {
		name, resourceSuffix string
		wantSuccess          bool
	}{
		{name: "root resource", wantSuccess: true},
		{name: "endpoint resource at root", resourceSuffix: "/mcp", wantSuccess: true},
		{name: "unrelated resource", resourceSuffix: "/other"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var origin string
			rootRequests := 0
			authorizationRequests := 0
			authorization := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				authorizationRequests++
				if r.URL.Path != "/.well-known/oauth-authorization-server" {
					t.Errorf("unexpected authorization request: %s", r.URL.Path)
				}
				issuer := "http://" + r.Host
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token", "response_types_supported": []string{"code"}, "code_challenge_methods_supported": []string{"S256"}})
			}))
			defer authorization.Close()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/mcp":
					// Like Redbark, GET is unsupported and has no auth challenge.
					w.WriteHeader(http.StatusMethodNotAllowed)
				case "/.well-known/oauth-protected-resource/mcp", "/.well-known/oauth-protected-resource":
					if tc.resourceSuffix == "/mcp" && r.URL.Path != "/.well-known/oauth-protected-resource" {
						w.WriteHeader(http.StatusNotFound)
						return
					}
					if r.URL.Path == "/.well-known/oauth-protected-resource" {
						rootRequests++
					}
					json.NewEncoder(w).Encode(map[string]any{"resource": origin + tc.resourceSuffix, "authorization_servers": []string{authorization.URL}, "scopes_supported": []string{"mcp:read"}})
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()
			origin = server.URL
			o, err := discoverOAuth(t.Context(), origin+"/mcp", "https://gateway.example/callback", "existing-client", "", server.Client(), false)
			if rootRequests == 0 {
				t.Fatal("root metadata was not fetched")
			}
			if !tc.wantSuccess {
				if err == nil || o != nil || authorizationRequests != 0 {
					t.Fatalf("accepted mismatched resource: config=%v, error=%v, authorization requests=%d", o, err, authorizationRequests)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if o.Resource != origin+tc.resourceSuffix || o.AuthURL != authorization.URL+"/authorize" || o.TokenURL != authorization.URL+"/token" || strings.Join(o.Scopes, " ") != "mcp:read" {
				t.Fatalf("incorrect root discovery: %#v", o)
			}
		})
	}
}

func TestDiscoveryRejectsExpiringClientSecret(t *testing.T) {
	for _, tc := range []struct {
		name, secret, wantError string
		expires                 int64
	}{
		{name: "finite secret", secret: "fixture-secret", expires: 2000000000, wantError: "expiring"},
		{name: "permanent secret", secret: "fixture-secret"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var origin string
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/mcp":
					w.WriteHeader(401)
				case "/.well-known/oauth-authorization-server":
					json.NewEncoder(w).Encode(map[string]any{"issuer": origin, "authorization_endpoint": origin + "/authorize", "token_endpoint": origin + "/token", "registration_endpoint": origin + "/register", "response_types_supported": []string{"code"}, "code_challenge_methods_supported": []string{"S256"}})
				case "/register":
					w.WriteHeader(201)
					json.NewEncoder(w).Encode(map[string]any{"client_id": "fixture-client", "client_secret": tc.secret, "client_secret_expires_at": tc.expires, "token_endpoint_auth_method": "client_secret_basic"})
				default:
					w.WriteHeader(404)
				}
			}))
			defer server.Close()
			origin = server.URL
			o, err := discoverOAuth(t.Context(), origin+"/mcp", "https://gateway.example/callback", "", "", server.Client(), false)
			if tc.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantError) || o != nil {
					t.Fatalf("expected %q, got config %v, error %v", tc.wantError, o != nil, err)
				}
			} else if err != nil || o.ClientSecret != tc.secret {
				t.Fatalf("non-expiring client rejected: %v", err)
			}
		})
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
	if _, err := discoverOAuth(t.Context(), origin+"/mcp", "https://gateway.example/callback", "client", "", server.Client(), false); err == nil || !strings.Contains(err.Error(), "advertised") {
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
	// Bypass the form validator and use a live listener: the socket hook must
	// reject both numeric addresses and DNS results, not just fail to connect.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	transport := publicTransport.(boundedPublicTransport).transport.(*http.Transport)
	for _, host := range []string{"127.0.0.1", "localhost"} {
		conn, err := transport.DialContext(t.Context(), "tcp", net.JoinHostPort(host, port))
		if conn != nil {
			conn.Close()
		}
		if err == nil || !strings.Contains(err.Error(), "private-network destination blocked") {
			t.Fatalf("missing socket boundary for %s: %v", host, err)
		}
	}
}
