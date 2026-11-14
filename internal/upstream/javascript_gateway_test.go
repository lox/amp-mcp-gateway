package upstream_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"ampcode.com/lox/amp-mcp-gateway/internal/browserauth"
	"ampcode.com/lox/amp-mcp-gateway/internal/browserbridge"
	"ampcode.com/lox/amp-mcp-gateway/internal/gateway"
	"ampcode.com/lox/amp-mcp-gateway/internal/jsintegration"
	"ampcode.com/lox/amp-mcp-gateway/internal/store"
	"ampcode.com/lox/amp-mcp-gateway/internal/upstream"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type fixtureTransport struct {
	target *url.URL
	base   http.RoundTripper
}

func (f fixtureTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	clone := r.Clone(r.Context())
	u := *r.URL
	u.Scheme = f.target.Scheme
	u.Host = f.target.Host
	clone.URL = &u
	return f.base.RoundTrip(clone)
}

type demoBearer struct{ token string }

func (b demoBearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return http.DefaultTransport.RoundTrip(r)
}

func TestGovernedJavaScriptReadWrite(t *testing.T) {
	t.Setenv("TYPESAFE_API_KEY", "")
	t.Setenv("JS_TEST_TOKEN", "fake-provider-token")
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	path := filepath.Join(t.TempDir(), "ledger.db")
	s, err := store.Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { s.Close() }()
	var mu sync.Mutex
	writes := 0
	provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fake-provider-token" {
			t.Error("missing broker auth")
			http.Error(w, "bad auth", 401)
			return
		}
		if r.URL.Path != "/repos/test/issues" {
			t.Errorf("unexpected path %s", r.URL)
			http.Error(w, "not found", 404)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "GET" {
			io.WriteString(w, `[{"number":17,"title":"First"}]`)
			return
		}
		var body struct {
			Title string `json:"title"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		// An intent must be durable before the provider can observe any write.
		attempts, err := s.HTTPAttempts(t.Context(), "js-case-"+body.Title)
		if err != nil || len(attempts) != 1 || attempts[0].Response != nil {
			t.Errorf("missing dispatch intent: %+v %v", attempts, err)
		}
		mu.Lock()
		writes++
		mu.Unlock()
		if body.Title == "lost" {
			c, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				c.Close()
			}
			return
		}
		io.WriteString(w, `{"number":23,"title":"Created"}`)
	}))
	defer provider.Close()
	target, _ := url.Parse(provider.URL)
	previous := *upstream.JavaScriptTransportForTest
	*upstream.JavaScriptTransportForTest = fixtureTransport{target, provider.Client().Transport}
	defer func() { *upstream.JavaScriptTransportForTest = previous }()
	input := map[string]any{"type": "object", "properties": map[string]any{"title": map[string]any{"type": "string"}}, "additionalProperties": false}
	object := map[string]any{"type": "object", "properties": map[string]any{"number": map[string]any{"type": "integer"}}, "required": []any{"number"}, "additionalProperties": false}
	source := `export async function listIssues(args,ctx) { const r=await ctx.http.request({method:'GET',path:'/repos/test/issues'}); return {number:r.body[0].number}; }
export async function createIssue(args,ctx) {
 if(args.title==='local') throw new Error('before HTTP');
 const r=await ctx.http.request({method:'POST',path:'/repos/test/issues',body:{title:args.title}});
 if(args.title==='throw') throw new Error('after HTTP');
 if(args.title==='schema') return {wrong:true};
 return {number:r.body.number};
}`
	definition := &jsintegration.Definition{Origin: "https://api.example.com", Source: source, Tools: []jsintegration.Tool{
		{Name: "createIssue", Handler: "createIssue", Description: "Create a disposable issue", InputSchema: input, OutputSchema: object, HTTP: []jsintegration.Grant{{Method: "POST", Path: "/repos/test/issues"}}},
		{Name: "listIssues", Handler: "listIssues", Description: "List disposable issues", InputSchema: input, OutputSchema: object, HTTP: []jsintegration.Grant{{Method: "GET", Path: "/repos/test/issues"}}},
	}}
	server := httptest.NewUnstartedServer(nil)
	cfg := gateway.Config{AmpUserID: "demo-owner", Demo: true, BaseURL: "http://" + server.Listener.Addr().String(), Connections: []upstream.Connection{{ID: "issues", Account: "Disposable test repository", TokenEnv: "JS_TEST_TOKEN", JavaScript: definition}}}
	m, err := upstream.New(cfg.BaseURL, cfg.Connections, s)
	if err != nil {
		t.Fatal(err)
	}
	browser, err := browserbridge.New(t.Context(), cfg.Connections, m, s)
	if err != nil {
		t.Fatal(err)
	}
	g, err := gateway.New(cfg, s, browser)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := browserauth.New(t.Context(), browserauth.Config{BaseURL: cfg.BaseURL, AmpUserID: cfg.AmpUserID, SessionKey: key, Demo: true, DemoPassword: "demo-only"})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	auth.Register(mux)
	mh, _ := g.DemoHandlers("demo-mcp-token")
	mux.Handle("/mcp", mh)
	mux.Handle("/", g.UI(auth, m, browser, false))
	server.Config.Handler = mux
	server.Start()
	defer server.Close()
	jar, _ := cookiejar.New(nil)
	admin := &http.Client{Jar: jar}
	post := func(path string, values url.Values) string {
		t.Helper()
		r, err := admin.PostForm(server.URL+path, values)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		b, _ := io.ReadAll(r.Body)
		if r.StatusCode != 200 {
			t.Fatalf("POST %s: %d %s", path, r.StatusCode, b)
		}
		return string(b)
	}
	post("/login", url.Values{"password": {"demo-only"}})
	// Discovery is static: no runtime instantiation, provider call or side effect.
	review := post("/connections/issues/discover", url.Values{})
	match := regexp.MustCompile(`name="ticket" value="([^"]+)"`).FindStringSubmatch(review)
	if len(match) != 2 {
		t.Fatal("missing review ticket")
	}
	post("/connections/issues/tools", url.Values{"ticket": {match[1]}, "default_policy": {"require_approval"}, "policy_0": {"require_approval"}, "policy_1": {"allow"}})
	client := mcp.NewClient(&mcp.Implementation{Name: "js-case-test", Version: "1"}, nil)
	session, err := client.Connect(t.Context(), &mcp.StreamableClientTransport{Endpoint: server.URL + "/mcp", HTTPClient: &http.Client{Transport: demoBearer{"demo-mcp-token"}}, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	submit := func(id, tool, title string) {
		t.Helper()
		result, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "call_tools", Arguments: map[string]any{"request_id": id, "calls": []any{map[string]any{"tool_id": "issues." + tool, "arguments": map[string]any{"title": title}}}}})
		if err != nil || result.IsError {
			t.Fatalf("submit: %v %+v", err, result)
		}
	}
	wait := func(id, status string) store.Operation {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			o, err := s.Get(t.Context(), id)
			if err != nil {
				t.Fatal(err)
			}
			if o.Status == status {
				return o
			}
			time.Sleep(10 * time.Millisecond)
		}
		o, _ := s.Get(t.Context(), id)
		t.Fatalf("%s did not become %s: %+v", id, status, o)
		return store.Operation{}
	}
	submit("js-case-denied", "createIssue", "denied")
	post("/operations/js-case-denied/deny", url.Values{})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- g.Run(ctx) }()
	defer func() {
		if cancel != nil {
			cancel()
			if err := <-done; err != nil {
				t.Error(err)
			}
		}
	}()
	wait("js-case-denied", "denied")
	if attempts, _ := s.HTTPAttempts(t.Context(), "js-case-denied"); len(attempts) != 0 {
		t.Fatal("denial dispatched HTTP")
	}
	submit("js-case-read", "listIssues", "")
	if o := wait("js-case-read", "succeeded"); !strings.Contains(string(o.Result), "17") {
		t.Fatalf("bad transformed read: %s", o.Result)
	}
	for _, tt := range []struct{ title, status string }{{"approved", "succeeded"}, {"local", "failed"}, {"lost", "unknown"}, {"throw", "unknown"}, {"schema", "unknown"}} {
		id := "js-case-" + tt.title
		submit(id, "createIssue", tt.title)
		wait(id, "pending")
		post("/operations/"+id+"/approve", url.Values{})
		o := wait(id, tt.status)
		attempts, err := s.HTTPAttempts(t.Context(), id)
		if err != nil {
			t.Fatal(err)
		}
		if tt.title == "local" {
			if len(attempts) != 0 {
				t.Fatal("local failure dispatched")
			}
			continue
		}
		if len(attempts) != 1 || (attempts[0].Response == nil) != (tt.title == "lost") {
			t.Fatalf("bad journal: %+v", attempts)
		}
		raw, _ := json.Marshal(attempts)
		if strings.Contains(string(raw), "fake-provider-token") || strings.Contains(strings.ToLower(string(raw)), "authorization") {
			t.Fatal("auth leaked into journal")
		}
		if tt.status == "succeeded" && !strings.Contains(string(o.Result), "23") {
			t.Fatalf("bad transformed write: %s", o.Result)
		}
	}
	mu.Lock()
	count := writes
	mu.Unlock()
	if count != 4 {
		t.Fatalf("writes=%d, want4", count)
	}
	// Re-submission is an observation of the same durable unknown operation.
	submit("js-case-lost", "createIssue", "lost")
	wait("js-case-lost", "unknown")
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	cancel = nil
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = store.Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Claim(t.Context()); err == nil {
		t.Fatal("restart scheduled an old handler")
	}
	attempts, err := s.HTTPAttempts(t.Context(), "js-case-lost")
	if err != nil || len(attempts) != 1 || attempts[0].Response != nil {
		t.Fatalf("lost uncertainty on restart: %+v %v", attempts, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if writes != 4 {
		t.Fatalf("replayed writes=%d", writes)
	}
	t.Log("read transformed; 4 writes exactly once; denied/local zero dispatch; lost/trap/schema unknown; restart no replay")
}
