package upstream

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ampcode.com/lox/amp-mcp-gateway/internal/store"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestJavaScriptExample(t *testing.T) {
	t.Setenv("GITHUB_ISSUES_TOKEN", "fake-example-token")
	raw, err := os.ReadFile("../../examples/github-issues.json")
	if err != nil {
		t.Fatal(err)
	}
	var c Connection
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	c.JavaScript.SourceFile = filepath.Join("../..", c.JavaScript.SourceFile)
	if err := c.JavaScript.Load(); err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(filepath.Join(t.TempDir(), "example.db"), base64.StdEncoding.EncodeToString(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	m, err := New("http://localhost", []Connection{c}, s)
	if err != nil {
		t.Fatal(err)
	}
	previous := javascriptTransport
	defer func() { javascriptTransport = previous }()
	for _, tt := range []struct {
		tool, method, response, want string
		args                         map[string]any
		status                       int
	}{
		{"listIssues", "GET", `[{"number":47,"title":"Open issue","html_url":"https://example.com/47","ignored":true}]`, `[{"number":47,"title":"Open issue","url":"https://example.com/47"}]`, map[string]any{"state": "closed"}, 200},
		{"createIssue", "POST", `{"number":91,"title":"Created issue","html_url":"https://example.com/91","ignored":true}`, `{"number":91,"title":"Created issue","url":"https://example.com/91"}`, map[string]any{"title": "Example title", "body": "Example body"}, 201},
	} {
		t.Run(tt.tool, func(t *testing.T) {
			calls := 0
			javascriptTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Method != tt.method || r.URL.Path != "/repos/OWNER/SANDBOX-REPO/issues" || r.Header.Get("Authorization") != "Bearer fake-example-token" {
					t.Errorf("wrong request: %s %s", r.Method, r.URL)
				}
				if tt.method == "GET" && r.URL.RawQuery != "per_page=20&state=closed" {
					t.Errorf("wrong query %s", r.URL.RawQuery)
				}
				if tt.method == "POST" {
					b, _ := io.ReadAll(r.Body)
					if string(b) != `{"title":"Example title","body":"Example body"}` {
						t.Errorf("wrong body %s", b)
					}
				}
				return &http.Response{StatusCode: tt.status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(tt.response)), Request: r}, nil
			})
			o := store.Operation{ID: tt.tool, Status: "running", Created: time.Now().Unix(), Expires: time.Now().Add(time.Minute).Unix()}
			if _, err := s.Submit(t.Context(), o); err != nil {
				t.Fatal(err)
			}
			result, err := m.Call(WithOperation(t.Context(), o.ID), c.ID, tt.tool, c.JavaScript.Binding("fake-example-token"), tt.args)
			if err != nil || result == nil || result.IsError || len(result.Content) != 1 {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			if got := result.Content[0].(*mcp.TextContent).Text; got != tt.want || calls != 1 {
				t.Fatalf("got=%s calls=%d", got, calls)
			}
		})
	}
}
