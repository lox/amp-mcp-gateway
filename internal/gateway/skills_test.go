package gateway

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.yaml.in/yaml/v3"
)

func skillSession(t *testing.T, h http.Handler, identity ampIdentity) *mcp.ClientSession {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(withAmpIdentity(r.Context(), identity)))
	}))
	t.Cleanup(server.Close)
	client := mcp.NewClient(&mcp.Implementation{Name: "skills-test", Version: "1"}, nil)
	if err := mcp.AddSendingCustomMethod[*listSkillsParams, *listSkillsResult](client, "skills/list"); err != nil {
		t.Fatal(err)
	}
	if err := mcp.AddSendingCustomMethod[*getSkillParams, *getSkillResult](client, "skills/get"); err != nil {
		t.Fatal(err)
	}
	session, err := client.Connect(t.Context(), &mcp.StreamableClientTransport{Endpoint: server.URL, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { session.Close() })
	return session
}

func TestMCPSkills(t *testing.T) {
	g, _, backend := fixture(t)
	session := skillSession(t, g.mcpHandler(), demoIdentity("owner"))
	caps := session.InitializeResult().Capabilities
	if settings, ok := caps.Extensions["io.modelcontextprotocol/skills"]; !ok || caps.Resources == nil || !reflect.DeepEqual(settings, map[string]any{}) {
		t.Fatalf("missing skills/resources capabilities: %+v", caps)
	}
	listed, err := mcp.CallCustomMethod[*listSkillsParams, *listSkillsResult](t.Context(), session, "skills/list", &listSkillsParams{})
	if err != nil {
		t.Fatal(err)
	}
	if len(listed.Skills) != 1 || listed.ResultType != "complete" || listed.CacheScope != "private" || listed.TTLMs != 0 {
		t.Fatalf("listing: %+v", listed)
	}
	for i, name := range []string{"using-gateway"} {
		entry := listed.Skills[i]
		if entry.URI != "skill://"+name+"/SKILL.md" || entry.Frontmatter["name"] != name || len(entry.Resources) != 2 {
			t.Fatalf("entry: %+v", entry)
		}
		got, err := mcp.CallCustomMethod[*getSkillParams, *getSkillResult](t.Context(), session, "skills/get", &getSkillParams{URI: entry.URI})
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got.Skill, entry) || got.ResultType != "complete" || got.CacheScope != "private" || got.TTLMs != 0 {
			t.Fatalf("get differs from listing: %+v", got)
		}
		seen := make(map[string]bool)
		for _, file := range entry.Resources {
			if seen[file.URI] || !strings.HasPrefix(file.URI, "skill://"+name+"/") {
				t.Fatalf("duplicate or foreign resource: %+v", file)
			}
			seen[file.URI] = true
			read, err := session.ReadResource(t.Context(), &mcp.ReadResourceParams{URI: file.URI})
			if err != nil {
				t.Fatal(err)
			}
			if len(read.Contents) != 1 || read.CacheScope != "private" || read.TTLMs != 0 {
				t.Fatalf("read: %+v", read)
			}
			content := read.Contents[0]
			if content.URI != file.URI || content.MIMEType != "text/markdown" || len(content.Text) != file.Size || fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(content.Text))) != file.Digest {
				t.Fatalf("resource differs from manifest: %+v", file)
			}
			if file.URI == entry.URI {
				if !strings.HasPrefix(content.Text, "---\n") {
					t.Fatal("missing frontmatter delimiter")
				}
				frontmatter, _, ok := strings.Cut(strings.TrimPrefix(content.Text, "---\n"), "\n---\n")
				var parsed map[string]any
				if !ok || yaml.Unmarshal([]byte(frontmatter), &parsed) != nil || !reflect.DeepEqual(parsed, entry.Frontmatter) {
					t.Fatalf("frontmatter differs from entry: %s", content.Text)
				}
			}
		}
		if !seen[entry.URI] {
			t.Fatal("manifest omits SKILL.md")
		}
	}
	// Discovery sends only metadata/manifests, not eagerly bundled file bodies.
	raw, err := json.Marshal(listed)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "# Using connected") {
		t.Fatal("listing eagerly returned file bodies")
	}
	resources, err := session.ListResources(t.Context(), nil)
	if err != nil || len(resources.Resources) != 0 {
		t.Fatalf("files should be discoverable through skill manifests: %+v, %v", resources, err)
	}
	if backend.calls.Load() != 0 {
		t.Fatal("skill discovery/read dispatched an upstream operation")
	}

	_, err = mcp.CallCustomMethod[*listSkillsParams, *listSkillsResult](t.Context(), session, "skills/list", &listSkillsParams{Cursor: "invented"})
	assertInvalidSkillParams(t, err)
	for _, uri := range []string{"", "skill://unknown/SKILL.md", "skill://using-gateway/reference/operations.md", "skill://using-gateway/../unknown/SKILL.md"} {
		_, err := mcp.CallCustomMethod[*getSkillParams, *getSkillResult](t.Context(), session, "skills/get", &getSkillParams{URI: uri})
		assertInvalidSkillParams(t, err)
	}
	for _, uri := range []string{"skill://using-gateway/secret.md", "skill://using-gateway/../unknown/SKILL.md", "skill://using-gateway/%2e%2e/unknown/SKILL.md", "file:///etc/passwd", "skill://using-gateway/SKILL.md?extra=1"} {
		_, err := session.ReadResource(t.Context(), &mcp.ReadResourceParams{URI: uri})
		assertInvalidSkillParams(t, err)
	}
}

func assertInvalidSkillParams(t *testing.T, err error) {
	t.Helper()
	var rpcErr *jsonrpc.Error
	if !errors.As(err, &rpcErr) || rpcErr.Code != jsonrpc.CodeInvalidParams {
		t.Fatalf("want invalid params, got %v", err)
	}
}
