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
	g, s, backend := fixture(t)
	ConfigureChrome(&g.cfg)
	g, err := New(g.cfg, s, backend)
	if err != nil {
		t.Fatal(err)
	}
	session := skillSession(t, g.mcpHandler(), demoIdentity("owner"))
	caps := session.InitializeResult().Capabilities
	if settings, ok := caps.Extensions["io.modelcontextprotocol/skills"]; !ok || caps.Resources == nil || !reflect.DeepEqual(settings, map[string]any{}) {
		t.Fatalf("missing skills/resources capabilities: %+v", caps)
	}
	listed, err := mcp.CallCustomMethod[*listSkillsParams, *listSkillsResult](t.Context(), session, "skills/list", &listSkillsParams{})
	if err != nil {
		t.Fatal(err)
	}
	if len(listed.Skills) != 2 || listed.ResultType != "complete" || listed.CacheScope != "private" || listed.TTLMs != 0 {
		t.Fatalf("listing: %+v", listed)
	}
	for i, name := range []string{"using-gateway", "using-shared-browser"} {
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
	if strings.Contains(string(raw), "# Using connected") || strings.Contains(string(raw), "# Browser calls") {
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
	for _, uri := range []string{"", "skill://unknown/SKILL.md", "skill://using-gateway/reference/operations.md", "skill://using-gateway/../using-shared-browser/SKILL.md"} {
		_, err := mcp.CallCustomMethod[*getSkillParams, *getSkillResult](t.Context(), session, "skills/get", &getSkillParams{URI: uri})
		assertInvalidSkillParams(t, err)
	}
	for _, uri := range []string{"skill://using-gateway/secret.md", "skill://using-gateway/../using-shared-browser/SKILL.md", "skill://using-gateway/%2e%2e/using-shared-browser/SKILL.md", "file:///etc/passwd", "skill://using-gateway/SKILL.md?extra=1"} {
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

func TestMCPSkillVisibility(t *testing.T) {
	g, s, backend := fixture(t)
	ConfigureChrome(&g.cfg)
	g.cfg.PrivateConnections = map[string]bool{"browser": true}
	g, err := New(g.cfg, s, backend)
	if err != nil {
		t.Fatal(err)
	}
	h := g.mcpHandler() // Shared server instance must not cache one actor's view.
	private := demoIdentity("owner")
	shared := private
	shared.ThreadVisibility = "thread_workspace_shared"
	multiplayer := private
	multiplayer.ThreadMultiplayer = new(true)
	influenced := private
	influenced.ThreadNonOwnerCanInfluence = new(true)
	for _, tc := range []struct {
		name     string
		identity ampIdentity
		visible  bool
	}{
		{"private solo", private, true},
		{"shared", shared, false},
		{"multiplayer", multiplayer, false},
		{"non-owner influence", influenced, false},
		{"missing identity claims", ampIdentity{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			session := skillSession(t, h, tc.identity)
			checkBrowserSkill(t, session, tc.visible)
		})
	}

	session := skillSession(t, h, private)
	// Re-evaluate live policies/configuration even on a session that saw the skill.
	g.mu.Lock()
	tool := g.tools["browser.click"]
	tool.Policy = "deny"
	g.tools[tool.ID] = tool
	g.mu.Unlock()
	checkBrowserSkill(t, session, false)
	g.mu.Lock()
	tool.Policy = "require_approval"
	g.tools[tool.ID] = tool
	g.mu.Unlock()
	checkBrowserSkill(t, session, true)
	g.mu.Lock()
	delete(g.tools, "browser.snapshot")
	g.mu.Unlock()
	checkBrowserSkill(t, session, false)

	unconfigured, _, _ := fixture(t)
	checkBrowserSkill(t, skillSession(t, unconfigured.mcpHandler(), private), false)
	// Canonical IDs on a remote namespace collision must not enable native skills.
	g.mu.Lock()
	for i := range g.cfg.Connections {
		if g.cfg.Connections[i].ID == "browser" {
			g.cfg.Connections[i].Browser = false
		}
	}
	g.tools["browser.snapshot"] = Tool{ID: "browser.snapshot", Connection: "browser", Name: "snapshot", Policy: "allow"}
	g.mu.Unlock()
	checkBrowserSkill(t, session, false)
}

func checkBrowserSkill(t *testing.T, session *mcp.ClientSession, visible bool) {
	t.Helper()
	listed, err := mcp.CallCustomMethod[*listSkillsParams, *listSkillsResult](t.Context(), session, "skills/list", &listSkillsParams{})
	if err != nil {
		t.Fatal(err)
	}
	want := 1
	if visible {
		want = 2
	}
	if len(listed.Skills) != want || listed.Skills[0].URI != "skill://using-gateway/SKILL.md" {
		t.Fatalf("listing leaked or omitted skill: %+v", listed)
	}
	_, err = mcp.CallCustomMethod[*getSkillParams, *getSkillResult](t.Context(), session, "skills/get", &getSkillParams{URI: "skill://using-shared-browser/SKILL.md"})
	if visible {
		if err != nil {
			t.Fatal(err)
		}
	} else {
		assertInvalidSkillParams(t, err)
	}
	for _, uri := range []string{"skill://using-shared-browser/SKILL.md", "skill://using-shared-browser/reference/browser-workflow.md"} {
		_, err := session.ReadResource(t.Context(), &mcp.ReadResourceParams{URI: uri})
		if visible {
			if err != nil {
				t.Fatal(err)
			}
		} else {
			assertInvalidSkillParams(t, err)
		}
	}
}
