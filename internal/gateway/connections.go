package gateway

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"ampcode.com/lox/mcp-gateway/internal/store"
	"ampcode.com/lox/mcp-gateway/internal/upstream"
)

// catalogue becomes the source of truth after the first browser save. Identity
// and deployment settings remain in the startup configuration.
type catalogue struct {
	Connections []upstream.Connection
	Tools       []Tool
}

// LoadCatalogue restores browser-managed connections and policies before startup validation.
func LoadCatalogue(ctx context.Context, cfg *Config, s *store.Store) error {
	raw, err := s.LoadCatalogue(ctx)
	if err != nil || raw == nil {
		return err
	}
	var c catalogue
	if err := json.Unmarshal(raw, &c); err != nil {
		return err
	}
	cfg.Connections, cfg.Tools = c.Connections, c.Tools
	return nil
}

func (g *Gateway) catalogue() catalogue { return catalogue{g.cfg.Connections, g.cfg.Tools} }

// Caller holds g.mu. Validate before persistence; publish only after commit.
func (g *Gateway) saveCatalogue(ctx context.Context, c catalogue, m *upstream.Manager) error {
	next := g.cfg
	next.Connections, next.Tools = c.Connections, c.Tools
	manager, err := upstream.New(next.BaseURL, next.Connections, g.store)
	if err != nil {
		return errors.New("invalid connection configuration")
	}
	compiled, err := New(next, g.store, m)
	if err != nil {
		return errors.New("tool definitions are invalid; schemas must be self-contained")
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return err
	}
	if err := g.store.SaveCatalogue(ctx, raw); err != nil {
		return errors.New("could not save; wait for running operations to finish and try again")
	}
	m.Install(manager)
	g.cfg.Connections, g.cfg.Tools = c.Connections, c.Tools
	g.tools, g.schemas, g.bindings = compiled.tools, compiled.schemas, compiled.bindings
	return nil
}

type toolDraft struct {
	Connection string
	Revision   string
	Tools      []Tool
	Expires    time.Time
}

var connectionID = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,60}$`)

func (g *Gateway) registerConnections(mux *http.ServeMux, m *upstream.Manager) {
	mux.HandleFunc("GET /connections/new", func(w http.ResponseWriter, r *http.Request) { g.addPage(w, nil, "") })
	mux.HandleFunc("POST /connections", func(w http.ResponseWriter, r *http.Request) { g.addConnection(w, r, m) })
	mux.HandleFunc("GET /connections/{id}/tools", g.connectionTools)
	mux.HandleFunc("POST /connections/{id}/discover", func(w http.ResponseWriter, r *http.Request) { g.discoverTools(w, r, m) })
	mux.HandleFunc("POST /connections/{id}/tools", func(w http.ResponseWriter, r *http.Request) { g.saveTools(w, r, m) })
}

func (g *Gateway) addPage(w http.ResponseWriter, values map[string]string, message string) {
	if values == nil {
		values = map[string]string{"auth": "oauth"}
	}
	g.render(w, map[string]any{"AddConnection": true, "Values": values, "Error": message, "BaseURL": g.cfg.BaseURL, "Owner": g.cfg.OwnerSubject})
}

func (g *Gateway) addConnection(w http.ResponseWriter, r *http.Request, m *upstream.Manager) {
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	if r.ParseForm() != nil {
		http.Error(w, "invalid form", 400)
		return
	}
	values := map[string]string{}
	for _, key := range []string{"id", "url", "account", "auth", "client_id"} {
		values[key] = strings.TrimSpace(r.PostForm.Get(key))
	}
	fail := func(message string) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(400)
		g.addPage(w, values, message)
	}
	if !connectionID.MatchString(values["id"]) {
		fail("Use 1–60 letters, numbers, dashes or underscores for the connection name.")
		return
	}
	if len(values["account"]) > 200 || len(values["url"]) > 2048 || len(values["client_id"]) > 1024 {
		fail("One of the fields is too long.")
		return
	}
	if err := upstream.ValidatePublicURL(values["url"]); err != nil {
		fail(err.Error())
		return
	}
	g.mu.RLock()
	exists := false
	for _, c := range g.cfg.Connections {
		if c.ID == values["id"] {
			exists = true
		}
	}
	g.mu.RUnlock()
	if exists {
		fail("That connection name is already in use.")
		return
	}
	c := upstream.Connection{ID: values["id"], URL: values["url"], Account: values["account"], PublicOnly: true}
	switch values["auth"] {
	case "none":
		c.NoAuth = true
	case "bearer":
		c.BearerToken = strings.TrimSpace(r.PostForm.Get("token"))
		if c.BearerToken == "" || strings.ContainsAny(c.BearerToken, "\r\n") {
			fail("Enter a bearer token without line breaks.")
			return
		}
	case "oauth":
		var err error
		c.OAuth, err = upstream.DiscoverOAuth(r.Context(), c.URL, g.cfg.BaseURL+"/connections/"+c.ID+"/callback", values["client_id"], strings.TrimSpace(r.PostForm.Get("client_secret")))
		if err != nil {
			fail(err.Error())
			return
		}
	default:
		fail("Choose an authentication method.")
		return
	}
	g.mu.Lock()
	for _, existing := range g.cfg.Connections {
		if existing.ID == c.ID {
			g.mu.Unlock()
			fail("That connection name is already in use.")
			return
		}
	}
	next := g.catalogue()
	next.Connections = append(append([]upstream.Connection(nil), next.Connections...), c)
	err := g.saveCatalogue(r.Context(), next, m)
	g.mu.Unlock()
	if err != nil {
		fail(err.Error())
		return
	}
	http.Redirect(w, r, "/connections/"+c.ID+"/tools", http.StatusSeeOther)
}

// Return only presentation-safe connection fields; credentials never reach templates.
func (g *Gateway) toolsPage(w http.ResponseWriter, id string, tools []Tool, ticket, message string, saved bool) {
	g.mu.RLock()
	var connection map[string]any
	for _, c := range g.cfg.Connections {
		if c.ID == id {
			connection = map[string]any{"ID": c.ID, "URL": c.URL, "Account": c.Account, "OAuth": c.OAuth != nil}
			if c.OAuth != nil {
				connection["AuthURL"], connection["Scopes"] = c.OAuth.AuthURL, strings.Join(c.OAuth.Scopes, " ")
			}
		}
	}
	g.mu.RUnlock()
	if connection == nil {
		http.NotFound(w, nil)
		return
	}
	rows := []map[string]any{}
	for _, tool := range tools {
		schema, _ := json.MarshalIndent(tool.InputSchema, "", "  ")
		rows = append(rows, map[string]any{"Tool": tool, "Schema": string(schema)})
	}
	g.render(w, map[string]any{"ToolReview": true, "Connection": connection, "Rows": rows, "Ticket": ticket, "Error": message, "Saved": saved, "Owner": g.cfg.OwnerSubject})
}

func (g *Gateway) connectionTools(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	g.mu.RLock()
	tools := []Tool{}
	for _, t := range g.cfg.Tools {
		if t.Connection == id {
			tools = append(tools, t)
		}
	}
	g.mu.RUnlock()
	g.toolsPage(w, id, tools, "", "", r.URL.Query().Get("saved") == "1")
}

func (g *Gateway) discoverTools(w http.ResponseWriter, r *http.Request, m *upstream.Manager) {
	id := r.PathValue("id")
	g.mu.RLock()
	revision := digest(g.catalogue())
	g.mu.RUnlock()
	discovered, err := m.ListTools(r.Context(), id)
	if err != nil {
		g.toolsPage(w, id, nil, "", "Could not fetch tools. Check the URL and credentials, or connect OAuth first. Existing policies are unchanged.", false)
		return
	}
	tools := []Tool{}
	names := map[string]bool{}
	for _, remote := range discovered {
		if remote == nil || remote.Name == "" || len(remote.Name) > 200 || names[remote.Name] {
			g.toolsPage(w, id, nil, "", "Server returned invalid or duplicate tool names.", false)
			return
		}
		names[remote.Name] = true
		raw, err := json.Marshal(remote.InputSchema)
		var schema map[string]any
		if err != nil || len(raw) > 256<<10 || json.Unmarshal(raw, &schema) != nil || schema == nil {
			g.toolsPage(w, id, nil, "", "Server returned an invalid or oversized tool schema.", false)
			return
		}
		tools = append(tools, Tool{ID: id + "." + remote.Name, Connection: id, Name: remote.Name, Description: remote.Description, InputSchema: schema, Policy: "deny"})
	}
	sort.Slice(tools, func(i, j int) bool { return tools[i].ID < tools[j].ID })
	g.mu.Lock()
	if revision != digest(g.catalogue()) {
		g.mu.Unlock()
		g.toolsPage(w, id, nil, "", "Configuration changed while fetching. Fetch again.", false)
		return
	}
	for i := range tools {
		// Keep policies only for identical definitions. Changed/new tools start disabled.
		for _, old := range g.cfg.Tools {
			if old.Connection == id && old.Name == tools[i].Name {
				tools[i].ID = old.ID
				if digest(old.InputSchema) == digest(tools[i].InputSchema) && old.Description == tools[i].Description {
					tools[i].Policy = old.Policy
				}
			}
		}
	}
	if g.drafts == nil {
		g.drafts = map[string]toolDraft{}
	}
	for key, draft := range g.drafts {
		if time.Now().After(draft.Expires) {
			delete(g.drafts, key)
		}
	}
	if len(g.drafts) >= 32 {
		g.mu.Unlock()
		g.toolsPage(w, id, nil, "", "Too many open reviews. Wait ten minutes and try again.", false)
		return
	}
	ticket := rand.Text()
	g.drafts[ticket] = toolDraft{Connection: id, Revision: revision, Tools: tools, Expires: time.Now().Add(10 * time.Minute)}
	g.mu.Unlock()
	g.toolsPage(w, id, tools, ticket, "", false)
}

func (g *Gateway) saveTools(w http.ResponseWriter, r *http.Request, m *upstream.Manager) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if r.ParseForm() != nil {
		http.Error(w, "invalid form", 400)
		return
	}
	id, ticket := r.PathValue("id"), r.PostForm.Get("ticket")
	g.mu.Lock()
	draft, ok := g.drafts[ticket]
	if !ok || draft.Connection != id || time.Now().After(draft.Expires) || draft.Revision != digest(g.catalogue()) {
		g.mu.Unlock()
		http.Error(w, "Review expired or configuration changed. Fetch tools again.", 409)
		return
	}
	next := g.catalogue()
	next.Tools = nil
	for _, t := range g.cfg.Tools {
		if t.Connection != id {
			next.Tools = append(next.Tools, t)
		}
	}
	for i, t := range draft.Tools {
		policy := r.PostForm.Get("policy_" + strconv.Itoa(i))
		if policy != "deny" && policy != "require_approval" && policy != "allow" {
			g.mu.Unlock()
			http.Error(w, "Choose a policy for every tool.", 400)
			return
		}
		t.Policy = policy
		next.Tools = append(next.Tools, t)
	}
	err := g.saveCatalogue(r.Context(), next, m)
	if err == nil {
		delete(g.drafts, ticket)
	}
	g.mu.Unlock()
	if err != nil {
		g.toolsPage(w, id, draft.Tools, ticket, err.Error(), false)
		return
	}
	http.Redirect(w, r, "/connections/"+id+"/tools?saved=1", http.StatusSeeOther)
}
