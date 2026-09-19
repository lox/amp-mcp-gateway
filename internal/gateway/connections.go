package gateway

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/url"
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
	Connections  []upstream.Connection
	Tools        []Tool
	ToolDefaults map[string]string `json:",omitempty"`
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
	cfg.ToolDefaults = c.ToolDefaults
	return nil
}

func (g *Gateway) catalogue() catalogue {
	return catalogue{g.cfg.Connections, g.cfg.Tools, g.cfg.ToolDefaults}
}

func validPolicy(policy string) bool {
	return policy == "deny" || policy == "require_approval" || policy == "allow"
}

func (cfg Config) defaultPolicy(id string) string {
	if policy := cfg.ToolDefaults[id]; policy != "" {
		return policy
	}
	return "require_approval"
}

// Caller holds g.mu. Validate before persistence; publish only after commit.
func (g *Gateway) saveCatalogue(ctx context.Context, c catalogue, m *upstream.Manager) error {
	next := g.cfg
	next.Connections, next.Tools = c.Connections, c.Tools
	next.ToolDefaults = c.ToolDefaults
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
	g.cfg.ToolDefaults = c.ToolDefaults
	g.tools, g.schemas, g.bindings = compiled.tools, compiled.schemas, compiled.bindings
	return nil
}

type toolDraft struct {
	Connection string
	Revision   string
	Tools      []Tool
	Expires    time.Time
	Default    string
	Changes    map[string]string // Non-nil for discovery reviews, even without changes.
	Removed    []string
}

func (draft toolDraft) edit(values url.Values) (toolDraft, error) {
	draft.Default = values.Get("default_policy")
	if !validPolicy(draft.Default) {
		return draft, errors.New("Choose a connection default.")
	}
	draft.Tools = append([]Tool(nil), draft.Tools...)
	for i := range draft.Tools {
		policy := values.Get("policy_" + strconv.Itoa(i))
		if policy != "inherit" && !validPolicy(policy) {
			return draft, errors.New("Choose a policy for every tool.")
		}
		if policy == "inherit" {
			policy = ""
		}
		draft.Tools[i].Policy = policy
	}
	return draft, nil
}

// Caller holds g.mu. Reviews also support editing saved policies while offline.
func (g *Gateway) newDraft(draft toolDraft) (string, error) {
	found := false
	for _, c := range g.cfg.Connections {
		if c.ID == draft.Connection {
			found = true
			break
		}
	}
	if !found {
		return "", errors.New("unknown connection")
	}
	if g.drafts == nil {
		g.drafts = map[string]toolDraft{}
	}
	for key, old := range g.drafts {
		// Page views replace offline edits for this connection, not discovery reviews.
		if time.Now().After(old.Expires) || (draft.Changes == nil && old.Changes == nil && old.Connection == draft.Connection) {
			delete(g.drafts, key)
		}
	}
	if len(g.drafts) >= 32 {
		return "", errors.New("Too many open reviews. Wait ten minutes and try again.")
	}
	draft.Revision = digest(g.catalogue())
	if draft.Default == "" {
		draft.Default = g.cfg.defaultPolicy(draft.Connection)
	}
	draft.Expires = time.Now().Add(10 * time.Minute)
	ticket := rand.Text()
	g.drafts[ticket] = draft
	return ticket, nil
}

var connectionID = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,60}$`)

func (g *Gateway) registerConnections(mux *http.ServeMux, m *upstream.Manager) {
	mux.HandleFunc("GET /connections/new", func(w http.ResponseWriter, r *http.Request) { g.addPage(w, nil, "") })
	mux.HandleFunc("POST /connections", func(w http.ResponseWriter, r *http.Request) { g.addConnection(w, r, m) })
	mux.HandleFunc("GET /connections/{id}/tools", func(w http.ResponseWriter, r *http.Request) { g.connectionTools(w, r, m) })
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
func (g *Gateway) toolsPage(w http.ResponseWriter, r *http.Request, m *upstream.Manager, id string, tools []Tool, ticket, message string, saved bool) {
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
	draft := g.drafts[ticket]
	g.mu.RUnlock()
	if connection == nil {
		http.NotFound(w, nil)
		return
	}
	if connection["OAuth"] == true {
		connection["AuthStatus"] = m.OAuthStatus(r.Context(), id)
	}
	rows := []map[string]any{}
	added, changed := 0, 0
	for _, tool := range tools {
		if draft.Changes[tool.ID] == "New" {
			added++
		}
		if draft.Changes[tool.ID] == "Changed" {
			changed++
		}
		schema, _ := json.MarshalIndent(tool.InputSchema, "", "  ")
		rows = append(rows, map[string]any{"Tool": tool, "Schema": string(schema), "Change": draft.Changes[tool.ID]})
	}
	g.render(w, map[string]any{"ToolReview": true, "Connection": connection, "Rows": rows, "Ticket": ticket, "Draft": draft, "Added": added, "Changed": changed, "Error": message, "Saved": saved, "Owner": g.cfg.OwnerSubject})
}

func (g *Gateway) connectionTools(w http.ResponseWriter, r *http.Request, m *upstream.Manager) {
	id := r.PathValue("id")
	g.mu.Lock()
	tools := []Tool{}
	for _, t := range g.cfg.Tools {
		if t.Connection == id {
			tools = append(tools, t)
		}
	}
	ticket, err := g.newDraft(toolDraft{Connection: id, Tools: tools})
	g.mu.Unlock()
	message := ""
	if err != nil {
		message = err.Error()
	}
	g.toolsPage(w, r, m, id, tools, ticket, message, r.URL.Query().Get("saved") == "1")
}

func (g *Gateway) discoverTools(w http.ResponseWriter, r *http.Request, m *upstream.Manager) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if r.ParseForm() != nil {
		http.Error(w, "invalid form", 400)
		return
	}
	id := r.PathValue("id")
	previousTicket := r.PostForm.Get("ticket")
	var previous toolDraft
	g.mu.Lock()
	revision := digest(g.catalogue())
	if previousTicket != "" {
		var ok bool
		previous, ok = g.drafts[previousTicket]
		if !ok || previous.Connection != id || time.Now().After(previous.Expires) || previous.Revision != revision {
			g.mu.Unlock()
			http.Error(w, "Edit expired or configuration changed. Reopen saved permissions.", 409)
			return
		}
		var err error
		previous, err = previous.edit(r.PostForm)
		if err != nil {
			g.mu.Unlock()
			http.Error(w, err.Error(), 400)
			return
		}
		g.drafts[previousTicket] = previous
	}
	g.mu.Unlock()
	failed := func(message string) {
		g.toolsPage(w, r, m, id, previous.Tools, previousTicket, message, false)
	}
	discovered, err := m.ListTools(r.Context(), id)
	if err != nil {
		failed("Could not fetch tools. Check the URL and credentials, or connect OAuth first. Existing policies are unchanged.")
		return
	}
	tools := []Tool{}
	names := map[string]bool{}
	for _, remote := range discovered {
		if remote == nil || remote.Name == "" || len(remote.Name) > 200 || names[remote.Name] {
			failed("Server returned invalid or duplicate tool names.")
			return
		}
		names[remote.Name] = true
		raw, err := json.Marshal(remote.InputSchema)
		var schema map[string]any
		if err != nil || len(raw) > 256<<10 || json.Unmarshal(raw, &schema) != nil || schema == nil {
			failed("Server returned an invalid or oversized tool schema.")
			return
		}
		tools = append(tools, Tool{ID: id + "." + remote.Name, Connection: id, Name: remote.Name, Description: remote.Description, InputSchema: schema})
	}
	sort.Slice(tools, func(i, j int) bool { return tools[i].ID < tools[j].ID })
	g.mu.Lock()
	if revision != digest(g.catalogue()) {
		g.mu.Unlock()
		g.toolsPage(w, r, m, id, nil, "", "Configuration changed while fetching. Fetch again.", false)
		return
	}
	draft := toolDraft{Connection: id, Tools: tools, Default: previous.Default, Changes: map[string]string{}}
	for i := range tools {
		draft.Changes[tools[i].ID] = "New"
		for _, old := range g.cfg.Tools {
			if old.Connection == id && old.Name == tools[i].Name {
				delete(draft.Changes, tools[i].ID)
				tools[i].ID = old.ID
				if digest(old.InputSchema) == digest(tools[i].InputSchema) && old.Description == tools[i].Description {
					tools[i].Policy = old.Policy
				} else {
					draft.Changes[old.ID] = "Changed"
					tools[i].Policy = "require_approval"
					if g.tools[old.ID].Policy == "deny" {
						tools[i].Policy = "deny"
					}
				}
			}
		}
	}
	for _, old := range g.cfg.Tools {
		if old.Connection == id && !names[old.Name] {
			draft.Removed = append(draft.Removed, old.ID)
		}
	}
	// Preserve unsaved choices only when the definition the owner saw is unchanged.
	for i := range tools {
		for _, old := range previous.Tools {
			if old.Name != tools[i].Name {
				continue
			}
			if digest(old.InputSchema) == digest(tools[i].InputSchema) && old.Description == tools[i].Description {
				tools[i].Policy = old.Policy
			} else {
				tools[i].Policy = "require_approval"
				if old.Policy == "deny" || (old.Policy == "" && previous.Default == "deny") {
					tools[i].Policy = "deny"
				}
			}
		}
	}
	delete(g.drafts, previousTicket)
	ticket, err := g.newDraft(draft)
	g.mu.Unlock()
	message := ""
	if err != nil {
		message = err.Error()
	}
	g.toolsPage(w, r, m, id, tools, ticket, message, false)
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
		http.Error(w, "Edit expired or configuration changed. Reopen saved permissions or fetch tools again.", 409)
		return
	}
	draft, err := draft.edit(r.PostForm)
	if err != nil {
		g.mu.Unlock()
		http.Error(w, err.Error(), 400)
		return
	}
	next := g.catalogue()
	next.ToolDefaults = maps.Clone(next.ToolDefaults)
	if next.ToolDefaults == nil {
		next.ToolDefaults = map[string]string{}
	}
	next.ToolDefaults[id] = draft.Default
	next.Tools = nil
	for _, t := range g.cfg.Tools {
		if t.Connection != id {
			next.Tools = append(next.Tools, t)
		}
	}
	next.Tools = append(next.Tools, draft.Tools...)
	err = g.saveCatalogue(r.Context(), next, m)
	if err == nil {
		clear(g.drafts) // Every older snapshot is now stale.
	} else {
		g.drafts[ticket] = draft
	}
	g.mu.Unlock()
	if err != nil {
		g.toolsPage(w, r, m, id, draft.Tools, ticket, err.Error(), false)
		return
	}
	http.Redirect(w, r, "/connections/"+id+"/tools?saved=1", http.StatusSeeOther)
}
