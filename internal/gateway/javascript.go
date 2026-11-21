package gateway

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"

	"ampcode.com/lox/amp-mcp-gateway/internal/jsintegration"
	"ampcode.com/lox/amp-mcp-gateway/internal/store"
	"ampcode.com/lox/amp-mcp-gateway/internal/upstream"
)

// LoadJavaScript retains startup source bytes before the saved review catalogue
// is loaded. Static installations belong only to the configured primary owner.
func LoadJavaScript(cfg *Config) error {
	for i := range cfg.Connections {
		c := &cfg.Connections[i]
		if c.JavaScript == nil {
			continue
		}
		if c.ManagedJavaScript {
			return errors.New("managed JavaScript bundles must be installed through the dashboard")
		}
		if err := c.JavaScript.Load(); err != nil {
			return fmt.Errorf("JavaScript connection %s: %w", c.ID, err)
		}
	}
	return nil
}

// Startup code is authoritative; saved policies and artifact pins remain separate.
// Removing an installation removes its tools. Never revive code from an old catalogue.
func reconcileJavaScript(cfg *Config, startup []upstream.Connection) error {
	installed := map[string]upstream.Connection{}
	for _, c := range startup {
		if c.JavaScript != nil {
			if _, ok := installed[c.ID]; ok {
				return errors.New("duplicate JavaScript installation")
			}
			installed[c.ID] = c
		}
	}
	removed := map[string]bool{}
	var connections []upstream.Connection
	for _, c := range cfg.Connections {
		if _, ok := installed[c.ID]; ok {
			if c.JavaScript == nil || c.ManagedJavaScript {
				return errors.New("JavaScript installation conflicts with saved connection")
			}
			continue
		}
		if c.JavaScript != nil && !c.ManagedJavaScript {
			removed[c.ID] = true
			continue
		}
		connections = append(connections, c)
	}
	for _, c := range startup {
		if c.JavaScript != nil {
			connections = append(connections, c)
		}
	}
	cfg.Connections = connections
	cfg.Tools = slices.DeleteFunc(slices.Clone(cfg.Tools), func(t Tool) bool { return removed[t.Connection] })
	return nil
}

// Persist candidate transitions independently of reviews: A → B → A must not
// resurrect A's consent even if B was never activated in the browser.
func javascriptGenerations(ctx context.Context, cfg *Config, previous []upstream.Connection, s *store.Store) error {
	installed := map[string]bool{}
	for i := range cfg.Connections {
		c := &cfg.Connections[i]
		if c.JavaScript == nil {
			continue
		}
		installed[c.ID] = true
		if c.ManagedJavaScript {
			continue // Uploaded generations are saved atomically with their catalogue.
		}
		c.JavaScript.Generation = ""
		fingerprint := c.JavaScriptBinding()
		key := "javascript-installation:" + c.ID
		raw, err := s.LoadToken(ctx, key)
		if err != nil {
			return err
		}
		var state struct{ Fingerprint, Generation string }
		if raw != nil {
			if err := json.Unmarshal(raw, &state); err != nil {
				return err
			}
		}
		if state.Fingerprint != fingerprint || state.Generation == "" {
			state.Fingerprint = fingerprint
			state.Generation = rand.Text()
			raw, err = json.Marshal(state)
			if err != nil {
				return err
			}
			if err := s.SaveToken(ctx, key, raw); err != nil {
				return err
			}
		}
		c.JavaScript.Generation = state.Generation
	}
	for _, c := range previous {
		if c.JavaScript != nil && !installed[c.ID] {
			if err := s.SaveToken(ctx, "javascript-installation:"+c.ID, []byte(`{}`)); err != nil {
				return err
			}
		}
	}
	return nil
}

// javascriptUpload deliberately excludes file paths, credentials, policy and generation.
// Never decode a browser bundle into upstream.Connection or call Definition.Load.
type javascriptUpload struct {
	ID, Account, Origin, Source string
	Tools                       []jsintegration.Tool
}

func (g *Gateway) javascriptUploadPage(w http.ResponseWriter, r *http.Request, message string) {
	data := map[string]any{"Section": "integrations", "JavaScriptUpload": true, "Error": message}
	if id := r.PathValue("id"); id != "" {
		connection := g.connectionView(id)
		if connection == nil || connection["ManagedJavaScript"] != true {
			http.NotFound(w, r)
			return
		}
		data["Installation"] = connection
	}
	w.Header().Set("Cache-Control", "no-store")
	g.render(w, r, data)
}

func (g *Gateway) uploadJavaScript(w http.ResponseWriter, r *http.Request, m *upstream.Manager) {
	fail := func(message string) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusBadRequest)
		g.javascriptUploadPage(w, r, message)
	}
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	if err := r.ParseMultipartForm(2 << 20); err != nil {
		http.Error(w, "Upload a JSON bundle smaller than 1 MiB.", http.StatusBadRequest)
		return
	}
	defer r.MultipartForm.RemoveAll()
	file, _, err := r.FormFile("bundle")
	if err != nil {
		fail("Choose a JSON bundle.")
		return
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil || len(raw) > 1<<20 {
		fail("The JSON bundle must be smaller than 1 MiB.")
		return
	}
	var upload javascriptUpload
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&upload); err != nil || decoder.Decode(new(any)) != io.EOF {
		fail("Invalid bundle. Use only ID, Account, Origin, Source and Tools; credentials belong in the separate token field.")
		return
	}
	if !connectionID.MatchString(upload.ID) || len(upload.Account) > 200 {
		fail("Use a connection ID of 1–60 letters, numbers, dashes or underscores, and an account label up to 200 characters.")
		return
	}
	definition := &jsintegration.Definition{Origin: upload.Origin, Source: upload.Source, Tools: upload.Tools, Generation: rand.Text()}
	if err := definition.Validate(); err != nil {
		fail("Invalid JavaScript definition. Check source size, HTTPS origin, tool schemas and exact HTTP grants.")
		return
	}
	if err := upstream.ValidatePublicURL(upload.Origin); err != nil {
		fail("Use a public HTTPS API origin.")
		return
	}
	token := strings.TrimSpace(r.PostForm.Get("token"))
	if len(token) > 16<<10 || strings.ContainsAny(token, "\r\n") {
		fail("Enter a bearer token without line breaks, up to 16 KiB.")
		return
	}
	id := r.PathValue("id")
	g.mu.Lock()
	next := g.catalogue()
	index := slices.IndexFunc(next.Connections, func(c upstream.Connection) bool { return c.ID == upload.ID })
	if id != "" {
		if id != upload.ID || index < 0 || !next.Connections[index].ManagedJavaScript || next.Connections[index].JavaScriptBinding() != r.PostForm.Get("revision") {
			g.mu.Unlock()
			http.Error(w, "Integration changed or bundle ID does not match. Reopen the replacement form.", http.StatusConflict)
			return
		}
		if token == "" {
			token = next.Connections[index].BearerToken
		}
	} else if index >= 0 || slices.ContainsFunc(next.Integrations, func(i Integration) bool { return i.ID == upload.ID }) {
		g.mu.Unlock()
		fail("That connection name is already in use.")
		return
	}
	if token == "" {
		g.mu.Unlock()
		fail("Enter a bearer token. It is stored encrypted and never shown again.")
		return
	}
	connection := upstream.Connection{ID: upload.ID, Account: upload.Account, JavaScript: definition, ManagedJavaScript: true, BearerToken: token}
	if index < 0 {
		next.Connections = append(next.Connections, connection)
	} else {
		next.Connections[index] = connection
	}
	// Old tools keep their saved blocks, but their artifact pins no longer match.
	// Saving also cancels queued authority and rejects changes during execution.
	err = g.saveCatalogue(r.Context(), next, m)
	g.mu.Unlock()
	if err != nil {
		fail(err.Error())
		return
	}
	http.Redirect(w, r, "/connections/"+upload.ID+"/tools", http.StatusSeeOther)
}

func (g *Gateway) javascriptArtifact(connection string) string {
	for _, c := range g.cfg.Connections {
		if c.ID == connection && c.JavaScript != nil {
			return c.JavaScriptBinding()
		}
	}
	return ""
}
