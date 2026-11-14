package gateway

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"

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
			if c.JavaScript == nil {
				return errors.New("JavaScript installation conflicts with saved connection")
			}
			continue
		}
		if c.JavaScript != nil {
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
		c.JavaScript.Generation = ""
		fingerprint := c.JavaScript.Binding(os.Getenv(c.TokenEnv))
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

func (g *Gateway) javascriptArtifact(connection string) string {
	for _, c := range g.cfg.Connections {
		if c.ID == connection && c.JavaScript != nil {
			return c.JavaScript.Binding(os.Getenv(c.TokenEnv))
		}
	}
	return ""
}
