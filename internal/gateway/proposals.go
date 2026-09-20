package gateway

import (
	"context"
	"crypto/rand"
	"errors"
	"maps"
	"net/http"
	"time"

	"ampcode.com/lox/mcp-gateway/internal/browserauth"
	"ampcode.com/lox/mcp-gateway/internal/store"
	"ampcode.com/lox/mcp-gateway/internal/upstream"
)

type policyChange struct {
	Connection string            `json:"connection"`
	Default    string            `json:"default_policy,omitempty"`
	Tools      map[string]string `json:"tools,omitempty"`
}

type policyInput struct {
	Changes []policyChange `json:"changes"`
}

type policyProposal struct {
	Revision string
	Expires  time.Time
	Identity ampIdentity
	Drafts   []toolDraft
}

type policyResult struct {
	ReviewURL string    `json:"review_url"`
	Expires   time.Time `json:"expires_at"`
}

// Only authentication middleware supplies identity; there are no model-reported
// identity fields. Proposals contain policies, never connection credentials.
func (g *Gateway) proposePolicies(ctx context.Context, in policyInput) (policyResult, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	identity, _ := ctx.Value(ampIdentityKey{}).(ampIdentity)
	if g.cfg.AmpUserID != "" && (identity.UserID != g.cfg.AmpUserID || !ampThreadID.MatchString(identity.ThreadID)) {
		return policyResult{}, errors.New("verified Amp identity required")
	}
	if len(in.Changes) == 0 || len(in.Changes) > 32 {
		return policyResult{}, errors.New("supply 1–32 connection changes")
	}
	p := policyProposal{Revision: digest(g.catalogue()), Expires: time.Now().Add(10 * time.Minute), Identity: identity}
	seen := map[string]bool{}
	changed := false
	for _, change := range in.Changes {
		if seen[change.Connection] {
			return policyResult{}, errors.New("duplicate connection")
		}
		seen[change.Connection] = true
		found := false
		for _, c := range g.cfg.Connections {
			found = found || c.ID == change.Connection
		}
		if !found || (change.Default != "" && !validPolicy(change.Default)) || len(change.Tools) > 1000 {
			return policyResult{}, errors.New("unknown connection or invalid policies")
		}
		d := toolDraft{Connection: change.Connection, Default: g.cfg.defaultPolicy(change.Connection)}
		if change.Default != "" {
			changed = changed || d.Default != change.Default
			d.Default = change.Default
		}
		matched := 0
		for _, tool := range g.cfg.Tools {
			if tool.Connection != change.Connection {
				continue
			}
			if policy, ok := change.Tools[tool.ID]; ok {
				matched++
				if policy != "inherit" && !validPolicy(policy) {
					return policyResult{}, errors.New("invalid tool policy")
				}
				if policy == "inherit" {
					policy = ""
				}
				changed = changed || tool.Policy != policy
				tool.Policy = policy
			}
			d.Tools = append(d.Tools, tool)
		}
		if matched != len(change.Tools) {
			return policyResult{}, errors.New("unknown tool or tool belongs to another connection")
		}
		p.Drafts = append(p.Drafts, d)
	}
	if !changed {
		return policyResult{}, errors.New("proposal contains no changes")
	}
	if g.proposals == nil {
		g.proposals = map[string]policyProposal{}
	}
	for ticket, old := range g.proposals {
		if time.Now().After(old.Expires) {
			delete(g.proposals, ticket)
		}
	}
	if len(g.proposals) >= 32 {
		return policyResult{}, errors.New("too many proposals; wait ten minutes")
	}
	ticket := rand.Text()
	actor := "authenticated bearer agent (no verified Amp identity)"
	if identity.UserID != "" {
		actor = "Amp user " + identity.UserID + " thread " + identity.ThreadID
	}
	if err := g.store.RecordEvent(ctx, store.Event{Kind: "policy-proposed", Actor: actor + " · proposal " + digest(ticket)}); err != nil {
		return policyResult{}, errors.New("could not record proposal")
	}
	g.proposals[ticket] = p
	return policyResult{ReviewURL: g.cfg.BaseURL + "/policy-proposals/" + ticket, Expires: p.Expires}, nil
}

func policyLabel(policy string) string {
	switch policy {
	case "allow":
		return "Allow"
	case "deny":
		return "Block"
	case "require_approval":
		return "Require approval"
	default:
		return "Use default"
	}
}

func (g *Gateway) reviewPolicies(w http.ResponseWriter, r *http.Request) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	p, ok := g.proposals[r.PathValue("ticket")]
	if !ok || time.Now().After(p.Expires) || p.Revision != digest(g.catalogue()) {
		http.Error(w, "Proposal expired or configuration changed. Ask the agent for a new proposal.", 409)
		return
	}
	connections := []map[string]any{}
	for _, d := range p.Drafts {
		rows := []map[string]string{}
		for _, t := range d.Tools {
			var before Tool
			for _, old := range g.cfg.Tools {
				if old.ID == t.ID {
					before = old
					break
				}
			}
			afterEffective := t.Policy
			if afterEffective == "" {
				afterEffective = d.Default
			}
			rows = append(rows, map[string]string{"ID": t.ID, "Before": policyLabel(before.Policy), "After": policyLabel(t.Policy), "BeforeEffective": policyLabel(g.tools[t.ID].Policy), "AfterEffective": policyLabel(afterEffective)})
		}
		connections = append(connections, map[string]any{"ID": d.Connection, "Before": policyLabel(g.cfg.defaultPolicy(d.Connection)), "After": policyLabel(d.Default), "Rows": rows})
	}
	g.render(w, map[string]any{"PolicyProposal": true, "Proposal": p, "Connections": connections, "Ticket": r.PathValue("ticket"), "Owner": g.cfg.OwnerSubject})
}

func (g *Gateway) decidePolicies(w http.ResponseWriter, r *http.Request, m *upstream.Manager) {
	decision, ticket := r.PathValue("decision"), r.PathValue("ticket")
	if decision != "apply" && decision != "discard" {
		http.NotFound(w, r)
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	p, ok := g.proposals[ticket]
	if !ok || time.Now().After(p.Expires) || p.Revision != digest(g.catalogue()) {
		http.Error(w, "Proposal expired or configuration changed. Ask the agent for a new proposal.", 409)
		return
	}
	event := store.Event{Kind: "policy-discarded", Actor: browserauth.Subject(r.Context()) + " · proposal " + digest(ticket)}
	var err error
	if decision == "discard" {
		err = g.store.RecordEvent(r.Context(), event)
	} else {
		next := g.catalogue()
		next.ToolDefaults = maps.Clone(next.ToolDefaults)
		if next.ToolDefaults == nil {
			next.ToolDefaults = map[string]string{}
		}
		next.Tools = append([]Tool(nil), next.Tools...)
		for _, d := range p.Drafts {
			next.ToolDefaults[d.Connection] = d.Default
			for _, tool := range d.Tools {
				for i := range next.Tools {
					if next.Tools[i].ID == tool.ID {
						next.Tools[i].Policy = tool.Policy
					}
				}
			}
		}
		event.Kind = "policy-applied"
		err = g.saveCatalogue(r.Context(), next, m, event)
		if err == nil {
			clear(g.drafts)
		}
	}
	if err != nil {
		http.Error(w, "Could not save decision. Running operations must finish first; retry from the review page.", 409)
		return
	}
	delete(g.proposals, ticket)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
