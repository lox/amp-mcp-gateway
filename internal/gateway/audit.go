package gateway

import (
	_ "embed"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	_ "time/tzdata"

	"ampcode.com/lox/amp-mcp-gateway/internal/store"
)

//go:embed audit.html
var auditHTML string

var auditTemplateFuncs = template.FuncMap{
	"stamp": func(epoch int64, zone string) string {
		loc, _ := time.LoadLocation(zone) // Validated before rendering.
		return time.Unix(epoch, 0).In(loc).Format("02 Jan 2006 · 15:04:05 MST")
	},
	"iso": func(epoch int64) string { return time.Unix(epoch, 0).UTC().Format(time.RFC3339) },
	"updated": func(events []store.Event) int64 {
		if len(events) == 0 {
			return 0
		}
		return events[len(events)-1].Time
	},
	"status": auditStatus,
	"event":  auditEvent,
	"actor": func(actor, owner string) string {
		switch {
		case actor == "gateway":
			return "Gateway"
		case actor == "restart":
			return "Gateway restart"
		case actor == "connection-reauthorized":
			return "Connection reauthorised"
		case actor == "catalogue-changed":
			return "Catalogue changed"
		case actor == "approval-grant-unavailable":
			return "Standing approval unavailable"
		case actor == "gateway-client":
			return "Gateway client"
		case actor == owner:
			return "Owner identity"
		case strings.HasPrefix(actor, "amp:"):
			return "Amp caller"
		default:
			return actor
		}
	},
	"requestURL": func(id string) string { return "/operations/" + url.PathEscape(id) },
}

func auditStatus(status string) string {
	switch status {
	case "pending":
		return "Awaiting approval"
	case "ready":
		return "Queued"
	case "running":
		return "Running"
	case "succeeded":
		return "Succeeded"
	case "failed":
		return "Failed"
	case "unknown":
		return "Outcome unconfirmed"
	case "denied":
		return "Denied"
	case "expired":
		return "Expired"
	default:
		return status
	}
}

func auditEvent(request store.AuditRequest, i int) string {
	events := request.Events
	e := events[i]
	switch e.Kind {
	case "ready":
		if i == 0 {
			if scope := request.Operation.ApprovalScope; scope != "" {
				return "Allowed by standing " + scope + " approval"
			}
			return "Allowed by policy"
		}
		if events[i-1].Kind == "pending" {
			return "Approved once"
		}
		if strings.HasPrefix(events[i-1].Kind, "approval-") {
			return "Approved for this request"
		}
		return "Queued for execution"
	case "approval-thread":
		return "Standing thread approval created"
	case "approval-project":
		return "Standing project approval created"
	case "approval-revoked":
		return "Standing approval revoked"
	case "lease-ready":
		return "Credential lease ready"
	case "lease-redeemed":
		return "Credential lease redeemed"
	case "lease-invalidated":
		return "Credential lease invalidated"
	case "pending":
		return "Requested · approval required"
	case "running":
		return "Execution started"
	case "succeeded":
		return "Execution succeeded"
	case "failed":
		return "Upstream reported an error"
	case "denied":
		if i == 0 {
			return "Denied by policy"
		}
		if e.Actor == "connection-reauthorized" {
			return "Denied after connection reauthorisation"
		}
		if e.Actor == "catalogue-changed" {
			return "Denied after catalogue change"
		}
		if e.Actor == "approval-grant-unavailable" {
			return "Standing approval expired or revoked"
		}
		if events[i-1].Kind == "running" {
			return "Blocked by execution-time policy check"
		}
	}
	return auditStatus(e.Kind)
}

func (g *Gateway) audit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.AuditFilter{Query: strings.TrimSpace(q.Get("q")), Connection: q.Get("connection"), Outcome: q.Get("outcome"), Until: time.Now().Unix()}
	if preset := q.Get("preset"); preset != "" {
		f.Outcome = preset
		if preset == "all" {
			f.Outcome = ""
		}
	}
	period, zone := q.Get("period"), q.Get("zone")
	if period == "" {
		period = "24h"
	}
	if f.Outcome == "active" {
		period = "all"
	}
	if zone == "" {
		zone = "Australia/Melbourne"
	}
	bad := func() { http.Error(w, "Invalid audit filters. Return to /audit to reset them.", http.StatusBadRequest) }
	if len(f.Query) > 256 || len(f.Connection) > 256 || (zone != "UTC" && zone != "Australia/Melbourne") {
		bad()
		return
	}
	if q.Get("view") == "events" {
		events, err := g.store.Events(r.Context())
		if err != nil {
			http.Error(w, "Audit unavailable. Try again shortly.", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		g.renderAudit(w, r, "audit-list", map[string]any{"Section": "audit", "RawAudit": true, "Events": events, "Zone": zone, "Owner": g.cfg.OwnerSubject})
		return
	}
	if end := q.Get("until"); end != "" {
		n, err := strconv.ParseInt(end, 10, 64)
		if err != nil || n <= 0 || n > f.Until {
			bad()
			return
		}
		f.Until = n
	}
	switch period {
	case "24h":
		f.Since = f.Until - 24*60*60
	case "7d":
		f.Since = f.Until - 7*24*60*60
	case "all":
	default:
		bad()
		return
	}
	switch f.Outcome {
	case "", "active", "investigate", "pending", "ready", "running", "succeeded", "failed", "unknown", "denied", "expired":
	default:
		bad()
		return
	}
	if q.Get("before") != "" || q.Get("before_id") != "" {
		var err error
		f.BeforeCreated, err = strconv.ParseInt(q.Get("before"), 10, 64)
		f.BeforeID = q.Get("before_id")
		if err != nil || f.BeforeCreated < 0 || f.BeforeCreated > f.Until || f.BeforeID == "" || len(f.BeforeID) > 256 {
			bad()
			return
		}
	}
	requests, more, err := g.store.Audit(r.Context(), f)
	if err != nil {
		http.Error(w, "Audit unavailable. Try again shortly.", http.StatusServiceUnavailable)
		return
	}
	values := url.Values{"q": {f.Query}, "connection": {f.Connection}, "outcome": {f.Outcome}, "period": {period}, "zone": {zone}}
	latest := "/audit?" + values.Encode()
	values.Set("until", strconv.FormatInt(f.Until, 10))
	var older string
	if more {
		last := requests[len(requests)-1].Operation
		values.Set("before", strconv.FormatInt(last.Created, 10))
		values.Set("before_id", last.ID)
		older = "/audit?" + values.Encode()
	}
	w.Header().Set("Cache-Control", "no-store")
	g.mu.RLock()
	connections := make([]map[string]string, 0, len(g.cfg.Connections))
	for _, c := range g.cfg.Connections {
		connections = append(connections, map[string]string{"ID": c.ID, "Account": c.Account})
	}
	g.mu.RUnlock()
	g.renderAudit(w, r, "audit-requests", map[string]any{
		"Section":  "audit",
		"Requests": requests, "Filter": f, "Period": period, "Zone": zone,
		"Owner": g.cfg.OwnerSubject, "Connections": connections,
		"Outcomes": []string{"active", "investigate", "pending", "ready", "running", "succeeded", "failed", "unknown", "denied", "expired"},
		"Older":    older, "Latest": latest,
	})
}

func (g *Gateway) renderAudit(w http.ResponseWriter, r *http.Request, fragment string, data map[string]any) {
	w.Header().Set("Vary", "HX-Request")
	data["Current"] = r.URL.RequestURI()
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := page.ExecuteTemplate(w, fragment, data); err != nil {
			slog.Error("render audit fragment", "error", err)
		}
		return
	}
	g.render(w, data)
}
