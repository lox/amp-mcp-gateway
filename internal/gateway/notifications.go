package gateway

import (
	"html/template"
	"log/slog"
	"net/http"
)

var notificationFeed = template.Must(template.New("notifications").Parse(`{{range .}}<span data-approval-id="{{.ID}}"></span>{{end}}`))

// notifications exposes only pending IDs to the owner-authenticated browser.
func (g *Gateway) notifications(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	operations, err := g.store.ListStatus(r.Context(), "pending")
	if err != nil {
		http.Error(w, "pending approvals unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := notificationFeed.Execute(w, operations); err != nil {
		slog.Error("render notification feed", "error", err)
	}
}
