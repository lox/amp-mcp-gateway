// Package webui serves the build-time Tailwind stylesheet shared by the UI pages.
package webui

import (
	"embed"
	"net/http"
)

//go:embed assets/ui.css
var assets embed.FS

// Stylesheet serves only the public stylesheet, not authenticated UI assets.
func Stylesheet(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-cache")
	http.ServeFileFS(w, r, assets, "assets/ui.css")
}
