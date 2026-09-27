package gateway

import "embed"

// Vendored htmx is served locally; see assets/htmx-LICENSE for provenance.
//
//go:embed assets/*
var assets embed.FS
