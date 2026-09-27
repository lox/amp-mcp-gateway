package gateway

import "embed"

// Vendored htmx is served locally; see README.md for provenance and assets/htmx-LICENSE.
//
//go:embed assets/*
var assets embed.FS
