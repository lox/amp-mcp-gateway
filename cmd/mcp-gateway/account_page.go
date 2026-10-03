package main

import (
	"html/template"
	"net/http"

	"ampcode.com/lox/amp-mcp-gateway/internal/browserauth"
)

func (r *accountRegistry) account(w http.ResponseWriter, req *http.Request) {
	id := r.current(browserauth.Subject(req.Context()))
	if id == "" {
		http.Error(w, "account unavailable", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = accountPage.Execute(w, id)
}

var accountPage = template.Must(template.New("account").Parse(`<!doctype html>
<html lang="en" class="dashboard"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Amp MCP Gateway · Account</title><link rel="stylesheet" href="/assets/ui.css"></head>
<body><a class="skip" href="#main">Skip to content</a><header class="topbar"><a class="brand" href="/account"><span class="brand-mark" aria-hidden="true"></span>gateway<span class="brand-slash" aria-hidden="true">/</span></a><span class="product-name">Account settings</span><form method="post" action="/logout"><button>Sign out</button></form></header>
<div class="shell"><aside class="sidebar"><nav aria-label="Main navigation"><a href="/approvals"><span class="nav-symbol" aria-hidden="true">↗</span>Approvals</a><a href="/connections"><span class="nav-symbol" aria-hidden="true">⊞</span>Connections</a><a href="/integrations"><span class="nav-symbol" aria-hidden="true">◇</span>Integrations</a><a href="/audit"><span class="nav-symbol" aria-hidden="true">≡</span>Audit</a><a href="/account" aria-current="page"><span class="nav-symbol" aria-hidden="true">@</span>Account</a></nav></aside><main id="main"><h1>Account</h1><p class="sub">Signed in with Amp.</p><section class="card"><h2>Amp account</h2><p><span class="badge succeeded">Signed in</span></p><dl><dt>Amp ID</dt><dd><code>{{.}}</code></dd></dl><p class="help">Your connections, credentials, policies, approvals and history are isolated to your Amp account.</p></section></main></div></body></html>`))
