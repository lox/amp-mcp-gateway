package gateway

import "html/template"

var page = template.Must(template.New("page").Funcs(auditTemplateFuncs).Parse(auditHTML + `{{define "suggestion"}}{{if .Suggestion.Policy}}
<details class="policy-suggestion" name="policy-explanation"><summary aria-label="Why {{if .Suggestion.Model}}Jev suggested{{else}}we require{{end}} {{if eq .Suggestion.Policy "allow"}}Allow{{else}}approval{{end}} for {{.Tool.Name}}"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 11v6m0-10v1"/></svg></summary><div class="suggestion-popover"><strong>{{if .Suggestion.Model}}Jev suggested {{if eq .Suggestion.Policy "allow"}}Allow{{else}}Require approval{{end}}{{else}}Approval fallback{{end}}</strong><p>{{.Suggestion.Reason}}</p>{{if .Suggestion.Model}}<p class="help">Based on tool metadata, not a safety guarantee.<br>Model: {{.Suggestion.Model}}</p>{{end}}</div></details>
{{end}}{{end}}
{{define "health"}}{{if .}}
<details class="health-details"><summary><span class="badge {{if eq .Status "Healthy"}}succeeded{{else}}pending{{end}}">{{.Status}}</span><span class="visually-hidden"> · Connection diagnostics</span></summary>
{{if or (eq .Status "Healthy") (eq .Status "Not tested")}}<p class="help">{{.Detail}}</p>{{end}}{{if .Refresh}}<p class="help">{{.Refresh}}</p>{{end}}
<div class="health-times">{{if not .CheckedAt.IsZero}}<p>Last tested: {{.CheckedAt.Format "02 Jan 2006 15:04:05 UTC"}}</p>{{end}}
{{if not .RefreshedAt.IsZero}}<p>Last refreshed: {{.RefreshedAt.Format "02 Jan 2006 15:04:05 UTC"}}</p>{{end}}
{{if not .ExpiresAt.IsZero}}<p>Access expires: {{.ExpiresAt.Format "02 Jan 2006 15:04:05 UTC"}}</p>{{end}}
{{if not .RetryAt.IsZero}}<p>Retry after: {{.RetryAt.Format "02 Jan 2006 15:04:05 UTC"}}</p>{{end}}</div></details>
{{if and (ne .Status "Healthy") (ne .Status "Not tested")}}<p class="help health-warning">{{.Detail}}</p>{{end}}{{end}}{{end}}
{{define "connection-health"}}<section class="connection-status" aria-label="Connection health">
<div id="health-{{.ID}}" class="connection-health" role="status">{{template "health" .Health}}</div>
<form class="connection-test actions" method="post" action="/connections/{{.ID}}/test"><button hx-post="/connections/{{.ID}}/test" hx-target="#health-{{.ID}}" hx-headers='{"Accept":"text/vnd.gateway.health+html"}' hx-disabled-elt="this" hx-sync="closest section:drop">Test connection</button>
{{if .OAuth}}<button formaction="/connections/{{.ID}}/connect">{{if and .Health (eq .Health.Status "Not connected")}}Connect OAuth{{else}}Reconnect OAuth{{end}}</button>{{end}}</form>
<p class="help test-error" role="alert" hidden></p></section>{{end}}
{{define "operation-status"}}{{with .Operation}}<div id="operation-live" role="status" {{if or (eq .Status "ready") (eq .Status "running")}}data-live hx-get="/operations/{{.ID}}" hx-trigger="live-update from:body queue:last" hx-swap="outerHTML"{{end}}>
<span class="badge {{.Status}}">{{.Status}}</span>
{{if or (eq .Status "ready") (eq .Status "running")}}{{if .ApprovalScope}}<p class="success">Authorised by the standing approval for this {{.ApprovalScope}}.</p>{{end}}<p class="sub">Execution status updates automatically.</p><a class="button" href="/operations/{{.ID}}">Refresh status</a>
{{else if eq .Status "unknown"}}<p class="note">The outcome is unknown. Check the upstream service before trying again. This call will not be retried automatically.</p>
{{else if eq .Status "denied"}}<p class="sub">This request was denied and was not executed.</p>
{{else if eq .Status "expired"}}<p class="sub">This request expired and was not executed.</p>{{end}}
{{if .Result}}<div class="card result"><h2>{{if eq .Status "failed"}}Error response{{else}}Result{{end}}</h2>{{range $.ResultBlocks}}<pre>{{.}}</pre>{{end}}<details><summary>{{if eq .Status "unknown"}}Stored response{{else}}Raw MCP response{{end}}</summary><pre>{{$.RawResult}}</pre></details></div>{{end}}
{{if $.Next}}<p><a class="button" href="/operations/{{$.Next}}">Review next request →</a></p>{{end}}
{{template "operation-history" $}}
</div>{{end}}{{end}}
{{define "operation-history"}}<details id="operation-history" class="card"><summary id="operation-history-summary">Request history</summary><div class="scroll"><table><thead><tr><th>Sequence</th><th>Transition</th><th>Actor</th></tr></thead><tbody>{{range .Events}}<tr><td>{{.Sequence}}</td><td>{{.Kind}}</td><td>{{.Actor}}</td></tr>{{else}}<tr><td colspan="3">No events yet.</td></tr>{{end}}</tbody></table></div></details>{{end}}
<!doctype html>
<html lang="en" class="dashboard"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="htmx-config" content='{"historyCacheSize":0,"allowEval":false,"allowScriptTags":false,"selfRequestsOnly":true,"timeout":30000}'><script src="/assets/htmx-2.0.8.min.js" defer></script><script src="/assets/notifications.js" defer></script><script src="/assets/live.js" defer></script><title>Amp MCP Gateway · {{if .Operation}}Request review{{else if or .Connection .AddConnection .PolicyProposal (eq .Section "connections")}}Connections{{else if or .FlyIntegration (eq .Section "integrations")}}Integrations{{else if eq .Section "audit"}}Audit{{else}}Approvals{{end}}</title><link rel="stylesheet" href="/assets/ui.css"></head><body><a class="skip" href="#main">Skip to content</a><header class="topbar"><a class="brand" href="/operations"><span class="brand-mark" aria-hidden="true"></span>gateway<span class="brand-slash" aria-hidden="true">/</span></a><span class="product-name">MCP control panel</span><small class="owner">{{.Owner}}</small>
<button id="notification-menu" class="notification-trigger" type="button" popovertarget="notification-panel" aria-label="Approval notifications" title="Approval notifications" hidden><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9M10 21h4M12 2V1"/></svg></button>
<section id="notification-panel" class="notification-panel" popover role="dialog" aria-labelledby="notification-heading" tabindex="-1" autofocus><h2 id="notification-heading">Approval notifications</h2><p id="notification-status" class="help" role="status"></p><button id="approval-notifications" type="button" aria-pressed="false" aria-describedby="notification-status">Enable notifications</button><p class="help notification-error" role="alert" hidden></p></section>
<form method="post" action="/logout"><button>Sign out</button></form></header>
<div class="shell"><aside class="sidebar"><nav aria-label="Main navigation"><a href="/operations" {{if or (and .Operation (eq .Operation.Status "pending")) (eq .Section "operations") (eq .Section "approval-grants")}}aria-current="page"{{end}}><span class="nav-symbol" aria-hidden="true">↗</span>Approvals</a><a href="/connections" {{if or .Connection .AddConnection .PolicyProposal (eq .Section "connections")}}aria-current="page"{{end}}><span class="nav-symbol" aria-hidden="true">⊞</span>Connections</a><a href="/integrations" {{if or .FlyIntegration (eq .Section "integrations")}}aria-current="page"{{end}}><span class="nav-symbol" aria-hidden="true">◇</span>Integrations</a><a href="/audit" {{if or (eq .Section "audit") (and .Operation (ne .Operation.Status "pending"))}}aria-current="page"{{end}}><span class="nav-symbol" aria-hidden="true">≡</span>Audit</a></nav>
{{if .AccountLink}}<nav aria-label="Account navigation"><a href="/account"><span class="nav-symbol" aria-hidden="true">@</span>Account</a></nav>{{end}}
<div id="notification-feed" hidden hx-get="/notifications" hx-trigger="approval-update queue:last"></div>
</aside><main id="main">
{{if .FlyIntegration}}
<div class="setup"><a href="/integrations">← Integrations</a><div class="heading"><div><h1>Fly.io</h1><p class="sub">Issue short-lived, scoped credentials for flyctl without exposing the stored parent token.</p></div>{{if .Configured}}<span class="badge succeeded">Connected</span>{{end}}</div>
{{if .Error}}<p class="error" role="alert">{{.Error}}</p>{{end}}{{if .Saved}}<p class="success" role="status">Fly.io integration saved. The governed tool is available to agents now.</p>{{end}}
<form method="post" action="/integrations/fly" autocomplete="off"><div class="card">
<div class="field"><label for="fly-account">Account label</label><input id="fly-account" name="account" value="{{.Account}}" maxlength="200" placeholder="Production app"><small>Shown during approval. This label is not verified by Fly.io.</small></div>
<div class="field"><label for="fly-token">Scoped access token</label><input id="fly-token" name="token" type="password" autocomplete="new-password" {{if not .Configured}}required{{end}}><small>{{if .Configured}}Leave blank to keep the stored token. Enter a replacement to rotate it.{{else}}Stored encrypted and never shown again. Use the narrowest Fly token that supports the work.{{end}}</small></div>
<div class="field"><label for="fly-policy">Permission for token requests</label><select id="fly-policy" name="policy"><option value="deny" {{if eq .Policy "deny"}}selected{{end}}>Block</option><option value="require_approval" {{if eq .Policy "require_approval"}}selected{{end}}>Require approval</option><option value="allow" {{if eq .Policy "allow"}}selected{{end}}>Allow</option></select><small>Approved requests return a one-time redemption URL. Redeemed tokens retain the parent scope and expire after at most 15 minutes.</small></div>
<details><summary>Create a scoped Fly.io token</summary><p class="help">For one app, run:</p><pre>fly tokens create deploy -a APP --name amp-mcp-gateway --expiry 720h</pre><p class="help">Use an organization token only when the orb genuinely needs authority across apps. Revoking the parent token invalidates every derived token.</p></details>
</div><p class="note">The gateway audits the request, approval and one-time redemption. Fly.io calls made afterward are not individually visible to the gateway.</p><div class="actions"><button class="primary">{{if .Configured}}Save changes{{else}}Connect Fly.io{{end}}</button><a class="button" href="/integrations">Cancel</a></div></form>
{{if .Configured}}<form class="danger-zone" method="post" action="/integrations/fly/remove"><button class="danger">Disconnect Fly.io</button></form>{{end}}</div>
{{else if .AddConnection}}
<div class="setup"><a href="/connections">← Connections</a><h1>Add MCP</h1><p class="sub">Connect a remote server, then choose which tools agents can use.</p>
{{if .Error}}<p class="error" role="alert">{{.Error}}</p>{{end}}
<form method="post" action="/connections" autocomplete="off"><div class="card">
<div class="field"><label for="connection-id">Connection name</label><input id="connection-id" name="id" value="{{.Values.id}}" placeholder="github" pattern="[a-zA-Z0-9_-]{1,60}" maxlength="60" required><small>Used in tool IDs, such as github.create_issue. Letters, numbers, dashes and underscores.</small></div>
<div class="field"><label for="connection-url">MCP server URL</label><input id="connection-url" type="url" name="url" value="{{.Values.url}}" placeholder="https://mcp.example.com/mcp" maxlength="2048" required><small>Remote Streamable HTTP, public HTTPS only. Local command-based servers are not supported.</small></div>
<div class="field"><label for="connection-account">Account label <small>(optional)</small></label><input id="connection-account" name="account" value="{{.Values.account}}" maxlength="200" placeholder="Personal account"><small>A label for approval pages, not a verified account identity.</small></div>
<div class="field"><label for="connection-auth">Authentication</label><select id="connection-auth" name="auth"><option value="oauth" {{if eq .Values.auth "oauth"}}selected{{end}}>OAuth — sign in with the provider</option><option value="bearer" {{if eq .Values.auth "bearer"}}selected{{end}}>Bearer token</option><option value="none" {{if eq .Values.auth "none"}}selected{{end}}>None — public server</option></select></div>
<div class="bearer-fields field"><label for="connection-token">Bearer token</label><input id="connection-token" name="token" type="password" autocomplete="new-password"><small>Stored encrypted. Never shown again.</small></div>
<div class="oauth-fields"><p class="help">We discover OAuth settings and try to register a client. You’ll review the authorization server and scopes before signing in.</p><details><summary>Use an existing OAuth client</summary><div class="field"><label for="client-id">Client ID</label><input id="client-id" name="client_id" value="{{.Values.client_id}}" maxlength="1024"></div><div class="field"><label for="client-secret">Client secret <small>(if required)</small></label><input id="client-secret" name="client_secret" type="password" autocomplete="new-password"></div><p class="help endpoint">Register this callback, replacing CONNECTION-NAME with the name above:<br><code>{{.BaseURL}}/connections/CONNECTION-NAME/callback</code></p></details></div>
</div><p class="note">No tools are enabled when you add a server. Adding a connection or saving policies cancels queued requests; running calls must finish first.</p><div class="actions"><button class="primary">Add server</button><a class="button" href="/connections">Cancel</a></div></form></div>
{{else if .PolicyProposal}}
<div class="permissions"><a href="/connections">← Connections</a><h1>Review policy proposal</h1>
<p class="note">An agent proposed these changes. Nothing has been applied. Only you can apply or discard this entire batch. Tool names are not safety classifications.</p>
{{if .Proposal.Identity.UserID}}<p>Verified Amp user: <code>{{.Proposal.Identity.UserID}}</code>{{if .Proposal.Identity.WorkspaceID}}<br>Workspace: <code>{{.Proposal.Identity.WorkspaceID}}</code>{{end}}{{if .Proposal.Identity.ProjectID}}<br>Project: <code>{{.Proposal.Identity.ProjectID}}</code>{{end}}<br>Thread: <a href="https://ampcode.com/threads/{{.Proposal.Identity.ThreadID}}">{{.Proposal.Identity.ThreadID}}</a></p>{{else}}<p>Authenticated bearer agent. No verified Amp user, workspace, project or thread identity.</p>{{end}}
<p class="help">Expires {{.Proposal.Expires.UTC.Format "15:04:05 UTC"}}. Any catalogue change invalidates this proposal. A restart also discards it.</p>
{{range .Connections}}<section class="card"><h2>{{.ID}}</h2><p>Thread access: <strong>{{if .BeforePrivate}}Private solo threads only{{else}}Any owner thread{{end}} → {{if .AfterPrivate}}Private solo threads only{{else}}Any owner thread{{end}}</strong></p><p>Connection default: <strong>{{.Before}} → {{.After}}</strong></p>
<p class="help">All saved tools shown below. Unspecified exceptions are preserved. “Use default” follows the connection default, including future tools.</p>
<div class="scroll"><table><thead><tr><th>Tool</th><th>Exception before → after</th><th>Effective before → after</th></tr></thead><tbody>
{{range .Rows}}<tr><td><code>{{.ID}}</code></td><td>{{.Before}} → {{.After}}</td><td><strong>{{.BeforeEffective}} → {{.AfterEffective}}</strong>{{if and (eq .Before .After) (eq .BeforeEffective .AfterEffective)}} <small>(unchanged)</small>{{end}}</td></tr>{{end}}
</tbody></table></div></section>{{end}}
<p class="help">Applying cancels queued requests. Running calls must finish first. This applies the stored proposal, not editable form values.</p>
<div class="actions"><form method="post" action="/policy-proposals/{{.Ticket}}/apply"><button class="primary">Apply proposed changes</button></form><form method="post" action="/policy-proposals/{{.Ticket}}/discard"><button>Discard proposal</button></form></div></div>
{{else if .ConnectionSettings}}
<div class="permissions"><a href="/connections">← Connections</a><div class="connection-heading"><h1>{{.Connection.ID}}</h1></div><p class="sub">{{.Connection.Account}} · configured account label</p>
<nav class="tabs" aria-label="Connection pages"><a href="/connections/{{.Connection.ID}}/tools">Tools &amp; permissions</a><a href="/connections/{{.Connection.ID}}/settings" aria-current="page">Settings</a></nav>
<section class="card"><h2>Connection settings</h2><dl><dt>Server URL</dt><dd>{{.Connection.URL}}</dd><dt>Account label</dt><dd>{{.Connection.Account}}</dd></dl>{{template "connection-health" .Connection}}
{{if .Connection.OAuth}}<h2>OAuth</h2><dl><dt>Authorization server</dt><dd>{{.Connection.AuthURL}}</dd><dt>Requested scopes</dt><dd><code>{{.Connection.Scopes}}</code></dd></dl>{{end}}<p class="help">Credentials are never displayed. Testing or reconnecting does not change tool permissions.</p></section></div>
{{else if .ToolReview}}
<div class="permissions"><a href="/connections">← Connections</a>
<div class="connection-heading"><h1>{{.Connection.ID}}</h1></div>
<p class="sub endpoint">{{.Connection.URL}}</p>
<nav class="tabs" aria-label="Connection pages"><a href="/connections/{{.Connection.ID}}/tools" aria-current="page">Tools &amp; permissions</a><a href="/connections/{{.Connection.ID}}/settings">Settings</a></nav>
{{template "connection-health" .Connection}}
{{if .Error}}<p class="error" role="alert">{{.Error}}</p>{{end}}{{if .Saved}}<p class="success" role="status">Policies saved. Enabled tools are available to agents now.</p>{{end}}
<form id="refresh-tools" method="post" action="/connections/{{.Connection.ID}}/discover"></form>
{{if .Ticket}}
<form id="policies" method="post" action="/connections/{{.Connection.ID}}/tools"><input type="hidden" name="ticket" value="{{.Ticket}}">
{{if .WorkloadIdentity}}<fieldset class="connection-access"><legend>Thread access</legend><label><input type="checkbox" name="private_connection" value="true" {{if .Draft.Private}}checked{{end}}><span><strong>Private connection</strong><small>Only expose this connection in your private, non-multiplayer threads where no non-owner can influence the call.</small></span></label></fieldset>{{end}}
<fieldset class="permission-default"><legend>Default permission for tools</legend><p class="help">Applies to tools without an exception.</p>
<div class="default-options"><label><input type="radio" name="default_policy" value="deny" {{if eq .Draft.Default "deny"}}checked{{end}}><span>Block</span></label><label><input type="radio" name="default_policy" value="require_approval" {{if eq .Draft.Default "require_approval"}}checked{{end}}><span>Require approval</span></label><label><input type="radio" name="default_policy" value="allow" {{if eq .Draft.Default "allow"}}checked{{end}}><span>Allow</span></label></div>
<p id="default-warning" class="default-warning" {{if ne .Draft.Default "allow"}}hidden{{end}}>Allow permits calls without approval for tools using the connection default. New tools get explicit reviewable policies. Tool names and read-only hints are not a safety guarantee.</p></fieldset>
<p class="note">Changed blocked tools stay blocked. Other changed tools require approval again.</p>
{{if .Draft.Removed}}<details><summary>Removed tools</summary><ul>{{range .Draft.Removed}}<li><code>{{.}}</code></li>{{end}}</ul></details>{{end}}
<div id="exceptions-card" class="card exceptions-card"><div class="exceptions-heading"><h2 id="tools-heading">Tools</h2><div class="refresh-tools"><button type="submit" formaction="/connections/{{.Connection.ID}}/discover">Refresh tools</button>{{if .JevAvailable}}<details class="refresh-options" name="policy-explanation"><summary aria-label="Refresh options">⋯</summary><div class="suggestion-popover"><button type="submit" name="skip_jev" value="true" formaction="/connections/{{.Connection.ID}}/discover">Refresh without Jev</button><p class="help">Keep tool metadata here. New tools require approval.</p></div></details>{{end}}{{if or .Draft.Changes .Draft.Removed}}<p class="help">{{.Added}} new · {{.Changed}} changed · {{len .Draft.Removed}} removed<br>Preview only · save to apply</p>{{end}}</div></div>
<p class="help suggestion-disclosure">{{if .JevAvailable}}Jev classifies new tools via TypeSafe using their names, descriptions and schemas.{{else}}Automatic suggestions unavailable: TYPESAFE_API_KEY is not set. New tools require approval unless blocked.{{end}}</p>
<div class="exception-search" id="exception-search" hidden><label class="visually-hidden" for="tool-search">Search tools</label><input type="search" id="tool-search" placeholder="Search tools…"><button type="button" id="add-exception">Add exception</button></div>
<div id="bulk-actions" class="bulk-actions" hidden><span id="selection-count">0 selected</span><button type="button" data-policy="allow">Allow</button><button type="button" data-policy="require_approval">Require approval</button><button type="button" data-policy="deny" class="danger">Block</button><button type="button" data-policy="inherit">Use default</button><button type="button" class="text-button" id="clear-selection">Clear</button></div>
<div class="policy-columns"><input id="select-visible" class="tool-select" type="checkbox" aria-label="Select visible tools"><span>Tool</span><span class="permission-column">Permission</span><span></span></div>
{{range $i,$row := .Rows}}<div class="policy-row" data-change="{{$row.Change}}"><input type="checkbox" class="tool-select" aria-label="Select {{$row.Tool.ID}}"><details><summary>{{$row.Tool.Name}} {{if $row.Change}}<span class="badge">{{$row.Change}}</span>{{end}}</summary><p><code>{{$row.Tool.ID}}</code></p><p>{{$row.Tool.Description}}</p><p class="help">Provider description · not a safety guarantee</p><pre>{{$row.Schema}}</pre></details><div class="policy-choice"><label class="visually-hidden" for="policy-{{$i}}">Permission for {{$row.Tool.Name}}</label><select class="tool-policy" id="policy-{{$i}}" name="policy_{{$i}}"><option value="inherit" {{if eq $row.Tool.Policy ""}}selected{{end}}>Use connection default</option><option value="deny" {{if eq $row.Tool.Policy "deny"}}selected{{end}}>Block</option><option value="require_approval" {{if eq $row.Tool.Policy "require_approval"}}selected{{end}}>Require approval</option><option value="allow" {{if eq $row.Tool.Policy "allow"}}selected{{end}}>Allow</option></select>{{template "suggestion" $row}}</div><button type="button" class="remove-exception" aria-label="Remove exception for {{$row.Tool.Name}}" title="Use connection default" hidden><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true"><path d="M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13M10 10v7m4-7v7"/></svg></button></div>{{end}}
<p id="no-matches" class="help" hidden></p>
<div id="tool-navigation" class="tool-navigation" hidden><p id="tool-count" class="help"></p><button type="button" class="text-button" data-view="exceptions">Exceptions</button><button type="button" class="text-button" data-view="all">All tools</button><button type="button" class="text-button" data-view="changes">New or changed</button></div>
</div><div class="policy-footer"><div class="actions"><button class="primary">Save changes</button><a class="button" href="/connections/{{.Connection.ID}}/tools">Discard</a></div><p id="edit-status" role="status" class="help"></p><p class="help">Nothing changes until you save. Saving cancels queued requests; running calls must finish first. Edits expire in ten minutes.</p></div></form>
<script>
(() => {
 const form = document.getElementById('policies');
 const rows = Array.from(form.querySelectorAll('.policy-row'));
 const search = document.getElementById('tool-search');
 const card = document.getElementById('exceptions-card');
 const selectAll = document.getElementById('select-visible');
 const status = document.getElementById('edit-status');
 const defaults = form.querySelectorAll('input[name="default_policy"]');
 let view = 'exceptions';
 let dirty = false;
 form.querySelectorAll('.policy-suggestion, .refresh-options').forEach(explanation => explanation.addEventListener('toggle', () => {
  if (!explanation.open) return;
  explanation.classList.remove('above');
  const panel = explanation.querySelector('.suggestion-popover');
  const bounds = panel.getBoundingClientRect();
  if (bounds.bottom > innerHeight && explanation.getBoundingClientRect().top > bounds.height + 6) explanation.classList.add('above');
  panel.scrollIntoView({ block: 'nearest', inline: 'nearest' });
 }));
 form.addEventListener('keydown', event => {
  if (event.key !== 'Escape') return;
  const explanation = form.querySelector('.policy-suggestion[open], .refresh-options[open]');
  if (explanation) { explanation.open = false; explanation.querySelector('summary').focus(); }
 });
 document.addEventListener('click', event => {
  form.querySelectorAll('.policy-suggestion[open], .refresh-options[open]').forEach(explanation => {
   if (!explanation.contains(event.target)) explanation.open = false;
  });
 });
 function filter() {
  const query = search.value.toLowerCase().trim();
  const activeView = query ? 'all' : view;
  const defaultPolicy = form.querySelector('input[name="default_policy"]:checked').value;
  const defaultLabel = { deny: 'Block', require_approval: 'Require approval', allow: 'Allow' }[defaultPolicy];
  for (const row of rows) {
   const policy = row.querySelector('.tool-policy');
   policy.querySelector('option[value="inherit"]').textContent = 'Default: ' + defaultLabel;
   const exception = policy.value !== 'inherit';
   row.hidden = !row.querySelector('details').textContent.toLowerCase().includes(query) || (activeView === 'exceptions' && !exception) || (activeView === 'changes' && !row.dataset.change);
   row.querySelector('.remove-exception').hidden = !exception;
   if (row.hidden) row.querySelector('.tool-select').checked = false;
  }
  const visible = rows.filter(row => !row.hidden);
  const selected = visible.filter(row => row.querySelector('.tool-select').checked).length;
  const exceptions = rows.filter(row => row.querySelector('.tool-policy').value !== 'inherit').length;
  selectAll.checked = visible.length > 0 && selected === visible.length;
  selectAll.indeterminate = selected > 0 && selected < visible.length;
  card.classList.toggle('bulk-mode', activeView !== 'exceptions');
  document.getElementById('tools-heading').textContent = query ? 'Search results (' + visible.length + ')' : view === 'exceptions' ? 'Exceptions (' + exceptions + ')' : view === 'all' ? 'All tools (' + rows.length + ')' : 'New or changed tools';
  document.getElementById('add-exception').hidden = activeView !== 'exceptions';
  document.getElementById('bulk-actions').hidden = activeView === 'exceptions';
  document.getElementById('selection-count').textContent = selected + ' selected';
  document.querySelectorAll('[data-policy]').forEach(button => { button.disabled = selected === 0; });
  document.querySelectorAll('[data-view]').forEach(button => { button.hidden = !query && button.dataset.view === view; });
  document.getElementById('tool-count').textContent = activeView === 'exceptions' ? (rows.length - exceptions) + ' tools use the default' : visible.length + ' of ' + rows.length + ' tools shown';
  document.getElementById('no-matches').hidden = visible.length !== 0;
  document.getElementById('no-matches').textContent = rows.length === 0 ? 'No tools yet. Refresh tools to discover what this server offers.' : query ? 'No matching tools.' : view === 'exceptions' ? 'No exceptions. All tools use the connection default.' : 'No new or changed tools in this review.';
 }
 function edited() { dirty = true; status.textContent = 'Unsaved changes'; filter(); }
 function show(viewName) {
  view = viewName; search.value = '';
  rows.forEach(row => { row.querySelector('.tool-select').checked = false; });
  filter();
  search.focus();
 }
 document.getElementById('exception-search').hidden = false;
 document.getElementById('tool-navigation').hidden = false;
 search.addEventListener('input', filter);
 document.querySelectorAll('[data-view]').forEach(button => button.addEventListener('click', () => show(button.dataset.view)));
 document.getElementById('add-exception').addEventListener('click', () => { show('all'); search.focus(); status.textContent = 'Choose a tool permission to add an exception. Changes are saved together.'; });
 selectAll.addEventListener('change', () => { rows.filter(row => !row.hidden).forEach(row => { row.querySelector('.tool-select').checked = selectAll.checked; }); filter(); });
 document.getElementById('clear-selection').addEventListener('click', () => { rows.forEach(row => { row.querySelector('.tool-select').checked = false; }); filter(); });
 rows.forEach(row => {
  row.querySelector('.tool-select').addEventListener('change', filter);
  row.querySelector('.tool-policy').addEventListener('change', edited);
  row.querySelector('.remove-exception').addEventListener('click', () => {
   row.querySelector('.tool-policy').value = 'inherit'; edited();
   (row.hidden ? document.getElementById('add-exception') : row.querySelector('.tool-policy')).focus();
  });
 });
 document.querySelectorAll('[data-policy]').forEach(button => button.addEventListener('click', () => {
  const selected = rows.filter(row => !row.hidden && row.querySelector('.tool-select').checked);
  selected.forEach(row => { row.querySelector('.tool-policy').value = button.dataset.policy; });
  edited(); status.textContent = selected.length + ' tools updated. Save changes to apply.';
 }));
 defaults.forEach(input => input.addEventListener('change', () => { document.getElementById('default-warning').hidden = input.value !== 'allow'; edited(); }));
 form.querySelector('input[name="private_connection"]')?.addEventListener('change', edited);
 form.addEventListener('submit', () => { dirty = false; });
 window.addEventListener('beforeunload', event => { if (dirty) { event.preventDefault(); event.returnValue = ''; } });
 filter();
})();
</script>
{{else}}<p class="help">Open <a href="/connections/{{.Connection.ID}}/tools">saved permissions</a> to edit without fetching the provider.</p><button form="refresh-tools">Refresh tools</button>{{end}}</div>
{{else}}
{{if .Operation}}{{with .Operation}}
<section class="operation">
{{if eq .Status "pending"}}<a href="/operations">← Approvals</a>{{else}}<a href="/audit">← Audit</a>{{end}}<div class="heading"><h1>{{$.Title}}</h1>{{if eq .Status "pending"}}<span class="badge {{.Status}}" role="status">{{.Status}}</span>{{end}}</div>
<p class="sub"><code>{{.Tool}}</code> · {{.Account}} <small>(configured account label)</small></p>
{{if .AmpThreadID}}<p class="attribution"><a href="https://ampcode.com/threads/{{.AmpThreadID}}">Open Amp thread ↗</a> · Amp identity verified. Not human approval or model attestation.</p>{{end}}
{{if eq .Status "pending"}}<div class="card"><h2>Review this request</h2><p>Account: <strong>{{.Account}}</strong> (configured label) · Connection: <code>{{.Connection}}</code></p>
{{if .AmpThreadID}}<div class="amp-context"><dl><dt>Workspace</dt><dd>{{if .AmpWorkspaceID}}<code>{{.AmpWorkspaceID}}</code>{{else}}Not provided by Amp{{end}}</dd><dt>Project</dt><dd>{{if .AmpProjectID}}<code>{{.AmpProjectID}}</code>{{else}}No project{{end}}</dd><dt>Thread</dt><dd><a href="https://ampcode.com/threads/{{.AmpThreadID}}">{{.AmpThreadID}}</a></dd></dl></div>{{end}}
<h3>Exact arguments</h3><pre>{{$.Arguments}}</pre><p class="note">Approve only if the account, tool and arguments are correct. This is not an effect preview.</p>
<div class="actions approval-actions"><form class="approval-form" method="post" action="/operations/{{.ID}}/approve">{{if and .AmpUserID .AmpThreadID}}<div class="remember-approval"><label class="remember-toggle"><input type="checkbox" name="remember" value="on" disabled><span><strong>Remember this approval</strong><small>Allow matching calls without asking again.</small></span></label><noscript><p class="help">Enable JavaScript to save an approval. You can still approve this request once.</p></noscript><div class="remember-options">
<details><summary><span class="breadth-summary">Same tool + same arguments</span> <span aria-hidden="true">·</span> <span class="change">Change</span></summary><label for="approval-breadth">Calls that can use this approval</label><select id="approval-breadth" name="breadth"><option value="exact">Same tool + same arguments</option><option value="tool">Same tool + any arguments</option><option value="connection">Any tool on this connection</option></select></details>
<details><summary><span class="scope-summary">This thread</span> <span aria-hidden="true">·</span> <span class="change">Change</span></summary><label for="approval-scope">Amp context</label><select id="approval-scope" name="scope"><option value="thread">This thread</option>{{if .AmpProjectID}}<option value="project">This project</option>{{end}}</select></details>
<details><summary><span class="expiry-summary">Until revoked</span> <span aria-hidden="true">·</span> <span class="change">Add expiry</span></summary><label for="approval-expiry">Expiry</label><select id="approval-expiry" name="expiry"><option value="never">Until revoked</option><option value="1h">In 1 hour</option><option value="24h">In 24 hours</option></select></details>
<p class="remember-warning" role="status">Identical calls may run again without asking. Configuration changes require approval again.</p><p class="help">Revoke saved approvals under <a href="/approval-grants">Standing approvals</a>. Expiry or revocation stops queued calls, not this request or calls already running.</p></div></div>{{end}}<button class="primary">Approve once</button></form><form method="post" action="/operations/{{.ID}}/deny"><button class="danger">Deny</button></form></div></div>
<script>
(() => {
 const form = document.querySelector('.approval-form');
 if (!form) return;
 const remember = form.querySelector('input[name="remember"]');
 if (!remember) return;
 const button = form.querySelector('.primary');
 const breadth = form.querySelector('[name="breadth"]');
 const scope = form.querySelector('[name="scope"]');
 const expiry = form.querySelector('[name="expiry"]');
 const warning = form.querySelector('.remember-warning');
 const labels = select => select.options[select.selectedIndex].textContent;
 function update() {
  button.textContent = remember.checked ? 'Approve & remember' : 'Approve once';
  form.querySelector('.breadth-summary').textContent = labels(breadth);
  form.querySelector('.scope-summary').textContent = labels(scope);
  form.querySelector('.expiry-summary').textContent = labels(expiry);
  expiry.closest('details').querySelector('.change').textContent = expiry.value === 'never' ? 'Add expiry' : 'Change';
  warning.textContent = breadth.value === 'exact'
   ? 'Identical calls may run again without asking. Configuration changes require approval again.'
   : breadth.value === 'tool'
    ? 'This tool may run again with any arguments without asking. Configuration changes require approval again.'
    : 'All tools on this connection may run with any arguments without asking. Blocked tools remain blocked, and configuration changes require approval again.';
 }
 [remember, breadth, scope, expiry].forEach(control => control.addEventListener('change', update));
 remember.checked = false;
 update();
 remember.disabled = false;
})();
</script>
{{else}}{{template "operation-status" $}}<p class="help live-error" role="alert" hidden></p>{{end}}
{{if eq .Status "pending"}}{{template "operation-history" $}}{{end}}
<details class="card"><summary>Request details</summary><dl><dt>Request ID</dt><dd><code>{{.ID}}</code></dd><dt>Tool</dt><dd><code>{{.Tool}}</code></dd><dt>Connection</dt><dd>{{.Connection}}</dd></dl><h3>Exact arguments</h3><pre>{{$.Arguments}}</pre></details>
<details class="card"><summary>Identity &amp; audit</summary><dl><dt>On behalf of</dt><dd>{{.Subject}}</dd>{{if .AmpUserID}}<dt>Amp user</dt><dd><code>{{.AmpUserID}}</code> (verified)</dd>{{end}}{{if .AmpWorkspaceID}}<dt>Amp workspace</dt><dd><code>{{.AmpWorkspaceID}}</code> (verified)</dd>{{end}}{{if .AmpProjectID}}<dt>Amp project</dt><dd><code>{{.AmpProjectID}}</code> (verified)</dd>{{end}}{{if .AmpThreadID}}<dt>Amp thread</dt><dd><code>{{.AmpThreadID}}</code> (verified)</dd>{{end}}{{if .AmpThreadContext}}<dt>Thread visibility</dt><dd><code>{{.AmpThreadVisibility}}</code> (verified at submission)</dd><dt>Multiplayer</dt><dd>{{if .AmpThreadMultiplayer}}Active{{else}}Inactive{{end}} (verified at submission)</dd><dt>Non-owner influence</dt><dd>{{if .AmpThreadNonOwnerCanInfluence}}Allowed{{else}}Not allowed{{end}} (verified at submission)</dd>{{end}}{{if .Private}}<dt>Connection access</dt><dd>Private solo threads only</dd>{{end}}{{if .ApprovalScope}}<dt>Standing approval</dt><dd>This {{.ApprovalScope}} · <code>{{.ApprovalGrant}}</code></dd>{{end}}<dt>Upstream account</dt><dd>{{.Account}} <small>(configured label, not verified identity)</small></dd><dt>Calling model</dt><dd>{{if .Model}}{{.Model}} — client-reported, unverified{{else}}Unknown — not supplied by client{{end}}</dd><dt>Request digest</dt><dd><code>{{.Digest}}</code></dd></dl></details></section>{{end}}
{{else if eq .Section "integrations"}}<div class="heading"><div><h1>Integrations</h1><p class="sub">Connect native services and expose governed capabilities to agents.</p></div></div><div class="integration-grid"><section class="card integration-card"><h2>Chrome</h2><p class="sub">Share one explicitly selected browser tab with an orb. You can disconnect it at any time.</p><a class="button" href="/integrations/chrome">Set up Chrome →</a></section><section class="card integration-card"><span class="provider-mark" aria-hidden="true">F</span><h2>Fly.io {{if .FlyConfigured}}<span class="badge succeeded integration-status">Connected</span>{{end}}</h2><p class="sub">Let approved or permitted agents redeem short-lived tokens for flyctl and the Machines API.</p><div class="actions"><a class="button {{if not .FlyConfigured}}primary{{end}}" href="/integrations/fly">{{if .FlyConfigured}}Manage{{else}}Connect{{end}}</a></div></section></div>
{{else if eq .Section "connections"}}<div class="heading"><div><h1>Connections</h1><p class="sub">Manage remote MCP servers, credentials and the tools agents can use.</p></div><a class="button primary" href="/connections/new">Add MCP</a></div><div class="connection-list">{{if .Connections}}<div class="connection-columns" aria-hidden="true"><span>Connection</span><span>Status · expand for details</span><span>Actions</span></div>{{end}}{{range .Connections}}<div class="connection-row"><div class="connection-identity"><strong><a href="/connections/{{.ID}}/tools">{{.ID}}</a></strong><p class="sub">{{.Account}}</p></div>
{{template "connection-health" .}}
<a class="button" href="/connections/{{.ID}}/tools">Manage tools</a></div>{{else}}<div class="empty"><h2>No connections yet</h2><p>Add a server, connect credentials, then review its tools.</p></div>{{end}}</div>
{{else if eq .Section "audit"}}{{if .RawAudit}}<div class="heading"><h1>Raw audit events</h1><a href="/audit">← Request history</a></div><p class="sub">The latest 200 events, including configuration changes. Newest first · {{.Zone}}.</p><div id="audit-live" class="card scroll" data-live hx-get="{{.Current}}" hx-trigger="live-update from:body queue:last">{{template "audit-list" .}}</div><p class="help live-error" role="alert" hidden></p>{{else}}{{template "audit-history" .}}{{end}}
{{else}}<h1>Approvals</h1><p class="sub">Review requests and manage standing approvals.</p><nav class="tabs" aria-label="Approval views"><a href="/operations" {{if ne .Section "approval-grants"}}aria-current="page"{{end}}>Needs approval</a><a href="/approval-grants" {{if eq .Section "approval-grants"}}aria-current="page"{{end}}>Standing approvals</a></nav>
{{if eq .Section "approval-grants"}}<h2>Standing approvals</h2><p class="sub">Saved approvals allow matching calls until they expire or you revoke them. Expiry or revocation stops queued calls, but cannot cancel directly approved requests or calls already running.</p>
<div class="card scroll">{{if .ApprovalGrants}}<table class="approval-grants"><thead><tr><th>Allowed calls</th><th>Connection</th><th>Scope</th><th>Amp context</th><th>Expiry</th><th></th></tr></thead><tbody>
{{range .ApprovalGrants}}<tr><td>{{if eq .Breadth "exact"}}Same tool + same arguments<br><code>{{.Tool}}</code><br><a href="/operations/{{.OperationID}}">View exact request</a>{{else if eq .Breadth "connection"}}All tools{{else}}Tool + any arguments<br><code>{{.Tool}}</code>{{end}}</td>
<td><code>{{.Connection}}</code></td><td>{{if eq .Scope "thread"}}This thread{{else}}This project{{end}}</td>
<td>{{if eq .Scope "thread"}}<a href="https://ampcode.com/threads/{{.AmpThreadID}}">{{.AmpThreadID}}</a>{{else}}Project <code>{{.AmpProjectID}}</code>{{if .AmpWorkspaceID}}<br><small>Workspace <code>{{.AmpWorkspaceID}}</code></small>{{end}}{{end}}</td>
<td>{{if eq .Expiry "never"}}Until revoked{{else}}{{.Expires.UTC.Format "2006-01-02 15:04:05 UTC"}}{{end}}</td><td><form method="post" action="/approval-grants/{{.ID}}/revoke"><button class="danger">Revoke</button></form></td></tr>{{end}}
</tbody></table>{{else}}<p class="sub">No standing approvals. Approvals you remember during request review appear here.</p>{{end}}</div>
{{else}}<div id="operations-live" class="card scroll" data-live hx-get="/operations" hx-trigger="live-update from:body queue:last">{{template "operations-list" .}}</div><p class="help live-error" role="alert" hidden></p>{{end}}{{end}}
{{end}}<footer>Local durable audit · encrypted payloads · not independently tamper-proof · no automatic write retries</footer></main></div>
</body></html>
{{- define "audit-list"}}<table class="audit-list"><thead><tr><th>Time</th><th>Sequence</th><th>Operation</th><th>Transition</th><th>Actor</th></tr></thead><tbody>{{range .Events}}<tr><td><time datetime="{{iso .Time}}">{{stamp .Time $.Zone}}</time></td><td>{{.Sequence}}</td><td>{{if .Operation}}<a href="/operations/{{.Operation}}">{{.Operation}}</a>{{else}}—{{end}}</td><td>{{.Kind}}</td><td>{{.Actor}}</td></tr>{{else}}<tr><td colspan="5">No events yet.</td></tr>{{end}}</tbody></table>{{end}}
{{- define "operations-list"}}{{if .Operations}}<table class="operation-list"><thead><tr><th>Request</th><th>Account</th><th>Status</th><th></th></tr></thead><tbody>{{range .Operations}}<tr><td><strong>{{.Tool}}</strong><span class="request-id">{{.ID}}</span></td><td>{{.Account}}</td><td><span class="badge {{.Status}}">{{.Status}}</span></td><td><a href="/operations/{{.ID}}">Review<span class="visually-hidden"> {{.ID}}</span> →</a></td></tr>{{end}}</tbody></table><p class="help">Showing up to 100 most recent pending requests.</p>{{else}}<div class="empty"><h2>Nothing needs your approval</h2><p>New requests that require approval will appear here.</p></div>{{end}}{{end}}`))
