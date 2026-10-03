package webui

// UserMenu is shared by authenticated pages with User and AccountLink fields.
const UserMenu = `{{define "user-menu"}}<div class="user-menu">
<button class="user-menu-trigger" type="button" popovertarget="user-panel" aria-label="User menu" title="{{.User.Name}}"><span class="user-avatar"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><circle cx="12" cy="8" r="4"/><path d="M4 22v-3a8 8 0 0 1 16 0v3"/></svg>{{if .User.Picture}}<img src="{{.User.Picture}}" alt="" referrerpolicy="no-referrer" onerror="this.hidden=true">{{end}}</span><span class="user-name">{{.User.Name}}</span></button>
<nav id="user-panel" class="user-panel" popover aria-label="User navigation">
<p class="user-identity">{{.User.Name}}</p>
{{if .AccountLink}}<a href="/account">Account</a>{{end}}
<form method="post" action="/logout"><button type="submit">Sign out</button></form>
</nav></div>{{end}}`
