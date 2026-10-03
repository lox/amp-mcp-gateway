package webui

// UserMenu is shared by authenticated page templates. Its argument is whether
// this deployment supports the account page; demo sessions only offer sign-out.
const UserMenu = `{{define "user-menu"}}<div class="user-menu">
<button class="user-menu-trigger" type="button" popovertarget="user-panel" aria-label="User menu" title="User menu"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><circle cx="12" cy="8" r="4"/><path d="M4 22v-3a8 8 0 0 1 16 0v3"/></svg></button>
<nav id="user-panel" class="user-panel" popover aria-label="User navigation">
{{if .}}<a href="/account">Account</a>{{end}}
<form method="post" action="/logout"><button type="submit">Sign out</button></form>
</nav></div>{{end}}`
