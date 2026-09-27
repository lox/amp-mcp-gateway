# Amp MCP Gateway

Managing auth for a pile of MCP servers in Amp is a pain. Amp MCP Gateway puts
them behind one connection, keeps their credentials in one place, and lets you
require approval before Amp calls particular tools. It remains compatible with
any client that supports Streamable HTTP MCP.

It's self-hosted, written in Go, and still a prototype. The demo works end to end
with fake services. DeepWiki discovery and Buildkite OAuth/discovery have been
tested; real provider execution still needs validation.

## How it works

The agent gets three execution tools and one policy proposal tool:

- `find_tools` searches the configured tools and returns their argument schemas.
  Queries allow at most 1,024 UTF-8 bytes and 32 distinct case-insensitive terms.
  Empty queries return all permitted tools; repeated terms do not change matches.
- `call_tools` submits a call to a specific tool. It either queues it, denies it,
  or returns a link for human approval.
- `get_operation` checks the status and retrieves the result.
- `propose_policy_changes` prepares an immutable batch for human browser review;
  it cannot apply policies or approve its own proposal.

For example, propose a connection default and explicit tool exceptions:

```json
{
  "changes": [{
    "connection": "notes",
    "private": true,
    "default_policy": "require_approval",
    "tools": {"notes.create": "deny"}
  }]
}
```

Use exact saved tool IDs. Omitted settings stay unchanged; policies are `allow`,
`require_approval`, or `deny`. Tool exceptions also accept `inherit` to remove an
exception. A connection can independently be `private`; all of its tools are then
discoverable and callable only when Amp's fresh per-call token verifies the owner's
thread is private, multiplayer is inactive, and no non-owner can influence it. Its
results are unavailable from shared or multiplayer contexts. This setting requires
Amp Workload Identity and is unavailable with legacy bearer authentication. No
tool-name-based safety classification is performed.
The tool returns one `review_url` and `expires_at` for up to 32 connections.
Only the signed-in owner can apply or discard the entire batch. The review shows
defaults, exceptions, and effective permissions before and after, including
unchanged tools and blocks. Changing a default also affects tools that inherit it.

Proposals expire after ten minutes, are lost on restart, and become invalid after
any catalogue change. Opening ordinary permission pages or creating another
proposal does not replace an existing proposal. At most 32 proposals may be open.
Applying uses the existing atomic catalogue save: queued calls are revoked and
running calls must finish first. Proposal, apply, and discard events are audited;
the apply event commits with the policies. Verified Amp user/thread attribution
comes only from workload authentication; bearer clients have no verified Amp
identity. These links do not authorize access without human browser login.
If prompted to sign in, reopen the review link after signing in.

![Reviewing an agent-proposed policy batch in the disposable demo](docs/images/policy-proposal.png)

For example, after finding `notes.create`, the agent calls `call_tools` with:

```json
{
  "request_id": "note-example-001",
  "calls": [
    {
      "tool_id": "notes.create",
      "arguments": {"text": "Release checklist reviewed"}
    }
  ]
}
```

That demo tool requires approval. You review the account and exact arguments in
the browser, then approve or deny. Amp-authenticated requests can be approved once,
for the current thread, or across the current project. Standing thread and project
approvals are listed under **Operations → Standing approvals** and can be revoked. The request and its
outcome are saved, so the agent can check back later without keeping the connection
open.

Finished calls show the result first, with JSON formatted for reading. Expand
**Raw MCP response** for the full response, or **Request details** and
**Identity & audit** for the arguments and attribution.

![Reviewing a demo request before approving it](docs/images/approval.png)

**Operations** opens to **Needs approval**. Switch to **All operations** to see
recent outcomes. Each request includes its history and, after a decision, a link
to the next pending request. **Audit** shows the latest 200 recorded events.

![Recent demo operations](docs/images/dashboard.png)

## Review a call inside Amp

The project plugin in [`.amp/plugins/gateway-review.ts`](.amp/plugins/gateway-review.ts)
adds `gateway_review_operation`: a read-only preview with an **Open approval page**
button. Reload plugins in Amp after checking out this branch. For personal use
outside this project, publish the same file as `gateway-review.ts` in your personal
plugins repository. A project copy takes precedence over a personal copy with the
same name; keep them in sync when publishing updates.

After `call_tools` returns a pending operation, Amp supplies its `operation_id`,
`approval_url`, tool, connection, account label and submitted arguments to the
widget. Use `Not available` for an absent account label. The preview is supplied
by Amp, **not fetched from the gateway**: verify the stored request on the approval
page. This first version pins links to `https://lox-mcp-gateway.fly.dev`; change
`gatewayOrigin` and the test URLs together for another deployment. It does not
support local demo or portal URLs unchanged.

The plugin holds no credentials and cannot submit, approve, deny or poll operations.
Cancel dismisses the preview without changing the request. After opening the page,
Amp uses the existing MCP `get_operation` tool with the same ID, up to 60 times at
five-second intervals. A timeout is not success; an unknown outcome must not be
automatically retried.

Browser launch is best effort and may target the orb rather than your browser.
Use the inline **Open approval page** link when needed. In the live fake-data test
below, the card rendered and confirmation returned, but automatic browser launch
failed; no operation was submitted or approved. An end-to-end approval test remains
to be done.

![Live Amp approval preview using fake data](docs/images/amp-gateway-review.png)

Run `mise run check-plugin` for the plugin tests (also run in Buildkite).

## Connect an MCP

Sign in to the gateway and open **Connections → Add MCP**. Enter the server URL and choose
OAuth, a bearer token, or no authentication for a public server. For OAuth, review
the authorization server and scopes, then sign in with the provider.

Use **Test connection** beside **Reconnect OAuth** to verify access without executing
tools or changing permissions. Health shows the last test, refresh and access-token
expiry. OAuth credentials refresh automatically while idle when the provider issues
a refresh token and expiry; revoked grants and uncertain refresh outcomes still need
attention. See [credential maintenance and recovery](docs/dev.md#connect-a-remote-mcp)
for retry and provider limits.

![Connection tests and automatic OAuth refresh in the disposable demo](docs/images/connection-health.png)

Open a connection's **Tools & permissions** page, click **Refresh tools**, set a connection default—usually **Require approval**—and
**Save changes**. Search finds tools across the connection, including those using
the default. Each result shows its permission; **Default: Require approval**, for
example, means it inherits the connection setting. Select multiple results to
allow or block them together, or reset them to the connection default. Mark the
connection private to restrict every tool independently of those permissions.
Nothing changes until you save. Refreshes keep unchanged permissions; changed
blocked tools remain blocked, while other changed tools go back to approval.

The connection's **Settings** page shows its endpoint, account label and OAuth settings.

![Reviewing tool permissions in the demo](docs/images/tool-review.png)

This supports remote Streamable HTTP servers on public HTTPS, not local commands.
See the [connection guide](docs/dev.md#connect-a-remote-mcp) for an example and
provider limitations.

## Connect a native integration

**Integrations** are native providers whose capabilities use the same discovery,
policy, approval and audit path as remote MCP tools. The first prototype is Fly.io.
Store one scoped Fly access token and the gateway exposes `fly.request_token`.
An approved call returns a caller-bound, single-use redemption URL—not a credential.
Redeeming that URL derives a Fly token that retains every parent restriction and
expires after at most 15 minutes.

This supports ordinary `flyctl` work that must run inside the calling orb, including
commands that need its source tree. The gateway records the request, approval and
redemption, but cannot observe individual Fly calls after issuing the short-lived
token. See the [Fly integration guide](docs/dev.md#flyio-integration) for setup and
the safe shell pattern.

## What's there today

Bearer-token and OAuth connections, token refresh, per-tool rules, browser
approvals, a reverse-connected Chrome extension for one selected tab, encrypted
storage for credentials, arguments and results, and a Fly.io short-lived
credential integration prototype.

A few limits worth knowing:

- One owner and one call per request. Search is keyword-based.
- Amp remote MCP definitions can authenticate with Amp Workload Identity; requests
  retain their verified workspace, project and thread context. Browser approvals
  use a separate OIDC login.
- Google Workspace login can require both your domain and your exact account.
  Validate the configured identity provider before relying on a deployment. The
  local demo uses a shared fixture token.
- Model names are reported by the client, not verified. Account names are labels.
- The audit log is local, not tamper-proof.
- New work pauses at 10,000 retained operations, 50,000 audit events, or 64 MiB
  of operation payload and audit field bytes. At most 16 operations can remain
  pending, ready or running. Existing work can still finish; history is retained.
- A timed-out call may have run upstream. We mark it `unknown` and don't retry it.

## Try it

The [dev guide](docs/dev.md) has setup instructions and runnable examples.
The [plan](docs/plan.md) covers what comes next; the [feature matrix and TODOs](docs/todo.md)
track what's implemented and what's still an idea.

To share a normal Chrome tab with an orb, load the unpacked extension from
`extension/`, pair it from **Integrations → Chrome** in the gateway dashboard,
and use the configured `browser.*` tools through `find_tools` and `call_tools`. See the
[Chrome extension guide](docs/dev.md#share-a-chrome-tab).
