# Delivery plan

## Problem and direction

Agents should connect once rather than carry a separate set of credentials for
every MCP server. We want to own the gateway, inspect consequential requests before
they execute, and retain an honest record of authority and outcomes.

The gateway discovers candidate tools, but execution always selects an explicit
tool ID. It is not another agent, identity provider or general workflow engine.

The [feature matrix](todo.md#feature-matrix) is the source of truth for current
coverage. Planned features below are proposals, not shipped capabilities or dates.

## Settled first-pass choices

- Go, the official MCP Go SDK, standard HTTP handlers and server-rendered HTML.
- One Streamable HTTP MCP endpoint: `find_tools`, `call_tools`, `get_operation`,
  and `propose_policy_changes` for human-only application of policy batches.
- Search an explicitly reviewed catalogue; do not expose newly discovered tools silently.
- One owner per isolated linked account, one shared HTTPS origin, one process and
  one SQLite volume. Each user has a separate database. Persist intent before dispatch.
- Amp OIDC for shared browser authentication; the actor API verifies a user in the
  allowed workspace and resolves their existing storage identity. Amp Workload
  Identity authenticates remote MCP calls. Do not match emails or accept manual IDs.
  Keep the signed thread link; neither
  model metadata nor account labels are authentication evidence. Demo retains bearer auth.
- Encrypt credentials and payloads. Transactional local audit is not tamper-proof.
- Approve the immutable stored request once or create a revocable standing approval
  for exact arguments, a tool, or a connection in its verified Amp thread or project.
  Default to exact arguments in this thread until revoked; optionally expire after
  one or 24 hours. Keep configuration bindings and check consent again at atomic claim.
  Never automatically retry an ambiguous dispatch.
- Permit tools from private connections only when each fresh Amp token attests a
  private, non-multiplayer thread where no non-owner can influence the call.
- Keep discovery local. Evaluate Jev only if it measurably improves tool selection
  and its data-handling requirements are acceptable.

## Delivery slices

### Direct Amp login — implemented locally

Amp login replaces Google authentication and the separate linking step. Existing
Google storage identities, database paths and derived keys remain unchanged;
verified Amp actors resolve through the migrated registry before provisioning.
Access and refresh tokens are encrypted per account. Project lookup and automatic
refresh are deferred. See the [migration contract](dev.md#amp-login-and-account-migration)
for configuration, scope and rollout requirements.

Validation covers signed OAuth, explicit workspace admission, legacy migration,
encrypted token isolation, workload routing and restart persistence. Live consent
and refresh issuance still need verification. Unlink, reassignment, automatic
offboarding, shared connections and multiple replicas remain out of scope.

### 1. Local vertical slice — complete

Discover a tool, submit a read or approval-required write, approve or deny it in
the browser, and inspect the durable outcome. Use disposable bearer/OAuth fixtures
so development needs no real credentials.

Evidence: SDK integration tests, race tests, browser approval/denial checks,
OAuth refresh and restart persistence. Dashboard screenshots live under
`docs/images/`. The fixture write echoes text; it is not a real notes integration.

### 2. One real integration and normal-client usage — next

The browser can now add a public HTTPS MCP server, discover OAuth metadata,
register a client or accept existing credentials, and fetch tools for explicit
policy review. Connections and pinned tools persist in encrypted SQLite. Connection
defaults (initially require approval) cover new tools, with explicit exceptions
and bulk editing. Refresh preserves unchanged choices, sends changed allowed
tools back to approval, and keeps blocks. Saves revoke queued authority and reject
stale reviews. OAuth status distinguishes saved credentials from verified access.
Agents can propose immutable batches of defaults and exceptions with one browser
review link. Proposals expire after ten minutes and cannot apply their own changes.
Public DeepWiki discovery is verified in the demo; Buildkite OAuth and tool
discovery have been validated against a real account. Real provider execution
remains to be tested.

A native Integrations prototype now includes Fly.io. The owner can store an encrypted
scoped parent token and publish `fly.request_token` under the existing policy,
approval, standing-grant and audit pipeline. Approved calls return an authenticated,
single-use URL which derives a locally attenuated Fly token at redemption with a
maximum 15-minute lifetime. This proves native integration routing and controlled
credential leasing; it does not yet prove a real Fly token, per-command Fly auditing,
or generalize provider-specific configuration beyond Fly.

Next choose one provider with both a low-risk read and a reversible write in a
disposable account or repository. Use the browser flow and verify its real auth
behavior before adding more onboarding features. Endpoint/credential editing,
connection removal, and automatic drift detection remain follow-ups.

Acceptance:

- Connect from an Amp thread through an Amp-hosted remote MCP definition using
  Amp Workload Identity.
- Link the provider, discover the read and write, and execute both through the gateway.
- Verify the provider-side effect, not just the gateway's success status.
- Exercise deny, expired approval, refresh, revoked grant and process restart.
- Record which upstream account actually receives the action. Keep configured labels
  visibly unverified until provider-specific identity introspection exists.

Provider and test account must be selected before implementation. GitHub in a
disposable private repository is a suggested starting point, subject to its current
MCP authentication support. Do not authorize or change a real account as part of
documentation/setup work.

### 3. Amp workload identity and browser login — implemented

Amp tokens authenticate `/mcp` against a fixed issuer, shared gateway-origin audience,
`token_use=mcp` and the linked account's user ID. The signed subject and thread ID plus
optional workspace/project IDs are stored and shown during review. Pending requests
default to one-off approval. A Remember checkbox reveals the allowed calls,
thread/project context and optional expiry. Standing approvals are encrypted,
bound to identity and configuration, listed for the owner, and revocable. New grants
default to no expiry; existing one-hour grants retain their deadline. Expiry, revocation or replaced
consent denies queued grant-authorized calls at atomic claim; directly approved
and already claimed calls are unaffected. Amp-hosted remote MCP definitions send the short-lived
token directly, without a local bridge or stored gateway credential. Native credential
redemption also accepts an orb-minted `token_use=exchanged` token with the same audience
and exact thread identity because the automatic MCP token is not exposed to the shell.
Browser login uses the verified Amp actor in the configured workspace. Legacy
storage subjects remain bound to their Amp IDs. There is no delegation tree.

Evidence: signed-token rejection tests, MCP identity persistence and idempotency
tests, thread/project grant boundary and revocation tests, signed Amp login fixtures,
and a successful production call through an Amp-hosted remote MCP definition.
General client-facing MCP OAuth
discovery and scopes are deferred.

### 4. Authority, account identity and meaningful approvals

Separate authorizing subject, executing workload, client, agent run and approver.
Add verified upstream identity where supported. Keep model provenance graded as
unknown, client-reported or runtime-observed rather than claiming model attestation.

Thread/project standing approvals are the first identity-bounded mandate. Add one
tool-specific effect preview and a resource-scoped mandate with enforceable
action/expiry/count limits. Stale resource state requires fresh review; subagents
may only narrow authority. Do not build a general policy language first.

Acceptance: negative tests demonstrate that changed arguments, resource state,
account or delegation cannot reuse an approval or exceed a mandate.

### 5. Fly deployment — existing single-owner deployment

An initial single-owner deployment runs on public Fly HTTPS with one Machine and
volume, separate environment secrets, Google login configuration and Amp workload
authentication. The tool catalogue is empty; startup now permits that state without
fake connections. Live health, Amp discovery, unauthorized rejection, Google
redirect and browser-login checks passed.
The [dev guide](dev.md#fly-amp-browser-login-and-workload-clients) covers registration
and deployment. Buildkite tests changes and deploys non-PR `main` builds serially;
its app-scoped Fly secret is configured and deployment has passed. Tailscale is optional additional
network protection, not authentication.

Shared-host linking and its Amp secret are configured. The direct Amp-login
replacement is not deployed; its live OAuth flow remains unverified.

Before real operational use: test backup/restore, define key rotation and retention,
bound unauthenticated traffic and upstream responses, and add health/connection
diagnostics. Add independent audit storage and signed checkpoints when the threat
model requires evidence that the gateway operator cannot rewrite.

Acceptance: restore a disposable deployment from backup, revoke access, recover
after an interrupted write without redispatch, and verify that no backend HTTP port
is accidentally public. Public HTTPS deployment is authorized; attaching real upstream
accounts still requires selecting a provider and approving its access.

## Verification and boundaries

Every slice runs `mise run check` and `mise run build`, adds behavior-focused tests,
and exercises affected browser states. Update the matrix when scope changes.
Protocol and security tests use fixtures; passing them does not certify a real IdP
or provider. Browser screenshots illustrate behavior but do not replace assertions.

Batching, semantic discovery, safe replay, cross-tool information controls and
compensating actions remain later work. No universal undo or exactly-once upstream
execution guarantee is promised. Multiple replicas require a different coordination
design; do not remove the current file lock to enable them.
