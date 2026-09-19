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
- One Streamable HTTP MCP endpoint: `find_tools`, `call_tools`, `get_operation`.
- Search a manually pinned catalogue; do not expose newly discovered tools silently.
- Single owner, one process, one SQLite disk. Persist intent before dispatch.
- Google Workspace OIDC for the browser; Amp workload OIDC for orb MCP calls.
  Match one Google subject and one Amp user. Keep the signed thread link; neither
  model metadata nor account labels are authentication evidence. Demo retains bearer auth.
- Encrypt credentials and payloads. Transactional local audit is not tamper-proof.
- Approve the immutable stored request once, recheck its configuration binding,
  and never automatically retry an ambiguous dispatch.
- Keep discovery local. Evaluate Jev only if it measurably improves tool selection
  and its data-handling requirements are acceptable.

## Delivery slices

### 1. Local vertical slice — complete

Discover a tool, submit a read or approval-required write, approve or deny it in
the browser, and inspect the durable outcome. Use disposable bearer/OAuth fixtures
so development needs no real credentials.

Evidence: SDK integration tests, race tests, browser approval/denial checks,
OAuth refresh and restart persistence. The README screenshots show this slice.
The fixture write echoes text; it is not a real notes integration.

### 2. One real integration and normal-client usage — next

Choose one provider with both a low-risk read and a reversible write in a disposable
account or repository. Start with explicit endpoint/client registration and pinned
schemas rather than a general onboarding framework.

Acceptance:

- Connect from an Amp orb through the token-minting `amp-mcp` stdio bridge.
- Link the provider, discover the read and write, and execute both through the gateway.
- Verify the provider-side effect, not just the gateway's success status.
- Exercise deny, expired approval, refresh, revoked grant and process restart.
- Record which upstream account actually receives the action. Keep configured labels
  visibly unverified until provider-specific identity introspection exists.

Provider and test account must be selected before implementation. GitHub in a
disposable private repository is a suggested starting point, subject to its current
MCP authentication support. Do not authorize or change a real account as part of
documentation/setup work.

### 3. Amp workload identity — implemented; Google setup pending

Amp tokens authenticate `/mcp` against a fixed issuer, gateway-origin audience and
one allowed user ID. A signed thread ID is required, stored and linked from the
approval page. All that user's threads share authority; there is no delegation tree.
The local bridge mints a token for each HTTP request, without storing long-lived
gateway credentials. Google browser login requires both the exact subject and
`hd=ljd.cc`. Both identities map explicitly to one configured owner.

Evidence: signed-token rejection tests, MCP identity persistence and idempotency
tests, bridge forwarding/renewal tests, Google domain fixture tests, and a live Amp
issuer check using this orb. Google credentials and real browser login are still
needed. General MCP OAuth discovery, scopes, per-thread grants and revocation are
deferred; the current bridge is specific to Amp orbs.

### 4. Authority, account identity and meaningful approvals

Separate authorizing subject, executing workload, client, agent run and approver.
Add verified upstream identity where supported. Keep model provenance graded as
unknown, client-reported or runtime-observed rather than claiming model attestation.

Add one tool-specific effect preview and one bounded mandate with enforceable
resource/action/expiry/count limits. Stale resource state requires fresh review;
subagents may only narrow authority. Do not build a general policy language first.

Acceptance: negative tests demonstrate that changed arguments, resource state,
account or delegation cannot reuse an approval or exceed a mandate.

### 5. Single-owner Fly deployment — awaiting Google registration

The demo app has been destroyed. `lox-mcp-gateway` is reserved; configuration now
targets public Fly HTTPS, one Machine and volume, separate environment secrets,
Google login and Amp workload authentication. Start with an empty tool catalogue.
The [dev guide](dev.md#fly-amp-clients-and-google-browser-login) covers registration
and deployment. No Machine is running until Google credentials are supplied.
Tailscale is optional additional network protection, not authentication.

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
