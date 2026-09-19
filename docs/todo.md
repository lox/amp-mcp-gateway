# Feature matrix and TODOs

**Implemented** means working code validated locally, not production certification.
**Partial** means the useful first-pass subset exists. **Planned** means proposed
scope, with no delivery date. **Later idea** is deliberately outside the next slices.

See the [plan](plan.md) for sequencing and acceptance criteria, and the
[dev guide](dev.md) for runnable examples. Keep status here rather than maintaining
separate copies of this matrix in each document.

## Feature matrix

| Capability | Status | Current behavior / remaining gap |
| --- | --- | --- |
| One MCP endpoint | Implemented | Streamable HTTP with `find_tools`, `call_tools`, `get_operation`. |
| Tool discovery | Partial | Keyword search returns pinned schemas and policies; no semantic/Jev ranking. |
| Exact execution routing | Implemented | Explicit tool ID and schema validation before dispatch to a configured upstream. |
| Batch calls | Planned | Exactly one operation per `call_tools` request today. |
| Central upstream credentials | Implemented | Environment or encrypted pasted bearer tokens; encrypted OAuth client credentials, grants and refresh. |
| Provider onboarding | Partial | Browser URL/auth flow, OAuth metadata discovery, PKCE and dynamic registration or supplied client credentials. No split-origin OAuth endpoints, expiring registration secrets, client-ID metadata documents or custom provider flows. |
| Real integrations | Partial | DeepWiki discovery verified in the demo; owner confirmed Buildkite OAuth and discovery. Authenticated provider execution remains unvalidated. |
| Connection UI | Partial | Add server, saved OAuth status, fetch/review tools, defaults and bulk exceptions. No endpoint/credential editing, removal, verified account or health dashboard yet. |
| OIDC login | Implemented | Owner confirmed live Google login; domain and exact-owner checks tested. Amp workload authentication verified against Fly; demo/legacy bearer retained. |
| Multiple users / workloads | Planned | No per-agent credentials, workload grants or user isolation. |
| On-behalf-of attribution | Partial | Verified Amp user and thread link stored separately from Google approval actor; no delegation chain or model attestation. |
| Model provenance | Partial | Optional unverified client label; no runtime assertions or inference-proxy observations. |
| Tool policies | Implemented | Connection defaults and explicit allow / require approval / deny exceptions, with search and bulk editing. New tools inherit defaults after save; unknown tools cannot execute. |
| Human approval | Implemented | Exact arguments, account label, digest, approve/deny, ten-minute expiry and status polling. |
| Effect previews | Planned | Exact payload only; no before/after effect or resource-state-aware approval. |
| Bounded mandates | Planned | No resource-scoped grants, call budgets, standing grants or subagent delegation. |
| Duplicate / restart safety | Implemented | Idempotency keys, atomic claims and persisted approvals; ambiguous outcomes are not retried. |
| Revocation | Partial | Token/key rotation, configuration changes and reconnect invalidation; no per-run/grant stop control. |
| Tool-definition review | Partial | Refresh shows additions, changes and removals. Unchanged exceptions persist; changed allowed tools require approval and blocks persist. No automatic refresh or drift detection. |
| Audit history | Partial | Durable operation transitions and encrypted payloads; no login, discovery, malformed-call or refresh audit. |
| Tamper-evident archive | Planned | No independent archive, signed checkpoints, immutable retention or receipts. |
| Local / orb development | Implemented | mise, pinned Go, setup script, supervised demo, helper client, race tests and vet. |
| Tailscale / Fly deployment | Partial | Fly HTTPS deployment healthy with separate secrets and browser-managed connections. Tailscale optional, unconfigured. |
| CI / automatic deployment | Implemented | Hosted Buildkite checks and serialized main deployments to Fly; app-scoped secret configured and deployment passed. |
| Operational hardening | Partial | Browser-added destinations are public HTTPS only with DNS/IP checks, bounded responses and discovery limits. Backup/restore, key rotation, retention, rate limits and OpenTelemetry remain. |
| Safe replay | Later idea | Protected recorded operations as test fixtures, without replaying production writes. |
| Cross-tool information controls | Later idea | Restricted-data to external-destination checks; needs runtime cooperation. |
| Recovery actions | Later idea | Explicit authorized compensating operations, never universal undo. |

## Next: prove a real integration

- [ ] Select a provider and disposable account/repository; confirm its MCP auth flow.
- [ ] Pin a low-risk read and reversible write, including schemas and policy.
- [ ] Test through the normal Amp client using the orb identity bridge against Fly.
- [ ] Verify upstream-side results for allowed, approved and denied calls.
- [ ] Exercise expired/revoked tokens, refresh, approval expiry and restart.
- [ ] Add provider identity introspection or document exactly what cannot be verified.
- [ ] Record reproducible setup without credentials in source or screenshots.

## Next: replace shared client credentials

- [x] Verify Amp workload issuer and reject wrong user/audience/signature/expiry/token use.
- [x] Persist verified Amp user and thread link separately from model metadata.
- [x] Add an orb MCP bridge that mints short-lived tokens per HTTP request.
- [x] Register Google web client and configure exact owner subject plus `ljd.cc` domain.
- [x] Validate live Google login.
- [ ] Validate a real provider call through production browser approval.
- [ ] Add general client-facing OAuth discovery/scopes if non-orb clients need it.

## Before operational use

- [x] Validate the private Fly demo, then retire its app and disposable data.
- [x] Select Fly public HTTPS with Google browser and Amp workload authentication.
- [x] Deploy `lox-mcp-gateway` after Google registration and separate secrets are supplied.
- [ ] Test consistent backup and restore with separately protected encryption keys.
- [ ] Design credential/key rotation, session revocation and retention procedures.
- [x] Bound browser-added upstream responses and tool discovery.
- [ ] Bound login-state allocation and request rates.
- [ ] Add connection diagnostics without leaking tokens or tool payloads.
- [ ] Define complete audit coverage, then add independent archival/checkpointing.
- [x] Add repeatable CI checks and create the Buildkite pipeline.
- [x] Configure its app-scoped Fly secret and verify the first automatic deployment.
- [ ] Add endpoint/credential editing and connection removal to the browser.
- [x] Allow policy revocation without fetching the provider's tool list again.

## Later, only with evidence of need

- [ ] Verified workload identities, delegation and revocable run grants.
- [ ] One supported effect preview and bounded mandate before a general policy system.
- [ ] Catalogue change detection and quarantine.
- [ ] Batched independent calls with per-operation outcomes, not transaction semantics.
- [ ] Evaluate local semantic search before sending private tool descriptions to Jev.
- [ ] OpenTelemetry correlation, separate from authoritative audit storage.
- [ ] Safe replay, information controls and explicit recovery actions.
- [ ] Rename the Go module from its original Amp path if external consumers need it;
      a GitHub clone already builds without fetching this repository as a dependency.
