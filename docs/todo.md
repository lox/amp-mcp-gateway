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
| One MCP endpoint | Implemented | Streamable HTTP with `find_tools`, `call_tools`, `get_operation`, `propose_policy_changes`. |
| Agent policy proposals | Implemented | Immutable multi-provider batches; before/after browser review, owner-only apply/discard, ten-minute expiry and catalogue binding. No agent self-approval. |
| Jev policy suggestions | Implemented | Dashboard discovery automatically suggests policies for new tools, with inline explanations before the owner saves. Missing key or classification failure requires approval; saved choices and blocked defaults are preserved. |
| Tool discovery | Partial | Keyword search returns pinned schemas and policies; no semantic/Jev ranking. |
| Exact execution routing | Implemented | Explicit tool ID and schema validation before dispatch to a configured upstream. |
| Batch calls | Planned | Exactly one operation per `call_tools` request today. |
| Central upstream credentials | Implemented | Environment or encrypted pasted bearer tokens; encrypted OAuth grants with proactive refresh, persisted rotation/uncertain outcomes and bounded safe retries. Provider grant lifetimes still apply. |
| Provider onboarding | Partial | Browser URL/auth flow, OAuth metadata discovery, PKCE, split-origin endpoints and dynamic registration or supplied client credentials. Expiring registration secrets and client-ID metadata documents unsupported. Dropbox consent, calls and refresh still need live validation. X app-only bearer calls remain unvalidated; its documented user-context flow requires an unsupported local stdio bridge. |
| Real integrations | Partial | DeepWiki discovery verified in the demo; Buildkite reads, browser approval and denial verified in production. Live Google Sheets/Drive/Gmail metadata discovery verified; Google consent, execution and refresh still need validation. |
| Native integrations | Partial | The Integrations UI supports Fly.io, while the top-level Secrets page uses the same governed-tool machinery for generic secrets. Fly redemption locally attenuates a token to at most 15 minutes; secret redemption returns the stored value only through a caller-bound, one-use URL. Real Fly validation and additional provider-specific integrations remain. |
| Thread/project secrets | Implemented | Owners add encrypted secrets in the browser. Each secret has an approval policy; one-time and standing thread/project approvals issue five-minute, identity-bound, single-use redemption URLs without putting values in MCP results. Rotation/removal invalidates queued authority and leases. Redeemed values cannot be confined from an approved shell-capable workload. |
| Connection UI | Partial | Add server, inline and bulk MCP connection tests, last-test/refresh/expiry and actionable health, fetch/review tools, defaults and bulk exceptions. The list sorts connections needing action first and shows auth type, effective policy counts and the last ledger call outcome. No endpoint/credential editing, removal, verified account or continuous access monitoring yet; test results reset on restart. |
| Chrome integration | Partial | Manifest V3 extension reverse-connects one selected HTTP(S) tab for snapshots, screenshots and policy-controlled interaction. Gateway reconnect authority survives deploys; restarting Chrome still requires pairing because the extension credential is session-only. Multiple tabs and durable device pairing are not implemented. |
| OIDC login | Implemented | Direct Amp login verifies a user actor in the allowed workspace. Per-account encrypted OAuth token retention; live consent/refresh issuance unverified. Demo and portal workflows retained. |
| Multiple users / workloads | Partial | Bare Amp user IDs key isolated databases, providers and state. Version 0 requires the explicit lossy offline migration. No email matching, reassignment, automatic offboarding, shared connections or delegation. See the [migration contract](dev.md#amp-login-and-account-migration). |
| On-behalf-of attribution | Partial | Verified Amp subject, user, workspace, project, thread visibility and multiplayer context are stored; the bare Amp user ID selects the approval account. No delegation chain or model attestation. |
| Model provenance | Partial | Optional unverified client label; no runtime assertions or inference-proxy observations. |
| Tool policies | Implemented | Connection defaults and explicit allow / require approval / deny exceptions, with search and bulk editing. Connections can independently require an Amp-attested private, owner-only, non-multiplayer context on every discovery, call and result lookup. New tools inherit defaults after save; unknown tools cannot execute. |
| Human approval | Implemented | Exact arguments, account label, digest, once/thread/project approve scopes, deny, ten-minute pending expiry, revocation and status polling. |
| Effect previews | Planned | Exact payload only; no before/after effect or resource-state-aware approval. |
| Bounded mandates | Partial | One-hour thread/project standing grants bind verified Amp identity, tool and configuration; expiry and revocation are checked at submission and atomic claim. No resource scope, call budgets or subagent delegation. |
| Duplicate / restart safety | Implemented | Idempotency keys, atomic claims and persisted approvals; ambiguous outcomes are not retried. |
| Revocation | Partial | Token/key rotation, configuration/reconnect invalidation and explicit standing-grant revocation; no per-run stop control or Amp token introspection. |
| Tool-definition review | Partial | Refresh shows additions, changes and removals. Unchanged exceptions persist; changed allowed tools require approval and blocks persist. No automatic refresh or drift detection. |
| Audit history | Partial | Durable operation transitions and encrypted payloads; no login, discovery, malformed-call or refresh audit. |
| Execution diagnostics | Partial | Stored stage and protocol codes; fixed hints for recognized HTTP authentication errors and validated Dropbox request IDs. No arbitrary response-body capture or distributed tracing. |
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
- [ ] Test through a normal Amp remote MCP definition using Amp Workload Identity
      against Fly.
- [ ] Verify upstream-side results for allowed, approved and denied calls.
- [ ] Exercise expired/revoked tokens, refresh, approval expiry and restart.
- [ ] Add provider identity introspection or document exactly what cannot be verified.
- [ ] Record reproducible setup without credentials in source or screenshots.

## Next: replace shared client credentials

- [x] Verify Amp workload issuer and reject wrong user/audience/signature/expiry/token use.
- [x] Persist verified Amp user and thread link separately from model metadata.
- [x] Accept Amp's short-lived MCP workload tokens directly from remote definitions.
- [x] Configure Amp browser login for an explicit workspace and user actor.
- [ ] Validate a real provider call through production browser approval.
- [ ] Add general client-facing OAuth discovery/scopes if non-orb clients need it.

## Before operational use

- [x] Validate the private Fly demo, then retire its app and disposable data.
- [x] Select Fly public HTTPS with Google browser and Amp workload authentication.
- [x] Deploy the single-owner Fly app after Google registration and separate secrets are supplied.
- [ ] Test consistent backup and restore with separately protected encryption keys.
- [ ] Design credential/key rotation, session revocation and retention procedures.
- [x] Bound browser-added upstream responses and tool discovery.
- [x] Bound pending browser OIDC login states and expiry cleanup.
- [ ] Bound request rates, including unauthenticated login traffic.
- [ ] Add connection diagnostics without leaking tokens or tool payloads.
- [ ] Define complete audit coverage, then add independent archival/checkpointing.
- [x] Add repeatable CI checks and create the Buildkite pipeline.
- [x] Configure its app-scoped Fly secret and verify the first automatic deployment.
- [ ] Add endpoint/credential editing and connection removal to the browser.
- [x] Allow policy revocation without fetching the provider's tool list again.
- [ ] Test the offline version 0 to version 1 migration against a complete stopped backup before any production switch.
- [ ] Roll out Amp-only identity and validate consent, refresh issuance, restart persistence and workload routing.
- [x] Add project-name lookup and token refresh using retained per-account credentials.
- [ ] Design unlink/reassignment and explicit offboarding; workspace removal alone
      does not revoke existing sessions or linked Amp workload access.

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
