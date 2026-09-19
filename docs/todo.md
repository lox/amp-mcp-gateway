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
| Central upstream credentials | Implemented | Environment bearer tokens; encrypted, persisted OAuth grants and refresh. |
| Provider onboarding | Partial | Manual endpoints and pre-registered OAuth clients; no discovery/dynamic registration. |
| Real integrations | Planned / unvalidated | Generic HTTP transport exists; end-to-end evidence uses two disposable fixtures. |
| Connection UI | Partial | Configured connections and OAuth reconnect; no verified account or health dashboard. |
| OIDC login | Partial | Browser approval login implemented with fixture tests; MCP uses one owner bearer token. |
| Multiple users / workloads | Planned | No per-agent credentials, workload grants or user isolation. |
| On-behalf-of attribution | Partial | Configured owner and approval actor; no authenticated delegation chain, client or run hierarchy. |
| Model provenance | Partial | Optional unverified client label; no runtime assertions or inference-proxy observations. |
| Tool policies | Implemented | Static allow / require approval / deny; unknown tools cannot execute. |
| Human approval | Implemented | Exact arguments, account label, digest, approve/deny, ten-minute expiry and status polling. |
| Effect previews | Planned | Exact payload only; no before/after effect or resource-state-aware approval. |
| Bounded mandates | Planned | No resource-scoped grants, call budgets, standing grants or subagent delegation. |
| Duplicate / restart safety | Implemented | Idempotency keys, atomic claims and persisted approvals; ambiguous outcomes are not retried. |
| Revocation | Partial | Token/key rotation, configuration changes and reconnect invalidation; no per-run/grant stop control. |
| Tool-definition review | Partial | Manual pinned catalogue; no drift detection or quarantine/review UI. |
| Audit history | Partial | Durable operation transitions and encrypted payloads; no login, discovery, malformed-call or refresh audit. |
| Tamper-evident archive | Planned | No independent archive, signed checkpoints, immutable retention or receipts. |
| Local / orb development | Implemented | mise, pinned Go, setup script, supervised demo, helper client, race tests and vet. |
| Tailscale / Fly deployment | Partial | Private Fly fake-service demo on one Machine and volume; access via `fly proxy`. Tailscale and real-account deployment remain unconfigured. |
| Operational hardening | Planned | Automated backup/restore, key rotation, retention, rate limits, response bounds and OpenTelemetry. |
| Safe replay | Later idea | Protected recorded operations as test fixtures, without replaying production writes. |
| Cross-tool information controls | Later idea | Restricted-data to external-destination checks; needs runtime cooperation. |
| Recovery actions | Later idea | Explicit authorized compensating operations, never universal undo. |

## Next: prove a real integration

- [ ] Select a provider and disposable account/repository; confirm its MCP auth flow.
- [ ] Pin a low-risk read and reversible write, including schemas and policy.
- [ ] Test through the normal Amp client with the current gateway bearer token.
- [ ] Verify upstream-side results for allowed, approved and denied calls.
- [ ] Exercise expired/revoked tokens, refresh, approval expiry and restart.
- [ ] Add provider identity introspection or document exactly what cannot be verified.
- [ ] Record reproducible setup without credentials in source or screenshots.

## Next: replace shared client credentials

- [ ] Confirm Amp's current OAuth interoperability requirements against MCP auth specs.
- [ ] Add client-facing OAuth backed by the existing OIDC provider.
- [ ] Test wrong issuer/audience, expiry, missing scopes, revocation and client binding.
- [ ] Persist subject and client evidence separately from reported agent/model metadata.

## Before operational use

- [x] Deploy the fake-service demo privately on Fly with a persistent volume.
- [ ] Select private ingress/host and obtain deployment approval.
- [ ] Test consistent backup and restore with separately protected encryption keys.
- [ ] Design credential/key rotation, session revocation and retention procedures.
- [ ] Bound login-state allocation, request rates and upstream response sizes.
- [ ] Add connection diagnostics without leaking tokens or tool payloads.
- [ ] Define complete audit coverage, then add independent archival/checkpointing.
- [ ] Add repeatable CI checks when the GitHub workflow and permissions are chosen.

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
