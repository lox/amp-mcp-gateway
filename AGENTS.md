# Amp MCP Gateway

Go MCP gateway for Amp with isolated owner accounts linked on one shared host. Use mise: `.agents/setup`, then `mise run check`.
Keep dependencies deliberate; use the official MCP SDK rather than handwritten JSON-RPC.

## Documentation

- Keep documentation current when behavior, setup, constraints, or operational
  procedures change.
- Keep `README.md` short: summarize the project, provide the minimum working quick
  start, and link to the appropriate file under `docs/` for detail.
- Put each fact in one authoritative place. Link to it instead of copying it across
  the README, development guide, plan, and TODOs.
- Remove stale instructions and obsolete status notes as part of the change that
  makes them stale. Do not accumulate speculative sections, duplicate explanations,
  progress narration, or documentation for behavior that does not exist.

## Invariants

- Never dispatch before persisting and atomically claiming an operation.
- Approval binds the immutable stored arguments, connection, owner and policy configuration.
- Never automatically retry an ambiguous upstream write. Mark it unknown.
- No tokens in logs, source, screenshots or tool results. `.local/` is disposable demo state.
- Production UI uses OIDC; demo password login is explicitly opt-in and only for fake data.
- One process/SQLite volume only. Do not remove the file lock or add replicas.
- Accounts share the production hostname and Amp browser authentication,
  but have identity-bound databases and derived keys. Never share a catalogue,
  credential manager, browser pairing manager or worker between accounts.
- Login requires a user actor in the configured Amp workspace. Resolve existing
  Amp IDs through the registry before provisioning; legacy Google subjects and
  issuers remain immutable storage identities. Never infer identity from email.

## Preview

`amp orb services ensure` starts the demo. Sign in with `demo-only` (public fixture password,
not a production credential). Two fake upstreams run on loopback port 8091.
No real user/provider credentials are needed. OAuth notes must be connected via the dashboard.
Portal URL comes from Amp, not from hardcoded configuration.
Use agent-browser and inspect login, pending approval and completed operation states.
