# Amp MCP Gateway

Go MCP gateway for Amp with isolated owner accounts linked on one shared host. Use mise: `.agents/setup`, then `mise run check`.
Keep dependencies deliberate; use the official MCP SDK rather than handwritten JSON-RPC.

## Invariants

- Never dispatch before persisting and atomically claiming an operation.
- Approval binds the immutable stored arguments, connection, owner and policy configuration.
- Never automatically retry an ambiguous upstream write. Mark it unknown.
- No tokens in logs, source, screenshots or tool results. `.local/` is disposable demo state.
- Production UI uses OIDC; demo password login is explicitly opt-in and only for fake data.
- One process/SQLite volume only. Do not remove the file lock or add replicas.
- Linked accounts share the production hostname and Google browser authentication,
  but have identity-bound databases and derived keys. Never share a catalogue,
  credential manager, browser pairing manager or worker between accounts.
- Account links bind a verified Google subject to the stable Amp user ID returned
  by Amp's actor API. Never infer links from email or accept a manually supplied ID.

## Preview

`amp orb services ensure` starts the demo. Sign in with `demo-only` (public fixture password,
not a production credential). Two fake upstreams run on loopback port 8091.
No real user/provider credentials are needed. OAuth notes must be connected via the dashboard.
Portal URL comes from Amp, not from hardcoded configuration.
Use agent-browser and inspect login, pending approval and completed operation states.
