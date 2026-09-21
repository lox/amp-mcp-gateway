# Amp MCP Gateway

Single-owner Go MCP gateway for Amp. Use mise: `.agents/setup`, then `mise run check`.
Keep dependencies deliberate; use the official MCP SDK rather than handwritten JSON-RPC.

## Invariants

- Never dispatch before persisting and atomically claiming an operation.
- Approval binds the immutable stored arguments, connection, owner and policy configuration.
- Never automatically retry an ambiguous upstream write. Mark it unknown.
- No tokens in logs, source, screenshots or tool results. `.local/` is disposable demo state.
- Production UI uses OIDC; demo password login is explicitly opt-in and only for fake data.
- One process/SQLite volume only. Do not remove the file lock or add replicas.

## Preview

`amp orb services ensure` starts the demo. Sign in with `demo-only` (public fixture password,
not a production credential). Two fake upstreams run on loopback port 8091.
No real user/provider credentials are needed. OAuth notes must be connected via the dashboard.
Portal URL comes from Amp, not from hardcoded configuration.
Use agent-browser and inspect login, pending approval and completed operation states.
