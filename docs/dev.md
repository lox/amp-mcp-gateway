# Development

The gateway uses Go, the official MCP Go SDK, server-rendered HTML and SQLite.
There is no frontend build. Run one process against one persistent disk; the file
lock prevents competing workers.

This is a single-owner prototype. Tests use fake services, not real accounts.
See the [plan](plan.md) and [feature matrix](todo.md) for what's still missing.

## Run the demo

Prerequisites: Linux or macOS, Git and curl. Setup installs mise if absent and the
pinned Go toolchain. Run commands from the repository root.

Clone the private repository with `gh repo clone lox/mcp-gateway` and enter the
checkout. GitHub authentication is required. Then:

```sh
.agents/setup
export PATH="$HOME/.local/bin:$PATH"
mise run check
mise run dev
```

On your machine, open `http://localhost:8080`. Sign in with **demo-only** and click
**Connect / reconnect OAuth** before submitting a notes request. The fake provider
authorizes immediately. Nothing connects to a real account.

The two loopback fixtures on port 8091 are `reference.echo` (allowed) and
`notes.create` (approval required). Both return the supplied text; the notes fixture
does not maintain a separate notes database. Demo keys are generated once in
`.local/demo-secrets.json`, mode 0600, and never printed by the helper client.

From another terminal:

```sh
# Discover tools and their argument schemas.
mise exec -- go run ./cmd/demo-client -args '{"query":"notes"}'

# An allowed read goes directly into the execution queue.
mise exec -- go run ./cmd/demo-client -tool call_tools -args \
  '{"request_id":"read-example-001","calls":[{"tool_id":"reference.echo","arguments":{"text":"Hello gateway"}}]}'

# A write waits for a human. The model label is unverified client metadata.
mise exec -- go run ./cmd/demo-client -tool call_tools -args \
  '{"request_id":"note-example-001","model_reported":"example-model","calls":[{"tool_id":"notes.create","arguments":{"text":"Release checklist reviewed"}}]}'

# Open the returned approval_url, review the exact arguments, and approve or deny.
mise exec -- go run ./cmd/demo-client -tool get_operation -args \
  '{"id":"note-example-001"}'
```

Reuse a `request_id` only for the exact same request. Poll `get_operation` for the
result. Do not generate a fresh ID to retry an ambiguous write.

For a new write, the `structuredContent` field of the MCP response looks like:

```json
{
  "id": "note-example-001",
  "status": "pending",
  "approval_url": "http://localhost:8080/operations/note-example-001"
}
```

After approval, poll the same ID until it reaches `succeeded`, `failed`, `denied`,
`expired` or `unknown`. A successful result includes the upstream MCP response in
`result`; the demo's `result.structuredContent` contains the original text and
`"fixture": true`. `ready` and `running` are intermediate states. If you repeat
these examples, use new IDs only for deliberately new operations.

For another MCP client, configure a Streamable HTTP connection to `/mcp` with an
`Authorization: Bearer <gateway-token>` header. In demo mode the token is the
`GatewayToken` field in the private local secrets file. Use your client's secret
storage; do not commit it or paste it into a chat. The demo helper reads it directly.
The helper refuses HTTP redirects so credentials stay at the chosen endpoint; pass
the final MCP URL when overriding `-url`.

### Amp orbs

`.agents/setup` installs and builds the project. `.amp/services.yaml` declares the
supervised demo; `.agents/demo` passes its assigned port and public origin.

```sh
amp orb services ensure
```

Open the portal URL printed by that command. It uses the same demo-only password.
Use the helper client inside the orb; ordinary remote MCP clients cannot bypass
Amp's portal authentication using the gateway bearer token alone.

## What approval actually guarantees

The gateway persists intent before returning an operation ID. Approval changes only
the status, never the stored arguments. The worker claims that request atomically
before contacting the upstream, then records its outcome and audit event together.

- Approval expires ten minutes after submission, including time spent queued.
- Repeated or concurrent approvals cannot dispatch the same operation twice.
- Changes to the pinned tool, policy, connection, owner, issuer or static upstream
  credential invalidate queued requests when checked at execution.
- Reconnecting OAuth denies **all** pending/ready requests conservatively. It is
  refused while any request is running. Submit new requests after reconnecting.
- OAuth grants are bound to the connection configuration; changed endpoints require
  reconnecting rather than receiving an existing credential.
- Timeouts and transport errors become `unknown`; a restart also marks previously
  running operations `unknown`. No automatic dispatch retries occur.
- `unknown` does not mean failure. Inspect the upstream before deciding what to do.
  There is no exactly-once guarantee across the upstream/network boundary.

The browser shows the tool, configured upstream account label, exact arguments,
request digest and model label. It is **not** an effect preview or a guarantee that
an upstream's implementation has not changed.

## Identity and audit boundaries

“On behalf of” currently means **the configured owner whose gateway bearer token
was used**. It does not prove which person or agent possessed that token. Browser
approvals check the owner's OIDC issuer/subject, audience, signature, expiry and nonce.
Model identity is explicitly client-reported and unverified; it never grants authority.
Upstream account names are configured labels, not verified provider identities.

The ledger retains operation identity, account label, owner, model label, request
digest, encrypted arguments/results and timestamped state transitions. Audit events
are durable local records, **not independently tamper-proof evidence**: an operator
with database access can change them. Discovery, rejected malformed requests,
browser logins and token refreshes do not yet have audit events. Tool results can
contain sensitive data and are returned only to the authenticated owner/client.

## Connect real services deliberately

1. Copy `gateway.example.json` to ignored `gateway.json`. Replace every placeholder
   endpoint, account label, tool name and schema with a reviewed real configuration.
2. Configure an OIDC client with callback `https://YOUR-ORIGIN/auth/callback` and set
   the exact issuer, client ID and stable owner subject in the config.
3. Register each upstream OAuth client with callback
   `https://YOUR-ORIGIN/connections/CONNECTION-ID/callback`. Explicit authorization
   and token endpoints are required; dynamic registration/discovery is not implemented.
4. Supply these secrets through your process manager or secret store:

   | Variable | Purpose |
   | --- | --- |
   | `GATEWAY_ENCRYPTION_KEY` | Random 32 bytes, standard base64; keep a backed-up copy |
   | `GATEWAY_SESSION_KEY` | Separate random 32 bytes, standard base64 |
   | `GATEWAY_TOKEN` | Random bearer token, at least 32 characters |
   | `GATEWAY_OIDC_SECRET` | Browser OIDC client secret |
   | Connection `TokenEnv` / `ClientSecretEnv` | Upstream credentials |

5. Run `mise run build`, then `bin/mcp-gateway -config gateway.json`. Production
   mode requires an HTTPS canonical BaseURL and serves HTTP behind your trusted TLS
   proxy. The config's `Listen` takes precedence over the command-line address;
   `-base-url` is for demo mode.

Tailscale Serve is a reasonable private TLS front door for a first real deployment.
A single Fly Machine with a persistent volume is another possible host. Neither is
provisioned here. Do not expose the backend HTTP port directly, put secrets in URLs,
enable real accounts in demo mode, or add replicas.

Stop the process before taking a consistent backup of the SQLite database and keep
the encryption key separately. Losing the key loses the encrypted data. Changing
the key is not a supported rotation procedure. Rotate the bearer token to revoke
agent access; rotate the session key when changing the OIDC trust configuration or
revoking browser sessions. Sign-out clears the browser cookie but cannot revoke a
copied session cookie; sessions otherwise last 12 hours.

## Verification and limits

`mise run check` checks formatting, runs the Go suite with the race detector, and
runs `go vet`. Tests cover the MCP protocol, argument substitution, stale approvals,
concurrent approval/claim, unknown outcomes, restart recovery, ciphertext integrity,
OIDC claim rejection/PKCE/state replay, OAuth refresh rotation and CSRF.

Deferred: multiple users, per-agent identities and delegation chains, verified model
attestation, semantic/Jev discovery, batch calls, stdio/legacy-SSE upstreams,
provider-specific account introspection, signed audit exports, retention and key
rotation, policy expressions and production deployment hardening. Keep this private
and low-volume until those operational requirements are addressed.
