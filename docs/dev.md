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

### Fly: Amp clients and Google browser login

The disposable `lox-mcp-gateway-test` app has been destroyed. Its replacement,
`lox-mcp-gateway`, is deployed at https://lox-mcp-gateway.fly.dev with Google
credentials and owner restrictions configured. Health, authenticated Amp discovery,
unauthenticated rejection and the Google redirect are checked; the owner still
needs to complete a real browser login.
`fly.toml` uses public HTTPS, one Machine in Sydney, and `/data/gateway.db` on a
persistent volume. It does not run demo mode or fake providers.

Hosted-domain login requests `openid email`, as required by Google's OIDC flow;
authorization still uses the verified subject and `hd` claim, not the email address.
If the browser reports `authentication failed`, check Fly logs for
`browser authentication failed` and its `reason`: `token_exchange`,
`missing_id_token`, `id_token_verification`, `nonce`, `owner` or `hosted_domain`.
These logs contain fixed stage names, not tokens, provider responses or user claims.
Start a fresh login after a failure; callback state is single-use.

To reproduce the deployment:

1. Register a dedicated Google OAuth **Web application** client in the `ljd.cc`
   Workspace organisation. Use an internal consent screen where available and the
   exact redirect URI `https://lox-mcp-gateway.fly.dev/auth/callback`.
2. Copy `gateway.fly.example.json` to ignored `gateway.json`. Set the client ID and
   your stable Google `sub`, obtained from a verified Google sign-in. Keep
   `HostedDomain: "ljd.cc"`. Both domain and exact owner must match; an email suffix
   or the `hd` login hint is not authorization. There is no first-login takeover.
3. Confirm `AmpUserID` is your immutable Amp ID. All orb threads created by that
   user share the configured owner's tool authority and can read its operations.
   Project restrictions and per-thread permissions are not implemented.
4. Supply `GATEWAY_OIDC_SECRET`, `GATEWAY_ENCRYPTION_KEY` and `GATEWAY_SESSION_KEY`
   through Fly secrets. Generate the latter two independently as 32 random bytes,
   standard base64. Back up the encryption key separately from the database.
   Never put credentials in source, command arguments, logs or chat.

Import configuration without printing it or putting it into process arguments:

```sh
{ printf 'GATEWAY_CONFIG='; base64 < gateway.json | tr -d '\n'; printf '\n'; } |
  fly secrets import --stage --app lox-mcp-gateway
```

Use `fly secrets import --stage` with protected stdin for the three secret values
too. `GATEWAY_CONFIG` is decoded by Fly into `/etc/gateway.json`; the encryption
and session keys remain environment secrets, not files on the database volume.
Do not set `GATEWAY_TOKEN`: setting `AmpUserID` disables shared-token MCP access.

Once configuration is complete, create the volume and public addresses once:

```sh
fly volumes create gateway_data --region syd --size 1 --app lox-mcp-gateway
fly ips allocate-v6 --app lox-mcp-gateway
fly ips allocate-v4 --shared --app lox-mcp-gateway
fly config validate
fly deploy --remote-only --ha=false
fly checks list
```

Subsequent deployments only need the final three commands. The default rolling
strategy updates the single Machine in place and waits for health checks. Do not
add replicas or use blue-green deployment with this SQLite setup. The Machine
stays running and incurs charges, as does the volume. Buildkite deploys merges to
`main` once its deployment secret is configured, as described below.
To suspend use, disable proxy auto-start before stopping the Machine; otherwise a
request can start it again. Snapshots do not replace a tested backup/restore process.

### Buildkite CI and deployment

[lox/mcp-gateway](https://buildkite.com/lox/mcp-gateway) uses the Hosted cluster's
`default` queue. The GitHub webhook builds branches and pull requests; fork PRs
are disabled. The pipeline uploads `.buildkite/pipeline.yml` from the checkout.

Checks run setup, build both Go commands, race tests, vet and formatting checks.
Fly config validation runs in the authenticated deploy job. Only non-PR `main`
builds deploy after checks pass. Deploys
share one concurrency slot, skip superseded main commits, use Fly's rolling
strategy without HA, and check public `/healthz` afterwards. Running deployments
are not automatically cancelled by a newer commit.

**One-time credential setup:** create an app-scoped Fly deploy token on your trusted
machine, not an organisation-wide token:

```sh
fly tokens create deploy --app lox-mcp-gateway --name buildkite --expiry 2160h
```

Store it as the Buildkite secret **`MCP_GATEWAY_FLY_DEPLOY`** in the **Hosted**
cluster (`9bd6538f-929f-4d0b-a667-6931e99428ce`). Restrict its agent access with:

```yaml
- pipeline_id: "01a0b80e-45e5-412e-a3a5-87d7aac08b8c"
  build_branch: "main"
  build_source: "webhook"
```

The deploy script retrieves it only after its branch and freshness checks. Keep
the Google and encryption secrets in Fly, not Buildkite. The deploy token expires
after 90 days; replace it before expiry and revoke the old token. Automatic deploys
are not operational until this secret exists. The policy deliberately rejects
API/manual builds; use a reviewed main push for normal deployment. Pipeline and
repository administrators remain trusted to change production code.

### Connect an Amp orb

Run `mise run build`, then add a command-based MCP entry in the orb's Amp settings
(replace the path with the checkout's absolute path):

```json
{
  "amp.mcpServers": {
    "gateway": {
      "command": "/path/to/mcp-gateway/bin/amp-mcp",
      "args": ["-url", "https://lox-mcp-gateway.fly.dev/mcp"]
    }
  }
}
```

The bridge obtains a new ten-minute token via `amp orb id-token` for each HTTP
request, using the gateway origin as the audience. It never prints tokens, follows
redirects, or automatically retries ambiguous tool calls. It needs an Amp orb and
the `amp` executable on PATH; a normal laptop or server-side remote MCP definition
cannot use this bridge's orb identity. The local demo still uses `demo-client`.

The gateway verifies Amp's fixed issuer and signature, exact audience, expiry,
`token_use=exchanged`, owner user ID and a thread ID. Stored operations include
the verified Amp user and thread link; the Google subject identifies the separate
human approval. Model labels remain unverified. This is workload authentication,
not an implementation of MCP OAuth discovery or a general OAuth authorization server.

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

With Amp authentication, “on behalf of” maps the verified Amp user to the configured
Google owner. The signed thread ID supplies an audit link, not a delegation chain
or proof of human consent. Other threads belonging to that Amp user share access.
Legacy bearer mode identifies only the configured owner, not the actual holder.
Browser approvals check the owner's OIDC issuer/subject, audience, signature,
expiry, nonce and configured hosted domain.
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
   | `GATEWAY_TOKEN` | Legacy/demo only when `AmpUserID` is absent; at least 32 characters |
   | `GATEWAY_OIDC_SECRET` | Browser OIDC client secret |
   | Connection `TokenEnv` / `ClientSecretEnv` | Upstream credentials |

5. Run `mise run build`, then `bin/mcp-gateway -config gateway.json`. Production
   mode requires an HTTPS canonical BaseURL and serves HTTP behind your trusted TLS
   proxy. The config's `Listen` takes precedence over the command-line address;
   `-base-url` is for demo mode.

Fly terminates public HTTPS for the intended deployment above. Tailscale remains
an optional private front door. Do not expose the backend HTTP port directly,
put secrets in URLs, enable real accounts in demo mode, or add replicas.

Stop the process before taking a consistent backup of the SQLite database and keep
the encryption key separately. Losing the key loses the encrypted data. Changing
the key is not a supported rotation procedure. Changing `AmpUserID` revokes the old
user on restart and invalidates queued operations. Changing identity configuration
also invalidates queued approvals; drain work before updating it. There is no
per-thread revocation or token introspection. In legacy mode, rotate the bearer
token to revoke access. Rotate the session key when changing OIDC configuration or
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
rotation, policy expressions and production deployment hardening. Keep usage
owner-only and low-volume; public ingress is not a claim of production certification.
