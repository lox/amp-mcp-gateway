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

## Connect a remote MCP

After signing in, click **Add MCP**. As a public read-only example:

- Connection name: `public-docs`
- MCP server URL: `https://mcp.deepwiki.com/mcp`
- Authentication: **None — public server**

Add the server and click **Refresh tools**. For this example set the connection
default to **Block**, choose **All tools**, and set `read_wiki_structure` to
**Allow**. Other tools inherit Block. Save, then check discovery:

```sh
mise exec -- go run ./cmd/demo-client -args '{"query":"public-docs"}'
```

For private providers, choose **Bearer token** or **OAuth**. OAuth discovers the
provider's metadata and tries dynamic client registration. If registration is
unavailable, expand **Use an existing OAuth client** and supply its client ID and,
if required, secret. Register the callback shown in the form with that provider.
Review the discovered authorization server and scopes before clicking
**Connect OAuth** (or **Reconnect OAuth**). After authorization, **Connected** means
credentials are saved, not that the provider has confirmed they still work. Fetch
tools to check access. An expired token without a refresh token shows **Reconnect
required**; a storage error shows **Status unavailable** rather than implying the
account is disconnected. Viewing status never refreshes credentials.
PKCE S256 is required. Providers requiring client-ID
metadata documents or custom authentication flows are not supported yet.
Discovered authorization and token endpoints must share an origin, except for
Google and Dropbox's exact published pairs, discovered from their respective issuers:

- Google: `https://accounts.google.com/o/oauth2/v2/auth` and `https://oauth2.googleapis.com/token`.
- Dropbox: `https://www.dropbox.com/oauth2/authorize` and `https://api.dropboxapi.com/oauth2/token`.

Other split-origin providers are rejected. Dynamic registration responses with
expiring client secrets are also rejected; registration renewal is not implemented.

Only public HTTPS port 443 is accepted through the browser. Private-network
addresses, redirects and proxies are blocked; DNS is checked at connection time.
Local stdio and legacy SSE servers are not supported by this flow. Static trusted
configuration can still use loopback fixtures. Discovery is limited to 500 tools,
2 MiB of tool definitions and a 30-second timeout. Schemas must be self-contained.

### Google Sheets, Drive and Gmail

Google requires an existing **Web application** OAuth client ID and secret;
it does not support dynamic client registration. You can reuse the client used
by another MCP client, keeping its existing redirect URIs. Add a gateway callback
for each connection name (replace the hostname for another deployment):

```text
https://lox-mcp-gateway.fly.dev/connections/google-sheets/callback
https://lox-mcp-gateway.fly.dev/connections/google-drive/callback
https://lox-mcp-gateway.fly.dev/connections/google-gmail/callback
```

In **Add MCP**, select OAuth and expand **Use an existing OAuth client**. Enter
the ID and secret in the gateway, not in chat or source control. Use these names
and endpoints:

| Connection name | MCP URL |
| --- | --- |
| `google-sheets` | `https://sheetsmcp.googleapis.com/mcp/v1` |
| `google-drive` | `https://drivemcp.googleapis.com/mcp/v1` |
| `google-gmail` | `https://gmailmcp.googleapis.com/mcp/v1` |

The gateway requests the scopes advertised by the provider; these can include
write access. Review them before connecting. Google authorization requests offline
access and consent so the gateway can receive a refresh token, including when
the OAuth client already has a grant. The Google account, consent-screen audience
and enabled APIs must permit the connection. See Google's
[Workspace MCP setup guide](https://developers.google.com/workspace/guides/configure-mcp-servers).

Fetch tools, keep **Require approval** as the default, and save. Test a harmless
read and browser approval/denial before disabling the original direct connection.
For Sheets, use a disposable spreadsheet. Verify refresh/reconnect before relying
on the gateway as the only route. Successful discovery alone does not prove that
Google granted access or that a tool call will succeed.

### Dropbox

In **Add MCP**, use connection name `dropbox`, URL `https://mcp.dropbox.com/mcp`
and **OAuth**. Dropbox advertises dynamic client registration; try that first.
If it rejects registration, supply an existing OAuth client with this callback:

```text
https://lox-mcp-gateway.fly.dev/connections/dropbox/callback
```

Review the advertised scopes before connecting; they include write access.
The gateway requests `token_access_type=offline` so Dropbox can issue a refresh
token. Fetch tools, keep **Require approval** as the default, and explicitly allow
only the reads you want. Verify a harmless read, approval/denial and token refresh
before removing the direct connection. Discovery support does not establish that
registration, consent or real calls have succeeded.

### Defaults, exceptions and refreshes

The suggested connection default is **Require approval**. The page starts with
**Exceptions**. **Add exception** opens the full tool list; choose a permission
for any tool you want to override. Searching from any view searches all tools in
the connection. Clearing the query restores that view. Inherited permissions show
**Default: Require approval**, **Default: Allow** or **Default: Block**, reflecting
the current draft default. Explicit exceptions keep their own permission.
Select visible tools and click a bulk permission button. Edits are staged until
**Save changes**. Filtering clears hidden selections. The remove button or the
**Default: …** option removes an exception; **Use default** does the same in bulk.
Expand a tool to read its description and schema; names and read-only annotations
never grant permissions.

![Search finds tools that inherit the connection default](images/tool-search.png)

Existing saved permissions are preserved as explicit exceptions on upgrade.
To adopt the default for them, select them in bulk and choose **Use default**
once. Changing a connection default never overrides explicit choices.
You can edit saved permissions without fetching the server, including when it is
offline. **Allow** as the default also allows new tools without approval after
you save a refresh; the form warns about this explicitly.

Fetching alone changes no live policies. Refresh keeps the default and exceptions
you are editing, including if the fetch fails; changed definitions still trigger
the approval/block rules below. You must save to publish these choices.
The preview marks new and changed tools
and lists removals. New tools inherit the default. Unchanged schemas/descriptions
keep their exceptions; changed tools require approval unless previously blocked,
in which case they remain blocked. This also applies to tools previously allowed
through the default. Removed tools disappear on save; historical operations remain.
Save publishes the reviewed snapshot, replacing that connection's tool list.
Edits expire after ten minutes and reject stale saves. Reopening saved permissions
replaces any earlier saved-permissions edit for that connection, including in
another tab; fetched-tool reviews remain independent. There is no background
refresh or drift detection; upstream behavior can still change between calls.
Editing endpoints, rotating pasted tokens, and removing connections in the UI
are follow-up work.

### Saved configuration and rollout

The first browser save copies the current connections and tools into encrypted
SQLite storage. After that, the saved catalogue replaces `Connections`, `Tools`
and `ToolDefaults` from the startup JSON, including after a deploy or restart.
Identity, listen and
deployment settings still come from the file/environment. Editing those JSON
fields will no longer change the running catalogue. Defaults are stored separately
from upstream credentials, so changing them does not discard OAuth grants.
An empty tool `Policy` means inherit; explicit policies remain exceptions.
Protect and back up the database **and its encryption key**; this includes pasted bearer tokens and OAuth
client secrets as well as grants.

Adding a connection or saving policies atomically denies **all** pending/ready
operations, recording `catalogue-changed` transitions. Running operations block
the save until they finish. There is not yet a separate audit record for each
configuration edit. Startup adds an empty `catalogue` table to existing databases;
existing grants and pinned tools remain unchanged until a browser save. Rolling
back to an older binary ignores the saved catalogue and uses file configuration,
so do not treat a binary rollback as a safe policy rollback. The previous
browser-onboarding binary rejects inherited (empty) policies at startup; after
adopting defaults, roll forward rather than rolling back to that binary.

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
unauthenticated rejection and the Google redirect are checked; the owner has
confirmed a successful real browser login.
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

Checks use the `setup-go` plugin to install the Go version from `mise.toml`, then
run formatting checks, race tests, vet and builds of both Go commands. A hosted
cache volume retains the mise toolchains and Go module/build caches; cache misses
fall back to normal downloads and compilation. The deploy job installs only
`flyctl` with the mise plugin, without rebuilding Go binaries locally; Fly's remote
Docker builder still builds the production image from source.

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
after 90 days; replace it before expiry and revoke the old token. The secret is
configured and automatic deployment has passed. The policy deliberately rejects
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

### Scoped approvals

**Approve once** remains an exact-arguments approval. For Amp-authenticated calls,
expand **Approve future calls for one hour** to also create a thread or project
grant. Both approve the current stored request once; only new submissions can use
the grant. Existing pending requests are not swept into it.

- A grant covers one exact pinned tool and connection, with **any schema-valid
  arguments**, including writes. There is no argument filter, call budget or
  effect preview. Only the signed-in browser owner can create or revoke it.
- Thread grants match the configured browser owner, verified Amp user and signed
  thread/workspace identity. Project grants match owner, Amp user and the exact
  signed `project_id` / `workspace_id` pair, allowing that user's other threads.
  An absent workspace claim must match an absent workspace claim.
- [Amp's workload OIDC documentation](https://ampcode.com/docs/orbs/handling-secrets#oidc)
  documents these signed claims (checked September 2026). The gateway extracts
  them only after signature, issuer, audience, expiry and token-use verification.
  It never accepts project IDs from tool arguments, headers or thread URLs.
  No signed project claim means no project-grant option; bearer clients have no
  scoped-grant option. Project names and project ownership are not inferred.
- Grants expire one hour after browser consent and survive an unchanged restart.
  Revoke them under **Scoped approvals** on the dashboard. Expiry/revocation is
  checked both at submission and atomic claim. A queued call whose grant becomes
  invalid is denied; already claimed calls cannot be cancelled or undone.
- Catalogue saves (including policy proposals) and OAuth reconnects permanently
  revoke **all** grants, conservatively, in the same transaction as queue
  invalidation. Normal OAuth token refresh does not revoke grants. Tool, schema,
  effective policy, connection or identity configuration changes also prevent
  fingerprint matching and dispatch. Startup-file changes use fingerprint
  matching, so restoring an identical configuration can reuse an unexpired,
  unrevoked grant. Explicit blocks always win.
- Audit events distinguish `grant-created:thread` / `grant-created:project` with
  the human actor from `grant-authorized` with the grant ID, and record revocation.
  Each scoped execution stores that ID and its own verified calling identity.
  Unknown outcomes and idempotent retries behave exactly as one-time calls do.
  Upgrading preserves existing request IDs; a retry retains the original stored
  identity and cannot add project claims or create new authority.

Grants do not isolate operation visibility: all authenticated threads of the
configured Amp user can still read the owner's operations. Existing `allow`
policies remain owner-wide. There is no delegation or general policy engine.

To exercise this against disposable fixtures, set `GATEWAY_DEMO_AMP_USER_ID` to
your immutable Amp user ID before starting the demo. It then uses real Amp OIDC
instead of its shared bearer token. Mint tokens for the demo's exact BaseURL;
browser login remains `demo-only`. Unset `GATEWAY_OIDC_SECRET` in this demo process
if inherited from production secrets. No real provider credentials are needed.

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
