# Governed JavaScript integrations

Owners can upload small JavaScript API adapters as ordinary gateway tools.
They use the existing discovery, browser review, policies, standing grants, atomic
operation claims and durable results. No MCP subprocess, container or Fly Machine
is created per integration or call. This is source-only JavaScript, not Node.js or
an arbitrary npm/MCP runner. Composition and agent-supplied code are not implemented.

## Upload an adapter

Open **Integrations → JavaScript → Add JavaScript integration**. Choose one JSON file and enter its bearer
token separately. The file contains only `ID`, optional `Account` label, `Origin`,
`Source` and `Tools` (see the form's inline example). `Tools` use the manifest
format below. Uploads reject unknown fields, including paths, credentials,
generation IDs and policy settings. Limits are 1 MiB for the file and 256 KiB
for source. Uploading validates metadata but does not evaluate code or call the API.

The example is a [GitHub issue adapter](../examples/github-issues.js) and its
[connection manifest](../examples/github-issues.json). Use a disposable repository:

1. Replace `OWNER/SANDBOX-REPO` in **both** files. Grants are exact paths, not
   templates or wildcards. Package the source inline for browser upload:

   ```sh
   jq --rawfile source examples/github-issues.js \
     '{ID, Account, Origin: .JavaScript.Origin, Source: $source, Tools: .JavaScript.Tools}' \
     examples/github-issues.json > github-issues-upload.json
   ```

2. Upload that file and enter a repository-scoped bearer token. Never embed the
   token in source or the JSON file. Source and token are stored encrypted in
   the owner's existing database; no gateway restart is required. Other owners
   have separate catalogues and credentials.
3. On **Tools & permissions**, click **Refresh tools**. Inspect source, schemas,
   exact HTTP grants and artifact digest. New tools require approval even if the
   connection default allows future tools; existing blocks remain blocked.
   Keep `createIssue` on `require_approval`; optionally allow `listIssues`.
   Save the review to make tools available.
4. Discover `github-issues.listIssues` / `github-issues.createIssue` through the
   normal Amp gateway connection. Approve or deny writes in the browser; inspect
   the operation's **HTTP attempts** afterward.

The installed adapter appears in **Integrations → JavaScript**, with links to
manage its bundle and review its connection's tools. It also appears in the normal
**Connections** list. To update, choose **Manage** under Integrations (or follow
**Settings → Manage integration** from its connection). Upload the same ID;
leave the token blank to retain it, or enter a new token to rotate it. Every
replacement pauses old tools until you refresh tools and save a fresh review,
even for identical source or a reversion. Saving cancels queued requests and
standing approvals; running operations must finish first. Stale replacement forms
are rejected. Disable and remove use the standard connection controls.

Discovery and connection tests do not execute the bundle or contact the API.
The example is exercised against a fake provider; live GitHub consent and writes
have not been validated. There is no browser editor, agent installation API,
version-history/rollback UI, OAuth, npm or composition.

### Operator-installed alternative

The connection manifest can still be added to the primary owner's `Connections`
in startup config, with a repository-scoped `GITHUB_ISSUES_TOKEN` environment
variable. `SourceFile` is read once at startup, relative to the gateway working
directory (absolute paths also work). Mount the file or include it in a custom
image; the standard image does not copy examples. Restart, then use the same
Tools & permissions review. Static installations belong only to the primary
owner, remain controlled by startup config and cannot be replaced through upload.

## Authoring contract

Export named `function handler(args, ctx)` functions, optionally `async`. Arguments
and return values must be JSON and satisfy the manifest's input/output schemas.
Integers beyond ±(2^53−1) would round in JavaScript, so arguments containing them
fail before dispatch; declare large identifiers as strings. Schemas may reference only their own document. Functions, cyclic values and `undefined` are not valid final results. Bundle dependencies ahead of time:
module imports, `require`, Node globals and standard-library modules are unavailable.

The only host capability is `await ctx.http.request({method, path, query?, headers?,
body?})`, returning `{status, body}`. `body` is parsed JSON (or null for an empty
response). Requests must be sequential, with at most one outstanding request.
An HTTP error status is data: the adapter must check it. Non-JSON, oversized or
lost responses, and responses with integers beyond ±(2^53−1), abort the operation. Only `Accept` and `Content-Type` headers are
accepted; JSON bodies default to `application/json`.

The broker supplies the fixed HTTPS origin and bearer credential. JavaScript
cannot select another connection, owner, origin, authorization header, cookie or
proxy. Each method/path pair must match the selected tool's manifest. Query
parameters and JSON bodies are adapter-controlled: an exact path grant does not
constrain their semantics or prove a function is read-only. Do not grant broad
GraphQL, proxy or arbitrary-query endpoints unless that authority is intended.
Redirects are returned, never followed. Destinations use the gateway's public-IP
DNS/dial checks; private, loopback and link-local addresses are rejected.

## Isolation and limits

A fresh QuickJS-NG Wasm instance runs each call inside wazero in the gateway
process. Only trusted compiled engine code is cached; JS heaps and globals are
never pooled. The pinned engine is `go-quickjs-wasi-reactor v0.15.1` (embedded Wasm
SHA-256 `718f30dac3b2b42f2ab18d622f8ca11139e193e40f941519165710e4a9b168a3`),
with wazero `v1.12.0`. The runtime ABI participates in the artifact binding.

| Resource | Limit |
| --- | --- |
| Active guest instances, across accounts | 2 |
| Wasm linear memory / QuickJS heap | 64 MiB / 32 MiB per instance |
| Guest turn / cumulative guest execution | 1 second / 5 seconds |
| Invocation, including admission wait and HTTP | 30 seconds |
| Each HTTP request / requests per invocation | 10 seconds / 10 |
| Source / input / final output | 256 KiB / 64 KiB / 256 KiB |
| Request JSON envelope / HTTP response body | 64 KiB / 1 MiB |
| Aggregate request envelopes + response bodies | 4 MiB per invocation |
| Journal response envelope / aggregate plaintext | 2 MiB / 8 MiB per operation |

Parsing, evaluation, promise jobs, native builtins and serialization run under
cancellable guest-turn deadlines. Host HTTP runs outside those turns. Guests
receive no filesystem mounts, environment, stdio, sockets, host clocks or host
randomness. JavaScript's built-in Date/Math facilities are not a host capability.

This is software isolation, **not a VM or OS security boundary**. A wazero/runtime
escape or a gateway bug can compromise the shared process. Runtime pages also do
not bound total Go-process RSS: compiled code, HTTP buffers, engine allocations
and the rest of the gateway need headroom. Measure production memory/concurrency
before enabling production workloads on the configured Fly allocation. No production capacity
or escape resistance is certified by the local tests.

## Governance, outcomes and upgrades

Uploaded source and its generation are saved atomically in the owner's encrypted
catalogue, which remains authoritative across restarts. Static source is read once
at startup; saving the file later cannot change an in-flight call. Removing a
static installation from startup config removes its tools; a saved catalogue
cannot restore that old code. Startup IDs cannot overwrite owner-uploaded bundles.
Reviewed tools pin the complete source/manifest, runtime ABI, credential and
installation generation. Changes disable execution until a new browser review;
changed permissions fall back to approval and existing blocks remain blocked.
A → B → A and removal/reinstallation do not resurrect old consent.

The worker claims the parent operation before executing JS. Before each possible
HTTP send, the broker rechecks authority and durably appends a sanitized intent
with the full destination URL, effective allowed headers and body.
It adds the bearer header only afterward. Known JSON responses are encrypted in
the ordered journal; authentication and arbitrary response headers are omitted.
Request/response bodies can contain sensitive application data and remain visible
to the authenticated owner. An upstream that echoes a secret can still put it in
its response; this is not general secret redaction or information-flow control.

Local failures before any possible HTTP dispatch are `failed`. Transport loss,
timeout, an exception or invalid final output after a possible dispatch is
`unknown`, even when earlier subrequests have known responses. The journal is an
inspection aid, not a replay queue. HTTP transport retries are disabled; neither
restart nor resubmitting the same operation replays uncertain effects. A fresh
operation is new authority and can duplicate an earlier effect: inspect provider
state before intentionally trying again.

Back up the SQLite database before upgrading. Journaled operations deliberately
use an encryption binding older binaries cannot read. Do not roll back an older
binary over a database containing these operations: restore a compatible offline
backup instead, and reconcile any writes that occurred after that backup.
