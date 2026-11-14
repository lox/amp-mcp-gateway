# Governed JavaScript integrations

An operator can install small JavaScript API adapters as ordinary gateway tools.
They use the existing discovery, browser review, policies, standing grants, atomic
operation claims and durable results. No MCP subprocess, container or Fly Machine
is created per integration or call. This is source-only JavaScript, not Node.js or
an arbitrary npm/MCP runner. Composition and agent-supplied code are not implemented.

## Install an adapter

The example is a [GitHub issue adapter](../examples/github-issues.js) and its
[connection manifest](../examples/github-issues.json). Use a disposable repository:

1. Replace `OWNER/SANDBOX-REPO` in **both** files. The manifest grants exact paths,
   not path templates or wildcards.
2. Add the manifest object to the primary owner's `Connections` in the gateway
   config. Supply a repository-scoped bearer token through `GITHUB_ISSUES_TOKEN`.
   Neither the token nor its value belongs in source or the manifest.
3. Make `SourceFile` readable at startup, relative to the gateway working directory
   (or use an absolute path). The standard Docker image does not copy example
   files: mount the bundle or include it in your own image. Restart the gateway.
4. Open **Connections → Tools & permissions → Refresh tools**. Inspect
   source, schemas, HTTP grants and artifact digest. Keep `createIssue` on
   `require_approval`; optionally allow `listIssues`. Save the review.
5. Discover `github-issues.listIssues` / `github-issues.createIssue` through the
   normal Amp gateway connection. Approve or deny writes in the browser; inspect
   the operation's **HTTP attempts** afterward.

Discovery and connection tests do not execute the bundle or contact the API.
The example is exercised against a fake provider; live GitHub consent and writes
have not been validated. JavaScript installations currently belong only to the
configured primary owner. There is no dashboard upload/editor or secondary-owner
installation flow. OAuth and anonymous adapters are not supported yet.

## Authoring contract

Export named `function handler(args, ctx)` functions, optionally `async`. Arguments
and return values must be JSON and satisfy the manifest's input/output schemas.
Schemas may reference only their own document. Functions, cyclic values and `undefined` are not valid final results. Bundle dependencies ahead of time:
module imports, `require`, Node globals and standard-library modules are unavailable.

The only host capability is `await ctx.http.request({method, path, query?, headers?,
body?})`, returning `{status, body}`. `body` is parsed JSON (or null for an empty
response). Requests must be sequential, with at most one outstanding request.
An HTTP error status is data: the adapter must check it. Non-JSON, oversized or
lost responses abort the operation. Only `Accept` and `Content-Type` headers are
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
before enabling this on the current 256 MiB Fly allocation. No production capacity
or escape resistance is certified by the local tests.

## Governance, outcomes and upgrades

Source is read once at startup and retained with the definition. Saving the file
later cannot change an in-flight call. Startup configuration is authoritative:
removing a static installation removes its tools; a saved catalogue cannot restore
old code. Reviewed tools pin the complete source/manifest, runtime ABI, credential
and installation generation. Changes disable execution until a new browser review;
changed permissions fall back to approval and existing blocks remain blocked.
A → B → A and removal/reinstallation do not resurrect old consent.

The worker claims the parent operation before executing JS. Before each possible
HTTP send, the broker rechecks authority and durably appends a sanitized intent.
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
