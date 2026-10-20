# Run a GitHub MCP server in a Fly sandbox

An operator can configure a public GitHub repository, optional install command and
stdio run command. The first connection test, tool refresh or approved call starts
a Fly Machine, clones/installs the repository and starts its stdio MCP process.
Subsequent requests reuse that same process. The VM destroys itself after ten
minutes idle; the next request starts a fresh one. Nothing executes locally in the
gateway process or on its filesystem. Existing review, approval and operation
history still apply to every call.

Each configured connection has its own serialized runner; Machines are never
pooled across connections or owners. Files and MCP session state survive between
requests within that instance, but not across idle expiry. There are no persistent
volumes, private repositories, provider credential injection or browser editor for
definitions. Internet egress is unrestricted. Tool arguments and returned content
are visible to the untrusted server; isolation does not prevent prompt injection
or govern downstream API use.

## Prepare the runner

Use a **separate app and custom private network for each installation/owner**.
Do not reuse the gateway app, its network, or an app holding other workloads or
secrets. The runtime rejects the default network and, when running on Fly, the
gateway's own app name; the operator must ensure the custom network is dedicated.
No public services or IP allocations are needed: result collection uses the Fly
management API, not a public MCP endpoint.

```sh
fly apps create YOUR-MCP-RUNNER --network YOUR-MCP-RUNNER-NETWORK
docker buildx build --platform linux/amd64 -f Dockerfile.sandbox \
  -t ghcr.io/YOUR-USER/mcp-sandbox:YOUR-VERSION --push .
fly tokens create deploy --app YOUR-MCP-RUNNER
```

Store the resulting app-scoped token as `FLY_MCP_RUNNER_TOKEN` in the gateway's
environment using your deployment secret mechanism. Never put the token in JSON,
command strings, source or screenshots. The image must be accessible to Fly;
the example assumes a public image. Configuration requires an immutable
`@sha256:` digest with 64 lowercase hex characters; mutable tags are rejected.
The image contains Node.js, Python, git, uv and the Go SDK-based runner; it is
distinct from the gateway image and must be built/published separately.

## Define a connection

Add this object to `Connections` in the startup gateway JSON, substituting a real
public GitHub repository and its commands:

```json
{
  "ID": "experiment",
  "Account": "Disposable MCP experiment",
  "Fly": {
    "App": "YOUR-MCP-RUNNER",
    "Image": "ghcr.io/YOUR-USER/mcp-sandbox@sha256:YOUR-DIGEST",
    "TokenEnv": "FLY_MCP_RUNNER_TOKEN",
    "Region": "syd",
    "MemoryMB": 512,
    "Repository": "https://github.com/OWNER/REPOSITORY",
    "Revision": "FULL-COMMIT-SHA",
    "InstallCmd": "npm ci",
    "RunCmd": "node dist/index.js"
  }
}
```

`Revision` and `InstallCmd` are optional. Without a revision, every new Machine
clones the repository's current default branch: a previously reviewed tool may
execute new code after idle expiry. Pin a commit and lock dependencies when that
is not acceptable. Even a pinned repository can download mutable dependencies
through its install/run commands.
`MemoryMB` defaults to 512 and accepts multiples of 256 up to 2048; CPU is one shared
vCPU. `RunCmd` is a shell command in the cloned repository and must speak MCP on
stdin/stdout. Install/start output is discarded rather than logged. Do not embed
credentials in either command. An MCP requiring a provider token is not supported
by this version.

Restart the gateway, open the connection's **Tools & permissions**, refresh tools,
then review and save policies. Discovery does not publish tools automatically.
Testing and discovery can start arbitrary install/start code and keep an existing
Machine warm, incurring compute charges even though no MCP tool is called. The
dashboard discloses this.

Unlike HTTP connections, Fly definitions remain startup-file managed after browser
saves. On restart, adding a Fly definition imports it; changing one resets its
non-blocked saved tools to require approval; removing one removes its tools and
policies. Existing HTTP connections remain browser-managed. A conflicting saved
HTTP/browser connection ID is rejected rather than overwritten. In a shared-host
deployment, startup connections belong to the configured primary Amp account,
not every account provisioned by login.

Unchanged connections keep their running instance through browser saves. Changed
or removed definitions stop reusing that instance; the old VM reaches its own idle
deadline. Gateway restarts do not adopt old Machines: those expire independently,
and subsequent requests start new ones.

Sandbox reviews, defaults, privacy and definition digests are stored in an optional
catalogue section that older binaries ignore, leaving supported HTTP/browser
connections available on rollback. A browser save from an older binary drops those
sandbox reviews; after upgrading again, rediscover and review sandbox tools.

## Execution and failure boundaries

- A tool call launches a Machine only after its operation has been durably claimed
  and its current policy/configuration binding checked. Discovery runs on the
  owner's explicit test/refresh action, outside the operation ledger.
- The guest's root supervisor runs clone/install/MCP commands as uid/gid 1000,
  with an explicit minimal environment. App secrets are excluded from the Fly
  process configuration; management credentials never enter the guest request.
- Configuration and the request/result mailbox are root-only. The gateway submits
  each request once through Fly exec, then polls using read-only exec commands.
  Atomic publication and unique request IDs prevent stale results from being used
  for later calls. No public bridge is needed. Requests are capped at 64 KiB,
  including their envelope, to fit within exec command arguments.
- Each MCP request has a three-minute deadline, including clone/install on first
  use; the gateway permits four minutes including boot, serialization waits and
  collection. Read-only readiness waits repeat on Fly's HTTP 408 within that
  budget; they never recreate the Machine or retry a tool. Results are capped at
  4 MiB; discovery is capped at 500 tools and 2 MiB.
- The root supervisor independently enforces request and ten-minute idle deadlines;
  exiting PID 1 with `auto_destroy` enabled tears down even escaped descendants.
  The gateway conservatively replaces instances nearing the idle deadline before
  submitting. A failed/ambiguous request force-destroys the instance using an
  independent cleanup context; it is never retried. A later explicit request can
  start another instance. MCP tool-level `isError` results do not poison the process.
- Idle cleanup does not need a working gateway. Guest/host failures can still
  defeat cleanup: monitor the dedicated app for leaked Machines. Failed image
  boots may require operator destruction. A lost response after dispatch leaves
  the operation `unknown`, not safely retryable.

The Fly VM is the host-isolation boundary; the unprivileged guest user protects
the supervisor and its deadline. This is not a production security certification.

## Cost and verification

Fly bills compute per second of runtime, including the idle tail—not per request.
At the [published rates](https://fly.io/pricing/), a 512 MiB shared-CPU Machine in
Sydney is about US$0.0065/hour, plus egress (currently US$0.04/GB in Oceania).
One hour of use plus ten minutes idle is about US$0.0076; ten MCPs used that way
once daily for 30 days cost about US$2.28 in compute. Cloning/installing also counts
as runtime. There is no provider-wide budget or admission quota. Definition changes,
gateway restarts and cleanup failures can temporarily leave extra Machines. There
are no volumes or dedicated IPs; destruction avoids stopped-rootfs storage charges.

`mise run check` covers the fake Machines API, approval path and unprivileged runner
checks. To exercise real privilege separation rather than skip those tests:

```sh
mise exec -- go test -race -c -o /tmp/mcp-sandbox.test ./internal/sandbox
sudo /tmp/mcp-sandbox.test -test.v
rm /tmp/mcp-sandbox.test
```

These use a local Git repository served over HTTP and a real stdio SDK fixture;
they do not establish Fly's actual VM isolation, image boot or auto-destroy behavior.
Validate a disposable installation on Fly before relying on it for real work.
