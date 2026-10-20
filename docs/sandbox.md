# Run a GitHub MCP server in a Fly sandbox

An operator can configure a public GitHub repository, optional install command and
stdio run command. Each connection test, tool refresh or approved tool call gets a
fresh Fly Machine. Nothing executes locally in the gateway process or on its
filesystem. Existing tool review, approval and durable operation history still apply.

This first version is intentionally cold and stateless: clone and install on every
request, no persistent volumes, no warm pool, no private repositories, no provider
credential injection, and no browser editor for definitions. Internet egress is
unrestricted. Tool arguments and returned content are visible to the untrusted
server; isolation does not prevent prompt injection or govern downstream API use.

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
the example assumes a public image. Use its immutable digest in configuration.
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

`Revision` and `InstallCmd` are optional. Without a revision, every request clones
the repository's current default branch: a previously reviewed tool may execute
new code. Pin a commit and lock dependencies when that is not acceptable. Even a
pinned repository can download mutable dependencies through its install/run commands.
`MemoryMB` defaults to 512 and accepts multiples of 256 up to 2048; CPU is one shared
vCPU. `RunCmd` is a shell command in the cloned repository and must speak MCP on
stdin/stdout. Install/start output is discarded rather than logged. Do not embed
credentials in either command. An MCP requiring a provider token is not supported
by this version.

Restart the gateway, open the connection's **Tools & permissions**, refresh tools,
then review and save policies. Discovery does not publish tools automatically.
Testing and discovery themselves execute arbitrary install/start code and incur
compute charges, even though no MCP tool is called. The dashboard discloses this.

Unlike HTTP connections, Fly definitions remain startup-file managed after browser
saves. On restart, adding a Fly definition imports it; changing one resets its
non-blocked saved tools to require approval; removing one removes its tools and
policies. Existing HTTP connections remain browser-managed. A conflicting saved
HTTP/browser connection ID is rejected rather than overwritten. In a shared-host
deployment, startup connections belong to the configured primary Amp account,
not every account provisioned by login.

## Execution and failure boundaries

- A tool call launches a Machine only after its operation has been durably claimed
  and its current policy/configuration binding checked. Discovery runs on the
  owner's explicit test/refresh action, outside the operation ledger.
- The guest's root supervisor runs clone/install/MCP commands as uid/gid 1000,
  with an explicit minimal environment. App secrets are excluded from the Fly
  process configuration; management credentials never enter the guest request.
- The request/result files are root-owned; results are published atomically and
  collected through read-only Fly exec commands. No public bridge is needed.
- Clone, installation and one MCP request have a combined three-minute timeout;
  the gateway permits four minutes including boot/collection. Read-only readiness
  waits repeat on Fly's HTTP 408 until that overall deadline; they never recreate
  the Machine or retry a tool. Results are capped at 4 MiB; discovery is capped at
  500 tools and 2 MiB.
- The gateway force-destroys the Machine after collection or failure, using an
  independent cleanup context. The supervisor exits after five minutes with
  `auto_destroy` enabled as fallback for gateway crashes or lost create responses.
  Guest/host failures can defeat normal cleanup: monitor the dedicated app for
  leaked Machines. Failed image boots may require operator destruction.
- Machine creation and tool execution are never automatically retried. A lost
  response after dispatch leaves the operation `unknown`, not safely retryable.
  A cleanup failure does not discard a known tool result.

The Fly VM is the host-isolation boundary; the unprivileged guest user protects
the supervisor and its deadline. This is not a production security certification.

## Cost and verification

Fly bills compute per second. At the [published rates](https://fly.io/pricing/),
a 512 MiB shared-CPU Machine in Sydney is about US$0.0065/hour, or US$0.00054
for five minutes, plus egress (currently US$0.04/GB in Oceania). Cloning/installing
counts as runtime. Many concurrent refreshes/calls can still create many Machines;
this version has no provider-wide budget or admission quota. There are no volumes
or dedicated IPs. Destroying Machines avoids ongoing stopped-rootfs storage charges.

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
