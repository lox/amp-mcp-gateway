# Amp MCP Gateway

Amp MCP Gateway puts remote MCP servers and native integrations behind one
Streamable HTTP MCP connection. It centralizes credentials, lets owners review
or deny consequential tool calls in a browser, and keeps a durable history of
requests and outcomes.

The gateway exposes four tools to agents:

- `find_tools` searches the owner's reviewed tool catalogue.
- `call_tools` submits one tool call for execution or human approval.
- `get_operation` returns the persisted status and result.
- `propose_policy_changes` prepares permission changes for human review.

It is self-hosted and supports isolated owner accounts on one shared host. Each
account has separate connections, credentials, approvals, and history. Remote
MCP connections can use OAuth or bearer tokens; native integrations and the
Chrome extension use the same policy, approval, and audit path.

This is a prototype, not a production security certification. In particular,
an upstream timeout may mean a write succeeded: the gateway records the outcome
as `unknown` and never retries it automatically.

## Get started

The disposable demo requires Linux or macOS, Git, and curl. It installs pinned
Go and Node.js toolchains through mise and uses only fake local services.

```sh
git clone https://github.com/lox/amp-mcp-gateway.git
cd amp-mcp-gateway
.agents/setup
export PATH="$HOME/.local/bin:$PATH"
mise run check
mise run dev
```

Open <http://localhost:8080>, sign in with `demo-only`, and select **Connect /
reconnect OAuth**. You can then discover the included tools, run the allowed echo
tool, and review a notes request that requires approval. Nothing in the demo
connects to a real account.

To connect another MCP client, configure a Streamable HTTP connection to `/mcp`.
Production deployments use [Amp Workload Identity](https://ampcode.com/docs/customize/mcp#amp-workload-identity);
the demo client reads its disposable bearer token from `.local/` without printing
it.

## Documentation

- [Development guide](docs/dev.md): runnable examples, remote MCP setup, native
  integrations, Chrome sharing, deployment, identity, and security boundaries.
- [Feature matrix and TODOs](docs/todo.md): implemented capabilities, known gaps,
  and future work.
- [Delivery plan](docs/plan.md): architecture decisions, sequencing, and acceptance
  criteria.

Run `mise run check` before submitting changes.
