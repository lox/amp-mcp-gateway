# mcp-gateway

Managing auth for a pile of MCP servers is a pain. This puts them behind one
connection, keeps their credentials in one place, and lets you require approval
before an agent calls particular tools.

It's self-hosted, written in Go, and still a prototype. The demo works end to end
with fake services. We haven't validated it against real providers yet.

## How it works

The agent gets three tools:

- `find_tools` searches the configured tools and returns their argument schemas.
- `call_tools` submits a call to a specific tool. It either queues it, denies it,
  or returns a link for human approval.
- `get_operation` checks the status and retrieves the result.

For example, after finding `notes.create`, the agent calls `call_tools` with:

```json
{
  "request_id": "note-example-001",
  "calls": [
    {
      "tool_id": "notes.create",
      "arguments": {"text": "Release checklist reviewed"}
    }
  ]
}
```

That demo tool requires approval. You review the account and exact arguments in
the browser, then approve or deny. The request and its outcome are saved, so the
agent can check back later without keeping the connection open.

![Reviewing a demo request before approving it](docs/images/approval.png)

The activity page shows what ran, what was denied, and who approved it.

![Demo operations and their audit history](docs/images/dashboard.png)

## What's there today

Bearer-token and OAuth connections, token refresh, per-tool rules, browser
approvals, and encrypted storage for OAuth tokens, arguments and results.

A few limits worth knowing:

- One owner and one call per request. Search is keyword-based.
- OIDC is for browser login. MCP clients still use a shared owner token.
- Model names are reported by the client, not verified. Account names are labels.
- The audit log is local, not tamper-proof.
- A timed-out call may have run upstream. We mark it `unknown` and don't retry it.

## Try it

The [dev guide](docs/dev.md) has setup instructions and runnable examples.
The [plan](docs/plan.md) covers what comes next; the [feature matrix and TODOs](docs/todo.md)
track what's implemented and what's still an idea.
