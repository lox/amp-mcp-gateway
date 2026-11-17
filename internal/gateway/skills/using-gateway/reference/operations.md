# Requests and durable operation results

Example: the user asks to inspect a connected service. Discover it first:

```json
{"query":"notes"}
```

Send this to `find_tools`, then use an exact returned `ID` and its current `InputSchema` in `call_tools`. For example, only if discovery returns `notes.write` with a required string `text` and the user has asked to write a note:

```json
{"request_id":"note-create-001","calls":[{"tool_id":"notes.write","arguments":{"text":"Draft release checklist"}}]}
```

`note-create-001` is an example, not a reusable ID. Store the ID you actually choose. Retrieve status and results with `get_operation`:

```json
{"id":"note-create-001"}
```

Interpret the operation's `status`:

- `pending`: approval is outstanding. Give the user `approval_url`; poll the same operation rather than resubmitting it.
- `ready` or `running`: queued or in flight. Continue checking the same operation.
- `succeeded`: inspect the upstream result and report what it actually confirms.
- `failed`, `denied` or `expired`: not success. Read the result/error and explain the issue before deciding what to do next.
- `unknown`: the upstream effect is ambiguous. Do not automatically retry. Verify the destination or ask the user.

If submission times out and `get_operation` reports the ID unavailable, recheck before deciding whether to resubmit. Any retransmission must keep the original ID and identical arguments, not create a new operation.

Policies returned by discovery are current hints, not lasting authority. The gateway rechecks configuration and approvals at execution. A policy change, disconnected integration, or private-thread restriction can make a previously discovered tool unavailable.
