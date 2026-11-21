# Browser calls and target binding

Use current schemas from `find_tools` query `browser`. Each example below is an argument object for one discovered tool inside a `call_tools` request, not a direct upstream call. Keep the request ID and obtain results through `get_operation` as described in the gateway skill.

- `browser.status`, `browser.snapshot`, `browser.screenshot`: `{}`.
- `browser.scroll`: `{"delta_y":650}` scrolls down; negative values scroll up.
- `browser.navigate`: `{"url":"https://example.com/account"}` navigates the shared tab. It can require approval; take a fresh snapshot after completion.

Example snapshot descriptors (illustrative values; copy real ones from the latest snapshot):

```json
{"document_id":"doc-example","backend_node_id":42,"expected_url":"https://example.com/account","expected_role":"textbox","expected_name":"Display name","text":"Example Name","submit":false}
```

Those are arguments for `browser.type`. For `browser.click`, supply the same five target descriptors for the intended clickable node, without `text` or `submit`. The extension checks all five before sending input. A mismatch is a safe pre-input rejection, not permission to guess a different node.

Typing replaces the field's contents. A click or `submit:true` can cause a write on the website; determine the user's intent before submitting. Owner policies, not this skill, decide which operations require browser approval.

Screenshots come back as MCP image content on the completed operation. Forward the tool's content to the agent rather than keeping only the structured operation metadata, otherwise the image can be lost.

A pre-input target rejection is `failed`. Once input might have reached the page, a disconnect or error can leave the operation `unknown`: inspect the page/destination or ask the user before retrying. A subsequent snapshot can help establish the outcome, but lack of a visible change does not prove a remote write never occurred.

If sharing ends or Chrome disconnects, use `browser.status` and ask the user to restore the shared tab. Do not silently switch to an unrelated browser session. A newly shared tab needs a fresh snapshot and new target descriptors.
