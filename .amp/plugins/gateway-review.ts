import type { PluginAPI } from '@ampcode/plugin'

export const description = 'Shows a read-only MCP Gateway preview and opens its browser approval page. Never approves or denies a call.'

const gatewayOrigin = 'https://lox-mcp-gateway.fly.dev'

export function reviewMessage(input: Record<string, unknown>) {
  if (typeof input.operation_id !== 'string' || !/^[A-Za-z0-9_-]{8,100}$/.test(input.operation_id)) {
    throw new Error('Expected a gateway operation ID.')
  }
  const url = `${gatewayOrigin}/operations/${input.operation_id}`
  if (input.approval_url !== url) throw new Error('Approval URL must match this operation on the configured gateway.')
  if (typeof input.tool !== 'string' || typeof input.connection !== 'string' || typeof input.account !== 'string'
    || !input.arguments || typeof input.arguments !== 'object' || Array.isArray(input.arguments)) {
    throw new Error('Expected tool, connection, account and an arguments object.')
  }
  // JSON quoting keeps line breaks in metadata visible; a longer fence prevents
  // tool arguments from escaping into active Markdown links or images.
  const metadata = JSON.stringify({ Tool: input.tool, Connection: input.connection, Account: input.account }, null, 2)
  const args = JSON.stringify(input.arguments, null, 2)
  const longest = Math.max(2, ...((metadata + args).match(/`+/g) ?? []).map(run => run.length))
  const fence = '`'.repeat(longest + 1)
  return {
    url,
    message: [
      '**Preview supplied by Amp. Verify the stored request on the gateway before approving.**',
      `${fence}json\n${metadata}\n${fence}`,
      '**Arguments**',
      `${fence}json\n${args}\n${fence}`,
      `Operation: ${input.operation_id}`,
      `[Open approval page](${url})`,
      'Opening the page does not execute the call. Approve or deny in the gateway.',
      'Cancel only dismisses this preview; it does not deny the operation.',
    ].join('\n\n'),
  }
}

export default function (amp: PluginAPI) {
  amp.registerTool({
    name: 'gateway_review_operation',
    title: 'Review gateway call',
    description: 'Show a read-only preview for a pending MCP Gateway operation and open its approval page. This tool does NOT approve, deny, submit, or poll. Supply the returned operation ID and approval_url plus a preview of the submitted call; do not invent account labels (use "Not available" when absent). After opened, poll the existing MCP get_operation with the SAME ID until terminal status or a bounded timeout. Never resubmit. If dismissed, stop unless the user asks otherwise.',
    inputSchema: {
      type: 'object',
      properties: {
        operation_id: { type: 'string' },
        approval_url: { type: 'string' },
        tool: { type: 'string' },
        connection: { type: 'string' },
        account: { type: 'string' },
        arguments: { type: 'object', additionalProperties: true },
      },
      required: ['operation_id', 'approval_url', 'tool', 'connection', 'account', 'arguments'],
      additionalProperties: false,
    },
    async execute(input, ctx) {
      const { url, message } = reviewMessage(input)
      const open = await ctx.ui.confirm({
        title: 'Review MCP tool call',
        message,
        confirmButtonText: 'Open approval page',
        requireHuman: true,
      })
      if (!open) return JSON.stringify({ status: 'dismissed', operation_id: input.operation_id, decisionSubmitted: false })
      // In remote executors system.open may target the remote machine. Keep the
      // human-clickable URL in both the dialog and result as the reliable fallback.
      let launchRequested = false
      try {
        await amp.system.open(url)
        launchRequested = true
      } catch {
        // Opening a browser is best effort; never imply that approval occurred.
      }
      return JSON.stringify({
        status: 'awaiting_browser_decision',
        operation_id: input.operation_id,
        approval_url: url,
        launchRequested,
        decisionSubmitted: false,
        next: 'Show the approval link to the user; the browser may have opened on the remote executor. Poll get_operation with this same ID, at most 60 times at 5-second intervals. Stop on succeeded, failed, denied, expired, or unknown. On unknown do not retry. On timeout report the last observed status and the link; never claim success or resubmit.',
      })
    },
  })
}
