import type { PluginAPI } from '@ampcode/plugin'

export const description = 'Links pending MCP Gateway calls to browser approval. Already-authorized calls skip the dialog.'

const gatewayOrigin = 'https://lox-mcp-gateway.fly.dev'
const statuses = ['pending', 'ready', 'running', 'succeeded', 'failed', 'denied', 'expired', 'unknown']

export default function (amp: PluginAPI) {
  amp.registerTool({
    name: 'gateway_review_operation',
    title: 'Review gateway call',
    description: 'Show a browser approval link only when the latest call_tools or get_operation response is pending. Copy its operation ID, status and approval_url; supply the tool name, not its arguments. Other statuses skip the dialog. This tool never submits, approves, denies or polls. Follow the returned next instruction; Approved is only a request to check gateway status, not proof of approval.',
    inputSchema: {
      type: 'object',
      properties: {
        operation_id: { type: 'string' },
        status: { type: 'string', enum: statuses, description: 'Exact status from the latest gateway response; do not infer from the presence of an approval URL.' },
        approval_url: { type: 'string', description: 'Required only for pending operations.' },
        tool: { type: 'string', description: 'Tool name to display for pending operations.' },
      },
      required: ['operation_id', 'status'],
      additionalProperties: false,
    },
    async execute(input, ctx) {
      const id = input.operation_id
      if (typeof id !== 'string' || !/^[A-Za-z0-9_-]{8,100}$/.test(id)) throw new Error('Expected a gateway operation ID.')
      if (typeof input.status !== 'string' || !statuses.includes(input.status)) throw new Error('Supply the exact gateway status.')

      if (input.status === 'pending') {
        const url = `${gatewayOrigin}/operations/${id}`
        if (input.approval_url !== url) throw new Error('Approval URL must match this operation on the configured gateway.')
        if (typeof input.tool !== 'string' || !input.tool.trim()) throw new Error('Supply the tool name.')
        const continued = await ctx.ui.confirm({
          title: `Approval required: ${input.tool}`,
          message: 'Open the approval page to review this tool call. After approving in the gateway, return here and click **Approved** to check the result.\n\nCancel only closes this dialog.',
          fields: [{ type: 'link', name: 'approval', label: 'Open approval page', value: url }],
          confirmButtonText: 'Approved',
          requireHuman: true,
        })
        if (!continued) return JSON.stringify({
          status: 'dismissed', operation_id: id, decisionSubmitted: false,
          next: 'Stop. Dismissing this card does not deny the gateway operation. Do not resubmit.',
        })
      }

      return JSON.stringify({
        status: 'check_operation', operation_id: id, decisionSubmitted: false,
        next: 'Read get_operation with this same ID. If pending, ready or running, poll at 5-second intervals for at most 5 minutes. Report terminal results from the gateway. Approved is not proof of approval. On unknown, do not retry. On timeout report the last observed status. Never resubmit the call.',
      })
    },
  })
}
