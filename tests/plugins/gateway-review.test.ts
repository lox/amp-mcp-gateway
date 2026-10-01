import { expect, test } from 'bun:test'
import register from '../../.amp/plugins/gateway-review'

const pending = {
  operation_id: 'preview-fixture-001', status: 'pending', tool: 'notes.create',
  approval_url: 'https://lox-mcp-gateway.fly.dev/operations/preview-fixture-001',
}

function tool() {
  let definition: any
  // No browser, network or credential API is supplied to the plugin.
  register({ registerTool: (value: any) => { definition = value } } as any)
  return definition
}

test.each([{}, undefined])('pending link-only dialog handles confirmation %j', async answer => {
  let calls = 0
  const output = JSON.parse(await tool().execute(pending, { ui: { confirm: async (options: any) => {
    calls++
    expect(options).toEqual({
      title: 'Approval required: notes.create',
      message: 'Open the approval page to review this tool call. After approving in the gateway, return here and click **Approved** to check the result.\n\nCancel only closes this dialog.',
      fields: [{ type: 'link', name: 'approval', label: 'Open approval page', value: pending.approval_url }],
      confirmButtonText: 'Approved', requireHuman: true,
    })
    return answer
  } } }))
  expect(calls).toBe(1)
  expect(output.operation_id).toBe(pending.operation_id)
  expect(output.decisionSubmitted).toBe(false)
  expect(output.status).toBe(answer ? 'check_operation' : 'dismissed')
  expect(output.next).toContain(answer ? 'Approved is not proof of approval' : 'Stop.')
})

test.each(['ready', 'running', 'succeeded', 'failed', 'denied', 'expired', 'unknown'])('%s skips approval even with an approval URL', async status => {
  let calls = 0
  const output = JSON.parse(await tool().execute({ ...pending, status }, { ui: { confirm: async () => { calls++; return {} } } }))
  expect(calls).toBe(0)
  expect(output.status).toBe('check_operation')
  expect(output.next).toContain('Read get_operation with this same ID')
  expect(output.decisionSubmitted).toBe(false)
})

test('ready needs neither tool name nor approval URL', async () => {
  const output = JSON.parse(await tool().execute({ operation_id: pending.operation_id, status: 'ready' }, {}))
  expect(output.status).toBe('check_operation')
})

test('missing status, unknown status and substituted links fail before any dialog', async () => {
  for (const patch of [
    { status: undefined }, { status: 'approved' }, { operation_id: '../login' },
    { approval_url: 'https://evil.example/operations/preview-fixture-001' },
    { operation_id: 'different-request' }, { tool: '' },
  ]) await expect(tool().execute({ ...pending, ...patch }, {})).rejects.toThrow()
})
