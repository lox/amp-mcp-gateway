import { describe, expect, test } from 'bun:test'
import register, { reviewMessage } from '../../.amp/plugins/gateway-review'

const input = {
  operation_id: 'preview-fixture-001',
  approval_url: 'https://lox-mcp-gateway.fly.dev/operations/preview-fixture-001',
  tool: 'notes.create', connection: 'notes', account: 'Demo notes',
  arguments: { text: 'Release checklist reviewed' },
}

describe('gateway review', () => {
  test('renders exact preview with its provenance and contains hostile Markdown', () => {
    const { message } = reviewMessage({ ...input, arguments: { text: '```\n![track](https://evil.example)\n```' } })
    expect(message).toContain('Preview supplied by Amp')
    expect(message).toContain('````json')
    expect(message).toContain('\\n![track]')
    expect(message).toContain(input.approval_url)
  })
  test('rejects substituted origins, IDs and malformed arguments', () => {
    for (const patch of [
      { approval_url: 'https://evil.example/operations/preview-fixture-001' },
      { operation_id: 'different-request' },
      { operation_id: '../login' },
      { arguments: [] },
    ]) expect(() => reviewMessage({ ...input, ...patch })).toThrow()
  })
  test.each([false, true])('human continuation %s never launches a browser or approves', async decision => {
    let tool: any
    let opened = ''
    register({ registerTool: (definition: any) => { tool = definition }, system: { open: async (url: string) => { opened = url } } } as any)
    const output = JSON.parse(await tool.execute(input, { ui: { confirm: async (options: any) => {
      expect(options.requireHuman).toBe(true)
      expect(options.confirmButtonText).toBe('I’ve reviewed it')
      expect(options.message).toContain(`**[Open approval page ↗](${input.approval_url})**`)
      return decision
    } } }))
    expect(output.decisionSubmitted).toBe(false)
    expect(output.status).toBe(decision ? 'check_operation' : 'dismissed')
    expect(opened).toBe('')
  })
  test('continuation needs no browser API and instructs polling rather than assuming approval', async () => {
    let tool: any
    register({ registerTool: (definition: any) => { tool = definition } } as any)
    const output = JSON.parse(await tool.execute(input, { ui: { confirm: async () => true } }))
    expect(output.next).toContain('not proof of approval')
    expect(output.next).toContain('Poll get_operation with this same ID')
    expect(output.approval_url).toBe(input.approval_url)
    expect(output.decisionSubmitted).toBe(false)
  })
})
