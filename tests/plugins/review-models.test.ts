import { expect, test } from 'bun:test'
import register from '../../docs/reviews/pinned-models.js'

test('production review plugin only registers its pinned review mode', () => {
  const modes: any[] = []
  // Production setup must need no event hooks, workspace or shell access.
  register({
    createAgent: (definition: any) => ({ definition }),
    registerAgentMode: (mode: any) => modes.push(mode),
  })
  expect(modes.map(mode => mode.key)).toEqual(['reviewbot-v1'])
  expect(modes[0].agent).toEqual({
    extends: 'medium',
    model: 'openai/gpt-5.6-sol',
    reasoningEffort: 'medium',
    oracle: { model: 'openai/gpt-5.6-sol', reasoningEffort: 'high' },
    display: { label: 'reviewbot-v1' },
  })
})
