// @amp-agent-mode {"key":"reviewbot-v1","label":"reviewbot-v1"}

export const description =
  "Pins the production reviewbot-v1 agent and Oracle models. Install in the Amp account that runs gateway reviews."

const model = "openai/gpt-5.6-sol"

export default function (amp) {
  const reviewer = amp.createAgent({
    extends: "medium",
    model,
    reasoningEffort: "medium",
    oracle: { model, reasoningEffort: "high" },
    display: { label: "reviewbot-v1" },
  })
  amp.registerAgentMode({
    key: "reviewbot-v1",
    description: "Production code review with a fixed main model. Use for amp-reviewbot reviews.",
    agent: reviewer.definition,
  })
}
