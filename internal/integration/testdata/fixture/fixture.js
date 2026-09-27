function echo() {
  const input = JSON.parse(Host.inputString())
  Host.outputString(JSON.stringify({
    content: [{ type: "text", text: `plugin:${input.text}` }]
  }))
}

function network() {
  Http.request({ url: "https://example.com", method: "GET" })
}

function spin() {
  while (true) {}
}

module.exports = { echo, network, spin }
