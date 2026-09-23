const assert = require("node:assert/strict");
const {webcrypto} = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

function event() {
  return {listener: null, addListener(listener) { this.listener = listener; }};
}
const debuggerDetach = event();
const tabRemoved = event();
const storedWrites = [];
const storage = {
  get: async () => ({}),
  set: async (value) => storedWrites.push(value),
  remove: async () => {},
};
const sentCommands = [];
const commandResponses = [];
const context = {
  chrome: {
    action: {setBadgeBackgroundColor: async () => {}, setBadgeText: async () => {}},
    debugger: {onDetach: debuggerDetach, sendCommand: async (target, method, params) => {
      sentCommands.push({tabId: target.tabId, method, params});
      return commandResponses.shift() || {};
    }},
    runtime: {getPlatformInfo: async () => ({os: "linux"}), onInstalled: event(), onMessage: event(), onStartup: event()},
    storage: {local: storage, session: storage},
    tabs: {get: async () => ({title: "Example", url: "https://example.com"}), onRemoved: tabRemoved},
  },
  clearInterval,
  clearTimeout,
  console,
  crypto: webcrypto,
  setInterval,
  setTimeout,
  URL,
  WebSocket: class {},
};
const source = fs.readFileSync(path.join(__dirname, "background.js"), "utf8");
vm.runInNewContext(`${source}\nthis.selectAllModifierForTest = selectAllModifier; this.commandForTest = command; this.executeForTest = execute; this.receiveForTest = receive; this.snapshotForTest = snapshot; this.screenshotForTest = screenshot; this.configForTest = () => currentConfig; this.drainForTest = () => operationQueue;`, context);

test("select-all uses Command on macOS and Control elsewhere", () => {
  assert.equal(context.selectAllModifierForTest("mac"), 4);
  assert.equal(context.selectAllModifierForTest("win"), 2);
  assert.equal(context.selectAllModifierForTest("linux"), 2);
});

test("commands stay bound to their captured share and tab", async () => {
  vm.runInNewContext("currentConfig = {shareID: 'share-one', tabId: 42}", context);
  await context.commandForTest({shareID: "share-one", tabId: 42}, "Page.enable");
  assert.equal(sentCommands.pop().tabId, 42);

  vm.runInNewContext("currentConfig = {shareID: 'share-two', tabId: 84}", context);
  await assert.rejects(
    context.commandForTest({shareID: "share-one", tabId: 42}, "Page.enable"),
    /shared tab changed/,
  );
  assert.equal(sentCommands.length, 0);
});

test("detach from a replaced tab does not disconnect the new share", async () => {
  vm.runInNewContext("currentConfig = {shareID: 'old-share', tabId: 42}", context);
  debuggerDetach.listener({tabId: 42});
  vm.runInNewContext("currentConfig = {shareID: 'new-share', tabId: 84}", context);
  await context.drainForTest();
  assert.equal(context.configForTest().tabId, 84);
});

test("detach from the current tab disconnects its share", async () => {
  vm.runInNewContext("currentConfig = {shareID: 'current-share', tabId: 84}", context);
  debuggerDetach.listener({tabId: 84});
  await context.drainForTest();
  assert.equal(context.configForTest(), null);
});

test("closing a replaced tab does not disconnect the new share", async () => {
  vm.runInNewContext("currentConfig = {shareID: 'old-share', tabId: 42}", context);
  tabRemoved.listener(42);
  vm.runInNewContext("currentConfig = {shareID: 'new-share', tabId: 84}", context);
  await context.drainForTest();
  assert.equal(context.configForTest().tabId, 84);
});

test("pairing replaces the one-time code with its reconnect credential", async () => {
  vm.runInNewContext("currentConfig = {pairingCode: 'one-time', shareID: 'paired-share', tabId: 105}", context);
  await context.receiveForTest(
    {type: "paired", reconnect_code: "reconnect-secret"},
    {shareID: "paired-share", tabId: 105},
  );
  assert.equal(context.configForTest().pairingCode, "reconnect-secret");
  assert.equal(storedWrites.some((write) => write.bridgeConfig?.pairingCode === "reconnect-secret"), true);
});

test("screenshots retry at lower quality to stay below the bridge limit", async () => {
  vm.runInNewContext("currentConfig = {shareID: 'share-three', tabId: 126}", context);
  commandResponses.push({data: "x".repeat(6 * 1024 * 1024 + 1)}, {data: "bounded"});
  const result = await context.screenshotForTest({shareID: "share-three", tabId: 126});
  assert.equal(result.mime_type, "image/jpeg");
  assert.equal(result.screenshot_data, "bounded");
  assert.deepEqual(sentCommands.splice(0).map((call) => call.params.quality), [70, 50]);
});

test("snapshots bind backend node IDs to the current document", async () => {
  vm.runInNewContext("currentConfig = {shareID: 'snapshot-share', tabId: 168}", context);
  commandResponses.push(
    {frameTree: {frame: {loaderId: "document-one"}}},
    {nodes: [{nodeId: "node", backendDOMNodeId: 7, role: {value: "button"}, name: {value: "Save"}}]},
    {frameTree: {frame: {loaderId: "document-one"}}},
  );
  const result = await context.snapshotForTest({shareID: "snapshot-share", tabId: 168});
  assert.equal(result.document_id, "document-one");
  assert.equal(result.nodes[0].backend_node_id, 7);
  sentCommands.splice(0);
});

test("node mutations reject IDs from an earlier document", async () => {
  vm.runInNewContext("currentConfig = {shareID: 'mutation-share', tabId: 210}", context);
  commandResponses.push({frameTree: {frame: {loaderId: "document-two"}}});
  await assert.rejects(
    context.executeForTest(
      {shareID: "mutation-share", tabId: 210},
      "click",
      {document_id: "document-one", backend_node_id: 7},
    ),
    /document changed/,
  );
  assert.deepEqual(sentCommands.splice(0).map((call) => call.method), ["Page.getFrameTree"]);
});
