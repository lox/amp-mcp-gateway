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
const tabUpdated = event();
const storedWrites = [];
function storage() {
  const data = {};
  return {
    data,
    get: async (keys) => Object.fromEntries((Array.isArray(keys) ? keys : [keys]).filter((key) => key in data).map((key) => [key, structuredClone(data[key])])),
    set: async (value) => { storedWrites.push(value); Object.assign(data, structuredClone(value)); },
    remove: async (key) => { delete data[key]; },
    setAccessLevel: async () => {},
  };
}
const sockets = [];
class WebSocket {
  static OPEN = 1;
  readyState = 1;
  sent = [];
  constructor() { sockets.push(this); }
  send(data) { this.sent.push(JSON.parse(data)); }
  close() { this.readyState = 3; }
}
const sentCommands = [];
const commandResponses = [];
const context = {
  chrome: {
    action: {setBadgeBackgroundColor: async () => {}, setBadgeText: async () => {}},
    debugger: {onDetach: debuggerDetach, attach: async () => {}, detach: async () => {}, sendCommand: async (target, method, params) => {
      sentCommands.push({tabId: target.tabId, method, params});
      return commandResponses.shift() || {};
    }},
    runtime: {getPlatformInfo: async () => ({os: "linux"}), onInstalled: event(), onMessage: event(), onStartup: event()},
    storage: {local: storage(), session: storage()},
    tabs: {get: async (id) => ({id, title: "Example", url: "https://example.com"}), onRemoved: tabRemoved, onUpdated: tabUpdated},
  },
  clearInterval,
  clearTimeout,
  console,
  crypto: webcrypto,
  setInterval,
  setTimeout,
  TextEncoder,
  URL,
  WebSocket,
};
const source = fs.readFileSync(path.join(__dirname, "background.js"), "utf8");
vm.runInNewContext(`${source}\nthis.selectAllModifierForTest = selectAllModifier; this.BeforeInputErrorForTest = BeforeInputError; this.commandForTest = command; this.executeForTest = execute; this.receiveForTest = receive; this.snapshotForTest = snapshot; this.screenshotForTest = screenshot; this.saveGatewayForTest = saveGateway; this.configForTest = () => currentConfig; this.drainForTest = () => operationQueue;`, context);

test.before(() => context.drainForTest());

test("select-all uses Command on macOS and Control elsewhere", () => {
  assert.equal(context.selectAllModifierForTest("mac"), 4);
  assert.equal(context.selectAllModifierForTest("win"), 2);
  assert.equal(context.selectAllModifierForTest("linux"), 2);
});

test("typing replaces existing text, clears it and submits only when requested", async () => {
  const sendCommand = context.chrome.debugger.sendCommand;
  const editor = {value: "Original invoice 42", selected: false, submissions: 0};
  vm.runInNewContext("currentConfig = {shareID: 'typing-share', tabId: 43}", context);
  context.chrome.debugger.sendCommand = async (_target, method, params) => {
    if (method === "Page.getFrameTree") return {frameTree: {frame: {loaderId: "typing-document"}}};
    if (method === "Accessibility.getPartialAXTree") {
      return {nodes: [{backendDOMNodeId: 7, role: {value: "textbox"}, name: {value: "Reference"}}]};
    }
    // Model Chrome's native editing defaults, not the event's descriptive key/code labels.
    // The real-browser proof checks these semantics against Chrome itself.
    if (method === "Input.dispatchKeyEvent" && params.type === "keyDown") {
      if (params.windowsVirtualKeyCode === 65 && params.modifiers === 2) editor.selected = true;
      if (params.windowsVirtualKeyCode === 8 && editor.selected) {
        editor.value = "";
        editor.selected = false;
      }
      if (params.windowsVirtualKeyCode === 13 && params.text === "\r" && params.unmodifiedText === "\r") editor.submissions++;
    }
    if (method === "Input.insertText" && params.text) {
      editor.value = editor.selected ? params.text : editor.value + params.text;
      editor.selected = false;
    }
    return {};
  };
  try {
    for (const [text, submit, submissions] of [["Invoice 84 · café 🦊", false, 0], ["", false, 0], ["Submitted once", true, 1]]) {
      await context.executeForTest(
        {shareID: "typing-share", tabId: 43},
        "type",
        {document_id: "typing-document", backend_node_id: 7, expected_url: "https://example.com", expected_role: "textbox", expected_name: "Reference", text, submit},
      );
      assert.equal(editor.value, text);
      assert.equal(editor.submissions, submissions);
    }
  } finally {
    context.chrome.debugger.sendCommand = sendCommand;
  }
});

test("gateway settings persist only a validated origin", async () => {
  const saved = await context.saveGatewayForTest("https://gateway.example/");
  assert.equal(saved, "https://gateway.example");
  assert.equal(storedWrites.some((write) => write.gatewayURL === saved), true);
  await assert.rejects(context.saveGatewayForTest("https://gateway.example/integrations/chrome"), /only the gateway origin/);
  await assert.rejects(context.saveGatewayForTest("http://gateway.example"), /must use HTTPS/);
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
  assert.equal("depth" in sentCommands.find((call) => call.method === "Accessibility.getFullAXTree").params, false);
  sentCommands.splice(0);
});

test("snapshots bound accessible text and total payload size", async () => {
  vm.runInNewContext("currentConfig = {shareID: 'large-snapshot', tabId: 189}", context);
  const largeName = "x".repeat(20 * 1024);
  const nodes = Array.from({length: 500}, (_, index) => ({
    nodeId: `node-${index}`,
    backendDOMNodeId: index + 1,
    role: {value: "textbox"},
    name: {value: largeName},
  }));
  commandResponses.push(
    {frameTree: {frame: {loaderId: "large-document"}}},
    {nodes},
    {frameTree: {frame: {loaderId: "large-document"}}},
  );
  const result = await context.snapshotForTest({shareID: "large-snapshot", tabId: 189});
  assert.equal(result.truncated, true);
  assert.equal(result.nodes[0].name.length, 16 * 1024);
  assert.ok(result.nodes.length < nodes.length);
  assert.ok(Buffer.byteLength(JSON.stringify(result)) <= 6 * 1024 * 1024);
  sentCommands.splice(0);
});

test("snapshots do not hide compact nodes after the first 500", async () => {
  vm.runInNewContext("currentConfig = {shareID: 'wide-snapshot', tabId: 198}", context);
  const nodes = Array.from({length: 600}, (_, index) => ({
    nodeId: `node-${index}`,
    backendDOMNodeId: index + 1,
    role: {value: "button"},
    name: {value: `Button ${index}`},
  }));
  commandResponses.push(
    {frameTree: {frame: {loaderId: "wide-document"}}},
    {nodes},
    {frameTree: {frame: {loaderId: "wide-document"}}},
  );
  const result = await context.snapshotForTest({shareID: "wide-snapshot", tabId: 198});
  assert.equal(result.nodes.length, 600);
  assert.equal(result.truncated, false);
  sentCommands.splice(0);
});

test("node mutations reject changed human-readable targets", async () => {
  vm.runInNewContext("currentConfig = {shareID: 'described-mutation', tabId: 199}", context);
  commandResponses.push(
    {frameTree: {frame: {loaderId: "described-document"}}},
    {nodes: [{backendDOMNodeId: 7, role: {value: "button"}, name: {value: "Delete account"}}]},
  );
  await assert.rejects(
    context.executeForTest(
      {shareID: "described-mutation", tabId: 199},
      "click",
      {document_id: "described-document", backend_node_id: 7, expected_url: "https://example.com", expected_role: "button", expected_name: "Save"},
    ),
    (error) => error instanceof context.BeforeInputErrorForTest && /target element changed/.test(error.message),
  );
  assert.deepEqual(sentCommands.splice(0).map((call) => call.method), ["Page.getFrameTree", "Accessibility.getPartialAXTree"]);
});

test("failures once the input phase starts stay ambiguous", async () => {
  vm.runInNewContext("currentConfig = {shareID: 'input-failure', tabId: 202}", context);
  const document = {frameTree: {frame: {loaderId: "input-document"}}};
  const node = {nodes: [{backendDOMNodeId: 7, role: {value: "button"}, name: {value: "Save"}}]};
  commandResponses.push(
    document, node,
    document, {},
    document, node,
    document, {model: {content: [0, 0, 10, 0, 10, 10, 0, 10]}},
    {frameTree: {frame: {loaderId: "replaced-document"}}},
  );
  await assert.rejects(
    context.executeForTest(
      {shareID: "input-failure", tabId: 202},
      "click",
      {document_id: "input-document", backend_node_id: 7, expected_url: "https://example.com", expected_role: "button", expected_name: "Save"},
    ),
    (error) => !(error instanceof context.BeforeInputErrorForTest) && /document changed/.test(error.message),
  );
  sentCommands.splice(0);
});

test("node mutations recheck matching human-readable targets after scrolling", async () => {
  vm.runInNewContext("currentConfig = {shareID: 'matching-mutation', tabId: 201}", context);
  const document = {frameTree: {frame: {loaderId: "matching-document"}}};
  const node = {nodes: [{backendDOMNodeId: 7, role: {value: "button"}, name: {value: "Save"}}]};
  commandResponses.push(
    document, node,
    document, {},
    document, node,
    document, {model: {content: [0, 0, 10, 0, 10, 10, 0, 10]}},
    document, {},
    document, {},
    document, {},
  );
  const result = await context.executeForTest(
    {shareID: "matching-mutation", tabId: 201},
    "click",
    {document_id: "matching-document", backend_node_id: 7, expected_url: "https://example.com", expected_role: "button", expected_name: "Save"},
  );
  assert.equal(result.clicked, 7);
  assert.equal(sentCommands.splice(0).filter((call) => call.method === "Accessibility.getPartialAXTree").length, 2);
});

test("scroll moves the document without hit testing a page element", async () => {
  vm.runInNewContext("currentConfig = {shareID: 'scroll-share', tabId: 200}", context);
  commandResponses.push({});
  await context.executeForTest({shareID: "scroll-share", tabId: 200}, "scroll", {delta_y: 240});
  const call = sentCommands.pop();
  assert.equal(call.method, "Runtime.evaluate");
  assert.equal(call.params.expression, "window.scrollBy(0, 240)");
});

test("node mutations reject IDs from an earlier document", async () => {
  vm.runInNewContext("currentConfig = {shareID: 'mutation-share', tabId: 210}", context);
  commandResponses.push({frameTree: {frame: {loaderId: "document-two"}}});
  await assert.rejects(
    context.executeForTest(
      {shareID: "mutation-share", tabId: 210},
      "click",
      {document_id: "document-one", backend_node_id: 7, expected_url: "https://example.com", expected_role: "button", expected_name: "Save"},
    ),
    /document changed/,
  );
  assert.deepEqual(sentCommands.splice(0).map((call) => call.method), ["Page.getFrameTree"]);
});

test("registration survives stop, tab closure and Chrome restart without resuming access", async () => {
  const message = (value) => new Promise((resolve) => context.chrome.runtime.onMessage.listener(value, {}, resolve));
  const acknowledge = async () => {
    const ws = sockets.at(-1);
    await ws.onopen();
    ws.onmessage({data: JSON.stringify({type: "paired", version: 2, reconnect_code: "browser-secret", browser_name: "Work Chrome"})});
    await context.drainForTest();
    return ws.sent[0];
  };
  await message({type: "disconnect"});
  sentCommands.splice(0);
  await message({type: "configureGateway", gatewayURL: "https://gateway.example"});
  assert.equal((await message({type: "pair", pairingCode: "one-time"})).ok, true);
  const registration = await acknowledge();
  assert.equal(registration.tab_id, 0);
  assert.equal(registration.share_id, "");
  assert.equal(sentCommands.length, 0, "registration must not attach to a tab");
  assert.equal(context.chrome.storage.local.data.registeredBrowser.pairingCode, "browser-secret");
  assert.equal((await message({type: "status"})).registered, true);

  await message({type: "pair", pairingCode: "mistyped-replacement"});
  await sockets.at(-1).onclose({code: 1008});
  const rejectedReplacement = await message({type: "status"});
  assert.equal(rejectedReplacement.registered, true, "a rejected new code must not erase the saved registration");
  assert.equal(rejectedReplacement.sharedTab, null);
  assert.equal(context.chrome.storage.local.data.registeredBrowser.pairingCode, "browser-secret");

  await message({type: "share", tabId: 11});
  const first = await acknowledge();
  assert.equal(first.tab_id, 11);
  assert.equal(first.pairing_code, "browser-secret");
  assert.equal((await message({type: "status"})).connected, true);
  const sharedSocket = sockets.at(-1);
  const getTab = context.chrome.tabs.get;
  try {
    context.chrome.tabs.get = async (id) => ({id, title: "", url: "https://example.com/statements"});
    const messagesBefore = sharedSocket.sent.length;
    tabUpdated.listener(12, {url: "https://private.example"});
    await context.drainForTest();
    assert.equal(sharedSocket.sent.length, messagesBefore, "unshared tab metadata must not leave Chrome");
    tabUpdated.listener(11, {title: "", url: "https://example.com/statements"});
    await context.drainForTest();
    assert.deepEqual(sharedSocket.sent.at(-1), {type: "tab", tab_title: "", tab_url: "https://example.com/statements"});
    context.chrome.tabs.get = async (id) => ({id, title: "Renamed statement", url: "https://example.com/statements"});
    tabUpdated.listener(11, {title: "Renamed statement"});
    await context.drainForTest();
    assert.equal(sharedSocket.sent.at(-1).tab_title, "Renamed statement");
  } finally {
    context.chrome.tabs.get = getTab;
  }
  await message({type: "disconnect"});
  const stopped = await message({type: "status"});
  assert.equal(stopped.registered, true);
  assert.equal(stopped.sharedTab, null);

  await message({type: "share", tabId: 22});
  const unacknowledged = sockets.at(-1);
  tabUpdated.listener(22, {title: "During handshake"});
  await context.drainForTest();
  assert.equal(unacknowledged.sent.length, 0, "hello must be the first wire message");
  const second = await acknowledge();
  assert.equal(second.tab_id, 22);
  assert.notEqual(second.share_id, first.share_id);
  assert.equal(unacknowledged.sent.at(-1).type, "tab", "refresh metadata after acknowledging the share");
  await message({type: "share", tabId: 33});
  const switched = await acknowledge();
  assert.equal(switched.tab_id, 33);
  assert.notEqual(switched.share_id, second.share_id);
  tabRemoved.listener(33);
  await context.drainForTest();
  assert.equal((await message({type: "status"})).registered, true);
  assert.equal((await message({type: "status"})).sharedTab, null);

  // Chrome clears session storage on restart, but not the registered browser.
  for (const key of Object.keys(context.chrome.storage.session.data)) delete context.chrome.storage.session.data[key];
  const connectionsBeforeRestart = sockets.length;
  context.chrome.runtime.onStartup.listener();
  await context.drainForTest();
  const restarted = await message({type: "status"});
  assert.equal(restarted.registered, true);
  assert.equal(restarted.browserName, "Work Chrome");
  assert.equal(restarted.sharedTab, null);
  assert.equal(sockets.length, connectionsBeforeRestart, "restart must not resume a share");

  await message({type: "share", tabId: 44});
  assert.equal((await acknowledge()).pairing_code, "browser-secret");
  await sockets.at(-1).onclose({code: 1008});
  assert.equal((await message({type: "status"})).registered, false);
  assert.equal(context.chrome.storage.local.data.registeredBrowser, undefined);
  sentCommands.splice(0);
});
