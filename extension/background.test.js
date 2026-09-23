const assert = require("node:assert/strict");
const {webcrypto} = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const event = {addListener() {}};
const storage = {
  get: async () => ({}),
  set: async () => {},
  remove: async () => {},
};
const sentTargets = [];
const context = {
  chrome: {
    action: {setBadgeBackgroundColor: async () => {}, setBadgeText: async () => {}},
    debugger: {onDetach: event, sendCommand: async (target) => sentTargets.push(target)},
    runtime: {onInstalled: event, onMessage: event, onStartup: event},
    storage: {local: storage, session: storage},
    tabs: {onRemoved: event},
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
vm.runInNewContext(`${source}\nthis.selectAllModifierForTest = selectAllModifier; this.commandForTest = command;`, context);

test("select-all uses Command on macOS and Control elsewhere", () => {
  assert.equal(context.selectAllModifierForTest("mac"), 4);
  assert.equal(context.selectAllModifierForTest("win"), 2);
  assert.equal(context.selectAllModifierForTest("linux"), 2);
});

test("commands stay bound to their captured share and tab", async () => {
  vm.runInNewContext("currentConfig = {shareID: 'share-one', tabId: 42}", context);
  await context.commandForTest({shareID: "share-one", tabId: 42}, "Page.enable");
  assert.equal(sentTargets.pop().tabId, 42);

  vm.runInNewContext("currentConfig = {shareID: 'share-two', tabId: 84}", context);
  await assert.rejects(
    context.commandForTest({shareID: "share-one", tabId: 42}, "Page.enable"),
    /shared tab changed/,
  );
  assert.equal(sentTargets.length, 0);
});
