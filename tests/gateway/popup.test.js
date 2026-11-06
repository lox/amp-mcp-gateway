const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

test('an idle registered browser can enter a replacement code without losing its registration first', async () => {
  const elements = new Map();
  const element = selector => {
    if (!elements.has(selector)) elements.set(selector, {
      hidden: false,
      open: false,
      addEventListener(name, fn) { this[name] = fn; },
      querySelector: element,
    });
    return elements.get(selector);
  };
  let storageChanged;
  let state = {registered: true, browserName: 'Work Chrome', status: 'disconnected', message: 'No tab is shared.'};
  const chrome = {
    tabs: {query: async () => [{id: 11, url: 'https://example.com'}]},
    runtime: {sendMessage: async message => {
      if (message.type === 'status') return state;
      if (message.type !== 'pair' || message.pairingCode !== 'replacement-code') return {ok: false, error: 'Invalid registration code'};
      state = {...state, browserName: 'Replacement Chrome'};
      storageChanged({registeredBrowser: {newValue: {name: state.browserName}}}, 'local');
      return {ok: true};
    }},
    storage: {
      local: {get: async () => ({gatewayURL: 'https://gateway.example'})},
      onChanged: {addListener(fn) { storageChanged = fn; }},
    },
  };
  const settle = () => new Promise(resolve => setImmediate(resolve));
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../../extension/popup.js'), 'utf8'), {
    chrome, document: {querySelector: element},
  });
  await settle();
  const registration = element('#registration');
  assert.equal(registration.hidden, false);
  assert.equal(registration.open, false, 'ordinary sharing does not show code entry');
  assert.equal(element('summary').hidden, false, 'replacement is available while registered');

  // Opening the native disclosure must expose a usable form, even with a stale credential.
  registration.open = true;
  storageChanged({}, 'session');
  await settle();
  assert.equal(registration.open, true);
  assert.equal(element('#pair').hidden, false);
  element('#code').value = 'replacement-code';
  await element('#pair').submit({preventDefault() {}, target: element('#pair')});
  await settle();
  assert.equal(element('#browser').textContent, 'Browser: Replacement Chrome');
  assert.equal(element('#disconnect').hidden, true, 'registration does not start sharing');
  assert.equal(registration.open, false, 'successful enrollment returns to sharing controls');
  assert.equal(element('#code').value, '', 'consumed codes are not retained in the popup');
  state = {registered: false, status: 'disconnected', message: 'Registration revoked.'};
  storageChanged({registeredBrowser: {}}, 'local');
  await settle();
  assert.equal(registration.open, true, 'unregistered browsers immediately get code entry');
  assert.equal(element('summary').hidden, true);
});
