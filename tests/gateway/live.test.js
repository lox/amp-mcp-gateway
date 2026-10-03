const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const source = fs.readFileSync(path.join(__dirname, '../../internal/gateway/assets/live.js'), 'utf8');

function fixture({hidden = false, enabled = false, hasList = true, focused = false} = {}) {
  const listeners = {};
  const sources = [];
  const triggers = [];
  const timers = [];
  const error = {hidden: true};
  const feed = {
    id: 'notification-feed',
    hasAttribute(name) { return name === 'hx-get' || (name === 'data-notifications-enabled' && enabled); },
    matches() { return false; },
    closest: () => null,
  };
  const list = {
    id: 'operations-live', contains: () => focused, querySelector: () => null,
    hasAttribute: name => name === 'hx-get', matches: () => false,
  };
  const document = {
    hidden, body: {}, activeElement: {},
    querySelector(selector) {
      if (selector === '[data-live]') return hasList ? list : null;
      if (selector === '#notification-feed[data-notifications-enabled]') return enabled ? feed : null;
      if (selector === '.notification-error') return error;
      return null;
    },
    addEventListener(name, fn) { listeners[name] = fn; },
  };
  vm.runInNewContext(source, {
    document,
    window: {getSelection: () => null, addEventListener() {}},
    queueMicrotask,
    setTimeout: (callback, delay) => timers.push({callback, delay}),
    htmx: {trigger(target, event) { triggers.push({target, event}); }},
    EventSource: class {
      static OPEN = 1;
      static CLOSED = 2;
      readyState = 1;
      constructor() { sources.push(this); }
      addEventListener(name, fn) { this[name] = fn; }
      close() { this.closed = true; }
    },
  });
  return {
    document, sources, triggers, feed, list, timers, error,
    enable(value) { enabled = value; listeners['gateway:notifications'](); },
    visibility(value) { document.hidden = value; listeners.visibilitychange(); },
    afterRequest(elt, successful) { listeners['htmx:afterRequest']({detail: {elt, successful}}); },
    request(elt) {
      let prevented = false;
      listeners['htmx:beforeRequest']({detail: {elt}, preventDefault() { prevented = true; }});
      return !prevented;
    },
  };
}

test('background SSE exists only for opted-in notifications, even on pages without a live list', () => {
  assert.equal(fixture({hidden: true}).sources.length, 0);
  const f = fixture({hidden: true, enabled: true, hasList: false});
  assert.equal(f.sources.length, 1);
  f.sources[0].ledger();
  assert.equal(f.triggers.length, 1);
  assert.equal(f.triggers[0].target, f.feed);
  assert.equal(f.triggers[0].event, 'approval-update');
  f.enable(false);
  assert.equal(f.sources[0].closed, true);
});

test('focused list links do not delay notifications', () => {
  const f = fixture({enabled: true, focused: true});
  f.sources[0].ledger();
  assert.equal(f.triggers.length, 1);
  assert.equal(f.triggers[0].target, f.feed);
});

test('returning to the foreground refreshes the list without opening another SSE connection', () => {
  const f = fixture({hidden: true, enabled: true});
  f.sources[0].ledger();
  f.visibility(false);
  assert.equal(f.sources.length, 1);
  assert.equal(f.triggers.filter(trigger => trigger.event === 'live-update').length, 1);
});

test('only the enabled notification feed can fetch while hidden', () => {
  const f = fixture({hidden: true, enabled: true});
  assert.equal(f.request(f.list), false);
  assert.equal(f.request(f.feed), true);
  f.enable(false);
  assert.equal(f.request(f.feed), false);
});

test('enabling notifications requests pending approvals on an existing connection', () => {
  const f = fixture();
  assert.equal(f.sources.length, 1);
  f.enable(true);
  assert.equal(f.sources.length, 1);
  assert.equal(f.triggers[0].target, f.feed);
  assert.equal(f.triggers[0].event, 'approval-update');
});

test('failed background notification GET reconnects and retries without another operation', () => {
  const f = fixture({hidden: true, enabled: true, hasList: false});
  f.sources[0].ledger();
  f.afterRequest(f.feed, false);
  assert.equal(f.error.hidden, false);
  assert.equal(f.sources[0].closed, true);
  assert.equal(f.sources.length, 1);
  assert.equal(f.timers[0].delay, 1000);
  f.timers[0].callback();
  f.sources[1].ledger();
  assert.equal(f.triggers.length, 2);
  f.afterRequest(f.feed, true);
  assert.equal(f.error.hidden, true);
});

test('a successful connection test does not depend on notification stream health', () => {
  const f = fixture({enabled: true, hasList: false});
  f.sources[0].readyState = 0;
  const error = {hidden: false};
  f.afterRequest({id: 'test-button', closest: () => ({querySelector: () => error})}, true);
  assert.equal(error.hidden, true);
});
