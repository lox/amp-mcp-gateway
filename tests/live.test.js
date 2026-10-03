const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const vm = require('node:vm');

test('audit refresh preserves expanded requests by identity, not row position', () => {
  const listeners = {};
  const entries = ['new', 'closed', 'expanded'].map(requestId => ({ dataset: { requestId }, open: false }));
  const fragment = {
    content: { querySelectorAll: () => entries },
    set innerHTML(value) {},
    get innerHTML() { return entries.map(e => `${e.dataset.requestId}:${e.open}`).join(','); },
  };
  const context = vm.createContext({
    document: {
      addEventListener: (name, callback) => { listeners[name] = callback; },
      querySelector: () => null,
      createElement: () => fragment,
    },
    window: { addEventListener() {}, getSelection: () => null },
  });
  vm.runInContext(readFileSync('internal/gateway/assets/live.js', 'utf8'), context);
  const target = {
    id: 'audit-live', innerHTML: 'old',
    hasAttribute: () => true, contains: () => false,
    querySelector: () => null, matches: () => false,
    querySelectorAll: () => [{ dataset: { requestId: 'expanded' } }, { dataset: { requestId: 'removed' } }],
  };
  const event = { detail: { target, shouldSwap: true, serverResponse: 'new HTML' } };
  listeners['htmx:beforeSwap'](event);
  assert.equal(event.detail.serverResponse, 'new:false,closed:false,expanded:true');
  assert.equal(event.detail.shouldSwap, true);
});

test('failed fragment refresh reconnects and retries without another ledger change', () => {
  const listeners = {};
  const timers = [];
  const sources = [];
  const error = { hidden: true };
  const target = {
    id: 'operation-live',
    closest: () => null,
    hasAttribute: name => name === 'data-live',
  };
  let live = target;
  let requests = 0;
  class EventSource {
    static OPEN = 1;
    static CLOSED = 2;
    readyState = 1;
    constructor() { sources.push(this); }
    addEventListener(name, callback) { this[name] = callback; }
    close() { this.readyState = EventSource.CLOSED; }
  }
  const context = vm.createContext({
    EventSource,
    document: {
      body: {},
      addEventListener: (name, callback) => { listeners[name] = callback; },
      querySelector: selector => selector === '[data-live]' ? live : selector === '.live-error' ? error : null,
    },
    window: { addEventListener() {}, getSelection: () => null },
    htmx: { trigger: () => { requests++; } },
    setTimeout: (callback, delay) => { timers.push({ callback, delay }); },
  });
  vm.runInContext(readFileSync('internal/gateway/assets/live.js', 'utf8'), context);
  sources[0].ledger();
  assert.equal(requests, 1);
  listeners['htmx:afterRequest']({ detail: { elt: target, successful: false } });
  assert.equal(error.hidden, false);
  assert.equal(sources[0].readyState, EventSource.CLOSED);
  assert.equal(sources.length, 1, 'do not reconnect in a hot loop');
  assert.equal(timers.length, 1);
  assert.equal(timers[0].delay, 1000);
  timers[0].callback();
  assert.equal(sources.length, 2);
  sources[1].ledger(); // Every new SSE connection sends its initial invalidation.
  assert.equal(requests, 2);
  listeners['htmx:afterRequest']({ detail: { elt: target, successful: true } });
  assert.equal(error.hidden, true);

  live = null; // Successful outerHTML swap replaced active execution with a result.
  vm.runInContext('syncLive()', context);
  listeners['htmx:afterRequest']({ detail: { elt: target, successful: true } });
  assert.equal(sources[1].readyState, EventSource.CLOSED);
  assert.equal(error.hidden, true, 'terminal result must not show a disconnected error');
});
