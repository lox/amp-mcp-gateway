const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const source = fs.readFileSync(path.join(__dirname, '../../internal/gateway/assets/notifications.js'), 'utf8');
const preferenceKey = 'gateway.approval-notifications';
const seenKey = 'gateway.notified-approvals';

function fixture({permission = 'default', secure = true, supported = true, storage = new Map(), failNotification = false} = {}) {
  const documentListeners = {};
  const windowListeners = {};
  const menu = {hidden: true};
  const button = {addEventListener(name, fn) { this[name] = fn; }, setAttribute(name, value) { this[name] = value; }};
  const status = {};
  const feed = {live: false, ids: [], toggleAttribute(name, on) { this.live = on; }, querySelectorAll() { return this.ids.map(id => ({dataset: {approvalId: id}})); }};
  const notifications = [];
  let requests = 0;
  let pending = Promise.resolve();
  const Notification = class {
    static permission = permission;
    static async requestPermission() { requests++; return this.permission; }
    constructor(title, options) {
      if (failNotification) throw new Error('unavailable');
      Object.assign(this, {title, options});
      notifications.push(this);
    }
    close() { this.closed = true; }
  };
  const window = {
    isSecureContext: secure, ...(supported ? {Notification} : {}),
    addEventListener(name, fn) { windowListeners[name] = fn; },
    focus() { this.focused = true; },
    location: {assign(url) { this.url = url; }},
  };
  const context = {
    window, Notification, Event: class { constructor(type) { this.type = type; } },
    document: {
      querySelector(selector) { return {'#notification-menu': menu, '#approval-notifications': button, '#notification-status': status, '#notification-feed': feed}[selector]; },
      addEventListener(name, fn) { documentListeners[name] = fn; },
      dispatchEvent() {},
    },
    localStorage: {getItem: key => storage.get(key) ?? null, setItem: (key, value) => storage.set(key, value), removeItem: key => storage.delete(key)},
    navigator: {locks: {request(name, fn) { pending = pending.then(fn); return pending; }}},
  };
  vm.runInNewContext(source, context);
  return {
    menu, button, status, feed, notifications, storage, window, Notification,
    requests: () => requests,
    async swap(ids) {
      feed.ids = ids;
      documentListeners['htmx:afterSwap']({detail: {target: feed}});
      await pending.catch(() => {});
    },
    storageEvent: () => windowListeners.storage({key: preferenceKey}),
    focus: () => windowListeners.focus(),
  };
}

test('permission is requested only on click; opt-in is required even with permission', async () => {
  const f = fixture({permission: 'granted'});
  assert.equal(f.menu.hidden, false);
  assert.equal(f.requests(), 0);
  assert.equal(f.feed.live, false);
  await f.swap(['existing']);
  assert.equal(f.notifications.length, 0);
  await f.button.click();
  assert.equal(f.requests(), 1);
  assert.equal(f.feed.live, true);
  assert.equal(f.button['aria-pressed'], 'true');
  await f.swap(['existing']);
  assert.equal(f.notifications.length, 1);
  await f.button.click();
  await f.swap(['later']);
  assert.equal(f.notifications.length, 1);
  assert.equal(f.feed.live, false);
});

test('repeated fragments, navigation and another tab do not repeat alerts', async () => {
  const storage = new Map([[preferenceKey, 'on']]);
  const first = fixture({permission: 'granted', storage});
  await first.swap(['one', 'two']);
  await first.swap(['two', 'one', 'three']);
  assert.equal(first.notifications.length, 3);
  const next = fixture({permission: 'granted', storage});
  await next.swap(['one', 'three', 'four']);
  assert.equal(next.notifications.length, 1);
  assert.equal(next.notifications[0].options.tag, 'gateway-approval-four');
});

test('notifications contain no tool data and clicking navigates without approving', async () => {
  const f = fixture({permission: 'granted', storage: new Map([[preferenceKey, 'on']])});
  await f.swap(['a/b?c']);
  const notification = f.notifications[0];
  assert.equal(notification.title, 'Approval needed');
  assert.equal(notification.options.body, 'Open Amp MCP Gateway to review this request.');
  notification.onclick();
  assert.equal(notification.closed, true);
  assert.equal(f.window.focused, true);
  assert.equal(f.window.location.url, '/operations/a%2Fb%3Fc');
});

test('blocked, insecure and unsupported browsers do not enable the feed', () => {
  for (const options of [{permission: 'denied'}, {secure: false}, {supported: false}]) {
    const f = fixture(options);
    assert.equal(f.menu.hidden, false, 'keep permission guidance accessible from the bell');
    assert.equal(f.feed.live, false);
    assert.equal(f.button.disabled, true);
    assert.equal(f.requests(), 0);
  }
});

test('dismissed permission prompt leaves notifications off', async () => {
  const f = fixture();
  await f.button.click();
  assert.equal(f.feed.live, false);
  assert.equal(f.storage.has(preferenceKey), false);
});

test('revoked permission and cross-tab opt-out stop notifications', async () => {
  const f = fixture({permission: 'granted', storage: new Map([[preferenceKey, 'on']])});
  f.Notification.permission = 'denied';
  await f.swap(['one']);
  assert.equal(f.notifications.length, 0);
  f.focus();
  assert.equal(f.feed.live, false);
  f.Notification.permission = 'granted';
  f.focus();
  assert.equal(f.feed.live, true);
  f.storage.delete(preferenceKey);
  f.storageEvent();
  assert.equal(f.feed.live, false);
});

test('notification failure is visible and is not recorded as delivered', async () => {
  const f = fixture({permission: 'granted', storage: new Map([[preferenceKey, 'on']]), failNotification: true});
  await f.swap(['one']);
  assert.match(f.status.textContent, /Could not show/);
  assert.equal(f.storage.has(seenKey), false);
});

test('asynchronous browser delivery failure is reported without replaying an ambiguous alert', async () => {
  const f = fixture({permission: 'granted', storage: new Map([[preferenceKey, 'on']])});
  await f.swap(['one']);
  f.notifications[0].onerror();
  assert.match(f.status.textContent, /Could not show/);
  await f.swap(['one']);
  assert.equal(f.notifications.length, 1);
});

test('unavailable site storage disables notifications with actionable guidance', () => {
  const f = fixture({permission: 'granted', storage: {get() { throw new Error('storage blocked'); }}});
  assert.equal(f.button.disabled, true);
  assert.equal(f.feed.live, false);
  assert.match(f.status.textContent, /Allow site storage/);
});
