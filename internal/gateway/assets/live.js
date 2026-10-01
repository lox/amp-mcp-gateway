// SSE carries only invalidations; authenticated htmx GETs render current state.
let ledgerSource = null;
let livePending = false;

function notificationTarget() {
  return document.querySelector('#notification-feed[data-notifications-enabled]');
}

function refreshNotifications() {
  const target = notificationTarget();
  if (target) htmx.trigger(target, 'approval-update');
}

function deferLiveSwap(target) {
  const selection = window.getSelection();
  const selected = selection && !selection.isCollapsed && selection.rangeCount > 0 &&
    selection.getRangeAt(0).intersectsNode(target);
  return selected || (target.id !== 'operation-live' &&
    (target.contains(document.activeElement) || target.querySelector('a:hover')));
}

function refreshLive() {
  const target = document.querySelector('[data-live]');
  if (!livePending || !target || document.hidden || deferLiveSwap(target)) return;
  livePending = false;
  htmx.trigger(document.body, 'live-update');
}

function stopLive() {
  ledgerSource?.close();
  ledgerSource = null;
}

function syncLive() {
  if (!notificationTarget() && (document.hidden || !document.querySelector('[data-live]'))) {
    stopLive();
    return;
  }
  if (ledgerSource) return;
  const source = new EventSource('/events');
  ledgerSource = source;
  source.addEventListener('ledger', () => {
    if (source !== ledgerSource) return;
    refreshNotifications();
    livePending = true;
    refreshLive();
  });
  source.onerror = () => {
    if (source !== ledgerSource) return;
    const error = document.querySelector('.live-error') || document.querySelector('.notification-error');
    if (error) {
      error.hidden = false;
      error.textContent = 'Live updates disconnected. Reconnecting; you can also refresh the page.';
    }
    if (source.readyState === EventSource.CLOSED) {
      // A rejected stream (e.g. expired login) cannot reconnect automatically.
      // A normal htmx GET will apply the existing full-page login redirect.
      refreshNotifications();
      htmx.trigger(document.body, 'live-update');
      setTimeout(() => {
        if (source === ledgerSource) {
          stopLive();
          syncLive();
        }
      }, 1000);
    }
  };
}

document.addEventListener('visibilitychange', () => {
  syncLive();
  refreshLive();
});
document.addEventListener('gateway:notifications', () => {
  syncLive();
  refreshNotifications();
  const error = document.querySelector('.notification-error');
  if (error && !notificationTarget()) error.hidden = true;
});
window.addEventListener('pagehide', stopLive);
window.addEventListener('pageshow', syncLive);
for (const name of ['focusout', 'mouseout', 'selectionchange']) {
  document.addEventListener(name, () => queueMicrotask(refreshLive));
}
syncLive();

// Preserve local UI state and report errors for all enhanced requests.
document.addEventListener('htmx:beforeRequest', event => {
  const { elt } = event.detail;
  const notification = elt.id === 'notification-feed';
  if ((notification && !notificationTarget()) ||
      (elt.hasAttribute('hx-get') && document.hidden && !notification)) {
    event.preventDefault();
    return;
  }
  if (elt.matches('.connection-test button')) {
    elt.textContent = 'Testing…';
    elt.closest('.connection-status').querySelector('.test-error').hidden = true;
  }
});

document.addEventListener('htmx:beforeSwap', event => {
  const { target } = event.detail;
  // A user may start interacting while the fragment GET is in flight.
  if (target.hasAttribute('data-live') && deferLiveSwap(target)) {
    event.detail.shouldSwap = false;
    livePending = true;
  }
  if ((target.id === 'audit-live' || target.id === 'operations-live') && event.detail.shouldSwap) {
    const fragment = document.createElement('template');
    fragment.innerHTML = event.detail.serverResponse;
    if (target.id === 'audit-live') {
      const expanded = new Set([...target.querySelectorAll('.audit-entry[open]')].map(entry => entry.dataset.requestId));
      for (const entry of fragment.content.querySelectorAll('.audit-entry')) {
        if (expanded.has(entry.dataset.requestId)) entry.open = true;
      }
      event.detail.serverResponse = fragment.innerHTML;
    }
    if (fragment.innerHTML === target.innerHTML) event.detail.shouldSwap = false;
  }
  if (target.matches('.connection-health')) {
    target.dataset.expanded = String(!!target.querySelector('details')?.open);
  }
  if (target.id === 'operation-live' && event.detail.shouldSwap) {
    const fragment = new DOMParser().parseFromString(event.detail.serverResponse, 'text/html');
    if (target.querySelector('#operation-history')?.open) {
      fragment.querySelector('#operation-history')?.setAttribute('open', '');
    }
    event.detail.serverResponse = fragment.body.innerHTML;
  }
});

document.addEventListener('htmx:afterSwap', event => {
  const { target } = event.detail;
  if (target.matches('.connection-health') && target.dataset.expanded === 'true') {
    const details = target.querySelector('details');
    if (details) details.open = true;
  }
  syncLive();
});

document.addEventListener('htmx:afterRequest', event => {
  const { elt, successful } = event.detail;
  const notification = elt.id === 'notification-feed';
  if (!successful && (elt.hasAttribute('data-live') || notification)) {
    // A failed GET consumed its invalidation. Reconnect for a fresh one instead
    // of waiting for another ledger change or the stream's minute-long lease.
    stopLive();
    setTimeout(syncLive, 1000);
  }
  const health = elt.closest('.connection-status');
  if (health) elt.textContent = 'Test connection';
  const error = notification ? document.querySelector('.notification-error')
    : health?.querySelector('.test-error') || document.querySelector('.live-error');
  if (!error) return;
  const live = notification ? notificationTarget() : document.querySelector('[data-live]');
  error.hidden = !!successful && (!live || ledgerSource?.readyState === EventSource.OPEN);
  error.textContent = health
    ? 'Could not complete the test. Check your session and try again. Your tool permissions are unchanged.'
    : notification ? 'Approval alerts are unavailable. Refresh the page to reconnect.'
      : 'Live updates are unavailable. Refresh the page to check the latest status.';
});
