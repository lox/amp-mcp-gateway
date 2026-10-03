// Desktop alerts are opt-in. The authenticated htmx fragment contains only IDs.
(() => {
  const menu = document.querySelector('#notification-menu');
  const button = document.querySelector('#approval-notifications');
  const status = document.querySelector('#notification-status');
  const feed = document.querySelector('#notification-feed');
  if (!menu || !button || !feed) return;

  const preferenceKey = 'gateway.approval-notifications';
  const seenKey = 'gateway.notified-approvals';
  const supported = window.isSecureContext && 'Notification' in window && !!navigator.locks;
  let enabled = false;

  function notificationError() {
    status.textContent = 'Could not show approval notifications. Check browser permissions and site storage.';
  }

  function update() {
    try {
      enabled = supported && Notification.permission === 'granted' && localStorage.getItem(preferenceKey) === 'on';
      button.disabled = !supported || Notification.permission === 'denied';
      status.textContent = !supported
        ? 'Desktop notifications require a supported browser and HTTPS.'
        : Notification.permission === 'denied'
          ? 'Notifications are blocked. Allow them in browser site settings, then reload.'
          : enabled
            ? 'On while a gateway tab stays open. Browser or system settings may silence alerts.'
            : 'Get desktop alerts for pending approvals. Keep a gateway tab open.';
    } catch {
      enabled = false;
      button.disabled = true;
      status.textContent = 'Notifications require browser storage. Allow site storage, then reload.';
    }
    button.textContent = enabled ? 'Disable notifications' : 'Enable notifications';
    button.setAttribute('aria-pressed', String(enabled));
    menu.hidden = false;
    feed.toggleAttribute('data-notifications-enabled', enabled);
    document.dispatchEvent(new Event('gateway:notifications'));
  }

  button.addEventListener('click', async () => {
    button.disabled = true;
    try {
      if (enabled) {
        localStorage.removeItem(preferenceKey);
      } else {
        const permission = await Notification.requestPermission();
        if (permission === 'granted') localStorage.setItem(preferenceKey, 'on');
      }
      update();
    } catch {
      update();
      status.textContent = 'Could not enable notifications. Check browser permissions and site storage.';
    }
  });

  document.addEventListener('htmx:afterSwap', event => {
    if (event.detail.target !== feed || !enabled) return;
    const ids = Array.from(feed.querySelectorAll('[data-approval-id]'), row => row.dataset.approvalId);
    // Serialize across tabs so one request produces one alert, even on reconnect.
    navigator.locks.request(seenKey, () => {
      if (Notification.permission !== 'granted' || localStorage.getItem(preferenceKey) !== 'on') return;
      const seen = new Set(JSON.parse(localStorage.getItem(seenKey) || '[]'));
      for (const id of ids) {
        if (seen.has(id)) continue;
        const notification = new Notification('Approval needed', {
          body: 'Open Amp MCP Gateway to review this request.',
          tag: `gateway-approval-${id}`,
        });
        notification.onerror = notificationError;
        notification.onclick = () => {
          notification.close();
          window.focus();
          window.location.assign(`/operations/${encodeURIComponent(id)}`);
        };
        seen.add(id);
      }
      // Bound local storage; the server returns at most 100 pending requests.
      localStorage.setItem(seenKey, JSON.stringify([...seen].slice(-1000)));
    }).catch(notificationError);
  });

  window.addEventListener('storage', event => {
    if (event.key === preferenceKey || event.key === null) update();
  });
  window.addEventListener('focus', update);
  update();
})();
