// Keep transport in htmx; these hooks preserve local UI state and report errors.
document.addEventListener('htmx:beforeRequest', event => {
  const { elt } = event.detail;
  if (elt.hasAttribute('hx-get') && document.hidden) {
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
});

document.addEventListener('htmx:afterRequest', event => {
  const { elt, successful } = event.detail;
  const health = elt.closest('.connection-status');
  if (health) elt.textContent = 'Test connection';
  const error = health?.querySelector('.test-error') || document.querySelector('.live-error');
  if (!error) return;
  error.hidden = !!successful;
  error.textContent = health
    ? 'Could not complete the test. Check your session and try again. Your tool permissions are unchanged.'
    : 'Live updates are unavailable. Refresh the page to check the latest status.';
});
