(() => {
  const form = document.querySelector('.review-setup');
  if (!form) return;
  let sequence = 0;
  function credentials() {
    const names = [...new Set(Array.from(form.querySelectorAll('[name="credential_name"]'), input => input.value).filter(Boolean))];
    for (const select of form.querySelectorAll('[data-review-credential-select]')) {
      const selected = select.value;
      const options = [new Option('Choose a credential', ''), ...names.map(name => new Option(name, name))];
      if (selected && !names.includes(selected)) options.push(new Option(`Missing credential: ${selected}`, selected));
      select.replaceChildren(...options);
      select.value = selected;
    }
  }
  credentials();
  form.addEventListener('input', event => {
    if (event.target.name === 'credential_name') credentials();
  });
  form.addEventListener('click', event => {
    const remove = event.target.closest('[data-review-remove]');
    if (remove) {
      const kind = remove.dataset.reviewRemove;
      const row = remove.closest(`[data-review-${kind}]`);
      const parent = row.parentElement;
      row.remove();
      const add = parent.parentElement.querySelector(`[data-review-add="${kind}"]`);
      add?.focus();
      credentials();
      return;
    }
    const add = event.target.closest('[data-review-add]');
    if (!add) return;
    const kind = add.dataset.reviewAdd;
    const installation = add.closest('[data-review-installation]');
    const index = `new${sequence++}`;
    const fragment = document.getElementById(`review-${kind}-template`).content.cloneNode(true);
    // Only generated index tokens are substituted, never user-provided HTML.
    for (const element of fragment.querySelectorAll('*')) {
      for (const attribute of Array.from(element.attributes)) {
        if (attribute.value.includes('__i__') || attribute.value.includes('__r__')) {
          element.setAttribute(attribute.name, attribute.value
            .replaceAll('__i__', installation?.dataset.reviewInstallation ?? index)
            .replaceAll('__r__', index));
        }
      }
    }
    const first = fragment.querySelector('input:not([type="hidden"])');
    const containers = { installation: '[data-review-installations]', repository: '[data-review-repositories]', credential: '[data-review-credentials]' };
    (installation ?? form).querySelector(containers[kind]).append(fragment);
    credentials();
    first?.focus();
  });
})();
