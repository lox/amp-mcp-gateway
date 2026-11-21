(() => {
  const form = document.querySelector('.review-setup');
  if (!form) return;
  let sequence = 0;
  const rows = form.querySelector('[data-review-repositories]');
  const newName = form.querySelector('[data-review-new-name]');
  const newProject = form.querySelector('[data-review-new-project]');
  const filter = form.querySelector('[data-review-filter]');
  const dirty = form.querySelector('[data-review-dirty]');
  // A rejected save re-renders unsaved values, so it starts dirty.
  const initial = form.hasAttribute('data-review-unsaved') ? '' : new URLSearchParams(new FormData(form)).toString();

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

  function refresh() {
    const all = rows ? Array.from(rows.querySelectorAll('[data-review-repository]')) : [];
    const query = filter?.value.trim().toLowerCase() ?? '';
    let enabled = 0;
    for (const row of all) {
      row.hidden = query !== '' && !row.querySelector('[data-review-name]').textContent.includes(query);
      if (row.querySelector('input[type="checkbox"]').checked) enabled++;
    }
    const count = form.querySelector('[data-review-count]');
    if (count) count.textContent = `${enabled} of ${all.length} enabled`;
    const changed = new URLSearchParams(new FormData(form)).toString() !== initial;
    form.classList.toggle('review-dirty', changed);
    if (dirty) dirty.textContent = changed ? 'Unsaved changes' : '';
  }

  // Repository names default to the installation owner when typed without one,
  // and the Amp project defaults to the same owner/repo.
  function repositoryName() {
    let name = newName.value.trim().toLowerCase();
    if (name && !name.includes('/')) {
      const owners = Array.from(form.querySelectorAll('[name$=".owner"]'), input => input.value.trim().toLowerCase()).filter(Boolean);
      if (owners.length === 1) name = `${owners[0]}/${name}`;
    }
    return name;
  }

  function clone(kind, index, installation) {
    const fragment = document.getElementById(`review-${kind}-template`).content.cloneNode(true);
    // Only generated index tokens are substituted, never user-provided HTML.
    for (const element of fragment.querySelectorAll('*')) {
      for (const attribute of Array.from(element.attributes)) {
        if (attribute.value.includes('__i__') || attribute.value.includes('__r__')) {
          element.setAttribute(attribute.name, attribute.value
            .replaceAll('__i__', installation ?? index)
            .replaceAll('__r__', index));
        }
      }
    }
    return fragment;
  }

  function addRepository() {
    const name = repositoryName();
    if (!name) {
      newName.focus();
      return false;
    }
    if (!name.includes('/')) {
      newName.setCustomValidity('Use owner/repo: the owner selects the installation');
      newName.reportValidity();
      return false;
    }
    const existing = Array.from(rows.querySelectorAll('[data-review-repository] [name$=".name"]')).find(input => input.value === name);
    if (existing) {
      newName.setCustomValidity(`${name} is already configured`);
      newName.reportValidity();
      return false;
    }
    const fragment = clone('repository', `new${sequence++}`);
    fragment.querySelector('[name$=".name"]').value = name;
    for (const label of fragment.querySelectorAll('[data-review-name]')) label.textContent = name;
    for (const control of fragment.querySelectorAll('[aria-label*="__name__"], [title*="__name__"]')) {
      for (const attribute of ['aria-label', 'title']) {
        if (control.hasAttribute(attribute)) control.setAttribute(attribute, control.getAttribute(attribute).replace('__name__', name));
      }
    }
    fragment.querySelector('[name$=".project"]').value = newProject.value.trim() || name;
    const row = fragment.querySelector('[data-review-repository]');
    rows.append(fragment);
    newName.value = newProject.value = '';
    newProject.placeholder = 'Amp project · defaults to the same name';
    if (filter) filter.value = '';
    refresh();
    row.scrollIntoView({ block: 'nearest' });
    newName.focus();
    return true;
  }

  credentials();
  refresh();

  form.addEventListener('input', event => {
    if (event.target.name === 'credential_name') credentials();
    if (event.target === newName) {
      newName.setCustomValidity('');
      newProject.placeholder = repositoryName() || 'Amp project · defaults to the same name';
    }
    refresh();
  });
  form.addEventListener('change', refresh);
  form.addEventListener('submit', event => {
    // Saving with a repository typed but not yet added still adds it (disabled).
    if (newName?.value.trim() && !addRepository()) {
      event.preventDefault();
      return;
    }
    form.classList.remove('review-dirty');
  });
  // Reveal invalid controls hidden in a closed popover or section, otherwise
  // the browser blocks the save without showing why.
  form.addEventListener('invalid', event => {
    event.target.closest('[popover]:not(:popover-open)')?.showPopover();
    const details = event.target.closest('details');
    if (details) details.open = true;
  }, true);
  for (const input of [newName, newProject]) {
    input?.addEventListener('keydown', event => {
      if (event.key === 'Enter') {
        event.preventDefault();
        addRepository();
      }
    });
  }
  form.addEventListener('click', event => {
    const remove = event.target.closest('[data-review-remove]');
    if (remove) {
      const kind = remove.dataset.reviewRemove;
      const row = remove.closest(`[data-review-${kind}]`);
      const container = row.parentElement;
      row.remove();
      (kind === 'repository' ? newName : container.parentElement.querySelector(`[data-review-add="${kind}"]`))?.focus();
      credentials();
      refresh();
      return;
    }
    const add = event.target.closest('[data-review-add]');
    if (!add) return;
    const kind = add.dataset.reviewAdd;
    if (kind === 'repository') {
      addRepository();
      return;
    }
    const fragment = clone(kind, `new${sequence++}`);
    const first = fragment.querySelector('input:not([type="hidden"])');
    const containers = { installation: '[data-review-installations]', credential: '[data-review-credentials]' };
    form.querySelector(containers[kind]).append(fragment);
    credentials();
    refresh();
    first?.focus();
  });
  // Keep each row's overrides chip in step with its popover.
  form.addEventListener('toggle', event => {
    const popover = event.target;
    if (!popover.matches?.('.review-overrides') || event.newState !== 'closed') return;
    const value = name => popover.querySelector(`[name$=".${name}"]`).value;
    const parts = [value('fail_on') && `fail on ${value('fail_on')}`, value('visibility'), value('timeout') && `${value('timeout')} min`].filter(Boolean);
    const chip = form.querySelector(`[popovertarget="${popover.id}"][data-review-overrides]`);
    chip.textContent = parts.length ? parts.join(' · ') : 'Defaults';
    chip.classList.toggle('review-overridden', parts.length > 0);
  }, true);
  window.addEventListener('beforeunload', event => {
    if (form.classList.contains('review-dirty')) event.preventDefault();
  });
})();
