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
    appendRepository(name, newProject.value.trim() || name, false).scrollIntoView({ block: 'nearest' });
    newName.value = newProject.value = '';
    newProject.placeholder = 'Amp project · same as repo';
    newName.focus();
    return true;
  }

  function configured() {
    return new Set(Array.from(rows.querySelectorAll('[data-review-repository] [name$=".name"]'), input => input.value));
  }

  function appendRepository(name, project, enabled) {
    const fragment = clone('repository', `new${sequence++}`);
    fragment.querySelector('[name$=".name"]').value = name;
    for (const label of fragment.querySelectorAll('[data-review-name]')) label.textContent = name;
    for (const control of fragment.querySelectorAll('[aria-label*="__name__"], [title*="__name__"]')) {
      for (const attribute of ['aria-label', 'title']) {
        if (control.hasAttribute(attribute)) control.setAttribute(attribute, control.getAttribute(attribute).replace('__name__', name));
      }
    }
    fragment.querySelector('[name$=".project"]').value = project;
    fragment.querySelector('input[type="checkbox"]').checked = enabled;
    const row = fragment.querySelector('[data-review-repository]');
    rows.append(fragment);
    if (filter) filter.value = '';
    refresh();
    return row;
  }

  // "Add from GitHub" lists what the saved installations can see. It only fills
  // in rows: nothing is approved until the form is saved and verified.
  const picker = form.querySelector('[data-review-picker]');
  const pickerList = picker?.querySelector('[data-review-picker-list]');
  const pickerStatus = picker?.querySelector('[data-review-picker-status]');
  function pickerSelection() {
    const count = pickerList.querySelectorAll('input[type="checkbox"]:checked').length;
    picker.querySelector('[data-review-picker-selected]').textContent = `${count} selected`;
    for (const button of picker.querySelectorAll('[data-review-picker-add]')) button.disabled = count === 0;
  }
  async function openPicker(url) {
    picker.hidden = false;
    pickerList.replaceChildren();
    picker.querySelector('[data-review-picker-filter]').value = '';
    pickerStatus.textContent = 'Loading repositories from GitHub…';
    pickerSelection();
    let names;
    try {
      const response = await fetch(url, { headers: { Accept: 'application/json' }, credentials: 'same-origin' });
      const body = await response.json();
      if (!response.ok) throw new Error(body.error || `HTTP ${response.status}`);
      names = body.repositories ?? [];
    } catch (error) {
      pickerStatus.textContent = `Could not list repositories: ${error.message}`;
      return;
    }
    const existing = configured();
    const available = names.filter(name => !existing.has(name));
    pickerStatus.textContent = `${names.length} visible to the App · ${available.length} not configured`;
    pickerList.replaceChildren(...available.map(name => {
      const item = document.createElement('li');
      item.dataset.name = name;
      const label = document.createElement('label');
      const box = document.createElement('input');
      box.type = 'checkbox';
      label.append(box, document.createTextNode(name));
      const project = document.createElement('input');
      project.value = name;
      project.setAttribute('aria-label', `Amp project for ${name}`);
      project.spellcheck = false;
      item.append(label, project);
      return item;
    }));
    if (!available.length) pickerStatus.textContent += ' · everything is already in the list';
    picker.querySelector('[data-review-picker-filter]').focus();
  }
  picker?.addEventListener('input', event => {
    if (event.target.matches('[data-review-picker-filter]')) {
      const query = event.target.value.trim().toLowerCase();
      for (const item of pickerList.children) item.hidden = query !== '' && !item.dataset.name.includes(query);
    }
    event.stopPropagation();
  });
  picker?.addEventListener('change', event => {
    pickerSelection();
    event.stopPropagation();
  });
  picker?.addEventListener('keydown', event => {
    if (event.key === 'Enter') event.preventDefault();
  });
  picker?.addEventListener('click', event => {
    const add = event.target.closest('[data-review-picker-add]');
    if (add) {
      const enable = add.dataset.reviewPickerAdd === 'enable';
      const existing = configured();
      let last;
      for (const item of pickerList.children) {
        const box = item.querySelector('input[type="checkbox"]');
        if (!box.checked || existing.has(item.dataset.name)) continue;
        last = appendRepository(item.dataset.name, item.querySelector('input:not([type])').value.trim() || item.dataset.name, enable);
      }
      picker.hidden = true;
      last?.scrollIntoView({ block: 'nearest' });
      form.querySelector('[data-review-picker-open]').focus();
    } else if (event.target.closest('[data-review-picker-close]')) {
      picker.hidden = true;
      form.querySelector('[data-review-picker-open]').focus();
    }
    event.stopPropagation();
  });
  form.querySelector('[data-review-picker-open]')?.addEventListener('click', event => openPicker(event.currentTarget.dataset.reviewPickerOpen));

  credentials();
  refresh();

  form.addEventListener('input', event => {
    if (event.target.name === 'credential_name') credentials();
    if (event.target === newName) {
      newName.setCustomValidity('');
      newProject.placeholder = repositoryName() || 'Amp project · same as repo';
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
