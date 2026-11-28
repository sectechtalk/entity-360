// Collapsible rail sections, shared by every 360 app: copy this file unchanged. Each .nav-label (a native button) heads
// the nav items that follow it until the next label.
export const NAV_COLLAPSE_KEY = 'e360.nav.collapsed';

export function readCollapsed(storage, key = NAV_COLLAPSE_KEY) {
  try {
    const value = JSON.parse(storage?.getItem(key) || '[]');
    return Array.isArray(value) ? value.filter(item => typeof item === 'string') : [];
  } catch { return []; }
}

export function sectionKey(text) {
  return String(text || '').trim().toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
}

// Every section starts collapsed. The sections a person opens are remembered per app under `${key}.open`; the section
// holding the page on screen is always shown (without being remembered), so the current page is never hidden.
export function installNavSections(nav, storage, storageKey = NAV_COLLAPSE_KEY) {
  const openKey = `${storageKey.replace(/\.collapsed$/, '')}.open`;
  const opened = new Set(readCollapsed(storage, openKey));
  const shown = new Set(); // opened for the current page only
  const labels = [...nav.querySelectorAll('.nav-label')];
  const itemsOf = label => {
    const out = [];
    for (let el = label.nextElementSibling; el && !el.classList.contains('nav-label'); el = el.nextElementSibling) out.push(el);
    return out;
  };
  const save = () => { try { storage?.setItem(openKey, JSON.stringify([...opened])); } catch { /* storage unavailable */ } };
  const isOpen = key => opened.has(key) || shown.has(key);
  const apply = label => {
    const closed = !isOpen(label.dataset.section);
    label.setAttribute('aria-expanded', String(!closed));
    label.title = `${closed ? 'Expand' : 'Collapse'} ${label.textContent.trim()}`;
    for (const el of itemsOf(label)) el.classList.toggle('nav-collapsed', closed);
  };
  for (const label of labels) {
    const key = label.dataset.section || sectionKey(label.textContent);
    label.dataset.section = key;
    const native = label.tagName === 'BUTTON';
    if (!native) { label.setAttribute('role', 'button'); label.tabIndex = 0; }
    if (!label.querySelector('.nav-chevron')) label.insertAdjacentHTML('beforeend', '<span class="nav-chevron" aria-hidden="true"></span>');
    const toggle = () => { if (isOpen(key)) { opened.delete(key); shown.delete(key); } else opened.add(key); apply(label); save(); };
    label.addEventListener('click', toggle);
    // A native button already turns Enter and Space into a click.
    if (!native) label.addEventListener('keydown', event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); toggle(); } });
    apply(label);
  }
  // Never leave the active page hidden inside a collapsed section.
  const expandItem = item => {
    let el = item?.previousElementSibling;
    while (el && !el.classList.contains('nav-label')) el = el.previousElementSibling;
    if (el && !isOpen(el.dataset.section)) { shown.add(el.dataset.section); apply(el); }
  };
  return {
    expandFor: view => expandItem(nav.querySelector(`[data-view="${view}"]`)),
    expandItem,
  };
}
