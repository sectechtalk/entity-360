// Collapsible sidebar sections. Each .nav-label heads the nav items that follow it until the next label.
export const NAV_COLLAPSE_KEY = 'e360.nav.collapsed';

export function readCollapsed(storage) {
  try {
    const value = JSON.parse(storage?.getItem(NAV_COLLAPSE_KEY) || '[]');
    return Array.isArray(value) ? value.filter(item => typeof item === 'string') : [];
  } catch { return []; }
}

export function sectionKey(text) {
  return String(text || '').trim().toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
}

export function installNavSections(nav, storage) {
  const collapsed = new Set(readCollapsed(storage));
  const labels = [...nav.querySelectorAll('.nav-label')];
  const itemsOf = label => {
    const out = [];
    for (let el = label.nextElementSibling; el && !el.classList.contains('nav-label'); el = el.nextElementSibling) out.push(el);
    return out;
  };
  const save = () => { try { storage?.setItem(NAV_COLLAPSE_KEY, JSON.stringify([...collapsed])); } catch { /* storage unavailable */ } };
  const apply = label => {
    const closed = collapsed.has(label.dataset.section);
    label.setAttribute('aria-expanded', String(!closed));
    label.title = `${closed ? 'Expand' : 'Collapse'} ${label.textContent.trim()}`;
    for (const el of itemsOf(label)) el.classList.toggle('nav-collapsed', closed);
  };
  for (const label of labels) {
    const key = label.dataset.section || sectionKey(label.textContent);
    label.dataset.section = key;
    label.setAttribute('role', 'button');
    label.tabIndex = 0;
    if (!label.querySelector('.nav-chevron')) label.insertAdjacentHTML('beforeend', '<span class="nav-chevron" aria-hidden="true"></span>');
    const toggle = () => { if (collapsed.has(key)) collapsed.delete(key); else collapsed.add(key); apply(label); save(); };
    label.addEventListener('click', toggle);
    label.addEventListener('keydown', event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); toggle(); } });
    apply(label);
  }
  return {
    // Never leave the active page hidden inside a collapsed section.
    expandFor(view) {
      const button = nav.querySelector(`[data-view="${view}"]`);
      let el = button?.previousElementSibling;
      while (el && !el.classList.contains('nav-label')) el = el.previousElementSibling;
      if (el && collapsed.has(el.dataset.section)) { collapsed.delete(el.dataset.section); apply(el); save(); }
    },
  };
}