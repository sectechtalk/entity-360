// Collapsible sections, installed once for the whole app so every section gets it, including ones a page renders later.
//
// Aaron's rule (2026-11-27): every section on every page is collapsible, and starts collapsed.
//  - A section (a panel, or a headed card inside one: see SECTIONS) with a heading gets an Expand / Collapse button on that heading. Collapsed, only the heading row
//    shows (title, count and the heading's own buttons such as Refresh or Export); the rest of the panel is hidden.
//  - A <details> section starts closed even when the page renders it open.
//  - A section you open stays open on that page in this browser (re-renders, refresh, coming back) until you collapse
//    it again. Counts in a heading ("Sign-ins 42") do not change which section it is.
// Not sections, so left alone: column filter dropdowns (.msel), the side drawer that a row opens (.drawer), dialogs and
// the left rail (its own groups fold already, see nav-sections.js), and alert cards such as "you need this role" (a
// message with its own fix button, not a section of the page).

export const SECTIONS_OPEN_KEY = 'e360.sections.open';
// AD posture on Security hardening is its own section beside Entra ID findings (findings.js wraps each in one).
const SECTION = '.panel, .posture-section';
const SKIP = '.msel, .drawer, dialog, .sidebar, #navigation, [role="alert"]';
// What counts as a section: panels, plus the headed cards inside them (source coverage cards, findings and their
// groups) and any block a page marks with .e360-section (the Setup guide marks each of its sections).
export const SECTIONS = `${SECTION}, .coverage-card, article.finding, .findings-group, .e360-section`;

// The words that name a section: its title without counts or the fold button's own words.
export function sectionTitle(head) {
  if (!head) return '';
  const title = head.matches?.('h2, h3, summary') ? head : head.querySelector?.('h2, h3') || head;
  let text = '';
  const walk = n => { for (const c of n.childNodes) { if (c.nodeType === 3) text += c.nodeValue; else if (c.nodeType === 1 && !c.classList.contains('sec-fold') && !c.classList.contains('count') && c.tagName !== 'BUTTON') walk(c); } };
  walk(title);
  return text.replace(/\d[\d,.]*/g, '#').replace(/\s+/g, ' ').trim();
}
export function sectionKey(view, title) { return `${view || 'summary'}::${title}`; }

export function readOpen(storage) {
  try { const v = JSON.parse(storage?.getItem(SECTIONS_OPEN_KEY) || '{}'); return v && typeof v === 'object' && !Array.isArray(v) ? v : {}; } catch { return {}; }
}

// The heading row of a panel, or null when the panel has no heading (then there is nothing to fold it under).
export function panelHead(panel) {
  return panel.querySelector(':scope > .panel-heading, :scope > header, :scope > h2, :scope > h3');
}

export function installSections(doc, storage = (() => { try { return doc?.defaultView?.localStorage; } catch { return null; } })()) {
  if (!doc || doc.__e360Sections) return; doc.__e360Sections = true;
  const win = doc.defaultView;
  const view = () => (win?.location?.hash || '').replace(/^#/, '').split(/[?&/]/)[0] || 'summary';
  // Which page a section belongs to: the page container it sits in (stable even for sections built before the page is
  // shown), else the page in the address bar.
  const scopeOf = node => node.parentElement?.closest('section[id], [id$="-panel"], [id$="-page"]')?.id || view();
  const openAll = () => Boolean(win?.__e360SectionsOpen);
  const isOpen = key => openAll() || Boolean(readOpen(storage)[key]);
  const remember = (key, open) => {
    const map = readOpen(storage);
    if (open) map[key] = true; else delete map[key];
    try { storage?.setItem(SECTIONS_OPEN_KEY, JSON.stringify(map)); } catch { /* private window: not remembered */ }
  };
  const seenDetails = new WeakSet();

  const setFolded = (panel, btn, folded) => {
    panel.classList.toggle('sec-folded', folded);
    btn.setAttribute('aria-expanded', String(!folded));
    btn.textContent = folded ? '▸ Expand' : '▾ Collapse';
    const t = panel.dataset.secTitle || 'this section';
    btn.title = folded ? `Show ${t}` : `Hide ${t}`;
    btn.setAttribute('aria-label', `${folded ? 'Expand' : 'Collapse'} ${t}`);
  };

  const foldPanel = panel => {
    if (panel.tagName === 'DETAILS' || panel.closest(SKIP)) return;
    const head = panelHead(panel);
    if (!head || head.querySelector('.sec-fold')) return;
    const title = sectionTitle(head);
    if (!title) return;
    const key = sectionKey(scopeOf(panel), title);
    // A panel whose heading was re-rendered keeps the state it had; a new panel starts collapsed unless opened before.
    const keep = panel.dataset.secKey === key ? panel.classList.contains('sec-folded') : !isOpen(key);
    panel.dataset.secKey = key; panel.dataset.secTitle = title;
    panel.classList.add('sec-panel');
    head.classList.add('sec-head');
    const btn = doc.createElement('button');
    btn.type = 'button'; btn.className = 'btn sec-fold';
    btn.dataset.busy = 'self'; // folding is instant; never borrow the busy look from an unrelated request
    btn.addEventListener('click', e => {
      e.preventDefault(); e.stopPropagation();
      const folded = !panel.classList.contains('sec-folded');
      remember(panel.dataset.secKey, !folded);
      setFolded(panel, btn, folded);
      syncAll();
    });
    head.append(btn);
    setFolded(panel, btn, keep);
  };

  // Expand all / Collapse all for the page on screen, in the page heading next to Export and Refresh.
  const actions = doc.querySelector('.page-heading .heading-actions');
  let allBtn = null;
  const onScreen = () => [...doc.querySelectorAll('.sec-panel')].filter(p => !p.closest(SKIP) && (p.getClientRects().length || p.parentElement?.closest('.sec-folded')?.getClientRects().length));
  const syncAll = () => {
    if (!allBtn) return;
    const list = onScreen();
    if (list.length) allBtn.style.removeProperty('display'); else allBtn.style.setProperty('display', 'none', 'important');
    const label = list.some(p => p.classList.contains('sec-folded')) ? 'Expand all' : 'Collapse all';
    if (allBtn.textContent !== label) allBtn.textContent = label;
  };
  if (actions) {
    allBtn = doc.createElement('button');
    allBtn.type = 'button'; allBtn.id = 'sections-toggle'; allBtn.className = 'btn'; allBtn.dataset.busy = 'self';
    allBtn.addEventListener('click', () => {
      const list = onScreen(); const expand = list.some(p => p.classList.contains('sec-folded'));
      for (const p of list) if (p.classList.contains('sec-folded') === expand) p.querySelector(':scope > .sec-head .sec-fold')?.click();
      syncAll();
    });
    actions.prepend(allBtn);
    win?.addEventListener?.('hashchange', () => setTimeout(syncAll, 0));
    doc.addEventListener('click', e => { if (e.target.closest?.('.sec-fold, #navigation, [role="tab"]')) setTimeout(syncAll, 0); });
  }

  const closeDetails = d => {
    if (seenDetails.has(d) || d.closest(SKIP) || d.matches('.msel')) return;
    seenDetails.add(d);
    const summary = d.querySelector(':scope > summary');
    const key = sectionKey(scopeOf(d), sectionTitle(summary) || 'details');
    d.dataset.secKey = key;
    if (isOpen(key)) d.open = true; else d.removeAttribute('open');
    // Only a person's own open or close is remembered; a page script opening it is not.
    d.addEventListener('toggle', () => { if (d.dataset.secUser === '1') { d.dataset.secUser = ''; remember(key, d.open); } });
    summary?.addEventListener('click', () => { d.dataset.secUser = '1'; });
  };

  const sweep = root => {
    if (!root?.querySelectorAll) return;
    if (root.matches?.(SECTIONS)) foldPanel(root);
    if (root.matches?.('details')) closeDetails(root);
    for (const p of root.querySelectorAll(SECTIONS)) foldPanel(p);
    for (const d of root.querySelectorAll('details')) closeDetails(d);
  };
  sweep(doc.body || doc.documentElement);
  syncAll();
  if (typeof win?.MutationObserver === 'function') {
    new win.MutationObserver(records => {
      for (const r of records) for (const n of r.addedNodes) if (n.nodeType === 1) { sweep(n); const p = n.closest?.(SECTIONS); if (p) foldPanel(p); } syncAll();
    }).observe(doc.documentElement, { childList: true, subtree: true });
  }
}
