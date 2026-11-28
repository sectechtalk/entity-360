// One tab component for every 360 app: role="tablist" with role="tab" buttons.
// Arrow keys (and Home/End) move between visible tabs and select them; only the selected tab is in the Tab order.
const visibleTabs = list => [...list.querySelectorAll('[role="tab"]')].filter(t => !t.hidden && !t.disabled);

// Call after the selected tab changes so the roving tabindex follows aria-selected.
// When the tablist names its panel (data-tabpanel="<id>"), every tab gets an id and aria-controls pointing at that
// one shared role="tabpanel", and the panel is labelled by the selected tab, so screen readers announce which tab's
// content they are in (Modern Web Guidance: tabs, "Basic markup").
export function syncTabs(list) {
  if (!list) return;
  const tabs = [...list.querySelectorAll('[role="tab"]')];
  const selected = tabs.find(t => t.getAttribute('aria-selected') === 'true') || visibleTabs(list)[0];
  for (const t of tabs) t.tabIndex = t === selected ? 0 : -1;
  const panel = list.dataset?.tabpanel && list.ownerDocument?.getElementById(list.dataset.tabpanel);
  if (!panel) return;
  for (const t of tabs) {
    if (!t.id) t.id = `${panel.id}-tab-${t.dataset.tab}`;
    t.setAttribute('aria-controls', panel.id);
  }
  if (selected) panel.setAttribute('aria-labelledby', selected.id);
}

// select(key) receives the tab's data-tab value on click or keyboard selection.
export function installTabs(list, select) {
  if (!list) return;
  list.addEventListener('click', e => { const t = e.target.closest('[role="tab"]'); if (t && list.contains(t)) select(t.dataset.tab); });
  list.addEventListener('keydown', e => {
    const tabs = visibleTabs(list), i = tabs.indexOf(e.target.closest('[role="tab"]'));
    if (i < 0) return;
    const next = { ArrowRight: i + 1, ArrowDown: i + 1, ArrowLeft: i - 1, ArrowUp: i - 1, Home: 0, End: tabs.length - 1 }[e.key];
    if (next === undefined) return;
    e.preventDefault();
    const t = tabs[(next + tabs.length) % tabs.length];
    select(t.dataset.tab); t.focus();
  });
  syncTabs(list);
}
