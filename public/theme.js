// Theme: dark by default; a stored choice ('light' | 'dark') wins. Loaded synchronously in <head> so there is no flash.
(function (root) {
  const KEY = 'e360-theme';
  function storedTheme(storage) { try { const v = storage && storage.getItem(KEY); return v === 'light' || v === 'dark' ? v : null; } catch { return null; } }
  function initialTheme(storage) { return storedTheme(storage) || 'dark'; }
  function applyTheme(doc, theme) {
    doc.documentElement.dataset.theme = theme;
    const btn = doc.getElementById && doc.getElementById('theme-toggle');
    if (btn) {
      const next = theme === 'dark' ? 'light' : 'dark';
      btn.setAttribute('aria-pressed', String(theme === 'dark'));
      btn.title = `Switch to ${next} mode`;
      const label = btn.querySelector('.theme-label'); if (label) label.textContent = theme === 'dark' ? 'Light mode' : 'Dark mode';
    }
  }
  function toggleTheme(doc, storage) {
    const next = doc.documentElement.dataset.theme === 'light' ? 'dark' : 'light';
    try { storage && storage.setItem(KEY, next); } catch { /* storage blocked: still switch for this page */ }
    applyTheme(doc, next); return next;
  }
  const api = { KEY, storedTheme, initialTheme, applyTheme, toggleTheme };
  if (typeof module === 'object' && module.exports) module.exports = api;
  if (root && root.document) {
    root.e360Theme = api;
    let ls = null; try { ls = root.localStorage; } catch { /* ignore */ }
    applyTheme(root.document, initialTheme(ls));
    root.document.addEventListener('DOMContentLoaded', () => {
      applyTheme(root.document, root.document.documentElement.dataset.theme);
      const b = root.document.getElementById('theme-toggle'); if (b) b.addEventListener('click', () => toggleTheme(root.document, ls));
    });
  }
})(typeof window !== 'undefined' ? window : null);
