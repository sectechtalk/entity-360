// Setup guide: every section folds and starts collapsed, like every other Entity 360 page. Following a contents link
// opens the section it points to.
import { installSections } from './sections.js';
for (const s of document.querySelectorAll('main > section')) s.classList.add('e360-section');
installSections(document);
const reveal = () => {
  const id = decodeURIComponent(location.hash.slice(1)); if (!id) return;
  const target = document.getElementById(id); const sec = target?.closest('.e360-section');
  const btn = sec?.querySelector(':scope > .sec-head .sec-fold');
  if (btn && sec.classList.contains('sec-folded')) btn.click();
  target?.scrollIntoView();
};
addEventListener('hashchange', reveal); reveal();
