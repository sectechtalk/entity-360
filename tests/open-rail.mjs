// Rail sections start collapsed. Browser tests that drive pages through the rail start with every rail section open,
// as a person who had opened them would (the app remembers opened sections under e360.nav.open).
import { readFileSync } from 'node:fs';
const html = readFileSync(new URL('../public/index.html', import.meta.url), 'utf8');
export const RAIL_SECTIONS = [...html.matchAll(/class="nav-label"[^>]*data-section="([a-z-]+)"/g)].map(m => m[1]);
export async function openRail(ctx) {
  await ctx.addInitScript(keys => { try { if (!localStorage.getItem('e360.nav.open')) localStorage.setItem('e360.nav.open', JSON.stringify(keys)); } catch { /* storage blocked */ } }, RAIL_SECTIONS);
}
