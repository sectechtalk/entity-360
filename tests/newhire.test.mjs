import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

// NEW HIRE pages (public/newhire.js): the section sits above INVESTIGATE, every page renders, every in-app link goes to a
// real page, the role table matches the app's role model, and the copy keeps the house style (no em dashes).
class Node {
  constructor(tag) { this.tag = tag; this.kids = []; this._text = ''; }
  set textContent(v) { this._text = String(v); this.kids = []; }
  get textContent() { return this._text + this.kids.map(k => typeof k === 'string' ? k : k.textContent).join(''); }
  append(...k) { this.kids.push(...k); }
  replaceChildren(...k) { this.kids = k; this._text = ''; }
  all(pred, out = []) { for (const k of this.kids) if (typeof k !== 'string') { if (pred(k)) out.push(k); k.all(pred, out); } return out; }
}
globalThis.document = { createElement: tag => new Node(tag) };
const { NEWHIRE_VIEWS, APP_ROLES, FEATURE_NEEDS, createNewHireUi } = await import('../public/newhire.js');
const { ROLE_GROUPS, VIEW_ROLES } = await import('../public/access-denied.js');

const html = readFileSync(new URL('../public/index.html', import.meta.url), 'utf8');
const app = readFileSync(new URL('../public/app.js', import.meta.url), 'utf8');
const navViews = new Set([...html.matchAll(/data-view="([a-z0-9-]+)"/g)].map(m => m[1]));

test('NEW HIRE is the first rail section, above INVESTIGATE, with Start here first', () => {
  const sections = [...html.matchAll(/data-section="([a-z-]+)"/g)].map(m => m[1]);
  assert.deepEqual(sections.slice(0, 2), ['new-hire', 'investigate']);
  assert.deepEqual([...html.matchAll(/data-view="([a-z0-9-]+)"/g)].slice(0, 2).map(m => m[1]), ['start', 'needs']);
  for (const v of Object.keys(NEWHIRE_VIEWS)) assert.match(html, new RegExp(`<section id="${v}-panel" hidden></section>`));
  assert.match(app, /const TITLES = \{ \.\.\.NEWHIRE_VIEWS,/);
});

test('NEW HIRE pages need no role, so a brand-new account can always read them', () => {
  for (const v of Object.keys(NEWHIRE_VIEWS)) assert.equal(VIEW_ROLES[v], undefined, v);
});

const panels = {};
const ui = createNewHireUi({ root: id => (panels[id] ||= new Node('section')) });
for (const v of Object.keys(NEWHIRE_VIEWS)) {
  test(`${v}: renders, links only to real pages, no em dashes`, () => {
    ui[v]();
    const page = panels[v];
    assert.ok(page.all(n => n.tag === 'h2').length >= 3);
    for (const a of page.all(n => n.tag === 'a')) assert.ok(navViews.has(a.href.slice(1)), `${a.textContent} -> ${a.href}`);
    assert.doesNotMatch(page.textContent, /—/, 'house style: no em dashes');
  });
}

test('What it needs: app roles and groups match the role model; the license facts new staff trip on are stated', () => {
  for (const [role, how] of APP_ROLES) {
    if (ROLE_GROUPS[role]) assert.match(how, new RegExp(ROLE_GROUPS[role]), role);
    else assert.match(how, /assigned by an administrator/, role);
  }
  const row = name => FEATURE_NEEDS.find(([f]) => f.startsWith(name));
  assert.match(row('Sign-ins')[1], /P1 or P2/);
  assert.match(row('Conditional Access')[1], /P1/);
  assert.match(row('PIM')[1], /P2 or Entra ID Governance/);
  assert.match(row('Remediation results')[1], /Windows Enterprise E3/);
});
