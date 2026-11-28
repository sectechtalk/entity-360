// Findings > AD posture: parsing the collector output, every check's rule, per-domain scoring, the score history,
// the posture PDF, the route and the page markup. The forest in these tests is fictional (ad.northwind.example).
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { inflateSync } from 'node:zlib';
import { parsePosture, evaluatePosture, evaluateDomain, templateFacts, escMatches, aceGrants, broadScope, trustInfo, scoreOf, collectPosture, addToHistory, createHistoryStore, historyFor, postureDocument, demoPostureRaw, demoHistory, CHECKS, GAPS, TRUST, FLAG, EKU, POSTURE_SCRIPT } from '../server/ad-posture.mjs';
import { renderPdf } from '../server/pdf.mjs';
import { roleForPath } from '../server/authflow.mjs';
import { createApp } from '../server/index.mjs';
import { postureHtml, sparkline, findingsHtml, groupedCards, FINDINGS_TITLE } from '../public/findings.js';
import { freePort } from './free-port.mjs';

const read = f => readFileSync(new URL(`../${f}`, import.meta.url), 'utf8');
const esc = v => String(v ?? '').replace(/[&<>"']/g, c => `&#${c.charCodeAt(0)};`);
const h = { esc, external: (u, l, c = 'btn') => `<a class="${c}" href="${u}">${esc(l)}</a>`, emptyBox: t => `<div class="inline-empty">${esc(t)}</div>` };
const NOW = Date.parse('2026-11-25T00:00:00Z');
const ROOT = 'S-1-5-21-1111-2222-3333', EMEA = 'S-1-5-21-4444-5555-6666';
const ENROLL = '0e10c968-78fb-11d2-90d4-00c04f79dc55';
const raw = () => parsePosture(JSON.stringify(demoPostureRaw(NOW)));
const byId = (d, id) => d.findings.find(f => f.id === id);
function pdfText(buf) {
  const s = buf.toString('latin1'), out = [];
  for (const m of s.matchAll(/<< \/Length (\d+) \/Filter \/FlateDecode >>\nstream\n/g)) {
    const start = m.index + m[0].length, body = inflateSync(buf.subarray(start, start + Number(m[1]))).toString('latin1');
    for (const t of body.matchAll(/\((.*?)\) Tj/g)) out.push(t[1].replace(/\\([()\\])/g, '$1'));
  }
  return out.join('\n');
}

test('parse: bad output and non-live statuses become messages, values are bounded', () => {
  assert.equal(parsePosture('not json').status, 'error');
  assert.deepEqual(parsePosture(JSON.stringify({ status: 'denied', message: 'Logon failure' })), { status: 'denied', message: 'Logon failure', server: '', domains: [] });
  assert.equal(parsePosture(JSON.stringify({ status: 'weird' })).status, 'error');
  const p = parsePosture('\uFEFF' + JSON.stringify({ status: 'live', domains: [{ name: 'x.example', sid: 'bad', dcs: [{ name: 'DC1', ldapSigning: 'maybe' }], spnAccounts: { sam: 'one' } }], pki: { status: 'read', templates: [{ name: 't', aces: [{ sid: 'S-1-1-0', type: 'Allow', rights: 'GenericAll', objectType: 'ABC' }] }] } }));
  assert.equal(p.domains[0].sid, '');
  assert.equal(p.domains[0].dcs[0].ldapSigning, 'unknown');
  assert.equal(p.domains[0].spnAccounts.length, 1, 'a single object (PowerShell unrolled array) is still a list');
  assert.equal(p.domains[0].gpo.status, 'unavailable');
  assert.equal(p.pki.templates[0].aces[0].objectType, 'abc');
});

test('ACEs: enroll and write rights, broad principals scoped to their domain or the whole forest', () => {
  assert.deepEqual(aceGrants({ rights: 'ReadProperty, ExtendedRight', objectType: ENROLL }), { enroll: true, write: false });
  assert.deepEqual(aceGrants({ rights: 'ExtendedRight', objectType: '00000000-0000-0000-0000-000000000000' }), { enroll: true, write: false });
  assert.deepEqual(aceGrants({ rights: 'ExtendedRight', objectType: '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' }), { enroll: false, write: false }, 'another extended right');
  assert.deepEqual(aceGrants({ rights: 'GenericAll', objectType: '' }), { enroll: true, write: true });
  assert.equal(aceGrants({ rights: 'ReadProperty, WriteDacl', objectType: '' }).write, true);
  const forest = raw();
  assert.equal(broadScope('S-1-5-11', forest), '*');
  assert.equal(broadScope(`${ROOT}-513`, forest), 'ad.northwind.example');
  assert.equal(broadScope(`${EMEA}-515`, forest), 'emea.ad.northwind.example');
  assert.equal(broadScope(`${ROOT}-512`, forest), null, 'Domain Admins is not broad');
  assert.equal(broadScope(`${ROOT}-1105`, forest), null);
});

test('ESC patterns: ESC1/2/3/4/9/15 rules, deny cancels allow, approval and RA signatures guard, unpublished never ESC1', () => {
  const forest = raw();
  const t = o => ({ name: 'T', displayName: 'T', nameFlag: 0, enrollFlag: 0, raSignatures: 0, ekus: [], appPolicies: [], schemaVersion: 2, owner: '', daclRead: true, aces: [{ sid: `${ROOT}-513`, type: 'Allow', rights: 'ExtendedRight', objectType: ENROLL }], ...o });
  forest.pki.cas[0].templates.push('T');
  const m = o => escMatches([templateFacts(t(o), forest)], 'ad.northwind.example');
  assert.equal(m({ nameFlag: FLAG.suppliesSubject, ekus: [EKU.clientAuth] }).esc1.length, 1);
  assert.equal(m({ nameFlag: FLAG.suppliesSan, ekus: [EKU.smartCard] }).esc1.length, 1, 'supplied SAN counts too');
  assert.equal(m({ nameFlag: FLAG.suppliesSubject, ekus: ['1.3.6.1.5.5.7.3.1'] }).esc1.length, 0, 'server auth only: no logon');
  assert.equal(m({ nameFlag: FLAG.suppliesSubject, ekus: [EKU.clientAuth], enrollFlag: FLAG.pendAll }).esc1.length, 0, 'manager approval');
  assert.equal(m({ nameFlag: FLAG.suppliesSubject, ekus: [EKU.clientAuth], raSignatures: 1 }).esc1.length, 0, 'authorized signature');
  assert.equal(m({ nameFlag: FLAG.suppliesSubject, ekus: [EKU.clientAuth], aces: [{ sid: `${ROOT}-513`, type: 'Allow', rights: 'ExtendedRight', objectType: ENROLL }, { sid: `${ROOT}-513`, type: 'Deny', rights: 'ExtendedRight', objectType: ENROLL }] }).esc1.length, 0, 'deny wins');
  assert.equal(m({ nameFlag: FLAG.suppliesSubject, ekus: [EKU.clientAuth], name: 'Unpublished' }).esc1.length, 0, 'not on any CA');
  const e2 = m({}); assert.equal(e2.esc2.length, 1, 'no EKU'); assert.match(e2.esc2[0].detail, /no EKU/);
  assert.equal(m({ ekus: [EKU.any] }).esc2.length, 1);
  assert.equal(m({ ekus: [EKU.agent] }).esc3.length, 1);
  assert.equal(m({ ekus: [EKU.clientAuth], enrollFlag: FLAG.noSecurityExt }).esc9.length, 1);
  assert.equal(m({ schemaVersion: 1, nameFlag: FLAG.suppliesSubject, ekus: ['1.3.6.1.5.5.7.3.1'] }).esc15.length, 1);
  const w = m({ name: 'Unpublished', ekus: ['1.3.6.1.5.5.7.3.3'], aces: [{ sid: 'S-1-5-11', type: 'Allow', rights: 'WriteProperty', objectType: '' }] });
  assert.equal(w.esc4.length, 1, 'ESC4 even when unpublished');
  assert.match(w.esc4[0].detail, /Authenticated Users can change the template \(not published on any CA\)/);
  assert.equal(m({ owner: 'S-1-1-0', ekus: ['1.3.6.1.5.5.7.3.3'] }).esc4.length, 1, 'a broad owner can rewrite the DACL');
  // Per domain: Domain Users of the root domain do not make a template open in the child domain.
  assert.equal(escMatches([templateFacts(t({ nameFlag: FLAG.suppliesSubject, ekus: [EKU.clientAuth] }), forest)], 'emea.ad.northwind.example').esc1.length, 0);
});

test('trusts: direction, SID filtering, selective authentication and TGT delegation', () => {
  const ext = trustInfo({ partner: 'partner.example', direction: 2, type: 2, attributes: 0 });
  assert.equal(ext.kind, 'External');
  assert.equal(ext.sidFiltering, 'Off');
  assert.equal(ext.risks.length, 2);
  assert.deepEqual(trustInfo({ partner: 'partner.example', direction: 2, type: 2, attributes: TRUST.quarantined | TRUST.selectiveAuth }).risks, []);
  assert.deepEqual(trustInfo({ partner: 'partner.example', direction: 1, type: 2, attributes: 0 }).risks, [], 'inbound: the partner trusts us, our resources are not exposed');
  const forest = trustInfo({ partner: 'other.example', direction: 3, type: 2, attributes: TRUST.forest | TRUST.treatAsExternal | TRUST.tgtDelegation });
  assert.equal(forest.kind, 'Forest trust');
  assert.match(forest.sidFiltering, /Relaxed/);
  assert.equal(forest.risks.length, 3);
  const child = trustInfo({ partner: 'emea.ad.northwind.example', direction: 3, type: 2, attributes: TRUST.withinForest });
  assert.deepEqual(child.risks, []);
  assert.match(child.sidFiltering, /same forest/);
  assert.equal(trustInfo({ partner: 'REALM', direction: 3, type: 3, attributes: 0 }).kind, 'MIT Kerberos realm');
});

test('demo forest: every check evaluates, root domain fails what it should, the child passes what it should', () => {
  const p = evaluatePosture(raw(), { now: NOW });
  const [root, emea] = p.domains;
  assert.equal(root.findings.length, CHECKS.length);
  for (const id of ['adcs-esc1', 'adcs-esc4', 'adcs-esc8', 'dc-ldap-signing', 'dc-channel-binding', 'dc-ntlm', 'kerberoastable', 'asrep-roastable', 'unconstrained-delegation', 'laps-missing', 'krbtgt-age', 'trusts']) assert.equal(byId(root, id).status, 'open', id);
  assert.deepEqual(byId(root, 'adcs-esc1').items.map(i => i.text), ['NW VPN User']);
  assert.equal(byId(root, 'adcs-esc1').items.length, 1, 'NW Web Server has server auth only, User does not take a supplied subject');
  assert.deepEqual(byId(root, 'dc-ldap-signing').items.map(i => i.text), ['NWDC01'], 'NWDC02 refused the unsigned bind');
  assert.equal(byId(root, 'dc-smb-signing').status, 'pass');
  assert.equal(byId(root, 'kerberoastable').severity, 'critical', 'a privileged SPN account raises it to critical');
  assert.match(byId(root, 'kerberoastable').items[0].detail, /^Privileged .*old · RC4 allowed/);
  assert.match(byId(root, 'kerberoastable').note, /2 with a password older than 365 days, 1 privileged\. gMSAs in this domain: 2/);
  assert.deepEqual(byId(root, 'laps-missing').items.map(i => i.text), ['NW-WS-0088', 'APP-OLD01', 'NW-WS-0031']);
  assert.match(byId(root, 'laps-missing').items[2].detail, /stale/);
  assert.equal(byId(root, 'adcs-ca-side').status, 'unavailable');
  assert.equal(root.findings[0].rank, 1);
  for (const id of ['dc-ldap-signing', 'dc-channel-binding', 'dc-smb-signing', 'dc-ntlm', 'kerberoastable', 'laps-missing', 'krbtgt-age', 'trusts', 'adcs-esc1']) assert.equal(byId(emea, id).status, 'pass', id);
  assert.equal(byId(emea, 'adcs-esc9').status, 'open', 'EMEA Domain Computers autoenroll the no-security-extension template');
  assert.equal(byId(emea, 'adcs-esc4').status, 'open', 'Authenticated Users is forest-wide');
  assert.ok(emea.score > root.score);
  assert.equal(root.trusts.length, 2);
  assert.equal(p.gaps, GAPS);
});

test('checks: unreadable sources become "could not check" with the reason, never a pass', () => {
  const f = raw();
  f.domains[0].gpo = { status: 'unavailable', message: 'SYSVOL on nwdc01 could not be read over SMB: The network path was not found.', values: {}, gpos: [] };
  f.domains[0].dcs.forEach(d => { d.ldapSigning = 'unknown'; d.ldapSigningDetail = 'Bind test failed: timeout'; });
  f.domains[0].errors = [{ check: 'spn', message: 'Size limit exceeded' }];
  f.pki = { status: 'unavailable', message: 'AD CS objects could not be read: denied', cas: [], templates: [], names: {} };
  const d = evaluateDomain(f.domains[0], f, { now: NOW });
  assert.match(byId(d, 'dc-channel-binding').reason, /network path was not found/);
  assert.equal(byId(d, 'dc-ntlm').status, 'unavailable');
  assert.match(byId(d, 'dc-ldap-signing').reason, /timeout/);
  assert.match(byId(d, 'kerberoastable').reason, /Size limit exceeded/);
  assert.match(byId(d, 'adcs-esc1').reason, /denied/);
  // No CA at all: AD CS checks pass with a note.
  const noCa = raw(); noCa.pki.cas = [];
  assert.match(byId(evaluateDomain(noCa.domains[0], noCa, { now: NOW }), 'adcs-esc1').note, /No enterprise CA/);
  // Not set by GPO: channel binding and NTLM are open; SMB signing passes only on Server 2025.
  const unset = raw(); unset.domains[0].gpo.values = {};
  const u = evaluateDomain(unset.domains[0], unset, { now: NOW });
  assert.equal(byId(u, 'dc-channel-binding').count, 2);
  assert.match(byId(u, 'dc-ntlm').items[0].detail, /Windows default is level 3/);
  assert.deepEqual(byId(u, 'dc-smb-signing').items.map(i => i.text), ['NWDC01']);
  // No LAPS schema at all.
  const nolaps = raw(); nolaps.domains[0].laps.windowsSchema = false; nolaps.domains[0].laps.computers.forEach(c => { c.windowsExpiry = null; });
  assert.match(byId(evaluateDomain(nolaps.domains[0], nolaps, { now: NOW }), 'laps-missing').note, /Neither LAPS schema extension is installed/);
});

test('score: weighted share of checked controls passing; unread controls are left out', () => {
  assert.equal(scoreOf([{ severity: 'critical', status: 'pass' }, { severity: 'critical', status: 'open' }]), 50);
  assert.equal(scoreOf([{ severity: 'critical', status: 'pass' }, { severity: 'medium', status: 'open' }, { severity: 'high', status: 'unavailable' }]), 77);
  assert.equal(scoreOf([{ severity: 'high', status: 'unavailable' }]), null);
  const unreachable = raw(); unreachable.domains[1] = { ...unreachable.domains[1], reachable: false, message: 'Domain emea could not be read from this host' };
  const p = evaluatePosture(unreachable, { now: NOW });
  assert.equal(p.domains[1].score, null);
  assert.equal(p.domains[1].findings.length, 0);
});

test('collect: cloud and non-Windows hosts are off with a reason; arguments go as an array; timeout is reported', async () => {
  assert.equal((await collectPosture({ config: { cloud: true } })).status, 'cloud');
  assert.match((await collectPosture({ config: { enabled: false, platform: 'linux' } })).message, /needs Entity 360 running on Windows/);
  let seen;
  const r = await collectPosture({ config: { enabled: true, server: 'nwdc01.ad.northwind.example', credential: 'C:\\e360\\ad-reader.xml', platform: 'win32' }, run: async (a, o) => { seen = [a, o]; return JSON.stringify(demoPostureRaw(NOW)); }, now: NOW });
  assert.deepEqual(seen[0], ['-Server', 'nwdc01.ad.northwind.example', '-CredentialPath', 'C:\\e360\\ad-reader.xml']);
  assert.equal(seen[1].timeout, 180000);
  assert.equal(r.status, 'live');
  assert.equal(r.domains.length, 2);
  assert.match((await collectPosture({ config: { enabled: true, platform: 'win32' }, run: async () => { throw Object.assign(new Error('x'), { killed: true }); } })).message, /timed out after 180 seconds/);
  assert.equal((await collectPosture({ config: { enabled: true, platform: 'win32' }, run: async () => JSON.stringify({ status: 'unreachable', message: 'Could not connect' }) })).status, 'unreachable');
});

test('history: one row per domain per day (last read wins), old rows age out, file store round-trips', async t => {
  const p = evaluatePosture(raw(), { now: NOW });
  const once = addToHistory([{ date: '2026-11-25', domain: 'ad.northwind.example', score: 1, open: {} }, { date: '2020-01-01', domain: 'ad.northwind.example', score: 5, open: {} }], p);
  assert.equal(once.filter(r => r.domain === 'ad.northwind.example').length, 1);
  assert.equal(once.find(r => r.domain === 'ad.northwind.example').score, p.domains[0].score);
  const dir = mkdtempSync(path.join(tmpdir(), 'e360-posture-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const store = createHistoryStore(path.join(dir, 'sub', 'posture-history.json'));
  assert.deepEqual(await store.load(), []);
  await store.record(p);
  await store.record(evaluatePosture(raw(), { now: NOW + 864e5 }));
  const rows = await store.load();
  assert.deepEqual(historyFor(rows, 'emea.ad.northwind.example').map(r => r.date), ['2026-11-25', '2026-11-26']);
});

test('PDF: scores, trend table, findings with playbooks, trusts and what could not be read', () => {
  const p = evaluatePosture(raw(), { now: NOW });
  const history = addToHistory(demoHistory(NOW), p);
  const text = pdfText(renderPdf(postureDocument(p, history, { domain: 'ad.northwind.example', viewer: 'analyst@northwind.example' })));
  for (const s of ['AD posture: ad.northwind.example', 'Score by domain', 'score trend', 'NW VPN User', 'svc-sql01', 'partner.example', 'Not readable over this connection', 'ESC7']) assert.match(text, new RegExp(s), s);
  assert.doesNotMatch(text, /EMEA Laptop/, 'the other domain is left out when one is picked');
  const all = pdfText(renderPdf(postureDocument(p, [], {})));
  assert.match(all, /emea\.ad\.northwind\.example: findings/);
  assert.match(all, /No history yet/);
});

test('route: E360.Reader, demo posture and PDF, unknown domain rejected', async t => {
  assert.equal(roleForPath('/api/findings/ad-posture'), 'E360.Reader');
  assert.equal(roleForPath('/api/findings/ad-posture/report.pdf'), 'E360.Reader');
  const port = await freePort();
  const app = createApp({ port, demoMode: true, postureHistory: { load: async () => [], record: async () => [] } });
  const server = app.listen(port, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const base = `http://127.0.0.1:${port}`;
  const cookie = (await fetch(`${base}/api/session`)).headers.get('set-cookie').split(';')[0];
  const get = p => fetch(base + p, { headers: { Cookie: cookie } });
  const r = await get('/api/findings/ad-posture');
  assert.equal(r.status, 200);
  const body = await r.json();
  assert.equal(body.status, 'live');
  assert.deepEqual(body.domains.map(d => d.name), ['ad.northwind.example', 'emea.ad.northwind.example']);
  assert.equal(body.history['ad.northwind.example'].length, 6, 'five months of demo history plus today');
  const pdf = await get('/api/findings/ad-posture/report.pdf?domain=emea.ad.northwind.example');
  assert.equal(pdf.status, 200);
  assert.match(pdf.headers.get('content-disposition'), /filename="entity-360-ad-posture-emea\.ad\.northwind\.example-\d{4}-\d{2}-\d{2}\.pdf"/);
  assert.equal((await get('/api/findings/ad-posture/report.pdf?domain=nope.example')).status, 400);
});

test('page: domain picker filters, scores with trend, inventory for one domain, off-state explains setup', () => {
  const p = evaluatePosture(raw(), { now: NOW });
  const data = { ...p, history: Object.fromEntries(p.domains.map(d => [d.name, historyFor(addToHistory(demoHistory(NOW), p), d.name)])) };
  const all = postureHtml({ data }, '', h);
  assert.match(all, /<select data-posture-domain><option value="" selected>All domains \(2\)/);
  assert.equal((all.match(/data-posture-score=/g) || []).length, 2);
  assert.match(all, /class="posture-spark"/);
  assert.match(all, /AD CS · ad\.northwind\.example/, 'all-domains view names the domain on each card');
  assert.doesNotMatch(all, /data-go=/, 'AD findings have no in-app view button');
  assert.match(all, /Not readable over this connection \(4\)/);
  const one = postureHtml({ data }, 'emea.ad.northwind.example', h);
  assert.match(one, /<option value="emea\.ad\.northwind\.example" selected>/);
  assert.equal((one.match(/data-posture-score=/g) || []).length, 1);
  assert.match(one, /Trusts \(1\)/);
  assert.match(one, /data-posture-pdf="emea\.ad\.northwind\.example"/);
  assert.doesNotMatch(one, /NW VPN User/);
  assert.match(postureHtml({ data: { status: 'off', message: 'AD posture needs Entity 360 running on Windows.' } }, '', h), /Set-E360AdReader\.ps1/);
  assert.match(postureHtml({ loading: true }, '', h), /Reading the forest/);
  assert.equal(sparkline([{ score: 10 }]), '');
  assert.match(sparkline([{ score: 10 }, { score: 90 }]), /aria-label="Score trend: 10, 90"/);
  // The existing cloud findings still render the fix link and the in-app view button.
  const cloud = findingsHtml({ data: { generated: '2026-11-25T00:00:00Z', findings: [{ id: 'x', title: 'X', severity: 'high', status: 'open', count: 1, rank: 1, why: 'w', items: [], playbook: { steps: ['s'], fix: { label: 'Fix', url: 'https://entra.microsoft.com/' }, guidance: 'https://learn.microsoft.com/', view: { key: 'emergency', label: 'E' } } }] } }, h);
  assert.match(cloud, /data-go="emergency"/);
});

test('collector script: read-only, same connection as the AD groups tab, wired into the check list', () => {
  const ps = readFileSync(POSTURE_SCRIPT, 'utf8');
  assert.doesNotMatch(ps, /CommitChanges|\bSet-AD|\bNew-AD|\bRemove-AD|\bAdd-AD|Set-ItemProperty|Remove-Item|\.Put\(|DeleteTree|Invoke-Command/i);
  assert.match(ps, /SecurityMasks\]::Dacl/);
  assert.match(ps, /Signing = \$false/);
  assert.match(ps, /\[CmdletBinding\(\)\]\s*param\(\s*\[string\]\$Server = '',\s*\[string\]\$CredentialPath = ''/);
  assert.match(read('package.json'), /node --check server\/ad-posture\.mjs/);
  assert.match(read('server/index.mjs'), /app\.get\('\/api\/findings\/ad-posture'/);
});

test('layout: passing and unreadable cards sit under their own headings, left-aligned one indent in; page is named Security hardening', () => {
  const card = (id, status) => ({ id, title: id, severity: 'high', status, count: status === 'open' ? 1 : status === 'pass' ? 0 : null, rank: status === 'open' ? 1 : null, why: 'w', reason: 'r', items: [], playbook: { steps: ['s'], guidance: 'https://learn.microsoft.com/' } });
  const html = groupedCards([card('a', 'open'), card('b', 'pass'), card('c', 'unavailable'), card('d', 'pass')], h);
  assert.ok(html.indexOf('data-finding="a"') < html.indexOf('Could not check (1)') && html.indexOf('Could not check (1)') < html.indexOf('Passing (2)'));
  assert.equal((html.match(/findings-list findings-sub/g) || []).length, 2);
  assert.doesNotMatch(groupedCards([card('b', 'pass')], h), /finding-rank/, 'no empty rank slot on unranked cards');
  const css = read('public/styles.css');
  assert.doesNotMatch(css, /(^|[}\s,])\.finding-pass,\.finding-na\{margin-left:auto/, 'margin-left:auto must not hit the card article, which also carries .finding-pass');
  assert.match(css, /\.finding-head \.finding-pass,\.finding-head \.finding-na\{margin-left:auto/);
  assert.match(css, /\.findings-list\.findings-sub\{padding:0 0 0 24px\}/);
  assert.equal(FINDINGS_TITLE[0], 'Security hardening');
  assert.match(read('public/index.html'), /data-view="findings" class="nav-item"><span data-nav-icon="clipboard-list"><\/span>Security hardening<\/a>/);
});
