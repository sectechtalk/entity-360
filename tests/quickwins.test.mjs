// Quick wins (2026-10-27): sign-in method, sign-in risk, CA controls, app credential expiry and consent type,
// custom vs built-in roles and app-scoped role assignments, and the two delegated scopes the code already used.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { signInCells, methodLabel, riskLabel, signInColumns } from '../public/signin-columns.js';
import { normalizeSignIn } from '../server/signins.mjs';
import { caControls } from '../server/access.mjs';
import { resolveScopes } from '../server/live.mjs';

const read = p => readFileSync(new URL(`../${p}`, import.meta.url), 'utf8');
const NEW_SCOPES = ['EntitlementManagement.Read.All', 'AdministrativeUnit.Read.All'];

test('scope fix: .env.example and the server default request EntitlementManagement and AdministrativeUnit (delegated)', () => {
  const env = read('.env.example').match(/^GRAPH_SCOPES=(.*)$/m)[1].split(',');
  const def = read('server/index.mjs').match(/process\.env\.GRAPH_SCOPES \|\| '([^']+)'/)[1].split(',');
  for (const s of NEW_SCOPES) { assert.ok(env.includes(s), `.env.example missing ${s}`); assert.ok(def.includes(s), `server default missing ${s}`); }
  assert.deepEqual([...env].sort(), [...def].sort(), '.env.example and the server default list the same scopes');
  assert.ok(!env.some(s => /\.ReadWrite\./.test(s)), 'read-only scopes only');
});

test('Authentication requirement shows the sign-in method (passkey, TAP, certificate)', () => {
  const ev = methods => normalizeSignIn({ id: 'r', createdDateTime: '2026-10-27T10:00:00Z', status: { errorCode: 0 }, authenticationRequirement: 'multiFactorAuthentication', authenticationDetails: methods }, 'u@x.test', 'beta');
  assert.equal(signInCells(ev([{ authenticationMethod: 'Passkey (device-bound)', succeeded: true }])).authReq, 'Multifactor authentication: Passkey (device-bound)');
  assert.equal(signInCells(ev([{ authenticationMethod: 'Temporary Access Pass', succeeded: true }])).authReq, 'Multifactor authentication: TAP');
  assert.equal(signInCells(ev([{ authenticationMethod: 'X.509 Certificate', succeeded: true }])).authReq, 'Multifactor authentication: Certificate');
  assert.equal(methodLabel([{ method: 'Password', succeeded: true }, { method: 'Microsoft Authenticator (push notification)', succeeded: false }]), 'Password');
  assert.equal(methodLabel([{ method: 'Previously satisfied', succeeded: true }]), 'Previously satisfied');
  assert.equal(signInCells(ev([])).authReq, 'Multifactor authentication');
  assert.equal(signInCells({ ...ev([{ authenticationMethod: 'Password', succeeded: true }]), version: 'v1.0' }).authReq, '\u2014', 'v1.0 still shows the beta-only dash');
});

test('Risk column reads riskLevelDuringSignIn and riskState', () => {
  const e = normalizeSignIn({ id: 'r', createdDateTime: '2026-10-27T10:00:00Z', riskLevelDuringSignIn: 'medium', riskState: 'atRisk' }, 'u@x.test', 'v1.0');
  assert.deepEqual(e.risk, { level: 'medium', state: 'atRisk' });
  assert.equal(signInCells(e).risk, 'Medium (At risk)');
  assert.equal(riskLabel({ level: 'none', state: 'none' }), 'None');
  assert.equal(riskLabel({ level: 'hidden' }), 'Hidden (needs Entra ID P2)');
  assert.equal(riskLabel({}), 'n/a');
  assert.ok(signInColumns().some(c => c.key === 'si.risk' && c.label === 'Risk'));
  assert.match(read('public/signins.js'), /<td>\$\{esc\(c\.risk\)\}<\/td>/);
});

test('Conditional Access Controls column summarizes grant and session controls', () => {
  assert.equal(caControls({ grantControls: { operator: 'OR', builtInControls: ['mfa', 'compliantDevice'] } }), 'Require MFA or Compliant device');
  assert.equal(caControls({ grantControls: { operator: 'AND', builtInControls: ['mfa'], authenticationStrength: { displayName: 'Phishing-resistant MFA' } }, sessionControls: { signInFrequency: { isEnabled: true, value: 4, type: 'hours' }, persistentBrowser: { isEnabled: true, mode: 'never' } } }), 'Require MFA and Auth strength: Phishing-resistant MFA; Sign-in every 4 hours; Persistent browser: never');
  assert.equal(caControls({ grantControls: { builtInControls: ['block'] } }), 'Block');
  assert.equal(caControls({ sessionControls: { signInFrequency: { isEnabled: true, frequencyInterval: 'everyTime' } } }), 'Sign-in every time');
  assert.equal(caControls({}), 'None returned');
  const live = read('server/live.mjs'), app = read('public/app.js');
  assert.match(live, /controls: caControls\(p\.evidence\)/); assert.match(live, /controls: caControls\(p\)/);
  assert.match(app, /<th>Policy<\/th><th>Result<\/th><th>Controls<\/th><th>Reason<\/th>/);
});

test('App permissions: Expires column for credentials and admin vs user consent values', () => {
  const live = read('server/live.mjs'), app = read('public/app.js');
  assert.match(live, /kind: 'Credential', expires: c\.endDateTime/);
  assert.match(live, /'Admin consent \(all users\)' : `User consent \(\$\{g\.principalId\}\)`, consent:/);
  assert.match(app, /<th>Date<\/th><th>Expires<\/th>/);
  assert.match(app, /const appVia = p => p\.consent \? `\$\{p\.consent\} consent`/);
});

test('Admin roles: custom vs built-in under Type, app-scoped assignments under Scope', async () => {
  const live = read('server/live.mjs'), app = read('public/app.js');
  assert.equal((live.match(/builtIn: r\.roleDefinition\?\.isBuiltIn \?\? null/g) || []).length, 3, 'active, eligible and PIM-group roles carry isBuiltIn');
  assert.match(app, /p\.builtIn === true \? 'Built-in' : p\.builtIn === false \? 'Custom'/);
  assert.match(app, /resultBadge\(x\.type\)\}<small>\$\{esc\(x\.definition\)\}<\/small>/);
  const fakeId = n => `00000000-0000-0000-0000-${String(n).padStart(12, '0')}`;
  const sp = fakeId(11), app1 = fakeId(12);
  const api = { async request(p) { return p.includes(sp) ? { '@odata.type': '#microsoft.graph.servicePrincipal', displayName: 'Payroll' } : { '@odata.type': '#microsoft.graph.application', displayName: 'Reg' }; } };
  const pols = [{ evidence: { directoryScopeId: `/${sp}` } }, { evidence: { directoryScopeId: `/${app1}` } }];
  await resolveScopes(api, pols, { unavailable: [] });
  assert.deepEqual(pols.map(p => p.scopeName), ['App: Payroll', 'App: Reg']);
  assert.ok(pols.every(p => p.appScoped));
});

test('one .btn style and no demo mode introduced by these changes', () => {
  const app = read('public/app.js');
  assert.doesNotMatch(app, /class="btn-[a-z]/);
  assert.doesNotMatch(read('server/access.mjs'), /demo/i);
});
