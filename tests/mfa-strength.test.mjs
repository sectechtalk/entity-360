// AUTHENTICATION > MFA strength: the ranked ladder, tenant state per method, CA acceptance and setup guides.
import test from 'node:test';
import assert from 'node:assert/strict';
import { loadPage } from '../server/bucket5.mjs';
import { LADDER, methodState, mfaPolicies, verdictFor, strengthRows, AUTHENTICATOR_AAGUIDS } from '../server/pages/strength.mjs';
import { pageHtml } from '../public/bucket5.js';

const esc = v => String(v ?? '').replace(/[&<>"']/g, c => `&#${c.charCodeAt(0)};`);
const h = { esc, external: (u, l) => `<a class="btn" href="${u}">${esc(l)}</a>`, emptyBox: t => `<div class="inline-empty">${esc(t)}</div>` };
function fakeApi(fixtures = {}) {
  const calls = [];
  const hit = u => Object.entries(fixtures).find(([k]) => u.includes(k))?.[1];
  return { calls,
    request: async u => { calls.push(u); const f = hit(u); if (f instanceof Error) throw f; return f ?? {}; },
    pages: async u => { calls.push(u); const f = hit(u); if (f instanceof Error) throw f; return { rows: f?.value || f || [] }; } };
}
const row = id => LADDER.find(r => r.id === id);

// A tenant like the lab: Authenticator (any mode), FIDO2 on, SMS and voice off, CBA off; one CA policy requires MFA.
export const LAB = {
  authenticationMethodsPolicy: { policyMigrationState: 'migrationComplete', authenticationMethodConfigurations: [
    { id: 'microsoftAuthenticator', state: 'enabled', includeTargets: [{ id: 'all_users', authenticationMode: 'any' }] },
    { id: 'fido2', state: 'enabled', isAttestationEnforced: false, keyRestrictions: { isEnforcementEnabled: false } },
    { id: 'sms', state: 'disabled' }, { id: 'voice', state: 'disabled' }, { id: 'x509Certificate', state: 'disabled' },
    { id: 'softwareOath', state: 'disabled' }, { id: 'hardwareOath', state: 'disabled' }, { id: 'temporaryAccessPass', state: 'enabled' }] },
  userRegistrationDetails: [
    { userPrincipalName: 'admin@x', methodsRegistered: ['windowsHelloForBusiness', 'passKeyDeviceBoundAuthenticator', 'microsoftAuthenticatorPush', 'microsoftAuthenticatorPasswordless', 'softwareOneTimePasscode'] },
    { userPrincipalName: 'lab1@x', methodsRegistered: ['microsoftAuthenticatorPush', 'softwareOneTimePasscode'] }],
  'conditionalAccess/policies': [
    { displayName: 'Require MFA for admins', state: 'enabled', grantControls: { operator: 'OR', builtInControls: ['mfa'] } },
    { displayName: 'Phishing-resistant for Azure', state: 'enabledForReportingButNotEnforced', grantControls: { authenticationStrength: { id: '00000000-0000-0000-0000-000000000004' } } }],
  authenticationStrengthPolicies: [
    { id: '00000000-0000-0000-0000-000000000004', displayName: 'Phishing-resistant MFA', policyType: 'builtIn', allowedCombinations: ['windowsHelloForBusiness', 'fido2', 'x509CertificateMultiFactor'] }],
};

test('the ladder keeps the runbook order: 12 rows, phishing-resistant first, SMS and voice last', () => {
  assert.equal(LADDER.length, 12);
  assert.deepEqual(LADDER.slice(0, 6).map(r => Boolean(r.pr)), [true, true, true, true, true, true]);
  assert.deepEqual(LADDER.slice(6).map(r => r.pr), [false, false, false, false, false, false]);
  assert.deepEqual(LADDER.slice(-2).map(r => r.id), ['sms', 'voice']);
  for (const r of LADDER) assert.ok(r.guide?.why && r.guide.steps?.length && r.guide.learn, r.id);
});

test('method state reads the Authentication methods policy', () => {
  const p = LAB.authenticationMethodsPolicy;
  assert.equal(methodState(row('fido2Key'), p).text, 'On');
  assert.equal(methodState(row('syncedPasskey'), p).on, true);
  assert.equal(methodState(row('whfb'), p).text, 'Set in Windows or Intune');
  assert.equal(methodState(row('sms'), p).on, false);
  assert.equal(methodState(row('totp'), p).text, 'On (in Authenticator)');
  assert.equal(methodState(row('phoneSignIn'), p).on, true);
  assert.equal(methodState(row('fido2Key'), null).text, 'Not read');
});

test('attestation, key restrictions, CBA binding and Authenticator mode change the state', () => {
  const cfg = (...c) => ({ authenticationMethodConfigurations: c });
  const attested = cfg({ id: 'fido2', state: 'enabled', isAttestationEnforced: true });
  assert.equal(methodState(row('syncedPasskey'), attested).text, 'Blocked (attestation enforced)');
  const keysOnly = cfg({ id: 'fido2', state: 'enabled', keyRestrictions: { isEnforcementEnabled: true, enforcementType: 'allow', aaGuids: ['cb69481e-8ff7-4039-93ec-0a2729a154a8'] } });
  assert.equal(methodState(row('authenticatorPasskey'), keysOnly).text, 'Blocked by key restrictions');
  const withAuth = cfg({ id: 'fido2', state: 'enabled', keyRestrictions: { isEnforcementEnabled: true, enforcementType: 'allow', aaGuids: [AUTHENTICATOR_AAGUIDS[0].toUpperCase()] } });
  assert.equal(methodState(row('authenticatorPasskey'), withAuth).on, true);
  const single = cfg({ id: 'x509Certificate', state: 'enabled', authenticationModeConfiguration: { x509CertificateAuthenticationDefaultMode: 'x509CertificateSingleFactor' } });
  assert.deepEqual(methodState(row('cba'), single), { text: 'On (single-factor: not MFA)', on: false });
  const pushOnly = cfg({ id: 'microsoftAuthenticator', state: 'enabled', includeTargets: [{ id: 'all_users', authenticationMode: 'push' }] });
  assert.equal(methodState(row('phoneSignIn'), pushOnly).text, 'Off (push only)');
  assert.equal(methodState(row('push'), pushOnly).on, true);
});

test('only enabled policies that require MFA or a strength count, with their combinations', () => {
  const pols = mfaPolicies(LAB['conditionalAccess/policies'], LAB.authenticationStrengthPolicies);
  assert.deepEqual(pols.map(p => p.name), ['Require MFA for admins']);
  assert.ok(pols[0].combos.includes('password,sms'));
  const strict = mfaPolicies([{ displayName: 'PR', state: 'enabled', grantControls: { authenticationStrength: { id: '00000000-0000-0000-0000-000000000004' } } }], LAB.authenticationStrengthPolicies);
  assert.deepEqual(strict[0].combos, ['windowsHelloForBusiness', 'fido2', 'x509CertificateMultiFactor']);
});

test('the verdict names the weakest method that is on, registered and accepted', () => {
  const pols = mfaPolicies(LAB['conditionalAccess/policies'], LAB.authenticationStrengthPolicies);
  const rows = strengthRows(LAB.authenticationMethodsPolicy, LAB.userRegistrationDetails, pols);
  const v = verdictFor(rows, pols);
  assert.equal(v.status, 'Warning');
  assert.match(v.headline, /Password \+ Authenticator code/);
  const strict = mfaPolicies([{ displayName: 'PR', state: 'enabled', grantControls: { authenticationStrength: { allowedCombinations: ['fido2', 'windowsHelloForBusiness'] } } }]);
  assert.equal(verdictFor(strengthRows(LAB.authenticationMethodsPolicy, LAB.userRegistrationDetails, strict), strict).status, 'OK');
  const sms = { authenticationMethodConfigurations: [{ id: 'sms', state: 'enabled' }] };
  assert.equal(verdictFor(strengthRows(sms, [{ methodsRegistered: ['mobilePhone'] }], pols), pols).status, 'Needs attention');
});

test('the page renders the ladder, guides for what is missing, and makes no write call', async () => {
  const api = fakeApi(LAB);
  const d = await loadPage(api, 'a-strength');
  assert.ok(api.calls.every(u => !/PATCH|POST/.test(u)));
  const [ladder, guides, policies] = d.tables;
  assert.equal(ladder.rows.length, 12);
  assert.deepEqual(ladder.rows[1].slice(4), [{ badge: true, text: 'Set in Windows or Intune', tone: 'info' }, '1', '1 of 1']);
  assert.equal(ladder.rows[10][4].tone, 'pass'); // SMS off is the good state
  assert.ok(guides.guides.some(g => g.title.startsWith('4. Certificate-based')));
  assert.deepEqual(guides.guides.map(g => g.title.split('.')[0]), ['3', '4', '9']); // WHfB registered, SMS and voice already off
  const smsOn = await loadPage(fakeApi({ ...LAB, authenticationMethodsPolicy: { authenticationMethodConfigurations: [{ id: 'sms', state: 'enabled' }] } }), 'a-strength');
  assert.match(smsOn.tables[1].guides.find(g => g.title.startsWith('11.')).code, /state = 'disabled'/);
  assert.deepEqual(policies.rows, [['Require MFA for admins', 'Password + Authenticator code (6-digit TOTP)']]);
  assert.equal(d.verdict.status, 'Warning');
  const html = pageHtml('a-strength', { data: d }, h);
  assert.match(html, /<details class="b5-guide">/);
  assert.match(html, /x509CertificateMultiFactor/);
  assert.match(html, /health-pass">Off/);
  assert.doesNotMatch(html, /—/);
});

test('a failed registration read becomes a note and counts show Not read', async () => {
  const d = await loadPage(fakeApi({ ...LAB, userRegistrationDetails: Object.assign(new Error('x'), { status: 403 }) }), 'a-strength');
  assert.equal(d.tables[0].rows[0][5], 'Not read');
  assert.ok(d.notes.some(n => n.startsWith('Registration report')));
});
