import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { signInCells, signInColumns, BETA_ONLY } from '../public/signin-columns.js';
const read = f => readFileSync(new URL('../' + f, import.meta.url), 'utf8');
test('beta-only sign-in fields show a dash on v1.0 and values on beta', () => {
  const v1 = signInCells({ version: 'v1.0', code: 50126, agentType: 'x', authRequirement: 'multiFactorAuthentication' });
  assert.equal(v1.agent, BETA_ONLY); assert.equal(v1.authReq, BETA_ONLY); assert.equal(v1.code, '50126');
  const b = signInCells({ version: 'beta', code: 0, agentType: 'notAgentic', authRequirement: 'multiFactorAuthentication' });
  assert.equal(b.agent, 'Not agentic'); assert.equal(b.authReq, 'Multifactor authentication');
});
test('Date, Request ID and IP are not filterable; categories are', () => {
  const off = signInColumns().filter(c => c.filter === false).map(c => c.label);
  assert.deepEqual(off, ['Date', 'Request ID', 'IP address']);
});
test('server maps agentType and authenticationRequirement', () => {
  const s = read('server/signins.mjs');
  assert.match(s, /agentType: s\.agent\?\.agentType/); assert.match(s, /authRequirement: s\.authenticationRequirement/);
});
test('all four Investigate tables move filters into headers', () => {
  const a = read('public/app.js'), si = read('public/signins.js');
  assert.ok((a.match(/filtersIntoHeaders\(/g) || []).length >= 3); assert.match(si, /filtersIntoHeaders\(box/);
  assert.match(a, /devCols\(i\)/); assert.match(a, /roles\.role/); assert.match(a, /apps\.role/);
  assert.match(si, /colspan="10"/); assert.doesNotMatch(read('public/index.html'), /<th scope="col">User<\/th>/);
});
