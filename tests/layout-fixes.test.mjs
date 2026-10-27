import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { MicrosoftApi, requestHeaders, readBody, azurePim } from '../server/live.mjs';
import { describeError } from '../server/model.mjs';
import { bannerFor } from '../public/access-text.js';
import { myRoles } from '../server/my-roles.mjs';

const res = (status, body, raw) => ({ ok: status < 400, status, headers: { get: () => null }, async text() { return raw ?? JSON.stringify(body); } });

test('every Graph/ARM call sends Accept-Language en-US, never the fetch default "*"', async () => {
  assert.equal(requestHeaders('t')['Accept-Language'], 'en-US');
  const seen = [];
  const api = new MicrosoftApi(async () => 'tok', { fetcher: async (url, o) => { seen.push(o.headers); return res(200, { value: [] }); } });
  await api.pages('/v1.0/roleManagement/directory/roleAssignmentScheduleInstances');
  await api.pages('/subscriptions/s/providers/Microsoft.Authorization/roleEligibilityScheduleInstances?api-version=2020-10-01', { origin: 'https://management.azure.com' });
  assert.ok(seen.length === 2 && seen.every(h => h['Accept-Language'] === 'en-US'));
});

test('a bare or non-JSON ARM 400 still surfaces its body text', async () => {
  assert.deepEqual(await readBody(res(400, null, '')), {});
  const b = await readBody(res(400, null, '<html>Bad filter value</html>'));
  assert.match(b.error.message, /Bad filter value/);
  const api = new MicrosoftApi(async () => 'tok', { fetcher: async () => res(400, { error: { code: 'InvalidFilterInQueryString', message: 'The filter is not valid.' } }) });
  const e = await api.request('/subscriptions/s/x', { origin: 'https://management.azure.com' }).catch(e => e);
  assert.match(describeError(e), /HTTP 400 \(InvalidFilterInQueryString: The filter is not valid\.\)/);
});

test('Azure PIM URL: asTarget() for the signed-in user, assignedTo() for others, %20-encoded, api-version 2020-10-01', async () => {
  const urls = [];
  const api = { async pages(u) { urls.push(u); return { rows: [] }; } };
  await azurePim(api, 'sub1', 'roleAssignmentScheduleInstances', 'me', { self: true });
  await azurePim(api, 'sub1', 'roleEligibilityScheduleInstances', 'p1');
  assert.equal(urls[0], '/subscriptions/sub1/providers/Microsoft.Authorization/roleAssignmentScheduleInstances?api-version=2020-10-01&$filter=asTarget()');
  assert.equal(urls[1], "/subscriptions/sub1/providers/Microsoft.Authorization/roleEligibilityScheduleInstances?api-version=2020-10-01&$filter=assignedTo('p1')");
  assert.ok(!urls.some(u => u.includes('+')));
});

test('role rows always have a label', async () => {
  const api = { async pages(u) { return /roleAssignmentScheduleInstances/.test(u) && u.startsWith('/v1.0') ? { rows: [{ id: 'a', roleDefinitionId: 'r1' }, { id: 'b' }] } : { rows: [] }; }, async request() { return { data: [] }; } };
  const r = await myRoles(api, { id: 'me' }, []);
  assert.deepEqual(r.rows.map(x => x.name), ['r1', 'Unnamed role']);
  const js = await readFile(new URL('../public/account.js', import.meta.url), 'utf8');
  assert.match(js, /external\(accessLink\(r\), r\.name \|\| r\.id \|\| 'Open'\)/);
});

test('tables scroll horizontally; in-cell buttons size to their text', async () => {
  const css = await readFile(new URL('../public/styles.css', import.meta.url), 'utf8');
  assert.match(css, /\.table-wrap\{overflow-x:auto!important/);
  assert.match(css, /width:max-content!important;min-width:100%!important/);
  assert.match(css, /\.table-wrap td \.btn\{width:auto!important;max-width:none!important;flex:0 0 auto!important;white-space:nowrap!important\}/);
  for (const f of ['app.js', 'account.js', 'billing.js', 'defender.js', 'deployment.js', 'licenses.js', 'index.html']) {
    const src = await readFile(new URL(`../public/${f}`, import.meta.url), 'utf8');
    const tables = src.match(/.{0,60}<table/g) || [];
    for (const t of tables) assert.match(t, /table-wrap[^"]*"><table$/, `${f}: table not wrapped: ${t}`);
  }
});

test('Access banner lists only Access sources; Summary and Health list all', () => {
  const r = { partialReasons: [{ source: 'Entra roles & PIM', reason: 'x' }, { source: 'Entra sign-ins', reason: 'y' }], unavailable: [{ source: 'Intune devices', reason: 'z' }] };
  const access = bannerFor(r, 'access');
  assert.match(access, /Entra roles & PIM/); assert.ok(!/sign-ins|Intune/.test(access));
  for (const v of ['summary', 'health']) assert.match(bannerFor(r, v), /Entra sign-ins/);
});
