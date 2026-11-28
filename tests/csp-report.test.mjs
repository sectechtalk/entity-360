// Trusted Types report-only: the header is sent, reports are parsed without keeping data, and repeats are counted once.
import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { parseReports, createCspReports, REPORT_ONLY_POLICY } from '../server/csp-report.mjs';
import { freePort } from './free-port.mjs';

const legacy = { 'csp-report': { 'document-uri': 'http://localhost:3600/?q=secret#signins', 'effective-directive': 'require-trusted-types-for', 'source-file': 'http://localhost:3600/app.js', 'line-number': 310, 'script-sample': 'Element innerHTML|<tr><td>alice@contoso.example' } };
const modern = [{ type: 'csp-violation', body: { documentURL: 'http://localhost:3600/', effectiveDirective: 'require-trusted-types-for', sourceFile: 'http://localhost:3600/pim.js', lineNumber: 165, sample: 'Element insertAdjacentHTML|<div>' } }];

test('policy: report-only Trusted Types for script sinks, reported to /csp-report', () => {
  assert.equal(REPORT_ONLY_POLICY, "require-trusted-types-for 'script'; report-uri /csp-report");
});

test('parseReports reads both report formats and keeps no query string or sample text', () => {
  assert.deepEqual(parseReports(legacy), [{ directive: 'require-trusted-types-for', page: '/', file: '/app.js', line: 310, sink: 'Element innerHTML' }]);
  assert.deepEqual(parseReports(modern), [{ directive: 'require-trusted-types-for', page: '/', file: '/pim.js', line: 165, sink: 'Element insertAdjacentHTML' }]);
  assert.doesNotMatch(JSON.stringify(parseReports(legacy)), /secret|alice/);
  assert.deepEqual(parseReports({ 'csp-report': { 'effective-directive': 'img-src' } }), [], 'other directives are ignored');
  assert.deepEqual(parseReports('junk'), []);
});

test('POST /csp-report logs each new violation once and counts repeats', async t => {
  const lines = [];
  const reports = createCspReports({ log: l => lines.push(l) });
  const app = express(); app.use(reports.router);
  const server = app.listen(0); await new Promise(r => server.once('listening', r)); t.after(() => server.close());
  const url = `http://127.0.0.1:${server.address().port}/csp-report`;
  for (let i = 0; i < 3; i++) {
    const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/csp-report' }, body: JSON.stringify(legacy) });
    assert.equal(r.status, 204);
  }
  await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/reports+json' }, body: JSON.stringify(modern) });
  assert.equal(lines.length, 2);
  assert.match(lines[0], /Element innerHTML at \/app\.js:310/);
  assert.deepEqual(reports.list().map(r => r.count), [3, 1]);
  const big = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/csp-report' }, body: JSON.stringify({ 'csp-report': { x: 'y'.repeat(20000) } }) });
  assert.equal(big.status, 413);
});

test('the app sends the report-only header next to the enforced CSP, and /csp-report needs no session', async t => {
  const p3797 = await freePort();
  const { createApp } = await import('../server/index.mjs');
  const server = createApp({ port: p3797, demoMode: true }).listen(p3797, '127.0.0.1');
  await new Promise(r => server.once('listening', r)); t.after(() => new Promise(r => server.close(r)));
  const page = await fetch(`http://127.0.0.1:${p3797}/`);
  assert.equal(page.headers.get('content-security-policy-report-only'), REPORT_ONLY_POLICY);
  assert.match(page.headers.get('content-security-policy'), /script-src 'self'/);
  const r = await fetch(`http://127.0.0.1:${p3797}/csp-report`, { method: 'POST', headers: { 'Content-Type': 'application/csp-report' }, body: JSON.stringify(legacy) });
  assert.equal(r.status, 204);
});
