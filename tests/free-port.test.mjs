// Test servers never use a fixed port (see free-port.mjs): fixed ports clashed across parallel test files and with
// Entity 360 and other apps running on the same PC, which hung the Windows test run.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { freePort } from './free-port.mjs';

const dir = fileURLToPath(new URL('.', import.meta.url));

test('freePort returns distinct usable ports', async () => {
  const a = await freePort(), b = await freePort();
  assert.ok(a > 0 && b > 0);
  assert.notEqual(a, b);
});

test('no test starts a server on a fixed port', () => {
  const bad = [];
  for (const f of readdirSync(dir).filter(f => f.endsWith('.test.mjs') || f.endsWith('harness.mjs'))) {
    readFileSync(dir + f, 'utf8').split('\n').forEach((l, i) => {
      if (/\.listen\(\s*\d{2,5}\b|\b(?:boot|start|signedIn)\(t,\s*\d{2,5}\b|\b(?:PORT|port)\s*=\s*\d{2,5}\b|startHarness\(t,\s*\{\s*port:\s*\d|\b(?:goto|fetch)\(\s*['\"`]https?:\/\/(?:127\.0\.0\.1|localhost):\d/.test(l)) bad.push(`${f}:${i + 1}`);
    });
  }
  assert.deepEqual(bad, []);
});

test('tests never read a real domain controller (tests/test-env.mjs is loaded by npm test)', () => {
  assert.equal(process.env.E360_AD_ENABLED, 'false');
});
