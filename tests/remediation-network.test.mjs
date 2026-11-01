import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync, spawn } from 'node:child_process';
import { createServer } from 'node:net';
import { fileURLToPath } from 'node:url';

// Runs the Intune detection script in Windows PowerShell 5.1 against local mock targets. Skips off Windows.
const script = fileURLToPath(new URL('../remediations/Detect-E360NetworkConnectivity.ps1', import.meta.url));
const has = process.platform === 'win32' && spawnSync('powershell.exe', ['-NoProfile', '-Command', 'exit 0']).status === 0;
const run = (targets, extra = '') => new Promise(resolve => {
  const list = targets.map(t => `'${t}'`).join(',');
  const p = spawn('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', `& '${script}' -Targets @(${list}) ${extra}; exit $LASTEXITCODE`]);
  let out = '', err = '';
  p.stdout.on('data', d => out += d); p.stderr.on('data', d => err += d);
  p.on('close', code => resolve({ code, out, err }));
});
const one = out => { const lines = out.split(/\r?\n/).filter(Boolean); assert.equal(lines.length, 1, out); assert.ok(lines[0].length < 2048, `length ${lines[0].length}`); return JSON.parse(lines[0]); };

test('remediation: healthy local target gives one JSON line and exit 0', { skip: !has && 'powershell.exe not available' }, async () => {
  const server = createServer(s => s.end()).listen(0, '127.0.0.1');
  await new Promise(r => server.once('listening', r));
  try {
    const { code, out, err } = await run([`127.0.0.1:${server.address().port}`]);
    assert.equal(err, '');
    const j = one(out);
    assert.equal(code, 0); assert.equal(j.ok, true); assert.equal(j.pass, 1); assert.equal(j.r[0].tcp, 'ok');
    assert.equal(typeof j.r[0].ms, 'number'); assert.equal(j.pre.ok, true);
  } finally { server.close(); }
});

test('remediation: DNS failure, refused port and bad target give exit 1 with issues', { skip: !has && 'powershell.exe not available' }, async () => {
  const server = createServer().listen(0, '127.0.0.1');
  await new Promise(r => server.once('listening', r));
  const port = server.address().port; server.close();
  const { code, out } = await run(['nohost.invalid:443', `127.0.0.1:${port}`, 'not a target'], '-TcpTimeoutMs 1500');
  const j = one(out);
  assert.equal(code, 1); assert.equal(j.ok, false); assert.equal(j.pass, 0);
  assert.deepEqual(j.r.map(r => r.dns), ['fail', 'ok', 'bad']);
  assert.ok(['refused', 'timeout'].includes(j.r[1].tcp));
  assert.equal(j.issues.length, 3);
});

test('remediation: many failing targets are truncated to valid JSON under 2,048 chars', { skip: !has && 'powershell.exe not available' }, async () => {
  const many = Array.from({ length: 80 }, (_, i) => `bad target number ${i} with padding text`);
  const { code, out } = await run(many);
  const j = one(out);
  assert.equal(code, 1); assert.equal(j.total, 80); assert.ok(j.trunc); assert.ok(j.issues.length <= 10);
});

test('remediation script stays Windows PowerShell 5.1 safe and read-only', async () => {
  const { readFile } = await import('node:fs/promises');
  const s = await readFile(script, 'utf8');
  assert.ok(!/\?\?|\?\.|\s\?\s.+\s:\s|-Parallel|Set-Content|Out-File|New-Item|Remove-Item|Set-ItemProperty|Start-Process/.test(s.replace(/<#[\s\S]*?#>/, '')));
  for (const t of ['login.microsoftonline.com:443', 'graph.microsoft.com:443', 'manage.microsoft.com:443']) assert.ok(s.includes(`'${t}'`));
});
