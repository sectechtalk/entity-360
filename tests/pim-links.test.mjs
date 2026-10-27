import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import { PIM_ACTIVATION_LINKS } from '../public/device-links.js';

test('My access has one Elevate (PIM) button group linking to the PIM activation pages in a new tab', async () => {
  assert.deepEqual(PIM_ACTIVATION_LINKS.map(([, u]) => u), [
    'https://entra.microsoft.com/#view/Microsoft_Azure_PIMCommon/ActivationMenuBlade/~/aadmigratedroles',
    'https://portal.azure.com/#view/Microsoft_Azure_PIMCommon/ActivationMenuBlade/~/azurerbac',
    'https://entra.microsoft.com/#view/Microsoft_Azure_PIMCommon/ActivationMenuBlade/~/aadgroup',
  ]);
  const account = await readFile(new URL('../public/account.js', import.meta.url), 'utf8');
  assert.match(account, /box\('Elevate \(PIM\)'.*PIM_ACTIVATION_LINKS\.map\(\(\[label, url\]\) => external\(url, label\)\)/);
  assert.match(account, /\$\('#my-access'\)\.innerHTML = elevate \+/);
  const app = await readFile(new URL('../public/app.js', import.meta.url), 'utf8');
  assert.match(app, /const external = [^\n]*target="_blank" rel="noopener noreferrer" class="\$\{cls \|\| 'btn'\}"/);
  const dir = new URL('../public/', import.meta.url);
  for (const f of (await readdir(dir)).filter(f => /\.(js|html)$/.test(f))) {
    const text = await readFile(new URL(f, dir), 'utf8');
    assert.equal(/ActivationMenuBlade/.test(text), f === 'device-links.js', `${f} must not repeat PIM activation links`);
  }
});
