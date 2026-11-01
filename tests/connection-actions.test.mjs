import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
const app = readFileSync(new URL('../public/app.js', import.meta.url), 'utf8');
const actions = app.slice(app.indexOf('<div class="conn-actions">'), app.indexOf('<div id="login-status"'));

test('connection panel shows one account action: Sign in when signed out, Sign out all connections when signed in', () => {
  assert.match(actions, /\['live', 'personal'\]\.includes\(s\.mode\) \? `[^`]*Sign out all connections<\/button>` : '<button id="microsoft-login" class="btn">Sign in with Microsoft/);
  assert.equal((actions.match(/id="microsoft-login"/g) || []).length, 1);
  assert.equal((actions.match(/id="logout-button"/g) || []).length, 1);
});

test('Connect Azure shows only when Azure access is missing; no Renew buttons', () => {
  assert.match(actions, /s\.mode === 'live' && !s\.azureConnected \? '<button id="azure-login" class="btn">Connect Azure<\/button>'/);
  assert.doesNotMatch(app, /Renew Azure access|Renew log access/);
  assert.match(app, /s\.logsConfigured && !s\.logsConnected\) \{\s*\$\('#logout-button'\)\.insertAdjacentHTML\('beforebegin'/);
  for (const b of actions.match(/<button[^>]*>/g)) assert.match(b, /class="btn"/);
});
