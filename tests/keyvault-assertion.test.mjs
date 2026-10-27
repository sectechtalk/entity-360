// These tests exercise demo routes; the hosted default is DEMO_MODE off.
process.env.DEMO_MODE ??= 'true';
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createVerify, generateKeyPairSync, createSign } from 'node:crypto';
import { createKeyVaultAssertion, signingInput, thumbprintHeader, validateVault, azureCliVaultToken } from '../server/keyvault-assertion.mjs';

const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const CLIENT = '00000000-0000-4000-8000-0000000000a3';
const THUMB = '00000000000000000000000000000000000000E1';
const VAULT = 'https://kv-e360-auth-xxxxx.vault.azure.net';
const ENDPOINT = 'https://login.microsoftonline.com/00000000-0000-4000-8000-0000000000a1/oauth2/v2.0/token';
const b64url = b => Buffer.from(b).toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
const decode = part => JSON.parse(Buffer.from(part.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'));

// A fake Key Vault: signs the digest it is given with a real RSA key, like the real sign operation does.
function fakeVault(log = []) {
  return async (url, options) => {
    log.push({ url: String(url), options });
    const body = JSON.parse(options.body);
    // sign(digest) with RSA PKCS#1 v1.5 SHA-256: wrap the digest in the DigestInfo structure
    const prefix = Buffer.from('3031300d060960864801650304020105000420', 'hex');
    const { privateEncrypt } = await import('node:crypto');
    const sig = privateEncrypt({ key: privateKey, padding: 1 }, Buffer.concat([prefix, Buffer.from(body.value.replace(/-/g, '+').replace(/_/g, '/'), 'base64')]));
    return { ok: true, status: 200, json: async () => ({ kid: 'x', value: b64url(sig) }) };
  };
}

test('thumbprint header: SHA-1 becomes x5t, SHA-256 becomes x5t#S256, anything else is refused', () => {
  assert.deepEqual(Object.keys(thumbprintHeader(THUMB)), ['x5t']);
  assert.deepEqual(Object.keys(thumbprintHeader('a'.repeat(64))), ['x5t#S256']);
  assert.equal(thumbprintHeader(THUMB).x5t, b64url(Buffer.from(THUMB, 'hex')));
  assert.throws(() => thumbprintHeader('abc'));
});

test('vault address and key name are validated', () => {
  assert.equal(validateVault(VAULT, 'entity360-auth').base, VAULT);
  for (const bad of ['http://kv.vault.azure.net', 'https://evil.example.com', 'https://kv-x.vault.azure.net.evil.com', 'https://user:pw@kv-e360-auth-xxxxx.vault.azure.net', 'https://kv-e360-auth-xxxxx.vault.azure.net/keys']) assert.throws(() => validateVault(bad, 'k'), /Key Vault address/, bad);
  assert.throws(() => validateVault(VAULT, '../x'), /key name/);
});

test('assertion is a valid RS256 JWT: correct claims, thumbprint header, signature verifies with the public key', async () => {
  const log = [];
  const make = createKeyVaultAssertion({ vaultUri: VAULT, keyName: 'entity360-auth', clientId: CLIENT, thumbprintHex: THUMB, getVaultToken: async () => ({ token: 'vault-token', expires: Date.now() + 3600000 }), fetcher: fakeVault(log) });
  const jwt = await make({ tokenEndpoint: ENDPOINT, clientId: 'ignored' });
  const [h, p, s] = jwt.split('.');
  assert.deepEqual(decode(h), { alg: 'RS256', typ: 'JWT', x5t: b64url(Buffer.from(THUMB, 'hex')) });
  const claims = decode(p);
  assert.equal(claims.iss, CLIENT);
  assert.equal(claims.sub, CLIENT);
  assert.equal(claims.aud, ENDPOINT);
  assert.ok(claims.exp - claims.iat <= 600 && claims.exp > claims.iat);
  assert.ok(claims.jti);
  const ok = createVerify('RSA-SHA256').update(`${h}.${p}`).verify(publicKey, Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64'));
  assert.equal(ok, true);
  // what was sent to the vault: only a digest, to the sign operation of the named key, with the bearer token
  assert.match(log[0].url, /^https:\/\/kv-e360-auth-xxxxx\.vault\.azure\.net\/keys\/entity360-auth\/sign\?api-version=/);
  assert.equal(log[0].options.headers.Authorization, 'Bearer vault-token');
  const sent = JSON.parse(log[0].options.body);
  assert.equal(sent.alg, 'RS256');
  assert.equal(sent.value, b64url(createHash('sha256').update(`${h}.${p}`).digest()));
});

test('the vault token is cached until it is near expiry, then renewed', async () => {
  let calls = 0, clock = 1_000_000;
  const make = createKeyVaultAssertion({ vaultUri: VAULT, keyName: 'entity360-auth', clientId: CLIENT, thumbprintHex: THUMB, now: () => clock, getVaultToken: async () => { calls++; return { token: 't' + calls, expires: clock + 600000 }; }, fetcher: fakeVault() });
  await make({ tokenEndpoint: ENDPOINT }); await make({ tokenEndpoint: ENDPOINT });
  assert.equal(calls, 1);
  clock += 600000 - 60000; // less than two minutes left
  await make({ tokenEndpoint: ENDPOINT });
  assert.equal(calls, 2);
});

test('failures are sanitized: no token or vault detail reaches the caller', async () => {
  const make = status => createKeyVaultAssertion({ vaultUri: VAULT, keyName: 'entity360-auth', clientId: CLIENT, thumbprintHex: THUMB, getVaultToken: async () => ({ token: 'SECRET-TOKEN', expires: Date.now() + 3600000 }), fetcher: async () => ({ ok: false, status, json: async () => ({ error: { message: 'SECRET detail' } }) }) });
  await assert.rejects(() => make(403)({ tokenEndpoint: ENDPOINT }), e => /Key Vault Crypto User/.test(e.message) && !/SECRET/.test(e.message));
  await assert.rejects(() => make(500)({ tokenEndpoint: ENDPOINT }), e => /could not sign/.test(e.message) && !/SECRET/.test(e.message));
  const unreachable = createKeyVaultAssertion({ vaultUri: VAULT, keyName: 'entity360-auth', clientId: CLIENT, thumbprintHex: THUMB, getVaultToken: async () => ({ token: 't', expires: Date.now() + 3600000 }), fetcher: async () => { throw new Error('ECONNRESET SECRET'); } });
  await assert.rejects(() => unreachable({ tokenEndpoint: ENDPOINT }), e => /could not be reached/.test(e.message) && !/SECRET/.test(e.message));
  const odd = createKeyVaultAssertion({ vaultUri: VAULT, keyName: 'entity360-auth', clientId: CLIENT, thumbprintHex: THUMB, getVaultToken: async () => ({ token: 't', expires: Date.now() + 3600000 }), fetcher: async () => ({ ok: true, status: 200, json: async () => ({ value: '<script>' }) }) });
  await assert.rejects(() => odd({ tokenEndpoint: ENDPOINT }), /unexpected signature/);
});

test('only the Microsoft sign-in endpoint is accepted as audience', async () => {
  const make = createKeyVaultAssertion({ vaultUri: VAULT, keyName: 'entity360-auth', clientId: CLIENT, thumbprintHex: THUMB, getVaultToken: async () => ({ token: 't', expires: Date.now() + 3600000 }), fetcher: fakeVault() });
  await assert.rejects(() => make({ tokenEndpoint: 'https://evil.example.com/token' }), /Unexpected sign-in endpoint/);
  await assert.rejects(() => make({}), /Unexpected sign-in endpoint/);
});

test('Azure CLI token helper parses the CLI output and reports a clean error otherwise', async () => {
  const ok = await azureCliVaultToken({ platform: 'linux', run: (cmd, args, opts, cb) => { assert.equal(cmd, 'az'); assert.ok(args.includes('https://vault.azure.net')); cb(null, JSON.stringify({ accessToken: 'abc', expires_on: String(Math.floor(Date.now() / 1000) + 3600) })); } });
  assert.equal(ok.token, 'abc');
  await assert.rejects(() => azureCliVaultToken({ platform: 'win32', run: (cmd, args, opts, cb) => { assert.equal(cmd, 'cmd.exe'); assert.equal(args[3], 'az account get-access-token --resource https://vault.azure.net -o json'); assert.equal(opts.shell, undefined); cb(new Error('ERROR: SECRET'), ''); } }), e => /az login/.test(e.message) && !/SECRET/.test(e.message));
  await assert.rejects(() => azureCliVaultToken({ platform: 'linux', run: (c, a, o, cb) => cb(null, 'not json') }), /unexpected token response/);
});

test('MSAL receives a callback, not key material, when Key Vault signing is on', async () => {
  const mod = await import('../server/index.mjs');
  let options;
  const app = mod.createApp({ port: 3655, confidential: true, useKeyVault: true, makeAssertion: () => async () => 'jwt', createConfidential: o => { options = o; return { getAuthCodeUrl: async () => 'https://login.example.test/authorize?state=x' }; } });
  const server = app.listen(3655, '127.0.0.1');
  await new Promise(r => server.once('listening', r));
  try {
    const first = await fetch('http://127.0.0.1:3655/api/session');
    const cookie = first.headers.get('set-cookie').split(';')[0];
    const res = await fetch('http://127.0.0.1:3655/auth/login', { redirect: 'manual', headers: { Cookie: cookie } });
    assert.equal(res.status, 302);
    assert.equal(typeof options.auth.clientAssertion, 'function');
    assert.equal(options.auth.clientCertificate, undefined);
  } finally { await new Promise(r => server.close(r)); }
});
