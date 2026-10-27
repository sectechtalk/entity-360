import { createHash, randomUUID } from 'node:crypto';
import { execFile } from 'node:child_process';
import { fail } from './model.mjs';

// Client authentication with a certificate whose private key never leaves Azure Key Vault. Entity 360 builds the
// JWT client assertion locally, asks Key Vault to sign its SHA-256 digest (a Key Vault "sign" operation), and hands
// the finished assertion to MSAL through its client-assertion callback. No key material is ever read.

const b64url = input => Buffer.from(input).toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
const fromHexToB64url = hex => b64url(Buffer.from(hex, 'hex'));
const VAULT_HOST = /^[a-z0-9-]{3,24}\.vault\.azure\.net$/i;
const KEY_NAME = /^[A-Za-z0-9-]{1,127}$/;
const API_VERSION = '7.4';

export function validateVault(vaultUri, keyName) {
  let url;
  try { url = new URL(vaultUri); } catch { throw fail('The Key Vault address is not valid.', 500); }
  if (url.protocol !== 'https:' || !VAULT_HOST.test(url.hostname) || url.username || url.password || (url.pathname !== '/' && url.pathname !== '')) throw fail('The Key Vault address must be https://<name>.vault.azure.net.', 500);
  if (!KEY_NAME.test(keyName || '')) throw fail('The Key Vault key name is not valid.', 500);
  return { base: `https://${url.hostname}`, keyName };
}

// Thumbprint header: SHA-1 hex (40) becomes x5t, SHA-256 hex (64) becomes x5t#S256.
export function thumbprintHeader(hex) {
  const clean = String(hex || '').replace(/[^0-9a-f]/gi, '');
  if (clean.length === 40) return { 'x5t': fromHexToB64url(clean) };
  if (clean.length === 64) return { 'x5t#S256': fromHexToB64url(clean) };
  throw fail('The certificate thumbprint must be 40 (SHA-1) or 64 (SHA-256) hexadecimal characters.', 500);
}

export function signingInput({ clientId, tokenEndpoint, thumbprintHex, now = Date.now(), jti = randomUUID() }) {
  const iat = Math.floor(now / 1000);
  const header = { alg: 'RS256', typ: 'JWT', ...thumbprintHeader(thumbprintHex) };
  const payload = { aud: tokenEndpoint, iss: clientId, sub: clientId, jti, nbf: iat - 30, iat, exp: iat + 600 };
  return `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
}

// Short-lived Key Vault access token for the signed-in Azure person, from the Azure CLI. A hosted deployment would
// use a managed identity instead; this function is the only part that changes.
export function azureCliVaultToken({ run = execFile, platform = process.platform } = {}) {
  return new Promise((resolve, reject) => {
    const azArgs = ['account', 'get-access-token', '--resource', 'https://vault.azure.net', '-o', 'json'];
    // On Windows az is a .cmd file, so it is started through cmd.exe with one fixed command string (no user input).
    const [command, args] = platform === 'win32' ? ['cmd.exe', ['/d', '/s', '/c', ['az', ...azArgs].join(' ')]] : ['az', azArgs];
    run(command, args, { timeout: 30000, windowsHide: true, maxBuffer: 64 * 1024 }, (error, stdout) => {
      if (error) return reject(fail('Azure sign-in is needed to use the Key Vault certificate. Run az login.', 502));
      try {
        const data = JSON.parse(stdout);
        const expires = data.expires_on ? Number(data.expires_on) * 1000 : Date.parse(data.expiresOn);
        if (!data.accessToken || !Number.isFinite(expires)) throw new Error('shape');
        resolve({ token: data.accessToken, expires });
      } catch { reject(fail('Azure returned an unexpected token response.', 502)); }
    });
  });
}

// Hosted (Azure Container Apps / App Service): the system-assigned managed identity endpoint. No secret is stored;
// the platform injects IDENTITY_ENDPOINT and IDENTITY_HEADER into the container.
export async function managedIdentityVaultToken({ env = process.env, fetcher = fetch } = {}) {
  const url = new URL(env.IDENTITY_ENDPOINT);
  url.searchParams.set('resource', 'https://vault.azure.net');
  url.searchParams.set('api-version', '2019-08-01');
  let response;
  try { response = await fetcher(url, { headers: { 'X-IDENTITY-HEADER': env.IDENTITY_HEADER }, redirect: 'error', signal: AbortSignal.timeout(15000) }); }
  catch { throw fail('The managed identity endpoint could not be reached.', 502); }
  if (!response.ok) throw fail('The managed identity could not get a Key Vault token.', 502);
  const data = await response.json().catch(() => ({}));
  const expires = Number(data.expires_on) * 1000;
  if (!data.access_token || !Number.isFinite(expires)) throw fail('The managed identity returned an unexpected token response.', 502);
  return { token: data.access_token, expires };
}

// Managed identity when the platform provides one, otherwise the Azure CLI sign-in (local development).
export const defaultVaultToken = (env = process.env) => env.IDENTITY_ENDPOINT && env.IDENTITY_HEADER ? managedIdentityVaultToken({ env }) : azureCliVaultToken();

export function createKeyVaultAssertion({ vaultUri, keyName, clientId, thumbprintHex, getVaultToken = () => defaultVaultToken(), fetcher = fetch, now = () => Date.now() }) {
  const vault = validateVault(vaultUri, keyName);
  thumbprintHeader(thumbprintHex); // fail at startup, not at sign-in
  let cached = null;
  async function vaultToken() {
    if (cached && cached.expires - now() > 120000) return cached.token;
    cached = await getVaultToken();
    return cached.token;
  }
  // Same shape MSAL passes: { clientId, tokenEndpoint }. The clientId MSAL passes is ignored in favor of the
  // configured one so a changed request cannot name another application.
  return async function clientAssertion({ tokenEndpoint } = {}) {
    if (typeof tokenEndpoint !== 'string' || !tokenEndpoint.startsWith('https://login.microsoftonline.com/')) throw fail('Unexpected sign-in endpoint.', 500);
    const input = signingInput({ clientId, tokenEndpoint, thumbprintHex, now: now() });
    const digest = createHash('sha256').update(input).digest();
    let response;
    try {
      response = await fetcher(`${vault.base}/keys/${vault.keyName}/sign?api-version=${API_VERSION}`, {
        method: 'POST', redirect: 'error', signal: AbortSignal.timeout(20000),
        headers: { Authorization: `Bearer ${await vaultToken()}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ alg: 'RS256', value: b64url(digest) }),
      });
    } catch (e) {
      if (e?.status) throw e;
      throw fail('Key Vault could not be reached. Try again.', 502);
    }
    if (!response.ok) {
      cached = response.status === 401 ? null : cached;
      throw fail(response.status === 403 ? 'Key Vault refused the signing request. Your Azure role may be missing Key Vault Crypto User.' : 'Key Vault could not sign the sign-in assertion.', 502);
    }
    const data = await response.json().catch(() => ({}));
    if (typeof data.value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(data.value)) throw fail('Key Vault returned an unexpected signature.', 502);
    return `${input}.${data.value}`;
  };
}
