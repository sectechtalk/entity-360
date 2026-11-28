// Sign-in for the Entity 360 MCP server. It uses the same confidential registration as the web app (certificate in
// Key Vault, or the key file), so nothing on the app registration changes: no public-client flows, no new redirect URI.
// Entra ignores the port of a localhost redirect URI, so the registered http://localhost:3600/auth/callback also
// matches http://localhost:3602/auth/callback, where the one-time `sign-in` command listens.
//
// The MSAL token cache (refresh token) is stored in the MCP data folder. On Windows it is encrypted with DPAPI for the
// current Windows user, so another account on the PC, or a copy of the file, cannot use it.
import { ConfidentialClientApplication, CryptoProvider } from '@azure/msal-node';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { readFileSync } from 'node:fs';
import { mkdir, readFile, writeFile, rename, rm, chmod } from 'node:fs/promises';
import { GUID, fail } from './model.mjs';
import { MicrosoftApi } from './live.mjs';
import { rolesFromClaims, newPending, checkCallback } from './authflow.mjs';
import { ROLE_RECHECK_MS, signInRequired, errorDetail } from './role-recheck.mjs';
import { createKeyVaultAssertion } from './keyvault-assertion.mjs';
import { configuredScopes } from './index.mjs';

export const SIGNIN_PORT = 3602;
export const SIGN_IN_AGAIN = 'Entity 360 MCP is not signed in. On the Entity 360 PC run: node --env-file=.env server/mcp.mjs sign-in';
const ARM_SCOPE = 'https://management.azure.com/user_impersonation';

export function mcpDir(env = process.env) {
  if (env.E360_MCP_DIR) return path.resolve(env.E360_MCP_DIR);
  return env.LOCALAPPDATA ? path.join(env.LOCALAPPDATA, 'Entity360', 'mcp') : path.join(os.homedir(), '.entity360', 'mcp');
}

export function scopesFor(resource) {
  if (resource === 'azure') return [ARM_SCOPE];
  return configuredScopes.map(s => (s.startsWith('https://') ? s : `https://graph.microsoft.com/${s}`));
}

// DPAPI through Windows PowerShell: no native module. The text goes over stdin, never on a command line.
const PS = path.join(process.env.WINDIR || 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
const runPs = (script, input) => new Promise((resolve, reject) => {
  const child = execFile(PS, ['-NoProfile', '-NonInteractive', '-Command', script], { windowsHide: true, maxBuffer: 16 * 1024 * 1024, timeout: 30000 }, (error, stdout) => (error ? reject(fail('Windows could not protect the sign-in cache (DPAPI).', 500)) : resolve(stdout.trim())));
  child.stdin.end(input);
});
const PROTECT = "Add-Type -AssemblyName System.Security; $t=[Console]::In.ReadToEnd(); [Convert]::ToBase64String([Security.Cryptography.ProtectedData]::Protect([Text.Encoding]::UTF8.GetBytes($t),$null,'CurrentUser'))";
const UNPROTECT = "Add-Type -AssemblyName System.Security; $t=[Console]::In.ReadToEnd().Trim(); [Text.Encoding]::UTF8.GetString([Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String($t),$null,'CurrentUser'))";

export function defaultProtector(platform = process.platform) {
  if (platform === 'win32') return { kind: 'dpapi', protect: text => runPs(PROTECT, text), unprotect: text => runPs(UNPROTECT, text) };
  // Elsewhere (Linux/macOS development) the file is readable by this OS user only.
  return { kind: 'file-0600', protect: async text => text, unprotect: async text => text };
}

function credential(env, root) {
  const thumb = (env.ENTRA_CERT_THUMBPRINT || '').replace(/[^0-9a-f]/gi, '');
  if (env.ENTRA_KEYVAULT_URI && env.ENTRA_KEYVAULT_CERT_NAME) return { clientAssertion: createKeyVaultAssertion({ vaultUri: env.ENTRA_KEYVAULT_URI, keyName: env.ENTRA_KEYVAULT_CERT_NAME, clientId: env.ENTRA_CLIENT_ID, thumbprintHex: thumb }) };
  if (!env.ENTRA_CERT_PRIVATE_KEY_PATH) return null;
  const resolved = path.resolve(env.ENTRA_CERT_PRIVATE_KEY_PATH);
  if (resolved.toLowerCase().startsWith(root.toLowerCase())) throw fail('The certificate key must be stored outside the Entity 360 folder.', 500);
  const privateKey = readFileSync(resolved, 'utf8');
  return { clientCertificate: thumb.length === 64 ? { thumbprintSha256: thumb, privateKey } : { thumbprint: thumb, privateKey } };
}

export function openBrowser(url, { platform = process.platform, run = execFile } = {}) {
  if (platform === 'win32') run('rundll32.exe', ['url.dll,FileProtocolHandler', url], { windowsHide: true }, () => {});
  else if (platform === 'darwin') run('open', [url], () => {});
  else run('xdg-open', [url], () => {});
}

export function createAuth({ env = process.env, root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..'), dir = mcpDir(env), protector = defaultProtector(), createClient = options => new ConfidentialClientApplication(options), now = () => Date.now(), recheckMs = ROLE_RECHECK_MS } = {}) {
  const tenantId = env.ENTRA_TENANT_ID || '', clientId = env.ENTRA_CLIENT_ID || '';
  const thumb = (env.ENTRA_CERT_THUMBPRINT || '').replace(/[^0-9a-f]/gi, '');
  const configured = GUID.test(tenantId) && GUID.test(clientId) && [40, 64].includes(thumb.length) && Boolean(env.ENTRA_CERT_PRIVATE_KEY_PATH || (env.ENTRA_KEYVAULT_URI && env.ENTRA_KEYVAULT_CERT_NAME));
  const setting = (env.ENTITY360_REQUIRE_APP_ROLES || 'auto').toLowerCase();
  const enforce = setting !== 'false';
  const cacheFile = path.join(dir, 'token-cache.bin'), accountFile = path.join(dir, 'account.json');
  let memory = null, client = null, roleState = { at: 0, roles: [], failedAt: 0 }, azureState = { at: 0, ok: false };

  const save = async (file, text) => {
    await mkdir(dir, { recursive: true });
    await writeFile(`${file}.tmp`, text, { mode: 0o600 });
    await rename(`${file}.tmp`, file);
    await chmod(file, 0o600).catch(() => {});
  };
  const readCache = async () => { try { return await protector.unprotect(await readFile(cacheFile, 'utf8')); } catch (e) { if (e.code === 'ENOENT') return ''; throw e; } };
  const plugin = {
    beforeCacheAccess: async c => { if (memory === null) memory = await readCache(); if (memory) c.tokenCache.deserialize(memory); },
    afterCacheAccess: async c => { if (c.cacheHasChanged) { memory = c.tokenCache.serialize(); await save(cacheFile, await protector.protect(memory)); } },
  };
  const getClient = () => {
    if (!configured) throw fail('Entity 360 confidential sign-in is not configured in .env (ENTRA_TENANT_ID, ENTRA_CLIENT_ID, ENTRA_CERT_THUMBPRINT and a Key Vault key or key file).', 409);
    return client ||= createClient({ auth: { clientId, authority: `https://login.microsoftonline.com/${tenantId}`, ...credential(env, root) }, cache: { cachePlugin: plugin }, system: { loggerOptions: { loggerCallback: () => {}, piiLoggingEnabled: false } } });
  };
  const savedAccount = async () => { try { return JSON.parse(await readFile(accountFile, 'utf8')); } catch { return null; } };
  const account = async () => {
    const saved = await savedAccount();
    const found = saved?.homeAccountId ? await getClient().getTokenCache().getAccountByHomeId(saved.homeAccountId) : null;
    if (!found) throw fail(SIGN_IN_AGAIN, 401);
    return found;
  };
  const token = async (resource, forceRefresh = false) => {
    const acct = await account();
    try { return await getClient().acquireTokenSilent({ account: acct, scopes: scopesFor(resource), forceRefresh }); }
    catch (e) { if (resource === 'graph' && signInRequired(e)) throw fail(SIGN_IN_AGAIN, 401); throw Object.assign(fail(`Microsoft did not issue a ${resource === 'azure' ? 'Azure' : 'Graph'} token (${errorDetail(e)}).`, resource === 'graph' ? 502 : 403), { reason: errorDetail(e) }); }
  };

  // Roles come from a fresh ID token at most every recheckMs (the web app's pattern). If Entra cannot be reached the
  // roles are unconfirmed and role-gated tools fail closed until a re-check works.
  async function roles() {
    const t = now();
    if (t - roleState.at < recheckMs && !roleState.failedAt) return { roles: roleState.roles, unconfirmed: false };
    if (roleState.failedAt && t - roleState.failedAt < 30000) return { roles: roleState.roles, unconfirmed: true };
    const acct = await account();
    let result;
    try { result = await getClient().acquireTokenSilent({ account: acct, scopes: scopesFor('graph'), forceRefresh: true }); }
    catch (e) { if (signInRequired(e)) throw fail(SIGN_IN_AGAIN, 401); roleState = { ...roleState, failedAt: t }; return { roles: roleState.roles, unconfirmed: true }; }
    const c = result?.idTokenClaims || {};
    const oid = acct.idTokenClaims?.oid || acct.localAccountId;
    if (!c.tid || String(c.tid).toLowerCase() !== tenantId.toLowerCase() || (c.aud && c.aud !== clientId) || (oid && c.oid && String(c.oid).toLowerCase() !== String(oid).toLowerCase())) throw fail(SIGN_IN_AGAIN, 401);
    roleState = { at: t, roles: rolesFromClaims(c), failedAt: 0 };
    return { roles: roleState.roles, unconfirmed: false };
  }

  async function azureConnected() {
    if (now() - azureState.at < recheckMs) return azureState.ok;
    try { azureState = { at: now(), ok: Boolean((await token('azure'))?.accessToken) }; } catch { azureState = { at: now(), ok: false }; }
    return azureState.ok;
  }

  return {
    configured, enforce, dir, protector: protector.kind,
    async context({ maxPages = Math.max(1, Math.min(50, Number(env.MAX_PAGES) || 10)), fetcher = fetch } = {}) {
      const acct = await account();
      const r = await roles();
      const azure = await azureConnected();
      const api = new MicrosoftApi(async resource => {
        if (resource === 'azure' && !azure) throw fail('Azure is not connected for this sign-in.', 403);
        if (resource === 'logs') throw fail('Log Analytics is not used by the MCP server.', 403);
        return (await token(resource)).accessToken;
      }, { fetcher, maxPages });
      return { mode: 'live', api, tenant: tenantId, azure, roles: r.roles, rolesUnconfirmed: r.unconfirmed, enforce, requester: { upn: acct.username || null, objectId: acct.idTokenClaims?.oid || acct.localAccountId || null } };
    },
    async status() {
      const saved = await savedAccount();
      return { configured, signedIn: Boolean(saved), account: saved?.username || null, folder: dir, cacheProtection: protector.kind };
    },
    async signOut() {
      memory = null; client = null;
      await rm(cacheFile, { force: true }); await rm(accountFile, { force: true });
    },
    // One-time interactive sign-in: auth code + PKCE in the browser, back to a listener on 127.0.0.1 only.
    async signIn({ port = SIGNIN_PORT, open = openBrowser, log = m => process.stderr.write(`${m}\n`), timeoutMs = 5 * 60000 } = {}) {
      const cca = getClient();
      const pkce = await new CryptoProvider().generatePkceCodes();
      const pending = newPending(pkce, now());
      const redirectUri = `http://localhost:${port}/auth/callback`;
      const url = await cca.getAuthCodeUrl({ scopes: scopesFor('graph'), redirectUri, state: pending.state, nonce: pending.nonce, codeChallenge: pkce.challenge, codeChallengeMethod: 'S256', prompt: 'select_account' });
      return await new Promise((resolve, reject) => {
        let done = false;
        const finish = (error, value) => { if (done) return; done = true; clearTimeout(timer); server.close(); error ? reject(error) : resolve(value); };
        const page = (res, status, text) => { res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' }); res.end(`<!doctype html><meta charset="utf-8"><title>Entity 360 MCP</title><p>${text}</p>`); };
        const server = http.createServer(async (req, res) => {
          const u = new URL(req.url, redirectUri);
          if (u.pathname !== '/auth/callback') return page(res, 404, 'Not found.');
          const query = Object.fromEntries(u.searchParams);
          const problem = checkCallback(pending, query, now());
          if (problem) { page(res, 400, problem); return finish(fail(problem, 400)); }
          try {
            const result = await cca.acquireTokenByCode({ code: query.code, scopes: scopesFor('graph'), redirectUri, codeVerifier: pending.verifier, nonce: pending.nonce });
            if (!result?.account || result.account.tenantId?.toLowerCase() !== tenantId.toLowerCase()) throw fail('The account is not in the configured tenant.', 403);
            if (result.idTokenClaims?.nonce !== pending.nonce) throw fail('The sign-in response did not match this request.', 400);
            await save(accountFile, JSON.stringify({ homeAccountId: result.account.homeAccountId, username: result.account.username, tenantId, signedInAt: new Date(now()).toISOString() }));
            roleState = { at: now(), roles: rolesFromClaims(result.idTokenClaims), failedAt: 0 };
            page(res, 200, 'Entity 360 MCP is signed in. You can close this tab.');
            finish(null, { account: result.account.username, roles: roleState.roles });
          } catch (e) {
            const msg = e.status ? e.message : `Sign-in did not complete (${errorDetail(e)}).`;
            page(res, 400, msg.replace(/[&<>"']/g, ''));
            finish(fail(msg, 400));
          }
        });
        const timer = setTimeout(() => finish(fail('Sign-in timed out after 5 minutes. Run sign-in again.', 408)), timeoutMs);
        server.on('error', e => finish(fail(e.code === 'EADDRINUSE' ? `Port ${port} is in use. Close the other sign-in or pass --port.` : 'Could not start the sign-in listener.', 500)));
        server.listen(port, '127.0.0.1', () => { log(`Opening the Microsoft sign-in page. If no browser opens, go to:\n${url}`); open(url); });
      });
    },
  };
}
