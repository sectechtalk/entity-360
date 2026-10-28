import express from 'express';
import { PublicClientApplication, ConfidentialClientApplication, CryptoProvider } from '@azure/msal-node';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import os from 'node:os';
import { mkdtemp, readFile, unlink, rmdir } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { accountReport, demoAccountReport, normalizeSnapshot } from './account.mjs';
import { intuneHealthReport, demoIntuneReport } from './intune.mjs';
import { decide, DecisionLog, rolesFromClaims, newPending, checkCallback, APP_ROLES } from './authflow.mjs';
import { createKeyVaultAssertion } from './keyvault-assertion.mjs';
import { connectionPlan, connectionKey } from './connections.mjs';
import { licenseReport, demoLicenseReport, personalAccountReport } from './licenses.mjs';
import { samePrincipalConnections, discoverTenants, aggregateContexts } from './portfolio.mjs';
import { billingReport, demoBillingReport } from './billing.mjs';
import { GUID, fail, timeRange } from './model.mjs';
import { profiles, searchDemo, demoReport } from './demo.mjs';
import { MicrosoftApi, searchLive, liveReport, activityReport, defenderReport, DEFENDER_DAYS } from './live.mjs';
import { deviceStates } from './access.mjs';
import { LAB_SIGNIN_USERS, lookupOptions, signInLookup, demoSignInLookup } from './signins.mjs';
import { hostingLinks, hostingIngress } from './hosting.mjs';
import { tabTable, whatIf, B3_DEFERRED } from './bucket3.mjs';
import { breakGlass, workspaces, runSavedQuery, B4_DEFERRED } from './bucket4.mjs';
import { loadPage as loadTenantPage } from './bucket5.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const configuredScopes = (process.env.GRAPH_SCOPES || 'User.Read,User.Read.All,Application.Read.All,GroupMember.Read.All,AuditLog.Read.All,Policy.Read.All,RoleManagement.Read.Directory,DeviceManagementManagedDevices.Read.All,ThreatHunting.Read.All,Device.Read.All,Organization.Read.All,DeviceManagementConfiguration.Read.All,DeviceManagementServiceConfig.Read.All,EntitlementManagement.Read.All,AdministrativeUnit.Read.All,PrivilegedEligibilitySchedule.Read.AzureADGroup').split(',').map(s => s.trim()).filter(Boolean);
const tenantId = process.env.ENTRA_TENANT_ID || '';
const clientId = process.env.ENTRA_CLIENT_ID || '';
const isConfigured = GUID.test(tenantId) && GUID.test(clientId);
const personalClientId = process.env.PERSONAL_CLIENT_ID || '';
// Confidential-client sign-in (authorization code + PKCE + certificate). The private key stays in a file outside this
// folder; only its path and the certificate thumbprint are configured. No client secret is supported.
const certThumbprint = (process.env.ENTRA_CERT_THUMBPRINT || '').replace(/[^0-9a-f]/gi, '');
const certKeyPath = process.env.ENTRA_CERT_PRIVATE_KEY_PATH || '';
// Preferred: the key stays in Azure Key Vault and the vault signs the assertion (no key file at all).
const kvUri = process.env.ENTRA_KEYVAULT_URI || '';
const kvKeyName = process.env.ENTRA_KEYVAULT_CERT_NAME || '';
const confidentialConfigured = isConfigured && [40, 64].includes(certThumbprint.length) && (Boolean(certKeyPath) || Boolean(kvUri && kvKeyName));
const appRolesSetting = (process.env.ENTITY360_REQUIRE_APP_ROLES || 'auto').toLowerCase();
const enforceAppRoles = appRolesSetting === 'true' || (appRolesSetting === 'auto' && confidentialConfigured);
const connectionConfig = { defaultTenant: tenantId, organizationClientId: clientId, personalClientId, allowMultipleTenants: process.env.ALLOW_MULTI_TENANT === 'true' };
const workspaceIds = (process.env.LOG_ANALYTICS_WORKSPACE_IDS || '').split(',').map(s => s.trim()).filter(s => GUID.test(s));
let telemetryRoles = {};
try { telemetryRoles = JSON.parse(process.env.TELEMETRY_ENTITY_ROLES || '{}'); } catch { throw new Error('TELEMETRY_ENTITY_ROLES must be valid JSON.'); }
const TTL = 8 * 60 * 60 * 1000;

function loadCertificate() {
  const resolved = path.resolve(certKeyPath);
  if (resolved.toLowerCase().startsWith(root.toLowerCase())) throw fail('The certificate key must be stored outside the Entity 360 folder.', 500);
  const privateKey = readFileSync(resolved, 'utf8');
  return certThumbprint.length === 64 ? { thumbprintSha256: certThumbprint, privateKey } : { thumbprint: certThumbprint, privateKey };
}

export function createApp({ port = Number(process.env.PORT || 3600), createMsal = options => new PublicClientApplication(options), createConfidential = options => new ConfidentialClientApplication(options), certificate = () => loadCertificate(), apiFetcher = fetch, confidential = confidentialConfigured, enforceRoles = enforceAppRoles, demoMode = process.env.DEMO_MODE === 'true',
  publicBaseUrl = process.env.PUBLIC_BASE_URL || '', useKeyVault = Boolean(kvUri && kvKeyName), makeAssertion = () => createKeyVaultAssertion({ vaultUri: kvUri, keyName: kvKeyName, clientId, thumbprintHex: certThumbprint }) } = {}) {
  const app = express();
  const sessions = new Map();
  const decisions = new DecisionLog();
  // Hosted mode (e.g. Azure Container Apps): PUBLIC_BASE_URL=https://<fqdn>. TLS ends at the platform ingress, so the
  // proxy is trusted, cookies are Secure, and only the public host/origin (plus localhost for probes) is accepted.
  const publicUrl = publicBaseUrl ? new URL(publicBaseUrl) : null;
  if (publicUrl && (publicUrl.protocol !== 'https:' || publicUrl.pathname.replace(/\/$/, '') !== '')) throw new Error('PUBLIC_BASE_URL must be https://<host> with no path.');
  const allowedHosts = [`localhost:${port}`, `127.0.0.1:${port}`, ...(publicUrl ? [publicUrl.host] : [])];
  const allowedOrigins = [`http://localhost:${port}`, `http://127.0.0.1:${port}`, ...(publicUrl ? [publicUrl.origin] : [])];
  const redirectUri = process.env.ENTRA_REDIRECT_URI || (publicUrl ? `${publicUrl.origin}/auth/callback` : `http://localhost:${port}/auth/callback`);
  const secureCookie = Boolean(publicUrl);
  app.disable('x-powered-by');
  if (publicUrl) app.set('trust proxy', 1);
  app.use((req, res, next) => {
    if (!allowedHosts.includes(req.headers.host)) return res.status(403).json({ error: 'This app accepts local requests only.' });
    res.set({ 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'X-Frame-Options': 'DENY', 'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-src https://login.microsoftonline.com; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'" });
    if (req.path.startsWith('/api/')) {
      res.set('Cache-Control', 'no-store');
      if (req.headers['sec-fetch-site'] === 'cross-site') return res.status(403).json({ error: 'Cross-site requests are not allowed.' });
      if (req.headers.origin && !allowedOrigins.includes(req.headers.origin)) return res.status(403).json({ error: 'Invalid request origin.' });
    }
    next();
  });
  app.use(express.json({ limit: '256kb' }));
  const sessionMiddleware = (req, res, next) => {
    const now = Date.now();
    for (const [key, session] of sessions) if (now - session.lastUsed > TTL) { session.cancelled = true; if (session.authRequest) session.authRequest.cancel = true; sessions.delete(key); }
    const cookie = (req.headers.cookie || '').split(';').map(c => c.trim()).find(c => c.startsWith('entity360='))?.slice(10);
    let session = sessions.get(cookie);
    if (!session) {
      const sid = randomBytes(32).toString('hex');
      // DEMO_MODE off (the hosted default): a new session is signed out, never demo.
      session = { id: sid, mode: demoMode ? 'demo' : 'signedout', profile: 'analyst', csrf: randomBytes(24).toString('hex'), lastUsed: now, resources: new Set(), login: null, connections: new Map(), authType: null, appRoles: [] };
      sessions.set(sid, session);
      // Lax, not Strict: the browser must send this cookie on the top-level GET back from login.microsoftonline.com to /auth/callback,
      // or the pending sign-in is lost. Cross-site POSTs still carry no cookie, and every non-GET also needs the CSRF header.
    }
    // Rolling expiry: refresh the cookie on every request so an active user is never cut off by maxAge.
    res.cookie('entity360', session.id, { httpOnly: true, sameSite: 'lax', secure: secureCookie, maxAge: TTL, path: '/' });
    session.lastUsed = now;
    req.session = session;
    if (!['GET', 'HEAD'].includes(req.method) && req.headers['x-csrf-token'] !== session.csrf) return res.status(403).json({ error: 'Refresh the page before trying again.' });
    next();
  };
  app.use(['/api', '/auth'], sessionMiddleware);
  // Signed-out sessions get 401 plus the sign-in path, never fixture data. Only session and sign-in routes stay open.
  const signedOutOpen = ['/session', '/logout', '/authz/log', '/auth/start', '/auth/status', '/auth/cancel'];
  app.use('/api', (req, res, next) => {
    if (demoMode || req.session.mode !== 'signedout' || signedOutOpen.includes(req.path)) return next();
    res.status(401).json({ error: 'Sign in with Microsoft first.', signin: '/auth/login' });
  });
  // Feature authorization. App roles open Entity 360 features; sources still enforce the viewer's own permissions.
  app.use('/api', (req, res, next) => {
    const s = req.session;
    const full = '/api' + req.path;
    const result = decide({ mode: s.mode === 'demo' ? 'demo' : 'live', path: full, roles: s.appRoles || [], enforce: enforceRoles && s.authType === 'confidential' });
    if (result.needed || !result.allowed) decisions.add({ user: s.account?.username, tenant: s.tenantId, path: full, outcome: result.allowed ? 'allowed' : 'denied', reason: result.reason, needed: result.needed });
    if (!result.allowed) return res.status(403).json({ error: 'Your Entity 360 roles do not include this feature.', requiredRole: result.needed });
    next();
  });
  const publicSession = s => ({
    mode: s.mode, csrf: s.csrf, configured: isConfigured,
    demoMode, signin: confidential ? '/auth/login' : null,
    viewer: s.mode === 'signedout' ? { name: 'Signed out', email: '', role: 'Not signed in' } : s.mode !== 'demo' ? { name: s.account?.name || s.account?.username, email: s.account?.username, id: s.account?.localAccountId, role: s.mode === 'personal' ? 'Personal Microsoft account' : 'Microsoft delegated access' } : { name: profiles[s.profile].name, email: profiles[s.profile].email, role: profiles[s.profile].role },
    personalConfigured: GUID.test(personalClientId), defaultTenant: tenantId, activeTenant: s.tenantId, multiTenantEnabled: connectionConfig.allowMultipleTenants, activeConnection: s.connectionKey,
    connections: [...s.connections.entries()].map(([key, c]) => ({ key, type: c.mode, tenant: c.tenantId, name: c.account.name || c.account.username, email: c.account.username })),
    profile: s.mode === 'demo' ? s.profile : undefined,
    azureConnected: s.resources.has('azure'), azureConnectMode: s.authType === 'confidential' ? 'redirect' : 'device-code',
    logsConnected: s.resources.has('logs'), logsConfigured: workspaceIds.length > 0,
    betaEnabled: process.env.ENABLE_GRAPH_BETA === 'true',
    signInDefaults: s.mode === 'demo' ? ['alex.morgan@contoso.example', 'jordan.lee@contoso.example'] : s.account?.username ? [s.account.username] : LAB_SIGNIN_USERS,
    labSignInUsers: s.mode === 'demo' ? ['alex.morgan@contoso.example', 'jordan.lee@contoso.example'] : LAB_SIGNIN_USERS,
    serverHost: os.hostname(), localCollectionSupported: process.platform === 'win32',
    authType: s.authType || (s.mode === 'demo' ? 'demo' : 'device-code'), appRoles: s.appRoles || [], rolesEnforced: enforceRoles && s.authType === 'confidential', confidentialSignIn: confidential, knownRoles: APP_ROLES,
  });
  const scopesFor = (resource, s = {}) => resource === 'azure' ? ['https://management.azure.com/user_impersonation'] : resource === 'logs' ? ['https://api.loganalytics.io/Data.Read'] : (s.mode === 'personal' ? ['User.Read'] : configuredScopes).map(s => s.startsWith('https://') ? s : `https://graph.microsoft.com/${s}`);
  const liveApi = s => {
    if (!['live', 'personal'].includes(s.mode) || !s.account || !s.msal) throw fail('Sign in with Microsoft first.', 401);
    const context = { mode: s.mode, account: s.account, msal: s.msal, resources: new Set(s.resources) };
    return new MicrosoftApi(async resource => {
      if (!context.resources.has(resource)) throw fail('Not connected.', 403);
      const scopes = scopesFor(resource, context);
      for (const forceRefresh of [false, true]) {
        try {
          const token = await context.msal.acquireTokenSilent({ account: context.account, scopes, forceRefresh });
          if (token?.accessToken) return token.accessToken;
        } catch { /* retry once with forceRefresh, then fall through */ }
      }
      // Only a Graph failure ends the session. An Azure or Log Analytics failure needs a reconnect, not a new sign-in.
      if (resource !== 'graph') { s.resources.delete(resource); throw fail(`${resource === 'logs' ? 'Log Analytics' : 'Azure'} access needs to be reconnected. Use Connect Azure to renew it.`, 403); }
      throw fail('Sign in again to renew delegated access.', 401);
    }, { fetcher: apiFetcher, maxPages: Math.max(1, Math.min(50, Number(process.env.MAX_PAGES) || 10)) });
  };
  // Confidential path: Azure (ARM) and Log Analytics tokens come silently from the signed-in account's refresh token,
  // which is multi-resource. Device code stays only for the local public-client mode.
  const silentResource = async (s, resource) => {
    if (s.authType !== 'confidential' || s.mode !== 'live' || !s.msal || !s.account) return false;
    if (resource === 'logs' && !workspaceIds.length) return false;
    try {
      const token = await s.msal.acquireTokenSilent({ account: s.account, scopes: scopesFor(resource, s) });
      if (!token?.accessToken) return false;
      s.resources.add(resource);
      return true;
    } catch (e) {
      s.silentErrors = { ...(s.silentErrors || {}), [resource]: e.errorCode || e.name || 'silent_failed' };
      return false;
    }
  };
  app.get('/api/hosting', async (req, res) => {
    const s = req.session;
    if (!s?.mode || s.mode === 'demo') return res.json({ groups: [] });
    const groups = hostingLinks();
    groups[0].status = s.mode === 'live' && s.resources?.has('azure') ? await hostingIngress(liveApi(s)) : 'Ingress: connect Azure to read';
    res.json({ groups });
  });
  app.get('/api/session', async (req, res) => {
    const s = req.session;
    if (s.authType === 'confidential' && !s.resources.has('azure') && !s.silentTried) { s.silentTried = true; await silentResource(s, 'azure'); await silentResource(s, 'logs'); }
    res.json(publicSession(s));
  });
  app.post('/api/demo', (req, res) => {
    if (!demoMode) throw fail('Demo mode is off. Set DEMO_MODE=true to use it locally.', 404);
    if (!Object.hasOwn(profiles, req.body.profile || 'analyst')) throw fail('Unknown demo profile.');
    const s = req.session;
    s.cancelled = true;
    if (s.authRequest) s.authRequest.cancel = true;
    s.mode = 'demo'; s.profile = req.body.profile || 'analyst'; s.authType = null; s.appRoles = []; s.pending = null; s.account = null; s.msal = null; s.resources = new Set(); s.login = null; s.connections.clear(); s.tenantId = null; s.connectionKey = null;
    res.json(publicSession(s));
  });
  app.get('/auth/login', async (req, res) => {
    const s = req.session;
    if (!confidential) return res.status(409).type('text/plain').send('Confidential sign-in is not configured. Set ENTRA_TENANT_ID, ENTRA_CLIENT_ID, ENTRA_CERT_THUMBPRINT and ENTRA_CERT_PRIVATE_KEY_PATH.');
    // Resume after a lost session (restart or scale-to-zero): reuse the last account as a hint and skip the account picker,
    // so Entra SSO can complete without a prompt.
    const hintCookie = (req.headers.cookie || '').split(';').map(c => c.trim()).find(c => c.startsWith('entity360hint='))?.slice(14);
    let resumeHint = null;
    try { resumeHint = req.query.resume === '1' && hintCookie ? decodeURIComponent(hintCookie) : null; } catch { resumeHint = null; }
    if (resumeHint && !/^[^\s@;,]+@[^\s@;,]+$/.test(resumeHint)) resumeHint = null;
    const pkce = await new CryptoProvider().generatePkceCodes();
    s.pending = newPending(pkce);
    const cca = createConfidential({ auth: { clientId, authority: `https://login.microsoftonline.com/${tenantId}`, ...(useKeyVault ? { clientAssertion: makeAssertion() } : { clientCertificate: certificate() }) }, system: { loggerOptions: { loggerCallback: () => {}, piiLoggingEnabled: false } } });
    s.pendingClient = cca;
    const url = await cca.getAuthCodeUrl({ scopes: scopesFor('graph', { mode: 'live' }), redirectUri, state: s.pending.state, nonce: s.pending.nonce, codeChallenge: pkce.challenge, codeChallengeMethod: 'S256', ...(resumeHint ? { loginHint: resumeHint } : { prompt: 'select_account' }) });
    res.redirect(url);
  });
  // Incremental consent for Azure or Log Analytics on the confidential client: auth code + PKCE, same account, back to the app.
  app.get('/auth/connect', async (req, res) => {
    const s = req.session;
    const resource = req.query.resource === 'logs' ? 'logs' : 'azure';
    if (!confidential || s.authType !== 'confidential' || !s.msal || !s.account) return res.redirect('/auth/login');
    const pkce = await new CryptoProvider().generatePkceCodes();
    s.pending = { ...newPending(pkce), resource };
    s.pendingClient = s.msal;
    const url = await s.msal.getAuthCodeUrl({ scopes: scopesFor(resource, s), redirectUri, state: s.pending.state, nonce: s.pending.nonce, codeChallenge: pkce.challenge, codeChallengeMethod: 'S256', loginHint: s.account.username });
    res.redirect(url);
  });
  app.get('/auth/callback', async (req, res) => {
    const s = req.session;
    const pending = s.pending, cca = s.pendingClient;
    s.pending = null; s.pendingClient = null; // single use
    const problem = checkCallback(pending, req.query);
    const failWith = message => { s.login = { status: 'error', error: message }; decisions.add({ path: '/auth/callback', outcome: 'denied', reason: message }); return res.redirect('/auth/error'); };
    if (problem || !cca) return failWith(problem || 'No sign-in is in progress. Start again.');
    try {
      const extra = pending.resource && pending.resource !== 'graph' ? pending.resource : null;
      const result = await cca.acquireTokenByCode({ code: req.query.code, scopes: scopesFor(extra || 'graph', { mode: 'live' }), redirectUri, codeVerifier: pending.verifier, nonce: pending.nonce });
      if (extra) {
        if (!result?.account || result.account.homeAccountId !== s.account?.homeAccountId) throw new Error('different_account');
        if (result.idTokenClaims?.nonce && result.idTokenClaims.nonce !== pending.nonce) throw new Error('nonce');
        s.resources.add(extra); s.login = { status: 'complete' };
        decisions.add({ user: result.account.username, tenant: tenantId, path: '/auth/callback', outcome: 'allowed', reason: `connected ${extra} by redirect consent` });
        return res.redirect('/');
      }
      if (!result?.account || result.account.tenantId?.toLowerCase() !== tenantId.toLowerCase()) throw new Error('wrong_tenant');
      if (result.idTokenClaims?.nonce !== pending.nonce) throw new Error('nonce');
      const key = connectionKey(result.account, tenantId);
      const roles = rolesFromClaims(result.idTokenClaims);
      s.msal = cca; s.account = result.account; s.mode = 'live'; s.tenantId = tenantId; s.connectionKey = key; s.resources = new Set(['graph']); s.authType = 'confidential'; s.appRoles = roles;
      if (result.account?.username) res.cookie('entity360hint', result.account.username, { httpOnly: true, sameSite: 'lax', secure: secureCookie, maxAge: 30 * 24 * 3600 * 1000, path: '/auth' });
      s.connections.set(key, { msal: cca, account: result.account, mode: 'live', tenantId, resources: s.resources });
      s.login = { status: 'complete' };
      await silentResource(s, 'azure');
      await silentResource(s, 'logs');
      decisions.add({ user: result.account.username, tenant: tenantId, path: '/auth/callback', outcome: 'allowed', reason: `azure ${s.resources.has('azure') ? 'connected silently' : 'needs consent'}; signed in; app roles: ${roles.join(', ') || 'none'}; sign-in methods (amr): ${[].concat(result.idTokenClaims?.amr || []).join(', ') || 'not in token'}` });
      res.redirect('/');
    } catch (e) {
      // Keep Entra's own codes (AADSTSnnnnn, MSAL errorCode/subError) so a Conditional Access refusal can be told apart from a certificate problem.
      const detail = [e.errorCode, e.subError, /AADSTS\d+/.exec(String(e.errorMessage || e.message || ''))?.[0]].filter(Boolean).join(' / ');
      failWith(e.message === 'different_account' ? 'Use the same Microsoft account you signed in with.' : e.message === 'wrong_tenant' ? 'The account is not in the configured tenant.' : `Sign-in did not complete. Check the registration, the certificate and your organization’s sign-in policy.${detail ? ` (${detail})` : ''}`);
    }
  });
  // A failed sign-in shows Entra's error (AADSTS code) here instead of dropping into demo data.
  app.get('/auth/error', (req, res) => {
    const msg = String(req.session.login?.error || 'Sign-in did not complete.').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
    res.status(401).type('html').send(`<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Entity 360 sign-in failed</title></head><body><h1>Sign-in failed</h1><p id="signin-error">${msg}</p><p><a href="/auth/login">Try signing in again</a></p></body></html>`);
  });
  app.get('/api/authz/log', (req, res) => res.json({ rows: decisions.list(100), enforced: enforceRoles && req.session.authType === 'confidential', roles: req.session.appRoles || [] }));
  app.post('/api/auth/start', async (req, res) => {
    const s = req.session;
    if (s.login?.status === 'pending') throw fail('A sign-in is already in progress.', 409);
    const plan = connectionPlan(req.body, connectionConfig, s);
    const resource = plan.resource;
    if (resource !== 'graph' && !s.account) throw fail('Connect your Microsoft account first.');
    if (resource === 'logs' && !workspaceIds.length) throw fail('Configure at least one Log Analytics workspace ID first.');
    if (s.authType === 'confidential' && resource !== 'graph') {
      if (await silentResource(s, resource)) { s.login = { status: 'complete', resource }; return res.json({ status: 'complete', session: publicSession(s) }); }
      return res.json({ status: 'redirect', url: `/auth/connect?resource=${resource}` });
    }
    s.cancelled = false;
    const msal = createMsal({ auth: { clientId: plan.clientId, authority: `https://login.microsoftonline.com/${plan.authorityTenant}` }, system: { loggerOptions: { loggerCallback: () => {}, piiLoggingEnabled: false } } });
    // Separate acquisition object until sign-in succeeds; a cancelled flow cannot replace a session.
    const login = { status: 'pending', resource, started: Date.now() };
    s.login = login;
    const priorAccount = s.account;
    const priorMsal = s.msal;
    if (priorMsal && s.tenantId === plan.tenant && s.mode === (plan.personal ? 'personal' : 'live')) msal.getTokenCache().deserialize(priorMsal.getTokenCache().serialize());
    const authRequest = { scopes: scopesFor(resource, { mode: plan.personal ? 'personal' : 'live' }), deviceCodeCallback: response => {
      login.code = response.userCode;
      login.verificationUri = response.verificationUri;
      login.expiresAt = new Date(Date.now() + response.expiresIn * 1000).toISOString();
    }, cancel: false };
    s.authRequest = authRequest;
    msal.acquireTokenByDeviceCode(authRequest).then(result => {
      if (s.cancelled || s.login !== login) return;
      if (!result?.account || result.account.tenantId?.toLowerCase() !== plan.tenant.toLowerCase()) throw new Error('wrong_tenant');
      if (resource !== 'graph' && priorAccount?.homeAccountId !== result.account.homeAccountId) throw new Error('different_account');
      const key = connectionKey(result.account, plan.tenant);
      s.resources = resource === 'graph' ? (s.connectionKey === key ? s.resources : new Set()) : s.resources;
      s.msal = msal; s.account = result.account; s.mode = plan.personal ? 'personal' : 'live'; s.tenantId = plan.tenant; s.connectionKey = key; s.resources.add(resource);
      s.connections.set(key, { msal, account: result.account, mode: s.mode, tenantId: plan.tenant, resources: s.resources });
      login.status = 'complete'; delete login.code;
    }).catch(error => {
      if (s.login !== login) return;
      login.status = 'error';
      login.error = error.message === 'different_account' ? 'Use the same Microsoft account for both connections.' : error.message === 'wrong_tenant' ? 'The account is not in the configured tenant.' : 'Sign-in did not complete. Check app consent, public-client configuration, and your organization’s sign-in policy, then retry.';
      delete login.code;
    });
    res.json({ status: 'pending' });
  });
  app.get('/api/auth/status', (req, res) => {
    const s = req.session;
    if (s.login?.status === 'pending' && Date.now() - s.login.started > 16 * 60000) { s.login.status = 'error'; s.login.error = 'Sign-in expired. Try again.'; s.cancelled = true; }
    res.json({ ...(s.login || { status: 'idle' }), session: publicSession(s) });
  });
  app.post('/api/auth/cancel', (req, res) => { req.session.cancelled = true; if (req.session.authRequest) req.session.authRequest.cancel = true; req.session.login = null; res.json({ ok: true }); });
  app.post('/api/connections/switch', (req, res) => {
    const s = req.session;
    if (s.login?.status === 'pending') throw fail('Cancel or finish the pending sign-in before switching.', 409);
    const c = s.connections.get(req.body.key);
    if (!c) throw fail('Connect this account and tenant in this browser session first.', 404);
    Object.assign(s, c, { connectionKey: req.body.key, login: null });
    res.json(publicSession(s));
  });
  app.post('/api/logout', (req, res) => {
    req.session.cancelled = true;
    if (req.session.authRequest) req.session.authRequest.cancel = true;
    sessions.delete(req.session.id);
    res.clearCookie('entity360', { path: '/', httpOnly: true, sameSite: 'lax', secure: secureCookie });
    res.clearCookie('entity360hint', { path: '/auth', httpOnly: true, sameSite: 'lax', secure: secureCookie });
    res.json({ ok: true });
  });
  app.get('/api/entities', async (req, res) => {
    if (req.session.mode === 'personal') throw fail('Use My account & device or Licenses for a personal account.', 409);
    const q = String(req.query.q || '').trim().slice(0, 150);
    res.json(req.session.mode === 'demo' ? { entities: searchDemo(q), partial: false } : await searchLive(liveApi(req.session), q, req.session.tenantId));
  });
  app.get('/api/investigate', async (req, res) => {
    if (req.session.mode === 'personal') throw fail('Organizational investigation needs an organizational connection.', 409);
    const range = timeRange(req.query.from, req.query.to);
    const id = String(req.query.id || '');
    if (!GUID.test(id)) throw fail('Invalid entity identifier.');
    const report = req.session.mode === 'demo' ? demoReport(id, range, req.session.profile) : await liveReport(liveApi(req.session), id, String(req.query.type), range, { tenant: req.session.tenantId, beta: process.env.ENABLE_GRAPH_BETA === 'true', azure: req.session.resources.has('azure'), logs: req.session.resources.has('logs'), workspaceIds, telemetryRoles });
    if (!report) throw fail('Entity not found.', 404);
    res.json(report);
  });
  // Azure activity log runs only when the user clicks the button. days: whole number 1 to 90, default 1.
  app.get('/api/activity', async (req, res) => {
    if (req.session.mode === 'personal') throw fail('The Azure activity log needs an organizational connection.', 409);
    const id = String(req.query.id || '');
    if (!GUID.test(id)) throw fail('Invalid entity identifier.');
    const raw = req.query.days === undefined ? '1' : String(req.query.days);
    if (!/^\d{1,2}$/.test(raw) || Number(raw) < 1 || Number(raw) > 90) throw fail('Lookback must be a whole number of days from 1 to 90.');
    const type = ['user', 'application', 'managedIdentity'].includes(String(req.query.type)) ? String(req.query.type) : 'user';
    if (req.session.mode === 'demo') return res.json({ events: [], days: Number(raw), partial: false, notes: ['Demo mode has no Azure activity log.'], source: null });
    if (!req.session.resources.has('azure')) throw fail('Connect Azure to load the activity log.', 409);
    res.json(await activityReport(liveApi(req.session), id, type, Number(raw), { tenant: req.session.tenantId }));
  });
  // Defender process events run only on the Defender tab. days: 1, 3, 7, 14 or 30 (default 1) to stay under the 1,000-row cap.
  app.get('/api/defender', async (req, res) => {
    if (req.session.mode === 'personal') throw fail('Defender hunting needs an organizational connection.', 409);
    const id = String(req.query.id || '');
    if (!GUID.test(id)) throw fail('Invalid entity identifier.');
    const days = req.query.days === undefined ? 1 : Number(req.query.days);
    if (!DEFENDER_DAYS.includes(days)) throw fail(`Timeframe must be one of ${DEFENDER_DAYS.join(', ')} days.`);
    if (req.session.mode === 'demo') return res.json({ days, events: [], partial: false, partialReasons: [], unavailable: [], notes: ['Demo mode has no Defender data.'] });
    res.json(await defenderReport(liveApi(req.session), id, days, { tenant: req.session.tenantId }));
  });
  // Per-device Intune policy states, loaded when a device is opened.
  app.get('/api/intune/device-states', async (req, res) => {
    if (req.session.mode === 'personal') throw fail('Intune device states need an organizational connection.', 409);
    const id = String(req.query.id || '');
    if (!GUID.test(id)) throw fail('Invalid device identifier.');
    if (req.session.mode === 'demo') return res.json({ deviceId: id, states: [], partial: false, link: 'https://intune.microsoft.com/' });
    res.json(await deviceStates(liveApi(req.session), id));
  });
  // Bucket 3 tables, loaded when their tab is opened. Live organizational connections only.
  app.get('/api/tab-table', async (req, res) => {
    if (req.session.mode !== 'live') throw fail('These tables need a live organizational connection.', 409);
    const table = String(req.query.table || '');
    if (table === 'diagnostics' && !req.session.resources.has('azure')) throw fail('Connect Azure to read Entra diagnostic settings.', 409);
    const days = [1, 7, 30].includes(Number(req.query.days)) ? Number(req.query.days) : 7;
    res.json({ ...(await tabTable(liveApi(req.session), table, { id: String(req.query.id || ''), type: String(req.query.type || 'user'), appId: String(req.query.appId || '').slice(0, 40), days })), deferred: B3_DEFERRED });
  });
  // Bucket 4 pages. Live organizational connections only; Logs reads through ARM.
  app.get('/api/emergency-access', async (req, res) => {
    if (req.session.mode !== 'live') throw fail('Emergency access needs a live organizational connection.', 409);
    res.json({ ...(await breakGlass(liveApi(req.session), { azure: req.session.resources.has('azure') })), deferred: B4_DEFERRED });
  });
  // Bucket 5 tenant pages. Live organizational connections only.
  app.get('/api/tenant-page/:key', async (req, res) => {
    if (req.session.mode !== 'live') throw fail('This page needs a live organizational connection.', 409);
    res.json(await loadTenantPage(liveApi(req.session), String(req.params.key), { azure: req.session.resources.has('azure') }));
  });
  app.get('/api/logs/workspaces', async (req, res) => {
    if (req.session.mode !== 'live' || !req.session.resources.has('azure')) throw fail('Connect Azure to list Log Analytics workspaces.', 409);
    res.json(await workspaces(liveApi(req.session)));
  });
  app.post('/api/logs/query', async (req, res) => {
    if (req.session.mode !== 'live' || !req.session.resources.has('azure')) throw fail('Connect Azure to run saved queries.', 409);
    res.json(await runSavedQuery(liveApi(req.session), { workspace: String(req.body?.workspace || ''), query: String(req.body?.query || ''), days: Number(req.body?.days) || 7 }));
  });
  app.post('/api/ca/whatif', async (req, res) => {
    if (req.session.mode !== 'live') throw fail('What If needs a live organizational connection.', 409);
    const id = String(req.body?.id || '');
    if (!GUID.test(id)) throw fail('Invalid entity identifier.');
    res.json(await whatIf(liveApi(req.session), { id, type: String(req.body?.type || 'user'), input: req.body?.input || {} }));
  });
  app.post('/api/signins/lookup', async (req, res) => {
    if (req.session.mode === 'personal') throw fail('Entra sign-in logs need an organizational connection.', 409);
    const options = lookupOptions(req.body);
    res.json(req.session.mode === 'demo' ? demoSignInLookup(options, req.session.profile) : await signInLookup(liveApi(req.session), options));
  });
  app.get('/api/account/report', async (req, res) => {
    const hours = Number(req.query.hours || 24);
    if (!Number.isFinite(hours) || hours < .25 || hours > 2160) throw fail('Invalid account timeframe.');
    res.json(req.session.mode === 'demo' ? demoAccountReport(req.session.profile) : req.session.mode === 'personal' ? await personalAccountReport(liveApi(req.session)) : await accountReport(liveApi(req.session), { tenant: req.session.tenantId, hours, beta: process.env.ENABLE_GRAPH_BETA === 'true' }));
  });
  app.post('/api/intune/health', async (req, res) => {
    const s = req.session;
    if (s.mode === 'personal') throw fail('Intune health needs an organizational connection.', 409);
    const snapshot = req.body?.snapshot ? normalizeSnapshot(req.body.snapshot) : null;
    res.json(s.mode === 'demo' ? demoIntuneReport(snapshot) : await intuneHealthReport(liveApi(s), { tenant: s.tenantId, beta: process.env.ENABLE_GRAPH_BETA === 'true', snapshot }));
  });
  app.get('/api/licenses', async (req, res) => {
    const s = req.session;
    if (req.query.scope === 'all') {
      if (s.mode === 'demo') {
        const report = demoLicenseReport(s.profile, req.query.example === 'personal');
        return res.json({ contexts: [{ key: 'demo', account: report.identity.upn, tenant: report.identity.tenant, status: report.partial ? 'partial' : 'queried', report }], sources: report.sources, complete: false, partial: report.partial, updatedAt: report.updatedAt, note: 'Fictional demonstration. Other organizations still require independent connection.' });
      }
      const connections = samePrincipalConnections(s);
      if (!connections.length) throw fail('Sign in first.', 401);
      return res.json(await aggregateContexts(connections, c => licenseReport(liveApi(c), { tenant: c.tenantId, personal: c.mode === 'personal' })));
    }
    res.json(s.mode === 'demo' ? demoLicenseReport(s.profile, req.query.example === 'personal') : await licenseReport(liveApi(s), { tenant: s.tenantId, personal: s.mode === 'personal' }));
  });
  app.post('/api/portfolio/discover', async (req, res) => {
    const s = req.session;
    if (s.mode === 'demo') return res.json({ tenants: [{ id: '11111111-1111-1111-1111-111111111111', name: 'Contoso (demo)', connectionStatus: 'demo' }], complete: false, partial: false, note: 'Fictional tenant discovery. Connect Azure in a live organizational context to discover ARM-visible directories.' });
    if (s.mode !== 'live' || !s.resources.has('azure')) throw fail('Connect Azure using the current organizational account to discover ARM-visible tenants.', 409);
    if (s.discovering) throw fail('Discovery already running.', 409);
    s.discovering = true;
    // Capture the active identity before any await; switching cannot redirect this scan.
    const anchor = { account: s.account, msal: s.msal, tenantId: s.tenantId, mode: s.mode, resources: new Set(s.resources) };
    try {
      const result = await discoverTenants(liveApi(anchor));
      if (result.tenants.length > 20) result.partial = true;
      const outcomes = [];
      for (const t of result.tenants.slice(0, 20)) {
        const known = [...s.connections.values()].find(c => c.tenantId === t.id && c.account.homeAccountId === anchor.account.homeAccountId);
        if (known) { outcomes.push({ ...t, connectionStatus: 'connected' }); continue; }
        if (!connectionConfig.allowMultipleTenants) { outcomes.push({ ...t, connectionStatus: 'multiTenantSetupRequired' }); continue; }
        try {
          const msal = createMsal({ auth: { clientId, authority: `https://login.microsoftonline.com/${t.id}` }, system: { loggerOptions: { loggerCallback: () => {}, piiLoggingEnabled: false } } });
          msal.getTokenCache().deserialize(anchor.msal.getTokenCache().serialize());
          const token = await msal.acquireTokenSilent({ account: anchor.account, authority: `https://login.microsoftonline.com/${t.id}`, scopes: scopesFor('graph') });
          const key = connectionKey(token.account, t.id);
          if (token.account.homeAccountId !== anchor.account.homeAccountId) throw new Error('different_principal');
          if (!sessions.has(s.id) || s.account?.homeAccountId !== anchor.account.homeAccountId || s.mode === 'demo') throw new Error('session_changed');
          const resources = new Set(['graph']);
          try { const arm = await msal.acquireTokenSilent({ account: token.account, authority: `https://login.microsoftonline.com/${t.id}`, scopes: scopesFor('azure') }); if (arm.accessToken && connectionKey(arm.account, t.id) === key && arm.account.homeAccountId === anchor.account.homeAccountId) resources.add('azure'); } catch { }
          s.connections.set(key, { account: token.account, msal, tenantId: t.id, mode: 'live', resources });
          outcomes.push({ ...t, connectionStatus: 'connectedSilently' });
        } catch { outcomes.push({ ...t, connectionStatus: 'signInOrConsentRequired' }); }
      }
      res.json({ ...result, tenants: outcomes, note: result.note + ' Up to 20 directories checked. Already-consented connections are attempted silently; other directories require explicit sign-in. No license assignments are changed.' });
    } finally { s.discovering = false; }
  });
  app.get('/api/billing', async (req, res) => {
    const s = req.session, days = Number(req.query.days || 30);
    if (!Number.isInteger(days) || days < 1 || days > 90) throw fail('Invalid billing timeframe.');
    if (s.mode === 'demo') { const report = demoBillingReport(s.profile); return res.json({ contexts: [{ key: 'demo', tenant: report.tenant, account: publicSession(s).viewer.email, status: report.partial ? 'partial' : 'queried', report }], sources: report.sources, complete: false, partial: report.partial, updatedAt: report.updatedAt, note: 'Fictional billing example.' }); }
    const connections = samePrincipalConnections(s);
    if (!connections.length) throw fail('Sign in first.', 401);
    const report = await aggregateContexts(connections, c => billingReport(liveApi(c), { tenant: c.tenantId, personal: c.mode === 'personal', azure: c.resources.has('azure'), days }));
    res.json(report);
  });
  app.post('/api/device/import', (req, res) => res.json(normalizeSnapshot(req.body)));
  app.post('/api/device/collect', async (req, res) => {
    if (process.platform !== 'win32') throw fail('Download and run the collector on the Windows computer being investigated.', 409);
    if (req.session.collectingDevice) throw fail('A local collection is already running.', 409);
    req.session.collectingDevice = true;
    let dir;
    try {
      dir = await mkdtemp(path.join(os.tmpdir(), 'entity360-device-'));
      const output = path.join(dir, 'snapshot.json');
      await promisify(execFile)(path.join(process.env.WINDIR || 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe'), ['-NoProfile', '-NonInteractive', '-File', path.join(root, 'public', 'Collect-Entity360Device.ps1'), '-OutputPath', output], { timeout: 60000, maxBuffer: 256 * 1024, windowsHide: true });
      const snapshot = normalizeSnapshot(JSON.parse((await readFile(output, 'utf8')).replace(/^\uFEFF/, '')));
      snapshot.provenance = 'Collected on the dashboard server host, under its Windows process identity; not proof of the browser computer';
      res.json(snapshot);
    } catch { throw fail('Local collection did not complete. Download the collector and run it interactively on the investigated PC.', 502); }
    finally {
      req.session.collectingDevice = false;
      if (dir) { await unlink(path.join(dir, 'snapshot.json')).catch(() => {}); await rmdir(dir).catch(() => {}); }
    }
  });
  app.use('/api', (req, res) => res.status(404).json({ error: 'Unknown API route.' }));
  // Hosted default: the page itself needs a live session, so the browser goes straight to Microsoft sign-in.
  app.get(['/', '/index.html'], sessionMiddleware, (req, res, next) => {
    if (demoMode || !confidential || ['live', 'personal'].includes(req.session.mode)) return next();
    res.redirect('/auth/login');
  });
  // no-cache: browsers revalidate (ETag) every load, so a new revision's HTML/JS/CSS is picked up immediately.
  app.use(express.static(path.join(root, 'public'), { setHeaders: (res, file) => { if (/\.(html|js|mjs|css)$/.test(file)) res.setHeader('Cache-Control', 'no-cache'); } }));
  app.use((error, req, res, next) => {
    if (res.headersSent) return next(error);
    const status = Number.isInteger(error.status) && error.status >= 400 && error.status < 600 ? error.status : 500;
    res.status(status).json({ error: status < 500 ? error.message : 'The request could not be completed. Try again or narrow the time range.', ...(status === 401 ? { signin: '/auth/login' } : {}) });
  });
  return app;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const port = Number(process.env.PORT || 3600);
  if (!Number.isInteger(port) || port < 1024 || port > 65535) throw new Error('PORT must be between 1024 and 65535.');
  // HOST=0.0.0.0 only inside a container; the default stays local-only.
  const host = process.env.HOST || '127.0.0.1';
  const server = createApp({ port }).listen(port, host, () => console.log(`Entity 360 ready: http://localhost:${port}\nMicrosoft connection: ${isConfigured ? 'configured' : 'setup required'}\nDemo mode: ${process.env.DEMO_MODE === 'true' ? 'on' : 'off'}`));
  server.on('error', error => { console.error(error.code === 'EADDRINUSE' ? `Port ${port} is already in use. Stop the existing instance or choose another PORT.` : 'Could not start the local server.'); process.exitCode = 1; });
}
