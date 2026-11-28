import { createCspReports, REPORT_ONLY_POLICY } from './csp-report.mjs';
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
import { remediationResults, scriptIdFrom } from './remediation-results.mjs';
import { RunAudit, requestRun, RUN_SCOPE } from './remediation-runs.mjs';
import { decide, DecisionLog, durableDecision, rolesFromClaims, newPending, checkCallback, APP_ROLES } from './authflow.mjs';
import { AuditTrail, auditStoreFromEnv } from './audit-trail.mjs';
import { ROLE_RECHECK_MS, recheckDue, recheckRoles, rolesUnconfirmed, markChecked } from './role-recheck.mjs';
import { createKeyVaultAssertion } from './keyvault-assertion.mjs';
import { connectionPlan, connectionKey } from './connections.mjs';
import { licenseReport, demoLicenseReport, personalAccountReport } from './licenses.mjs';
import { samePrincipalConnections, discoverTenants, aggregateContexts } from './portfolio.mjs';
import { billingReport, demoBillingReport } from './billing.mjs';
import { GUID, fail, timeRange } from './model.mjs';
import { profiles, searchDemo, demoReport } from './demo.mjs';
import { MicrosoftApi, searchLive, liveReport, activityReport, defenderReport, DEFENDER_DAYS } from './live.mjs';
import { deviceStates } from './access.mjs';
import { deviceDetails, demoDeviceDetails, searchDemoDevices } from './devices.mjs';
import { LAB_SIGNIN_USERS, lookupOptions, signInLookup, demoSignInLookup } from './signins.mjs';
import { hostingLinks, hostingIngress } from './hosting.mjs';
import { tabTable, whatIf, B3_DEFERRED } from './bucket3.mjs';
import { breakGlass, workspaces, runSavedQuery, B4_DEFERRED } from './bucket4.mjs';
import { findingsOverview } from './findings.mjs';
import { incidentQueue, demoQueueApi } from './incidents.mjs';
import { collectPosture, evaluatePosture, parsePosture, demoPostureRaw, demoHistory, addToHistory, historyFor, createHistoryStore, postureDocument } from './ad-posture.mjs';
import { loadPage as loadTenantPage } from './bucket5.mjs';
import { pimTable, pimPolicy, pimRequest } from './pim.mjs';
import { accessReport, searchScope, auditRecord } from './access-report.mjs';
import { gatherEntity, buildDocument, demoGather, demoDeviceGather, reportFileName, REPORT_TYPES } from './entity-report.mjs';
import { renderPdf } from './pdf.mjs';
import { cloudHosted } from './ad-forest.mjs';
import { isHostedDemo, readOnlyScopes, hostedBlock, visitorTenant, hostedAudit, hostedSignInError, HOSTED_IDLE_MS, HOSTED_TENANT_LIMIT } from './hosted-demo.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const configuredScopes = (process.env.GRAPH_SCOPES || 'User.Read,User.Read.All,Application.Read.All,GroupMember.Read.All,AuditLog.Read.All,Policy.Read.All,RoleManagement.Read.Directory,DeviceManagementManagedDevices.Read.All,DeviceManagementScripts.Read.All,ThreatHunting.Read.All,Device.Read.All,Organization.Read.All,DeviceManagementConfiguration.Read.All,DeviceManagementServiceConfig.Read.All,EntitlementManagement.Read.All,AdministrativeUnit.Read.All,PrivilegedEligibilitySchedule.Read.AzureADGroup,RoleEligibilitySchedule.Read.Directory,RoleAssignmentSchedule.Read.Directory,RoleAssignmentSchedule.ReadWrite.Directory,PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup,RoleManagementPolicy.Read.Directory,RoleManagementPolicy.Read.AzureADGroup,DeviceManagementManagedDevices.PrivilegedOperations.All').split(',').map(s => s.trim()).filter(Boolean);
// Hosted demo for other tenants (server/hosted-demo.mjs).
const hostedDemoMode = isHostedDemo();
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
const configuredWorkspaceIds = (process.env.LOG_ANALYTICS_WORKSPACE_IDS || '').split(',').map(s => s.trim()).filter(s => GUID.test(s));
let telemetryRoles = {};
try { telemetryRoles = JSON.parse(process.env.TELEMETRY_ENTITY_ROLES || '{}'); } catch { throw new Error('TELEMETRY_ENTITY_ROLES must be valid JSON.'); }
const TTL = 8 * 60 * 60 * 1000;
// Days of durable audit history reloaded into the admin pages after a restart.
const HISTORY_DAYS = 14;
const defaultAudit = () => new AuditTrail(auditStoreFromEnv());

function loadCertificate() {
  const resolved = path.resolve(certKeyPath);
  if (resolved.toLowerCase().startsWith(root.toLowerCase())) throw fail('The certificate key must be stored outside the Entity 360 folder.', 500);
  const privateKey = readFileSync(resolved, 'utf8');
  return certThumbprint.length === 64 ? { thumbprintSha256: certThumbprint, privateKey } : { thumbprint: certThumbprint, privateKey };
}

export function createApp({ port = Number(process.env.PORT || 3600), createMsal = options => new PublicClientApplication(options), createConfidential = options => new ConfidentialClientApplication(options), certificate = () => loadCertificate(), apiFetcher = fetch, confidential = confidentialConfigured, enforceRoles = enforceAppRoles, demoMode = process.env.DEMO_MODE === 'true',
  publicBaseUrl = process.env.PUBLIC_BASE_URL || '', useKeyVault = Boolean(kvUri && kvKeyName), makeAssertion = () => createKeyVaultAssertion({ vaultUri: kvUri, keyName: kvKeyName, clientId, thumbprintHex: certThumbprint }),
  hosted = hostedDemoMode, audit = hosted ? hostedAudit(new AuditTrail({ problem: 'off in the hosted demo: nothing about visitors is stored' })) : defaultAudit(), roleRecheckMs = ROLE_RECHECK_MS, postureHistory = createHistoryStore() } = {}) {
  if (hosted && (!publicBaseUrl || !confidential)) throw new Error('E360_HOSTED_DEMO=true needs PUBLIC_BASE_URL and confidential sign-in (ENTRA_CLIENT_ID, ENTRA_CERT_THUMBPRINT and the Key Vault certificate).');
  // Hosted demo: sessions end after 60 idle minutes; locally and on the private hosted copy, 8 hours.
  const IDLE = hosted ? HOSTED_IDLE_MS : TTL;
  // Hosted demo: write scopes are never requested, and the host's own Log Analytics workspaces are not offered.
  const requestedScopes = hosted ? readOnlyScopes(configuredScopes) : configuredScopes;
  const workspaceIds = hosted ? [] : configuredWorkspaceIds;
  const credential = () => useKeyVault ? { clientAssertion: makeAssertion() } : { clientCertificate: certificate() };
  const app = express();
  const cspReports = createCspReports();
  app.locals.cspReports = cspReports;
  const sessions = new Map();
  const decisions = new DecisionLog();
  app.locals.audit = audit;
  // Every decision is kept in memory; denials, sign-ins and role re-check results also go to the durable audit trail.
  const logDecision = fields => { const row = decisions.add(fields); if (durableDecision(row)) audit.record({ type: 'authz', ...row }); return row; };
  // Phase 4.8: audit trail of admin-requested Remediation runs (memory + the durable audit trail).
  const runAudit = new RunAudit({ record: rec => audit.record(rec) });
  // After a restart the admin pages reload the last HISTORY_DAYS of durable records once. A failed read is retried next time.
  let historyLoad = null;
  const loadHistory = () => historyLoad ||= audit.recent({ days: HISTORY_DAYS, types: ['remediation-run', 'authz'] })
    .then(recs => { runAudit.restore(recs.filter(r => r.type === 'remediation-run')); decisions.restore(recs.filter(r => r.type === 'authz')); return { error: null }; })
    .catch(e => { historyLoad = null; return { error: `Earlier records could not be read from the audit trail (${e.message}).` }; });
  const endSession = (s, res) => {
    s.cancelled = true;
    if (s.authRequest) s.authRequest.cancel = true;
    sessions.delete(s.id);
    res.clearCookie(SESSION_COOKIE, { path: '/', httpOnly: true, sameSite: 'lax', secure: secureCookie });
  };
  // Hosted mode (e.g. Azure Container Apps): PUBLIC_BASE_URL=https://<fqdn>. TLS ends at the platform ingress, so the
  // proxy is trusted, cookies are Secure, and only the public host/origin (plus localhost for probes) is accepted.
  const publicUrl = publicBaseUrl ? new URL(publicBaseUrl) : null;
  if (publicUrl && (publicUrl.protocol !== 'https:' || publicUrl.pathname.replace(/\/$/, '') !== '')) throw new Error('PUBLIC_BASE_URL must be https://<host> with no path.');
  const allowedHosts = [`localhost:${port}`, `127.0.0.1:${port}`, ...(publicUrl ? [publicUrl.host] : [])];
  const allowedOrigins = [`http://localhost:${port}`, `http://127.0.0.1:${port}`, ...(publicUrl ? [publicUrl.origin] : [])];
  const redirectUri = process.env.ENTRA_REDIRECT_URI || (publicUrl ? `${publicUrl.origin}/auth/callback` : `http://localhost:${port}/auth/callback`);
  const secureCookie = Boolean(publicUrl);
  // Hosted (HTTPS): the session cookie uses the __Host- prefix, so the browser accepts it only with Secure, Path=/ and no
  // Domain, and no other site or subdomain can set or overwrite it. Locally over http the prefix is impossible, so the plain name stays.
  const SESSION_COOKIE = secureCookie ? '__Host-entity360' : 'entity360';
  const HINT_COOKIE = secureCookie ? '__Secure-entity360hint' : 'entity360hint';
  const readCookie = (req, name) => (req.headers.cookie || '').split(';').map(c => c.trim()).find(c => c.startsWith(`${name}=`))?.slice(name.length + 1);
  app.disable('x-powered-by');
  if (publicUrl) app.set('trust proxy', 1);
  app.use((req, res, next) => {
    if (!allowedHosts.includes(req.headers.host)) return res.status(403).json({ error: 'This app accepts local requests only.' });
    if (publicUrl) res.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.set({ 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'X-Frame-Options': 'DENY', 'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-src https://login.microsoftonline.com; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'" });
    res.set('Content-Security-Policy-Report-Only', REPORT_ONLY_POLICY);
    if (req.path.startsWith('/api/')) {
      res.set('Cache-Control', 'no-store');
      if (req.headers['sec-fetch-site'] === 'cross-site') return res.status(403).json({ error: 'Cross-site requests are not allowed.' });
      if (req.headers.origin && !allowedOrigins.includes(req.headers.origin)) return res.status(403).json({ error: 'Invalid request origin.' });
    }
    next();
  });
  app.use(cspReports.router);
  app.use(express.json({ limit: '256kb' }));
  const sessionMiddleware = (req, res, next) => {
    const now = Date.now();
    for (const [key, session] of sessions) if (now - session.lastUsed > IDLE) { session.cancelled = true; if (session.authRequest) session.authRequest.cancel = true; sessions.delete(key); }
    const cookie = readCookie(req, SESSION_COOKIE);
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
    res.cookie(SESSION_COOKIE, session.id, { httpOnly: true, sameSite: 'lax', secure: secureCookie, maxAge: IDLE, path: '/' });
    // One-time cleanup after the rename: drop the old unprefixed cookie a hosted browser may still hold.
    if (secureCookie && readCookie(req, 'entity360') !== undefined) res.clearCookie('entity360', { path: '/', httpOnly: true, sameSite: 'lax', secure: true });
    session.lastUsed = now;
    req.session = session;
    if (!['GET', 'HEAD'].includes(req.method) && req.headers['x-csrf-token'] !== session.csrf) return res.status(403).json({ error: 'Refresh the page before trying again.' });
    next();
  };
  // Basic in-memory rate limit for sign-in starts and requests without a valid session cookie: 120 per minute per client IP.
  // No dependency and no state beyond memory; behind the platform proxy req.ip is the client (trust proxy is on when hosted).
  const hits = new Map(), LIMIT = 120, WINDOW = 60000;
  app.use(['/auth/login', '/api'], (req, res, next) => {
    const hasSession = sessions.has(readCookie(req, SESSION_COOKIE));
    if (hasSession && req.baseUrl !== '/auth/login') return next();
    const now = Date.now(), key = req.ip || 'unknown', h = hits.get(key);
    if (!h || now - h.start > WINDOW) { hits.set(key, { start: now, n: 1 }); if (hits.size > 5000) for (const [k, v] of hits) if (now - v.start > WINDOW) hits.delete(k); return next(); }
    if (++h.n > LIMIT) { res.set('Retry-After', String(Math.ceil((h.start + WINDOW - now) / 1000))); return res.status(429).json({ error: 'Too many requests. Wait a minute and try again.' }); }
    next();
  });
  app.use(['/api', '/auth'], sessionMiddleware);
  // Signed-out sessions get 401 plus the sign-in path, never fixture data. Only session and sign-in routes stay open.
  const signedOutOpen = ['/session', '/logout', '/auth/start', '/auth/status', '/auth/cancel'];
  app.use('/api', (req, res, next) => {
    if (demoMode || req.session.mode !== 'signedout' || signedOutOpen.includes(req.path)) return next();
    res.status(401).json({ error: 'Sign in with Microsoft first.', signin: '/auth/login' });
  });
  // Hosted demo: refuse routes that write, run on this server, show the host's own data or mix tenants, and cap each
  // visitor tenant at HOSTED_TENANT_LIMIT API requests a minute (memory only).
  const tenantHits = new Map();
  if (hosted) app.use('/api', (req, res, next) => {
    const why = hostedBlock(req.method, '/api' + req.path);
    if (why) return res.status(403).json({ error: `Not available in the hosted demo. ${why}`, hostedDemo: true });
    const t = req.session.tenantId;
    if (!t) return next();
    const now = Date.now(), h = tenantHits.get(t);
    if (!h || now - h.start > WINDOW) { tenantHits.set(t, { start: now, n: 1 }); if (tenantHits.size > 5000) for (const [k, v] of tenantHits) if (now - v.start > WINDOW) tenantHits.delete(k); return next(); }
    if (++h.n > HOSTED_TENANT_LIMIT) { res.set('Retry-After', String(Math.ceil((h.start + WINDOW - now) / 1000))); return res.status(429).json({ error: 'Your tenant has sent too many requests to the demo. Wait a minute and try again.' }); }
    next();
  });
  // In-session access re-check (server/role-recheck.mjs, the HeatMap 360 pattern): at most every 5 minutes, or when the
  // person asks (POST /api/session/recheck), Entra issues a fresh ID token and its roles claim replaces the session's roles.
  app.use('/api', async (req, res, next) => {
    const s = req.session, now = Date.now();
    if (req.path === '/logout' || !recheckDue(s, now, { force: req.method === 'POST' && req.path === '/session/recheck', interval: roleRecheckMs })) return next();
    const wasUnconfirmed = rolesUnconfirmed(s);
    const r = await recheckRoles(s, { scopes: scopesFor('graph', s), tenantId: s.tenantId || tenantId, clientId, now });
    const who = { user: s.account?.username, tenant: s.tenantId, source: 'role-check', path: '/api' + req.path };
    if (!r.joined && r.status === 'changed') {
      const what = [r.removed.length && `removed ${r.removed.join(', ')}`, r.added.length && `added ${r.added.join(', ')}`].filter(Boolean).join('; ');
      logDecision({ ...who, outcome: r.removed.length ? 'denied' : 'allowed', reason: `roles re-checked with Entra: ${what}; now ${r.roles.join(', ') || 'none'}`, needed: [...r.removed, ...r.added].join(', ') });
    }
    if (!r.joined && r.status === 'unavailable' && !wasUnconfirmed) logDecision({ ...who, outcome: 'denied', reason: `roles could not be confirmed with Entra (${r.reason}); role-gated features stay closed until a re-check succeeds` });
    if (r.status === 'ended') {
      if (!r.joined) logDecision({ ...who, outcome: 'denied', reason: `sign-in no longer valid (${r.reason}); session ended` });
      endSession(s, res);
      return res.status(401).json({ error: 'Your Microsoft sign-in is no longer valid for Entity 360. Sign in again.', signin: '/auth/login' });
    }
    next();
  });
  // Feature authorization. App roles open Entity 360 features; sources still enforce the viewer's own permissions.
  app.use('/api', (req, res, next) => {
    const s = req.session;
    const full = '/api' + req.path;
    // Hosted demo: app roles are not enforced (visitors' tenants have no Entity 360 role assignments); Graph still
    // enforces the visitor's own permissions, and every write or host-only route is refused above.
    const enforce = enforceRoles && s.authType === 'confidential' && !hosted;
    const result = decide({ mode: s.mode === 'demo' ? 'demo' : 'live', path: full, roles: s.appRoles || [], enforce });
    // Fail closed: when the last role re-check could not reach Entra, role-gated features wait for a successful one.
    const unconfirmed = result.allowed && Boolean(result.needed) && enforce && rolesUnconfirmed(s);
    if (result.needed || !result.allowed) logDecision({ user: s.account?.username, tenant: s.tenantId, path: full, outcome: result.allowed && !unconfirmed ? 'allowed' : 'denied', reason: unconfirmed ? 'roles not confirmed: the last re-check with Entra failed' : result.reason, needed: result.needed });
    if (!result.allowed) return res.status(403).json({ error: 'Your Entity 360 roles do not include this feature.', requiredRole: result.needed });
    if (unconfirmed) return res.status(503).set('Retry-After', '30').json({ error: 'Entity 360 could not confirm your roles with Microsoft just now. Try again in a minute.', rolesUnconfirmed: true });
    next();
  });
  // Signed out on the hosted app: only what the sign-in page needs. No tenant, lab users, host name or role names.
  const signedOutSession = s => ({ mode: 'signedout', csrf: s.csrf, configured: isConfigured, demoMode: false, signin: '/auth/login', confidentialSignIn: true, viewer: { name: 'Signed out', email: '', role: 'Not signed in' }, connections: [], appRoles: [], rolesEnforced: false, signInDefaults: [], labSignInUsers: [], knownRoles: [], authType: 'confidential', hostedDemo: hosted });
  const publicSession = s => hosted && s.mode !== 'signedout' ? { ...fullSession(s), hostedDemo: true, defaultTenant: null, multiTenantEnabled: false, labSignInUsers: [], signInDefaults: s.account?.username ? [s.account.username] : [], serverHost: '', localCollectionSupported: false, logsConfigured: false, rolesEnforced: false } : fullSession(s);
  const fullSession = s => s.mode === 'signedout' && confidential && !demoMode ? signedOutSession(s) : ({
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
    rolesCheckedAt: s.rolesCheck?.at ? new Date(s.rolesCheck.at).toISOString() : null, rolesUnconfirmed: rolesUnconfirmed(s),
  });
  const scopesFor = (resource, s = {}) => resource === 'azure' ? ['https://management.azure.com/user_impersonation'] : resource === 'logs' ? ['https://api.loganalytics.io/Data.Read'] : (s.mode === 'personal' ? ['User.Read'] : requestedScopes).map(s => s.startsWith('https://') ? s : `https://graph.microsoft.com/${s}`);
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
    if (hosted || !s?.mode || s.mode === 'demo') return res.json({ groups: [] });
    const groups = hostingLinks();
    groups[0].status = s.mode === 'live' && s.resources?.has('azure') ? await hostingIngress(liveApi(s)) : 'Ingress: connect Azure to read';
    res.json({ groups });
  });
  app.get('/api/session', async (req, res) => {
    const s = req.session;
    if (s.authType === 'confidential' && !s.resources.has('azure') && !s.silentTried) { s.silentTried = true; await silentResource(s, 'azure'); await silentResource(s, 'logs'); }
    res.json(publicSession(s));
  });
  // "Check my roles again" (after a PIM for Groups activation): the re-check middleware above has already run, forced.
  app.post('/api/session/recheck', (req, res) => res.json(publicSession(req.session)));
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
    const hintCookie = readCookie(req, HINT_COOKIE);
    let resumeHint = null;
    try { resumeHint = req.query.resume === '1' && hintCookie ? decodeURIComponent(hintCookie) : null; } catch { resumeHint = null; }
    if (resumeHint && !/^[^\s@;,]+@[^\s@;,]+$/.test(resumeHint)) resumeHint = null;
    const pkce = await new CryptoProvider().generatePkceCodes();
    s.pending = newPending(pkce);
    // Hosted demo: any work or school tenant signs in through /organizations; the tenant comes from the token.
    const cca = createConfidential({ auth: { clientId, authority: `https://login.microsoftonline.com/${hosted ? 'organizations' : tenantId}`, ...credential() }, system: { loggerOptions: { loggerCallback: () => {}, piiLoggingEnabled: false } } });
    s.pendingClient = cca;
    // ?consent=1 (hosted demo): a visitor's admin approves Entity 360 for their whole organization (prompt=consent shows
    // "Consent on behalf of your organization" to admins).
    const prompt = hosted && req.query.consent === '1' ? { prompt: 'consent' } : resumeHint ? { loginHint: resumeHint } : { prompt: 'select_account' };
    const url = await cca.getAuthCodeUrl({ scopes: scopesFor('graph', { mode: 'live' }), redirectUri, state: s.pending.state, nonce: s.pending.nonce, codeChallenge: pkce.challenge, codeChallengeMethod: 'S256', ...prompt });
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
    const consentUrl = `${publicUrl?.origin || ''}/auth/login?consent=1`;
    const entraError = hosted && req.query.error ? hostedSignInError(`${String(req.query.error).slice(0, 60)} ${/AADSTS\d+/.exec(String(req.query.error_description || ''))?.[0] || ''}`.trim(), consentUrl) : null;
    const failWith = message => { s.login = { status: 'error', error: message }; logDecision({ path: '/auth/callback', outcome: 'denied', reason: message }); return res.redirect('/auth/error'); };
    if (problem || !cca) return failWith(entraError || problem || 'No sign-in is in progress. Start again.');
    try {
      const extra = pending.resource && pending.resource !== 'graph' ? pending.resource : null;
      const result = await cca.acquireTokenByCode({ code: req.query.code, scopes: scopesFor(extra || 'graph', { mode: 'live' }), redirectUri, codeVerifier: pending.verifier, nonce: pending.nonce });
      if (extra) {
        if (!result?.account || result.account.homeAccountId !== s.account?.homeAccountId) throw new Error('different_account');
        if (result.idTokenClaims?.nonce && result.idTokenClaims.nonce !== pending.nonce) throw new Error('nonce');
        s.resources.add(extra); s.login = { status: 'complete' };
        logDecision({ user: result.account.username, tenant: tenantId, path: '/auth/callback', outcome: 'allowed', reason: `connected ${extra} by redirect consent` });
        return res.redirect('/');
      }
      if (!hosted && (!result?.account || result.account.tenantId?.toLowerCase() !== tenantId.toLowerCase())) throw new Error('wrong_tenant');
      if (result.idTokenClaims?.nonce !== pending.nonce) throw new Error('nonce');
      // Hosted demo: the visitor's tenant, with tid tied to iss and the account. Later token calls go to that tenant's
      // own authority (a cache keyed to /organizations would miss), so the cache moves to a tenant-bound client.
      const signedTenant = hosted ? visitorTenant(result) : tenantId;
      let client = cca;
      if (hosted) {
        client = createConfidential({ auth: { clientId, authority: `https://login.microsoftonline.com/${signedTenant}`, ...credential() }, system: { loggerOptions: { loggerCallback: () => {}, piiLoggingEnabled: false } } });
        client.getTokenCache().deserialize(cca.getTokenCache().serialize());
      }
      const key = connectionKey(result.account, signedTenant);
      const roles = rolesFromClaims(result.idTokenClaims);
      s.msal = client; s.account = result.account; s.mode = 'live'; s.tenantId = signedTenant; s.connectionKey = key; s.resources = new Set(['graph']); s.authType = 'confidential'; s.appRoles = roles;
      markChecked(s);
      if (result.account?.username) res.cookie(HINT_COOKIE, result.account.username, { httpOnly: true, sameSite: 'lax', secure: secureCookie, maxAge: 30 * 24 * 3600 * 1000, path: '/auth' });
      s.connections.set(key, { msal: client, account: result.account, mode: 'live', tenantId: signedTenant, resources: s.resources });
      s.login = { status: 'complete' };
      await silentResource(s, 'azure');
      await silentResource(s, 'logs');
      logDecision({ user: result.account.username, tenant: signedTenant, path: '/auth/callback', outcome: 'allowed', reason: `azure ${s.resources.has('azure') ? 'connected silently' : 'needs consent'}; signed in; app roles: ${roles.join(', ') || 'none'}; sign-in methods (amr): ${[].concat(result.idTokenClaims?.amr || []).join(', ') || 'not in token'}` });
      res.redirect('/');
    } catch (e) {
      // Keep Entra's own codes (AADSTSnnnnn, MSAL errorCode/subError) so a Conditional Access refusal can be told apart from a certificate problem.
      const detail = [e.errorCode, e.subError, /AADSTS\d+/.exec(String(e.errorMessage || e.message || ''))?.[0]].filter(Boolean).join(' / ');
      const hostedHelp = hosted ? (e.message === 'personal_account' ? 'Personal Microsoft accounts cannot use the demo. Sign in with a work or school account.' : e.message === 'wrong_issuer' ? 'The sign-in token did not match its tenant.' : hostedSignInError(detail, consentUrl)) : null;
      failWith(hostedHelp ? hostedHelp : e.message === 'different_account' ? 'Use the same Microsoft account you signed in with.' : e.message === 'wrong_tenant' ? 'The account is not in the configured tenant.' : `Sign-in did not complete. Check the registration, the certificate and your organization’s sign-in policy.${detail ? ` (${detail})` : ''}`);
    }
  });
  // A failed sign-in shows Entra's error (AADSTS code) here instead of dropping into demo data.
  app.get('/auth/error', (req, res) => {
    const msg = String(req.session.login?.error || 'Sign-in did not complete.').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
    res.status(401).type('html').send(`<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Entity 360 sign-in failed</title></head><body><h1>Sign-in failed</h1><p id="signin-error">${msg}</p><p><a href="/auth/login">Try signing in again</a></p></body></html>`);
  });
  app.get('/api/authz/log', async (req, res) => { const history = await loadHistory(); res.json({ rows: decisions.list(100), enforced: enforceRoles && req.session.authType === 'confidential', roles: req.session.appRoles || [], audit: audit.status(), historyError: history.error }); });
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
    endSession(req.session, res);
    res.clearCookie(HINT_COOKIE, { path: '/auth', httpOnly: true, sameSite: 'lax', secure: secureCookie });
    res.json({ ok: true });
  });
  app.get('/api/entities', async (req, res) => {
    if (req.session.mode === 'personal') throw fail('Use My account & device or Licenses for a personal account.', 409);
    const q = String(req.query.q || '').trim().slice(0, 150);
    res.json(req.session.mode === 'demo' ? { entities: [...searchDemo(q), ...searchDemoDevices(q)], partial: false } : await searchLive(liveApi(req.session), q, req.session.tenantId));
  });
  // Device lookup: one device's details and the people tied to it. /api/device prefix = E360.Reader, like the person pages.
  app.get('/api/device/details', async (req, res) => {
    if (req.session.mode === 'personal') throw fail('Device lookup needs an organizational connection.', 409);
    const entraId = String(req.query.entraId || ''), intuneId = String(req.query.intuneId || '');
    if ((!entraId && !intuneId) || (entraId && !GUID.test(entraId)) || (intuneId && !GUID.test(intuneId))) throw fail('Invalid device identifier.');
    const report = req.session.mode === 'demo' ? demoDeviceDetails({ entraId, intuneId }) : await deviceDetails(liveApi(req.session), { entraId, intuneId }, { beta: process.env.ENABLE_GRAPH_BETA === 'true', tenant: req.session.tenantId });
    if (!report) throw fail('Device not found.', 404);
    res.json(report);
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
  // Single-entity PDF report: everything Entity 360 can read about one user, app, managed identity or device, read at request
  // time with the viewer's delegated token and returned as a PDF (nothing stored). /api/investigate prefix = E360.Reader.
  // One audit line per report: requester, entity type, the entity id unless it is a person (as for access reports), outcome.
  app.get('/api/investigate/report.pdf', async (req, res) => {
    const s = req.session, type = String(req.query.type || ''), started = Date.now();
    if (s.mode === 'personal') throw fail('The entity report needs an organizational connection.', 409);
    if (!REPORT_TYPES.includes(type)) throw fail('Invalid entity type.');
    const id = String(req.query.id || ''), entraId = String(req.query.entraId || ''), intuneId = String(req.query.intuneId || '');
    const range = type === 'device' ? null : timeRange(req.query.from, req.query.to);
    const requester = { upn: s.account?.username || null, objectId: s.account?.idTokenClaims?.oid || s.account?.localAccountId || null };
    const record = (outcome, extra = {}) => audit.record({ type: 'entity-report', time: new Date().toISOString(), requester, entityType: type, entityId: type === 'user' ? null : (id || entraId || intuneId || null), outcome, ms: Date.now() - started, ...extra });
    let gathered;
    try {
      if (s.mode === 'demo') {
        if (type === 'device') { const d = demoDeviceDetails({ entraId, intuneId }); if (!d) throw fail('Device not found.', 404); gathered = demoDeviceGather(d); }
        else { if (!GUID.test(id)) throw fail('Invalid entity identifier.'); const r = demoReport(id, range, s.profile); if (!r) throw fail('Entity not found.', 404); gathered = demoGather(r, range); }
      } else gathered = await gatherEntity(liveApi(s), { id, type, entraId, intuneId }, { range, tenant: s.tenantId, beta: process.env.ENABLE_GRAPH_BETA === 'true', azure: s.resources.has('azure'), logs: s.resources.has('logs'), workspaceIds, telemetryRoles });
    } catch (e) { record('failed', { error: String(e.message).slice(0, 300) }); throw e; }
    const doc = buildDocument(gathered, { viewer: requester.upn || '', hosting: cloudHosted() ? 'cloud' : 'local', azure: s.mode === 'live' && s.resources.has('azure') });
    const pdf = renderPdf(doc);
    record('ok', { sections: doc.sections.length, unread: doc.sections.filter(x => x.status === 'unavailable').length, bytes: pdf.length });
    res.set({ 'Content-Type': 'application/pdf', 'Content-Disposition': `attachment; filename="${reportFileName(doc.title, gathered.generated)}"`, 'Cache-Control': 'no-store' });
    res.send(pdf);
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
  // Findings overview: ranked findings from data the other pages already read, each with a playbook. E360.Reader (ROUTE_ROLES).
  app.get('/api/findings', async (req, res) => {
    if (req.session.mode !== 'live') throw fail('Findings need a live organizational connection.', 409);
    res.json(await findingsOverview(liveApi(req.session), { azure: req.session.resources.has('azure') }));
  });
  // Incident queue (INVESTIGATE > Incidents): Defender XDR incidents and alerts plus Identity Protection risk, read with
  // the viewer's own token (four optional delegated read scopes, Grant-E360IncidentScopes.ps1). E360.Reader (ROUTE_ROLES).
  app.get('/api/incidents', async (req, res) => {
    const s = req.session;
    if (s.mode === 'demo') return res.json(await incidentQueue(demoQueueApi(), { now: Date.parse('2026-11-20T18:00:00Z') }));
    if (s.mode !== 'live') throw fail('The incident queue needs a live organizational connection.', 409);
    res.json(await incidentQueue(liveApi(s)));
  });
  // AD posture (Findings > AD posture): read from a DC by the host's AD reader, not with the viewer's token, so every
  // E360.Reader sees the same forest. One read at a time; the result is reused for 10 minutes unless ?refresh=1.
  // Each live read adds today's score per domain to the history file and one 'ad-posture' audit line.
  const postureState = { result: null, at: 0, running: null };
  const postureRead = async (s, refresh) => {
    if (s.mode === 'personal') throw fail('AD posture needs an organizational connection.', 409);
    if (s.mode === 'demo') { const p = evaluatePosture(parsePosture(JSON.stringify(demoPostureRaw()))); return { posture: p, history: addToHistory(demoHistory(), p) }; }
    if (!refresh && postureState.result && Date.now() - postureState.at < 10 * 60e3) return { posture: postureState.result, history: await postureHistory.load(), cached: true };
    const requester = { upn: s.account?.username || null, objectId: s.account?.idTokenClaims?.oid || s.account?.localAccountId || null }, started = Date.now();
    postureState.running ||= collectPosture().finally(() => { postureState.running = null; });
    const p = await postureState.running;
    audit.record({ type: 'ad-posture', time: new Date().toISOString(), requester, outcome: p.status, domains: p.domains.length, scores: Object.fromEntries(p.domains.map(d => [d.name, d.score])), ms: Date.now() - started });
    if (p.status !== 'live') return { posture: p, history: [] };
    postureState.result = p; postureState.at = Date.now();
    return { posture: p, history: (await postureHistory.record(p)) || await postureHistory.load() };
  };
  app.get('/api/findings/ad-posture', async (req, res) => {
    const { posture, history, cached } = await postureRead(req.session, req.query.refresh === '1');
    res.json({ ...posture, cached: !!cached, history: Object.fromEntries((posture.domains || []).map(d => [d.name, historyFor(history, d.name)])) });
  });
  app.get('/api/findings/ad-posture/report.pdf', async (req, res) => {
    const { posture, history } = await postureRead(req.session, false);
    if (posture.status !== 'live') throw fail(posture.message || 'AD posture could not be read.', 409);
    const domain = String(req.query.domain || '');
    if (domain && !posture.domains.some(d => d.name === domain)) throw fail('Unknown domain.');
    const pdf = renderPdf(postureDocument(posture, history, { domain, viewer: req.session.account?.username || (req.session.mode === 'demo' ? 'Demo' : '') }));
    res.set({ 'Content-Type': 'application/pdf', 'Content-Disposition': `attachment; filename="${reportFileName(`ad-posture-${domain || posture.forest || 'forest'}`, posture.generated)}"`, 'Cache-Control': 'no-store' });
    res.send(pdf);
  });
  // Bucket 5 tenant pages. Live organizational connections only.
  app.get('/api/tenant-page/:key', async (req, res) => {
    if (req.session.mode !== 'live') throw fail('This page needs a live organizational connection.', 409);
    res.json(await loadTenantPage(liveApi(req.session), String(req.params.key), { azure: req.session.resources.has('azure'), beta: process.env.ENABLE_GRAPH_BETA === 'true' }));
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
  // Unified PIM tables (MY ACCOUNT > PIM, INVESTIGATE > PIM). /api/account and /api/investigate need E360.Reader (ROUTE_ROLES).
  // Delegated token of the signed-in user only; requests are selfActivate/selfDeactivate, so nobody can elevate someone else.
  const pimApi = s => { if (s.mode !== 'live') throw fail('PIM needs a live organizational sign-in.', 409); return liveApi(s); };
  // My PIM (/api/me/pim) needs only a live organizational sign-in, no app role: it reads with filterByCurrentUser and
  // writes only selfActivate/selfDeactivate for the session's own object id. Nothing from the request body picks the principal.
  const pimMe = s => { const id = s.account?.idTokenClaims?.oid || s.account?.localAccountId || ''; if (!GUID.test(id)) throw fail('No signed-in user object id.', 401); return { id, self: true }; };
  app.get('/api/me/pim', async (req, res) => res.json(await pimTable(pimApi(req.session), pimMe(req.session), { azure: req.session.resources.has('azure') })));
  app.post('/api/me/pim/policy', async (req, res) => res.json(await pimPolicy(pimApi(req.session), String(req.body?.type || ''), req.body?.target)));
  // One durable audit record per PIM request: who, what, for how long, and Microsoft's answer. The body is untrusted, so
  // only the validated request (r.request) is kept on success and raw values are clipped on failure.
  const clip = v => v == null ? null : (typeof v === 'string' ? v : JSON.stringify(v)).slice(0, 300);
  app.post('/api/me/pim/request', async (req, res) => {
    const s = req.session, api = pimApi(s), me = pimMe(s), requester = { upn: s.account?.username || null, objectId: me.id };
    if (req.body?.type === 'Azure role' && !s.resources.has('azure')) throw fail('Connect Azure to activate Azure roles.', 409);
    try {
      const r = await pimRequest(api, me, req.body), q = r.request || {};
      audit.record({ type: 'pim-request', requester, kind: q.type ?? null, action: q.action ?? null, target: q.target ?? null, minutes: q.minutes ?? null, reason: clip(q.reason), requestId: r.id ?? null, status: r.status ?? null, outcome: 'ok' });
      res.json(r);
    } catch (e) { audit.record({ type: 'pim-request', requester, kind: clip(req.body?.type), action: clip(req.body?.action), target: clip(req.body?.target), outcome: 'failed', error: clip(e.message) }); throw e; }
  });
  // GOVERNANCE > Access report: E360.Admin (ROUTE_ROLES). Read at run time with the viewer's delegated token; nothing stored.
  // One E360_AUDIT line per run: requester, scope kind, group or role id (never a user's id), row count, outcome.
  app.get('/api/access-report/search', async (req, res) => res.json({ results: await searchScope(pimApi(req.session), String(req.query.kind || ''), String(req.query.q || '')) }));
  app.post('/api/access-report/run', async (req, res) => {
    const s = req.session, api = pimApi(s), kind = String(req.body?.kind || ''), id = String(req.body?.id || ''), started = Date.now();
    const requester = { upn: s.account?.username || null, objectId: s.account?.idTokenClaims?.oid || s.account?.localAccountId || null };
    try {
      const r = await accessReport(api, kind, id);
      audit.record(auditRecord({ requester, kind, scopeId: id, rows: r.rows.length, outcome: 'ok', ms: Date.now() - started }));
      res.json(r);
    } catch (e) { audit.record(auditRecord({ requester, kind, scopeId: id, outcome: 'failed', ms: Date.now() - started, error: e.message })); throw e; }
  });  app.get('/api/investigate/pim', async (req, res) => {
    const id = String(req.query.id || '');
    if (!GUID.test(id)) throw fail('Pick a user first.', 400);
    res.json(await pimTable(pimApi(req.session), { id, self: false }, { azure: req.session.resources.has('azure') }));
  });
  // Phase 4.7: network connectivity Remediation results per device. /api/intune prefix = E360.Intune, no fallback.
  app.get('/api/intune/remediation-results', async (req, res) => {
    const s = req.session;
    if (s.mode === 'personal') throw fail('Remediation results need an organizational connection.', 409);
    const scriptId = scriptIdFrom();
    if (s.mode !== 'live' || !scriptId) return res.json(await remediationResults(null, scriptId && s.mode === 'live' ? scriptId : null));
    try { res.json(await remediationResults(liveApi(s), scriptId)); }
    catch (e) { if (e?.status === 403) return res.status(403).json({ error: e.reason || e.message, denied: 'source', scope: 'DeviceManagementScripts.Read.All' }); throw e; }
  });
  // Phase 4.8: single-device run now. E360.Admin only (ROUTE_ROLES), CSRF checked by the session middleware,
  // the admin's own delegated token, one audit record per request whatever the outcome.
  app.post('/api/intune/remediation-run', async (req, res) => {
    const s = req.session;
    if (s.mode !== 'live') throw fail('Run now needs a live organizational connection.', 409);
    const requester = { upn: s.account?.username || null, objectId: s.account?.idTokenClaims?.oid || s.account?.localAccountId || null };
    try { res.json({ record: await requestRun({ api: liveApi(s), scriptId: scriptIdFrom(), managedDeviceId: req.body?.managedDeviceId, reason: req.body?.reason, requester, audit: runAudit }) }); }
    catch (e) { if (e?.audit) return res.status(e.status || 500).json({ error: e.message, record: e.audit, ...(e.status === 403 ? { denied: 'source', scope: RUN_SCOPE } : {}) }); throw e; }
  });
  app.get('/api/intune/remediation-runs', async (req, res) => { const history = await loadHistory(); res.json({ rows: runAudit.list(200), audit: audit.status(), historyError: history.error }); });
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
  // Fleet deployment log: only for signed-in readers (the global guard above returns 401 when signed out; E360.Reader via ROUTE_ROLES).
  app.get('/api/deployment-log', async (req, res) => { res.set('Cache-Control', 'no-store'); res.type('application/json').send(await readFile(path.join(root, 'public', 'deployment-log.json'), 'utf8')); });
  app.use('/api', (req, res) => res.status(404).json({ error: 'Unknown API route.' }));
  // Never served as static files: the deployment log (see /api/deployment-log), backups and editor leftovers, dotfiles.
  app.use((req, res, next) => (/^\/deployment-log\.json$/i.test(req.path) || /\.(pre-[^/]*|bak|orig|old|tmp)$|~$/i.test(req.path) || /(^|\/)\./.test(req.path) ? res.status(404).type('text/plain').send('Not found.') : next()));
  // Hosted default: the page itself needs a live session, so the browser goes straight to Microsoft sign-in.
  app.get(['/', '/index.html', '/setup.html'], sessionMiddleware, (req, res, next) => {
    if (demoMode || !confidential || ['live', 'personal'].includes(req.session.mode)) return next();
    // Hosted demo: a signed-out visitor first sees what the demo is, what it reads and how their admin approves it.
    if (hosted) return res.set('Cache-Control', 'no-cache').sendFile(path.join(root, 'public', 'hosted-welcome.html'));
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
  const app = createApp({ port }), audit = app.locals.audit.status();
  const server = app.listen(port, host, () => console.log(`Entity 360 ready: http://localhost:${port}\nMicrosoft connection: ${isConfigured ? 'configured' : 'setup required'}\nDemo mode: ${process.env.DEMO_MODE === 'true' ? 'on' : 'off'}\nDurable audit trail: ${audit.durable ? `${audit.kind} ${audit.where}` : audit.problem}`));
  // Container Apps sends SIGTERM when it scales in: write pending audit records before the process exits.
  const stop = () => { server.close(); app.locals.audit.close({ timeoutMs: 20000 }).finally(() => process.exit(0)); };
  process.once('SIGTERM', stop);
  process.once('SIGINT', stop);
  server.on('error', error => { console.error(error.code === 'EADDRINUSE' ? `Port ${port} is already in use. Stop the existing instance or choose another PORT.` : 'Could not start the local server.'); process.exitCode = 1; });
}
