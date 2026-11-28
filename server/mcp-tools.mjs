// Entity 360 MCP tools: the read-only lookups an AI client (Claude, LM Studio, Open WebUI, Jan...) may call.
// Each tool reuses the same data function the web page uses, with the same E360 app role (ROUTE_ROLES via `route`).
// Nothing here writes to Microsoft: no remediation runs, no PIM requests, no device collection.
// Answers are compacted by default because local models have small context windows; `detail: true` returns more.
import * as z from 'zod';
import { GUID, fail, timeRange, describeError } from './model.mjs';
import { searchDemo, demoReport } from './demo.mjs';
import { searchLive, liveReport } from './live.mjs';
import { deviceDetails, demoDeviceDetails, searchDemoDevices } from './devices.mjs';
import { findingsOverview } from './findings.mjs';
import { lookupOptions, signInLookup, demoSignInLookup } from './signins.mjs';
import { breakGlass } from './bucket4.mjs';
import { accessReport, searchScope } from './access-report.mjs';

export const SHORT = { list: 15, string: 300 };
export const DETAIL = { list: 200, string: 2000 };

// Generic size limit for any report: long lists keep their first items plus a note, long strings are clipped.
export function compact(value, { list = SHORT.list, string = SHORT.string } = {}, depth = 0) {
  if (typeof value === 'string') return value.length > string ? `${value.slice(0, string)}…` : value;
  if (Array.isArray(value)) {
    const kept = value.slice(0, list).map(v => compact(v, { list, string }, depth + 1));
    if (value.length > list) kept.push(`… ${value.length - list} more not shown (call again with detail: true for up to ${DETAIL.list})`);
    return kept;
  }
  if (value && typeof value === 'object') {
    if (depth > 8) return '[nested data not shown]';
    return Object.fromEntries(Object.entries(value).filter(([, v]) => v !== undefined && v !== null && v !== '').map(([k, v]) => [k, compact(v, { list, string }, depth + 1)]));
  }
  return value;
}

const pick = (o, keys) => Object.fromEntries(keys.filter(k => o?.[k] !== undefined && o?.[k] !== null && o?.[k] !== '').map(k => [k, o[k]]));
const limits = detail => (detail ? DETAIL : SHORT);

export function shapeSearch(result) {
  return { results: (result.entities || []).map(e => pick(e, ['id', 'type', 'name', 'subtitle', 'enabled', 'department', 'appId', 'entraId', 'intuneId'])), partial: Boolean(result.partial) };
}

// The full investigation report is tens of KB. The short form keeps who/what, the counts, memberships, policies,
// failures first, then the most recent events.
export function shapeInvestigation(report, detail = false) {
  const lim = limits(detail);
  const event = e => pick(e, ['time', 'category', 'title', 'result', 'source', 'target', 'actor', 'ip', 'detail']);
  const events = report.events || [];
  const failed = events.filter(e => e.result && !/^success/i.test(String(e.result)));
  return compact({
    entity: pick(report.entity, ['id', 'name', 'type', 'subtitle', 'enabled', 'department', 'appId']),
    range: report.range,
    summary: report.summary,
    partial: Boolean(report.partial),
    relationships: (report.relationships || []).map(r => pick(r, ['name', 'kind', 'relation', 'source', 'detail'])),
    policies: (report.policies || []).map(p => pick(p, ['name', 'kind', 'status', 'assignment', 'detail'])),
    failedEvents: (detail ? failed : failed.slice(0, 10)).map(event),
    failedEventsMore: detail ? undefined : Math.max(0, failed.length - 10) || undefined,
    recentEvents: events.map(event),
    sources: (report.sources || []).map(s => pick(s, ['name', 'status', 'count', 'coverage'])),
    notes: report.notes,
  }, lim);
}

// Items listed per finding in the short form. `more` is always recomputed from what is actually listed here, so
// count = items listed + more (the server's own `more` only covers its ITEM_LIMIT cut, not this one).
export const SHORT_FINDING_ITEMS = 5;

export function shapeFindings(result, detail = false) {
  const lim = limits(detail);
  return compact({
    generated: result.generated,
    findings: (result.findings || []).map(f => {
      const all = f.items || [];
      const items = all.slice(0, detail ? lim.list : SHORT_FINDING_ITEMS);
      const total = Number.isFinite(f.count) ? Math.max(f.count, all.length + (f.more || 0)) : all.length + (f.more || 0);
      const more = Math.max(0, total - items.length);
      return {
        ...pick(f, ['rank', 'title', 'severity', 'status', 'count', 'why', 'note', 'reason']),
        fix: f.playbook?.fix,
        steps: detail ? f.playbook?.steps : undefined,
        items,
        more,
        moreHint: more && !detail && all.length > items.length ? `call again with detail: true to list ${Math.min(all.length, DETAIL.list)} of them` : undefined,
      };
    }),
  }, lim);
}

// Sign-ins come grouped (same app, result, device, IP, policies). The short form keeps one line per group.
export function shapeSignIns(result, detail = false) {
  const line = e => ({
    ...pick(e, ['user', 'app', 'resource', 'kind', 'result', 'code', 'reason', 'conditionalAccess', 'ip', 'location']),
    device: [e.device?.name, e.device?.os, e.device?.compliant === true ? 'compliant' : e.device?.compliant === false ? 'not compliant' : ''].filter(Boolean).join(' · ') || undefined,
    policies: (e.policies || []).filter(p => !/notApplied|notEnabled/i.test(p.status)).map(p => `${p.name}: ${p.status}`),
    methods: (e.methods || []).map(m => m.method).filter(Boolean),
    correlationId: detail ? e.correlationId : undefined,
  });
  return compact({
    range: result.range,
    users: (result.users || []).map(u => pick(u, ['user', 'status', 'count', 'notes'])),
    totalEvents: result.totalEvents,
    groups: (result.groups || []).map(g => ({ count: g.count, first: g.first, last: g.last, ...line(g.event || {}), ...(detail ? { times: (g.events || []).map(e => e.time) } : {}) })),
    partial: Boolean(result.partial),
    partialReasons: result.partialReasons,
  }, limits(detail));
}

const id = z.string().regex(GUID, 'Use the object ID (a GUID) from search.');
const detailArg = z.boolean().optional().describe('true returns the longer form (more rows). Leave it off on small local models.');

// ctx: { mode: 'demo' | 'live', api, tenant, azure, beta, workspaceIds, telemetryRoles, profile }
const needsLive = (ctx, what) => { if (ctx.mode !== 'live') throw fail(`${what} needs a live Microsoft sign-in. Demo mode has no data for it.`, 409); };

export const TOOLS = [
  {
    name: 'search',
    route: '/api/entities',
    title: 'Search people, apps and devices',
    description: 'Find users, service principals/apps, managed identities and devices in Entra ID and Intune by the start of a name, UPN, serial number or object ID. Returns ids to use with investigate and device.',
    input: { query: z.string().min(2).max(150).describe('Start of a display name or UPN, a device name or serial, or an object ID.') },
    async run(ctx, { query }) {
      const q = query.trim();
      return shapeSearch(ctx.mode === 'demo' ? { entities: [...searchDemo(q), ...searchDemoDevices(q)], partial: false } : await searchLive(ctx.api, q, ctx.tenant));
    },
  },
  {
    name: 'investigate',
    route: '/api/investigate',
    title: 'Investigate a user or app',
    description: 'One person, app or managed identity: group memberships, directory and Azure roles, Conditional Access policies that apply, and recent sign-in, audit and activity events, failures first.',
    input: {
      id: id.describe('Object ID from search.'),
      type: z.enum(['user', 'application', 'managedIdentity']).optional().describe('Entity type from search. Default user.'),
      days: z.number().int().min(1).max(90).optional().describe('How many days of events to read. Default 7.'),
      detail: detailArg,
    },
    async run(ctx, { id: entityId, type = 'user', days = 7, detail = false }) {
      const now = Date.now(), range = timeRange(new Date(now - days * 86400000).toISOString(), new Date(now).toISOString());
      const report = ctx.mode === 'demo' ? demoReport(entityId, range, ctx.profile) : await liveReport(ctx.api, entityId, type, range, { tenant: ctx.tenant, beta: ctx.beta, azure: ctx.azure, logs: false, workspaceIds: [], telemetryRoles: ctx.telemetryRoles || {} });
      if (!report) throw fail('Entity not found.', 404);
      return shapeInvestigation(report, detail);
    },
  },
  {
    name: 'device',
    route: '/api/device/details',
    title: 'Look up a device',
    description: 'One device from Entra ID and Intune: OS, compliance, management, encryption and the people tied to it (primary user, registered owner, logged-on users).',
    input: { entraId: id.optional().describe('Entra device object ID (entraId from search).'), intuneId: id.optional().describe('Intune managed device ID (intuneId from search).'), detail: detailArg },
    async run(ctx, { entraId = '', intuneId = '', detail = false }) {
      if (!entraId && !intuneId) throw fail('Give entraId or intuneId from search.');
      const report = ctx.mode === 'demo' ? demoDeviceDetails({ entraId, intuneId }) : await deviceDetails(ctx.api, { entraId, intuneId }, { beta: ctx.beta, tenant: ctx.tenant });
      if (!report) throw fail('Device not found.', 404);
      return compact(report, limits(detail));
    },
  },
  {
    name: 'findings',
    route: '/api/findings',
    title: 'Tenant findings',
    description: 'Ranked identity risks across the tenant (admins and users without MFA, break-glass gaps, expiring or old app credentials, stale guests, apps open to everyone, sync problems), each with why it matters and the Entra fix link.',
    input: { detail: detailArg },
    async run(ctx, { detail = false }) {
      needsLive(ctx, 'Findings');
      return shapeFindings(await findingsOverview(ctx.api, { azure: ctx.azure }), detail);
    },
  },
  {
    name: 'signins',
    route: '/api/signins/lookup',
    title: 'Sign-in lookup',
    description: 'Entra sign-in log for up to 10 users: grouped successes and failures with error codes, apps, devices, IPs and the Conditional Access result.',
    input: {
      users: z.array(z.string().email()).min(1).max(10).describe('User principal names, e.g. alex@contoso.com.'),
      hours: z.number().min(0.25).max(2160).optional().describe('How far back to look, in hours. Default 24.'),
      detail: detailArg,
    },
    async run(ctx, { users, hours = 24, detail = false }) {
      const options = lookupOptions({ users, hours });
      return shapeSignIns(ctx.mode === 'demo' ? demoSignInLookup(options, ctx.profile) : await signInLookup(ctx.api, options), detail);
    },
  },
  {
    name: 'emergency_access',
    route: '/api/emergency-access',
    title: 'Emergency access (break-glass) check',
    description: 'Break-glass accounts: whether they exist, are excluded from Conditional Access, hold Global Administrator, and have recent sign-ins or alerts.',
    input: { detail: detailArg },
    async run(ctx, { detail = false }) {
      needsLive(ctx, 'Emergency access');
      return compact(await breakGlass(ctx.api, { azure: ctx.azure }), limits(detail));
    },
  },
  {
    name: 'find_group_or_role',
    route: '/api/access-report/search',
    title: 'Find a group or directory role',
    description: 'Find a group or Entra directory role by the start of its name, to get the id for access_report. Admin only.',
    input: { kind: z.enum(['group', 'role']), name: z.string().min(1).max(64).describe('Start of the group or role name.') },
    async run(ctx, { kind, name }) {
      needsLive(ctx, 'Group and role search');
      return { results: await searchScope(ctx.api, kind, name) };
    },
  },
  {
    name: 'access_report',
    route: '/api/access-report/run',
    title: 'Who has access',
    description: 'Everyone with access to a group (members, owners, eligible), a directory role (active and eligible, with scope), or everything one user can access. Admin only.',
    input: { kind: z.enum(['group', 'role', 'user']), id: id.describe('Group, role definition or user id (from find_group_or_role or search).'), detail: detailArg },
    async run(ctx, { kind, id: scopeId, detail = false }) {
      needsLive(ctx, 'The access report');
      return compact(await accessReport(ctx.api, kind, scopeId), limits(detail));
    },
  },
];

// The message an AI client sees when a tool fails. Upstream detail (Graph codes) only for 4xx; 5xx stays generic.
export function toolError(error) {
  const status = Number(error?.status) || 500;
  if (status < 500) return error.message;
  return `${error?.message && error.status ? error.message : 'The lookup could not be completed.'}${error?.reason ? ` (${error.reason})` : ''}`.trim() || describeError(error);
}
