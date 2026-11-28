// Entity 360 MCP server: lets any MCP client (Claude Desktop, Claude Code, LM Studio, Open WebUI with Ollama, Jan...)
// call Entity 360's read-only lookups. Run it from the Entity 360 folder so it reads the same .env:
//
//   node --env-file=.env server/mcp.mjs sign-in      one time: Microsoft sign-in in the browser, cached for this Windows user
//   node --env-file=.env server/mcp.mjs              stdio (the client starts it)  -- Claude Desktop, Claude Code, LM Studio, Jan
//   node --env-file=.env server/mcp.mjs --http       http://127.0.0.1:3601/mcp with a bearer key -- Open WebUI, Claude Code, LM Studio
//   node server/mcp.mjs --demo                       fictional Contoso data, no sign-in, no internet
//   node --env-file=.env server/mcp.mjs status | key | sign-out
//
// It signs in as the person (delegated), checks the same E360 app roles as the web app, and writes every tool call
// to the Entity 360 audit trail. stdout carries the MCP protocol in stdio mode, so every log line goes to stderr.
import express from 'express';
import path from 'node:path';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { TOOLS, toolError } from './mcp-tools.mjs';
import { decide } from './authflow.mjs';
import { fail } from './model.mjs';
import { AuditTrail, auditStoreFromEnv } from './audit-trail.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const VERSION = JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8')).version;
export const HTTP_PORT = 3601;
const log = m => process.stderr.write(`${m}\n`);

const INSTRUCTIONS = 'Entity 360 reads Microsoft Entra ID, Intune and Defender for the signed-in person, within their own permissions. '
  + 'Start with search to get an id, then call investigate (users and apps) or device. findings ranks tenant-wide risks. '
  + 'All tools are read-only. Answers are shortened by default; pass detail: true only when more rows are needed.';

// One MCP server with every tool. getContext() returns the demo or live context for each call (roles re-checked there).
export function buildServer({ getContext, audit = null, transport = 'stdio', tools = TOOLS } = {}) {
  const server = new McpServer({ name: 'entity-360', title: 'Entity 360', version: VERSION }, { instructions: INSTRUCTIONS });
  for (const tool of tools) {
    server.registerTool(tool.name, { title: tool.title, description: tool.description, inputSchema: tool.input, annotations: { title: tool.title, readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true } }, async args => {
      const started = Date.now();
      let ctx = null;
      const record = (outcome, error) => {
        if (!audit || ctx?.mode !== 'live') return;
        audit.record({ type: 'mcp-tool', tool: tool.name, transport, requester: ctx.requester || null, outcome, ms: Date.now() - started, error: error ? String(error).slice(0, 300) : null,
          ...(tool.name === 'access_report' ? { scope: args.kind, scopeId: args.kind === 'user' ? null : args.id } : {}) });
      };
      try {
        ctx = await getContext();
        const d = decide({ mode: ctx.mode, path: tool.route, roles: ctx.roles || [], enforce: Boolean(ctx.enforce) });
        if (!d.allowed) throw fail(`Your Entity 360 roles do not include ${tool.name} (it needs ${d.needed}).`, 403);
        if (d.needed && ctx.enforce && ctx.rolesUnconfirmed) throw fail('Entity 360 could not confirm your roles with Microsoft just now. Try again in a minute.', 503);
        const result = await tool.run(ctx, args);
        record('ok');
        return { content: [{ type: 'text', text: JSON.stringify(result) }] };
      } catch (e) {
        const message = toolError(e);
        record(e?.status === 403 ? 'denied' : 'failed', message);
        return { isError: true, content: [{ type: 'text', text: message }] };
      }
    });
  }
  return server;
}

// Streamable HTTP, stateless: a fresh server per request. Bound to 127.0.0.1 by the caller. Every request needs the
// bearer key; the Host check stops DNS rebinding and the Origin check stops other web pages calling it from a browser.
export function createHttpApp({ port = HTTP_PORT, key, makeServer }) {
  if (typeof key !== 'string' || key.length < 32) throw new Error('An HTTP access key of at least 32 characters is required.');
  const expected = Buffer.from(`Bearer ${key}`);
  const hosts = new Set([`127.0.0.1:${port}`, `localhost:${port}`, `host.docker.internal:${port}`]);
  const app = express();
  app.disable('x-powered-by');
  app.use((req, res, next) => {
    res.set({ 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
    if (!hosts.has(String(req.headers.host || '').toLowerCase())) return res.status(403).json({ error: 'This server accepts local requests only.' });
    const origin = req.headers.origin;
    if (origin && !/^https?:\/\/(localhost|127\.0\.0\.1)(:\d{1,5})?$/i.test(origin)) return res.status(403).json({ error: 'Invalid request origin.' });
    const got = Buffer.from(String(req.headers.authorization || ''));
    if (got.length !== expected.length || !timingSafeEqual(got, expected)) return res.status(401).set('WWW-Authenticate', 'Bearer').json({ error: 'Missing or wrong access key.' });
    next();
  });
  app.use(express.json({ limit: '256kb' }));
  app.post('/mcp', async (req, res) => {
    const server = makeServer();
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
    res.on('close', () => { transport.close().catch(() => {}); server.close().catch(() => {}); });
    try { await server.connect(transport); await transport.handleRequest(req, res, req.body); }
    catch { if (!res.headersSent) res.status(500).json({ jsonrpc: '2.0', error: { code: -32603, message: 'Internal error' }, id: null }); }
  });
  app.all('/mcp', (req, res) => res.status(405).set('Allow', 'POST').json({ jsonrpc: '2.0', error: { code: -32000, message: 'Method not allowed.' }, id: null }));
  app.use((req, res) => res.status(404).json({ error: 'Not found. The MCP endpoint is /mcp.' }));
  return app;
}

// The HTTP access key lives next to the token cache, readable by this Windows user only.
export async function httpKey(dir) {
  const file = path.join(dir, 'http-key.txt');
  try { const k = (await readFile(file, 'utf8')).trim(); if (k.length >= 32) return k; } catch { /* create below */ }
  const k = randomBytes(32).toString('hex');
  await mkdir(dir, { recursive: true });
  await writeFile(file, `${k}\n`, { mode: 0o600 });
  return k;
}

function parseArgs(argv) {
  const out = { command: 'serve', http: false, demo: false, port: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--http') out.http = true;
    else if (a === '--demo') out.demo = true;
    else if (a === '--port') out.port = Number(argv[++i]);
    else if (['sign-in', 'sign-out', 'status', 'key'].includes(a)) out.command = a;
    else throw new Error(`Unknown argument: ${a}`);
  }
  if (out.port !== null && (!Number.isInteger(out.port) || out.port < 1024 || out.port > 65535)) throw new Error('--port must be between 1024 and 65535.');
  return out;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const { createAuth, mcpDir, SIGNIN_PORT } = await import('./mcp-auth.mjs');
  const dir = mcpDir();
  if (args.command === 'key') { console.log(await httpKey(dir)); return; }
  const auth = args.demo ? null : createAuth();
  if (args.command === 'status') { console.log(JSON.stringify(await auth.status(), null, 2)); return; }
  if (args.command === 'sign-out') { await auth.signOut(); console.log('Signed out. The cached Microsoft sign-in for Entity 360 MCP was removed.'); return; }
  if (args.command === 'sign-in') {
    const r = await auth.signIn({ port: args.port || SIGNIN_PORT });
    console.log(`Signed in as ${r.account}. Entity 360 roles: ${r.roles.join(', ') || 'none'}. Token cache: ${(await auth.status()).cacheProtection} in ${dir}`);
    return;
  }
  const audit = args.demo ? null : new AuditTrail({ ...auditStoreFromEnv(), write: line => process.stderr.write(`${line}\n`) });
  const getContext = args.demo ? async () => ({ mode: 'demo', profile: 'analyst', roles: [], enforce: false }) : () => auth.context();
  if (!args.demo && !auth.configured) log('Warning: Entity 360 sign-in is not configured in .env. Tools will answer with setup instructions. Use --demo for fictional data.');
  const stop = async () => { await audit?.close({ timeoutMs: 10000 }).catch(() => {}); process.exit(0); };
  process.once('SIGINT', stop); process.once('SIGTERM', stop);
  if (args.http) {
    const port = args.port || HTTP_PORT;
    const app = createHttpApp({ port, key: await httpKey(dir), makeServer: () => buildServer({ getContext, audit, transport: 'http' }) });
    const server = app.listen(port, '127.0.0.1', () => log(`Entity 360 MCP ready: http://127.0.0.1:${port}/mcp (${args.demo ? 'demo data' : 'live, signed-in person'}). Access key: node server/mcp.mjs key`));
    server.on('error', e => { log(e.code === 'EADDRINUSE' ? `Port ${port} is already in use.` : 'Could not start the MCP HTTP server.'); process.exit(1); });
    return;
  }
  await buildServer({ getContext, audit, transport: 'stdio' }).connect(new StdioServerTransport());
  log(`Entity 360 MCP ready on stdio (${args.demo ? 'demo data' : 'live, signed-in person'}).`);
  process.stdin.on('close', stop);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(e => { log(e?.message || String(e)); process.exit(1); });
}
