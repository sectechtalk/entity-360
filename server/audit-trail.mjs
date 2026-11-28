// Durable audit trail. Every audit record (Remediation run requests, access report runs, PIM requests, sign-ins,
// authorization denials and role re-check results) is written twice:
//   1. one `E360_AUDIT {json}` line on stdout, for the live log stream (unchanged behaviour), and
//   2. a store that outlives the container, so a restart or scale-to-zero no longer loses the record.
// Hosted, the store is a private GitHub repository written through the contents API with a fine-grained token that has
// Contents read/write on that one repository only: the same $0 pattern as HeatMap 360's hm-360-data. For local work it
// can be a folder. With neither configured, records go to stdout only and the admin pages say so.
//
// Layout: one JSON Lines file per UTC day, audit/YYYY-MM/YYYY-MM-DD.jsonl, rolling to YYYY-MM-DD.1.jsonl, .2 ... when a
// part passes MAX_PART bytes. Records are batched (one commit per batch), written by one writer at a time, and a failed
// write keeps them and retries with backoff. The contents API cannot rewrite history, so any later edit of a day file
// shows in the repository's commit history. Tokens are never logged; GitHub errors are reported by HTTP status only.
import { createHash, randomUUID } from 'node:crypto';
import { mkdir, readFile, readdir, rename, writeFile } from 'node:fs/promises';
import path from 'node:path';

export const AUDIT_PREFIX = 'E360_AUDIT ';
export const MAX_PART = 512 * 1024;
export const RETRY_MS = [5_000, 30_000, 120_000, 300_000];
const DAY_FILE = /^(\d{4}-\d{2}-\d{2})(?:\.(\d{1,4}))?\.jsonl$/;
const SAFE_PATH = /^audit\/\d{4}-\d{2}\/\d{4}-\d{2}-\d{2}(?:\.\d{1,4})?\.jsonl$/;
const SAFE_FOLDER = /^audit\/\d{4}-\d{2}$/;
export const REPO = /^[A-Za-z0-9-]{1,39}\/[A-Za-z0-9._-]{1,100}$/;

const check = (p, re = SAFE_PATH) => { if (!re.test(p)) throw new Error(`refusing audit path ${p}`); return p; };
const err = (message, status) => Object.assign(new Error(message), { status });
export const partPath = (day, n = 0) => `audit/${day.slice(0, 7)}/${day}${n ? `.${n}` : ''}.jsonl`;
const dayOf = iso => String(iso).slice(0, 10);

// ---------------------------------------------------------------- stores: { kind, label, list, get, put }
//   list(folder) -> [{ name, size }]      get(path) -> { text, sha } | null      put(path, text, sha|null) -> { sha }
// put with a stale sha fails with status 409, so a second writer can never overwrite records it has not read.
export function createLocalAuditStore(dir) {
  const hash = text => createHash('sha1').update(text).digest('hex');
  const file = p => path.join(dir, ...check(p).split('/'));
  return {
    kind: 'local', label: dir,
    async list(folder) {
      try { const names = await readdir(path.join(dir, ...check(folder, SAFE_FOLDER).split('/'))); return Promise.all(names.filter(n => DAY_FILE.test(n)).map(async name => ({ name, size: Buffer.byteLength(await readFile(path.join(dir, ...folder.split('/'), name), 'utf8')) }))); }
      catch (e) { if (e.code === 'ENOENT') return []; throw e; }
    },
    async get(p) {
      try { const text = await readFile(file(p), 'utf8'); return { text, sha: hash(text) }; } catch (e) { if (e.code === 'ENOENT') return null; throw e; }
    },
    async put(p, text, sha) {
      const current = await this.get(p);
      if ((current?.sha ?? null) !== (sha ?? null)) throw err('audit file changed since it was read', 409);
      await mkdir(path.dirname(file(p)), { recursive: true });
      await writeFile(`${file(p)}.tmp`, text);
      await rename(`${file(p)}.tmp`, file(p));
      return { sha: hash(text) };
    },
  };
}

export function createGitHubAuditStore({ repo, branch = 'main', token, fetchImpl = (...a) => fetch(...a) }) {
  if (!REPO.test(repo || '')) throw new Error('E360_AUDIT_REPO must be owner/repo');
  if (!token) throw new Error('E360_AUDIT_GITHUB_TOKEN is not set');
  const [owner, name] = repo.split('/');
  const base = `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(name)}/contents`;
  const headers = extra => ({ authorization: `Bearer ${token}`, accept: 'application/vnd.github+json', 'x-github-api-version': '2022-11-28', 'user-agent': 'entity-360-audit', ...extra });
  const call = async (url, init = {}) => {
    const r = await fetchImpl(url, { ...init, headers: headers(init.headers), redirect: 'error', signal: AbortSignal.timeout(20_000) });
    if (r.status === 404) return null;
    // 409: branch moved or sha conflict; 422: "sha does not match". Both mean re-read and try again.
    if (r.status === 409 || r.status === 422) throw err(`audit repository conflict (HTTP ${r.status})`, 409);
    if (!r.ok) throw err(`audit repository returned HTTP ${r.status}`, r.status);
    return r;
  };
  const ref = `ref=${encodeURIComponent(branch)}`;
  return {
    kind: 'github', label: repo,
    async list(folder) {
      const r = await call(`${base}/${check(folder, SAFE_FOLDER)}?${ref}`);
      if (!r) return [];
      const rows = await r.json();
      return (Array.isArray(rows) ? rows : []).filter(e => e.type === 'file' && DAY_FILE.test(e.name)).map(e => ({ name: e.name, size: e.size }));
    },
    async get(p) {
      const r = await call(`${base}/${check(p)}?${ref}`);
      if (!r) return null;
      const j = await r.json();
      // Parts stay under MAX_PART, well inside the 1 MB the JSON form returns inline.
      if (j.encoding !== 'base64' || typeof j.content !== 'string') throw err('audit file was not returned inline', 502);
      return { text: Buffer.from(j.content, 'base64').toString('utf8'), sha: j.sha };
    },
    async put(p, text, sha) {
      const body = { message: `e360 audit: ${p.split('/').pop()}`, branch, content: Buffer.from(text, 'utf8').toString('base64'), ...(sha ? { sha } : {}) };
      const r = await call(`${base}/${check(p)}`, { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
      if (!r) throw err('audit repository or branch not found (check E360_AUDIT_REPO and the token)', 404);
      return { sha: (await r.json()).content?.sha };
    },
  };
}

// Settings (Container Apps env vars; the token is a secret reference, never in git or the image):
//   E360_AUDIT_REPO=owner/repo  E360_AUDIT_GITHUB_TOKEN=<secretref>  [E360_AUDIT_BRANCH=main]   or   E360_AUDIT_DIR=<folder>
export function auditStoreFromEnv(env = process.env, { fetchImpl } = {}) {
  if (env.E360_AUDIT_REPO) {
    try { return { store: createGitHubAuditStore({ repo: env.E360_AUDIT_REPO, branch: env.E360_AUDIT_BRANCH || 'main', token: env.E360_AUDIT_GITHUB_TOKEN, fetchImpl }), problem: null }; }
    catch (e) { return { store: null, problem: e.message }; }
  }
  if (env.E360_AUDIT_DIR) return { store: createLocalAuditStore(path.resolve(env.E360_AUDIT_DIR)), problem: null };
  return { store: null, problem: 'not configured (set E360_AUDIT_REPO and E360_AUDIT_GITHUB_TOKEN)' };
}

// ---------------------------------------------------------------- the trail
export class AuditTrail {
  constructor({ store = null, problem = null, write = line => process.stdout.write(line + '\n'), now = () => Date.now(), maxPart = MAX_PART, maxPending = 5000, delayMs = 1500, retryMs = RETRY_MS } = {}) {
    Object.assign(this, { store, problem, write, now, maxPart, maxPending, delayMs, retryMs });
    this.pending = []; this.parts = new Map(); this.failures = 0; this.dropped = 0; this.lastWriteAt = null; this.lastError = null; this.timer = null; this.flushing = null;
  }

  // Synchronous for callers: the stdout line is written now, the durable write follows within a couple of seconds.
  record(entry) {
    const rec = { id: randomUUID(), time: new Date(this.now()).toISOString(), ...entry };
    try { this.write(AUDIT_PREFIX + JSON.stringify(rec)); } catch { /* logging must not fail the request */ }
    if (!this.store) return rec;
    this.pending.push(rec);
    if (this.pending.length > this.maxPending) {
      const lost = this.pending.splice(0, this.pending.length - this.maxPending);
      this.dropped += lost.length;
      try { this.write(AUDIT_PREFIX + JSON.stringify({ type: 'audit-dropped', time: new Date(this.now()).toISOString(), count: lost.length, reason: this.lastError })); } catch { /* ignore */ }
    }
    this.schedule(this.delayMs);
    return rec;
  }

  schedule(ms) {
    if (this.timer || !this.store) return;
    this.timer = setTimeout(() => { this.timer = null; this.flush().catch(() => {}); }, ms);
    this.timer.unref?.();
  }

  // One writer at a time. Records that arrive during a write go in the next batch.
  flush() {
    if (!this.store) return Promise.resolve();
    if (this.flushing) return this.flushing;
    this.flushing = (async () => {
      while (this.pending.length) {
        const batch = this.pending.slice();
        try { await this.writeBatch(batch); this.failures = 0; this.lastError = null; this.lastWriteAt = new Date(this.now()).toISOString(); }
        catch (e) {
          this.lastError = e.message; this.failures++;
          clearTimeout(this.timer); this.timer = null;
          this.schedule(this.retryMs[Math.min(this.failures - 1, this.retryMs.length - 1)]);
          break;
        }
      }
    })().finally(() => { this.flushing = null; });
    return this.flushing;
  }

  async writeBatch(batch) {
    const byDay = new Map();
    for (const rec of batch) { const d = dayOf(rec.time); if (!byDay.has(d)) byDay.set(d, []); byDay.get(d).push(rec); }
    for (const [day, recs] of byDay) {
      // Pack lines into chunks that fit a part, write each, and drop exactly those records from pending.
      let chunk = [], bytes = 0;
      const send = async () => { if (!chunk.length) return; await this.append(day, chunk.map(r => JSON.stringify(r) + '\n').join('')); const done = new Set(chunk); this.pending = this.pending.filter(r => !done.has(r)); chunk = []; bytes = 0; };
      for (const rec of recs) {
        const n = Buffer.byteLength(JSON.stringify(rec)) + 1;
        if (bytes + n > this.maxPart) await send();
        chunk.push(rec); bytes += n;
      }
      await send();
    }
    for (const d of this.parts.keys()) if (!byDay.has(d) && d < dayOf(new Date(this.now()).toISOString())) this.parts.delete(d);
  }

  // The newest part of a day, from the store (once) and then from memory.
  async currentPart(day) {
    if (this.parts.has(day)) return this.parts.get(day);
    const names = (await this.store.list(`audit/${day.slice(0, 7)}`)).map(f => DAY_FILE.exec(f.name)).filter(m => m && m[1] === day);
    const n = names.length ? Math.max(...names.map(m => Number(m[2] || 0))) : 0;
    const found = await this.store.get(partPath(day, n));
    const part = { n, text: found?.text ?? '', sha: found?.sha ?? null };
    this.parts.set(day, part);
    return part;
  }

  async append(day, lines) {
    for (let attempt = 0; ; attempt++) {
      let part = await this.currentPart(day);
      if (part.text && Buffer.byteLength(part.text) + Buffer.byteLength(lines) > this.maxPart) { part = { n: part.n + 1, text: '', sha: null }; this.parts.set(day, part); }
      const text = part.text && !part.text.endsWith('\n') ? `${part.text}\n${lines}` : part.text + lines;
      try {
        const { sha } = await this.store.put(partPath(day, part.n), text, part.sha);
        this.parts.set(day, { n: part.n, text, sha });
        return;
      } catch (e) {
        this.parts.delete(day);
        if (e.status !== 409 || attempt >= 2) throw e;
      }
    }
  }

  // Records of the last `days` UTC days (oldest first), from the store plus anything not written yet. Duplicates (a
  // write that succeeded but whose answer was lost, then retried) are removed by id.
  async recent({ days = 14, types = null } = {}) {
    const out = new Map();
    const keep = r => r && typeof r === 'object' && typeof r.time === 'string' && (!types || types.includes(r.type));
    if (this.store) {
      const today = new Date(this.now());
      const wanted = Array.from({ length: days }, (_, i) => new Date(Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), today.getUTCDate() - i)).toISOString().slice(0, 10));
      const months = [...new Set(wanted.map(d => d.slice(0, 7)))];
      const listed = (await Promise.all(months.map(m => this.store.list(`audit/${m}`)))).flat();
      const files = listed.map(f => DAY_FILE.exec(f.name)).filter(m => m && wanted.includes(m[1])).map(m => ({ day: m[1], n: Number(m[2] || 0) }))
        .sort((a, b) => a.day.localeCompare(b.day) || a.n - b.n);
      const texts = await Promise.all(files.map(f => this.store.get(partPath(f.day, f.n)).then(r => r?.text || '')));
      for (const text of texts) for (const line of text.split('\n')) {
        if (!line.trim()) continue;
        let r; try { r = JSON.parse(line); } catch { continue; }
        if (keep(r)) out.set(r.id || `${r.time}:${line.length}`, r);
      }
    }
    for (const r of this.pending) if (keep(r)) out.set(r.id, r);
    return [...out.values()].sort((a, b) => a.time.localeCompare(b.time));
  }

  status() {
    return { durable: Boolean(this.store), kind: this.store?.kind || 'none', where: this.store?.label || null, problem: this.store ? null : this.problem,
      pending: this.pending.length, lastWriteAt: this.lastWriteAt, lastError: this.lastError, dropped: this.dropped };
  }

  // On shutdown (SIGTERM when Container Apps scales in): write what is pending, but never hang past the grace period.
  async close({ timeoutMs = 20_000 } = {}) {
    clearTimeout(this.timer); this.timer = null;
    if (!this.store || !this.pending.length) return;
    let timer;
    await Promise.race([this.flush(), new Promise(r => { timer = setTimeout(r, timeoutMs); })]);
    clearTimeout(timer);
  }
}
