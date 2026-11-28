// Minimal PDF writer for the single-entity report. No dependencies: the 14 standard PDF fonts (Helvetica, Helvetica-Bold)
// need no embedding, text is WinAnsi-encoded, and page streams are deflated with node:zlib.
// Input is a document model: { title, subtitle, meta: [[label, value]], sections: [{ title, status, blocks: [...] }], footer }.
// Block types: { type: 'text', text, style? } · { type: 'kv', rows: [[label, value]] } · { type: 'table', columns: [{ label, w }], rows: [[cell]] }
//              · { type: 'list', items: [text] } · { type: 'heading', text } · { type: 'callout', text, tone: 'warn' | 'info' }
import { deflateSync } from 'node:zlib';

// Advance widths (1/1000 em) for WinAnsi codes 32..255, from the Adobe AFM files of the standard fonts.
const HELV = [278,278,355,556,556,889,667,191,333,333,389,584,278,333,278,278,556,556,556,556,556,556,556,556,556,556,278,278,584,584,584,556,1015,667,667,722,722,667,611,778,722,278,500,667,556,833,722,778,667,778,722,667,611,722,667,944,667,667,611,278,278,278,469,556,333,556,556,500,556,556,278,556,556,222,222,500,222,833,556,556,556,556,333,500,278,556,500,722,500,500,500,334,260,334,584,350,556,350,222,556,333,1000,556,556,333,1000,667,333,1000,350,611,350,350,222,222,333,333,350,556,1000,333,1000,500,333,944,350,500,667,278,333,556,556,556,556,260,556,333,737,370,556,584,333,737,333,400,584,333,333,333,556,537,278,333,333,365,556,834,834,834,611,667,667,667,667,667,667,1000,722,667,667,667,667,278,278,278,278,722,722,778,778,778,778,778,584,778,722,722,722,722,667,667,611,556,556,556,556,556,556,889,500,556,556,556,556,278,278,278,278,556,556,556,556,556,556,556,584,611,556,556,556,556,500,556,500];
const HELV_BOLD = [278,333,474,556,556,889,722,238,333,333,389,584,278,333,278,278,556,556,556,556,556,556,556,556,556,556,333,333,584,584,584,611,975,722,722,722,722,667,611,778,722,278,556,722,611,833,722,778,667,778,722,667,611,722,667,944,667,667,611,333,278,333,584,556,333,556,611,556,611,556,333,611,611,278,278,556,278,889,611,611,611,611,389,556,333,611,556,778,556,556,500,389,280,389,584,350,556,350,278,556,500,1000,556,556,333,1000,667,333,1000,350,611,350,350,278,278,500,500,350,556,1000,333,1000,556,333,944,350,500,667,278,333,556,556,556,556,280,556,333,737,370,556,584,333,737,333,400,584,333,333,333,611,556,278,333,333,365,556,834,834,834,611,722,722,722,722,722,722,1000,722,667,667,667,667,278,278,278,278,722,722,778,778,778,778,778,584,778,722,722,722,722,667,667,611,556,556,556,556,556,556,889,556,556,556,556,556,278,278,278,278,611,611,611,611,611,611,611,584,611,611,611,611,611,556,611,556];
const WIDTHS = { F1: HELV, F2: HELV_BOLD };

// Unicode characters WinAnsi has outside Latin-1, plus readable stand-ins for common symbols it lacks.
const WIN = { '€': 0x80, '‚': 0x82, 'ƒ': 0x83, '„': 0x84, '…': 0x85, '†': 0x86, '‡': 0x87, 'ˆ': 0x88, '‰': 0x89, 'Š': 0x8a, '‹': 0x8b, 'Œ': 0x8c, 'Ž': 0x8e,
  '‘': 0x91, '’': 0x92, '“': 0x93, '”': 0x94, '•': 0x95, '–': 0x96, '—': 0x97, '˜': 0x98, '™': 0x99, 'š': 0x9a, '›': 0x9b, 'œ': 0x9c, 'ž': 0x9e, 'Ÿ': 0x9f };
const SUBST = { '→': '->', '←': '<-', '↔': '<->', '⇒': '=>', '≥': '>=', '≤': '<=', '≠': '!=', '✓': 'Yes', '✔': 'Yes', '✕': 'x', '✗': 'x', ' ': ' ', ' ': ' ', ' ': ' ', '​': '', '﻿': '', '↗': '' };

// String to WinAnsi byte string (one JS char per byte). Characters outside WinAnsi become '?'.
export function winAnsi(value) {
  let out = '';
  for (const ch of String(value ?? '').normalize('NFC')) {
    const code = ch.codePointAt(0);
    if (ch === '\t') { out += ' '; continue; }
    if (code < 32) continue;
    if (code < 127 || (code >= 160 && code <= 255)) { out += ch; continue; }
    if (WIN[ch]) { out += String.fromCharCode(WIN[ch]); continue; }
    if (ch in SUBST) { out += winAnsi(SUBST[ch]); continue; }
    const base = ch.normalize('NFD').replace(/[̀-ͯ]/g, '');
    out += base !== ch && base.length === 1 && base.charCodeAt(0) < 256 ? base : '?';
  }
  return out;
}
const charWidth = (font, c) => { const i = c.charCodeAt(0) - 32; return (WIDTHS[font][i] ?? 556); };
export const textWidth = (bytes, font, size) => { let w = 0; for (const c of bytes) w += charWidth(font, c); return w * size / 1000; };
const pdfString = bytes => `(${bytes.replace(/[\\()]/g, m => `\\${m}`).replace(/[\x80-\xff]/g, c => `\\${c.charCodeAt(0).toString(8).padStart(3, '0')}`)})`;

// Break WinAnsi text into lines no wider than `width`. Words longer than a line (URLs, IDs) are split by character.
export function wrap(bytes, font, size, width) {
  const lines = [];
  for (const para of bytes.split(/\r?\n/)) {
    let line = '';
    for (const word of para.split(/ +/)) {
      const candidate = line ? `${line} ${word}` : word;
      if (textWidth(candidate, font, size) <= width) { line = candidate; continue; }
      if (line) lines.push(line);
      line = '';
      let rest = word;
      while (textWidth(rest, font, size) > width) {
        let n = 1;
        while (n < rest.length && textWidth(rest.slice(0, n + 1), font, size) <= width) n++;
        lines.push(rest.slice(0, n)); rest = rest.slice(n);
      }
      line = rest;
    }
    lines.push(line);
  }
  return lines;
}

const PAGE = { w: 612, h: 792, margin: 48, top: 56, bottom: 52 };
const COLOR = { ink: '0.10 0.12 0.16', muted: '0.40 0.43 0.48', accent: '0.12 0.30 0.55', rule: '0.80 0.82 0.86', head: '0.92 0.94 0.97', zebra: '0.97 0.975 0.98', warnFill: '1 0.96 0.86', warnInk: '0.50 0.32 0.00', infoFill: '0.92 0.95 1', okInk: '0.10 0.45 0.20', badInk: '0.70 0.15 0.10' };
const MAX_CELL_LINES = 14;

class Layout {
  constructor(doc) { this.doc = doc; this.pages = []; this.outline = []; this.newPage(); }
  get width() { return PAGE.w - 2 * PAGE.margin; }
  newPage() { this.ops = []; this.pages.push(this.ops); this.y = PAGE.h - PAGE.top; }
  ensure(h) { if (this.y - h < PAGE.bottom) { this.newPage(); return true; } return false; }
  text(x, y, bytes, { font = 'F1', size = 9, color = COLOR.ink } = {}) { if (bytes) this.ops.push(`BT /${font} ${size} Tf ${color} rg ${x.toFixed(2)} ${y.toFixed(2)} Td ${pdfString(bytes)} Tj ET`); }
  rect(x, y, w, h, color) { this.ops.push(`${color} rg ${x.toFixed(2)} ${y.toFixed(2)} ${w.toFixed(2)} ${h.toFixed(2)} re f`); }
  line(x1, y1, x2, y2, color = COLOR.rule, width = 0.5) { this.ops.push(`${color} RG ${width} w ${x1.toFixed(2)} ${y1.toFixed(2)} m ${x2.toFixed(2)} ${y2.toFixed(2)} l S`); }
  paragraph(value, { font = 'F1', size = 9, color = COLOR.ink, indent = 0, gap = 4 } = {}) {
    const lead = size * 1.3;
    for (const l of wrap(winAnsi(value), font, size, this.width - indent)) { this.ensure(lead); this.y -= lead; this.text(PAGE.margin + indent, this.y + 2, l, { font, size, color }); }
    this.y -= gap;
  }
  sectionTitle(section, index) {
    this.ensure(70);
    this.y -= 22;
    const label = winAnsi(`${index}. ${section.title}`);
    this.text(PAGE.margin, this.y, label, { font: 'F2', size: 14, color: COLOR.accent });
    const status = section.status === 'unavailable' ? ['NOT READ', COLOR.badInk] : section.status === 'partial' ? ['PARTIAL', COLOR.warnInk] : section.status === 'empty' ? ['NONE FOUND', COLOR.muted] : null;
    if (status) { const s = winAnsi(status[0]); this.text(PAGE.w - PAGE.margin - textWidth(s, 'F2', 8), this.y + 2, s, { font: 'F2', size: 8, color: status[1] }); }
    this.outline.push({ title: label, page: this.pages.length - 1, y: this.y + 18 });
    this.y -= 6; this.line(PAGE.margin, this.y, PAGE.w - PAGE.margin, this.y, COLOR.accent, 0.8); this.y -= 8;
  }
  heading(value) { this.ensure(40); this.y -= 6; this.paragraph(value, { font: 'F2', size: 10.5, color: COLOR.ink, gap: 2 }); }
  callout(value, tone = 'warn') {
    const size = 8.5, lead = size * 1.3, pad = 6, lines = wrap(winAnsi(value), 'F1', size, this.width - 2 * pad - 4);
    let i = 0;
    while (i < lines.length) {
      this.ensure(lead + 2 * pad);
      const fit = Math.max(1, Math.min(lines.length - i, Math.floor((this.y - PAGE.bottom - 2 * pad) / lead)));
      const h = fit * lead + 2 * pad;
      this.rect(PAGE.margin, this.y - h, this.width, h, tone === 'warn' ? COLOR.warnFill : COLOR.infoFill);
      this.rect(PAGE.margin, this.y - h, 2.5, h, tone === 'warn' ? COLOR.warnInk : COLOR.accent);
      let y = this.y - pad;
      for (const l of lines.slice(i, i + fit)) { y -= lead; this.text(PAGE.margin + pad + 4, y + 2.5, l, { size, color: tone === 'warn' ? COLOR.warnInk : COLOR.ink }); }
      this.y -= h; i += fit;
    }
    this.y -= 6;
  }
  list(items) { for (const item of items) { const bullet = winAnsi('•'); this.ensure(12); this.text(PAGE.margin + 4, this.y - 9.7, bullet, { size: 9, color: COLOR.muted }); this.paragraph(item, { indent: 14, gap: 1 }); } this.y -= 3; }
  kv(rows) {
    const size = 8.5, lead = size * 1.32, keyW = Math.min(170, this.width * 0.32), valW = this.width - keyW - 8;
    rows.forEach(([k, v], i) => {
      const kl = wrap(winAnsi(k), 'F2', size, keyW - 4), vl = wrap(winAnsi(display(v)), 'F1', size, valW).slice(0, 40);
      const n = Math.max(kl.length, vl.length), h = n * lead + 4;
      this.ensure(h <= 300 ? h : lead * 3);
      if (i % 2 === 0 && h <= this.y - PAGE.bottom) this.rect(PAGE.margin, this.y - h, this.width, h, COLOR.zebra);
      let y = this.y - 2;
      for (let j = 0; j < n; j++) {
        y -= lead;
        if (y < PAGE.bottom) { this.newPage(); y = this.y - lead; }
        this.text(PAGE.margin + 4, y + 2.5, kl[j] || '', { font: 'F2', size, color: COLOR.muted });
        this.text(PAGE.margin + keyW + 8, y + 2.5, vl[j] || '', { size });
      }
      this.y = y - 2;
    });
    this.y -= 8;
  }
  table(columns, rows) {
    const size = 7.5, lead = size * 1.3, pad = 3;
    const total = columns.reduce((s, c) => s + (c.w || 1), 0);
    const widths = columns.map(c => (c.w || 1) / total * this.width);
    const xs = widths.reduce((acc, w, i) => (acc.push(i ? acc[i - 1] + widths[i - 1] : PAGE.margin), acc), []);
    const header = () => {
      const hl = columns.map((c, i) => wrap(winAnsi(c.label), 'F2', size, widths[i] - 2 * pad));
      const h = Math.max(...hl.map(l => l.length)) * lead + 2 * pad;
      this.rect(PAGE.margin, this.y - h, this.width, h, COLOR.head);
      hl.forEach((lines, i) => lines.forEach((l, j) => this.text(xs[i] + pad, this.y - pad - (j + 1) * lead + 2.5, l, { font: 'F2', size, color: COLOR.ink })));
      this.y -= h;
    };
    this.ensure(60); header();
    rows.forEach((row, r) => {
      const cells = columns.map((c, i) => { const l = wrap(winAnsi(display(row[i])), 'F1', size, widths[i] - 2 * pad); return l.length > MAX_CELL_LINES ? [...l.slice(0, MAX_CELL_LINES - 1), winAnsi('… (continued in the source)')] : l; });
      const h = Math.max(1, ...cells.map(l => l.length)) * lead + 2 * pad;
      if (this.ensure(h)) header();
      if (r % 2 === 1) this.rect(PAGE.margin, this.y - h, this.width, h, COLOR.zebra);
      cells.forEach((lines, i) => lines.forEach((l, j) => this.text(xs[i] + pad, this.y - pad - (j + 1) * lead + 2.5, l, { size })));
      this.y -= h;
      this.line(PAGE.margin, this.y, PAGE.w - PAGE.margin, this.y, COLOR.rule, 0.3);
    });
    this.y -= 10;
  }
  block(b) {
    if (b.type === 'text') return this.paragraph(b.text, b.style === 'muted' ? { color: COLOR.muted, size: 8.5 } : {});
    if (b.type === 'heading') return this.heading(b.text);
    if (b.type === 'callout') return this.callout(b.text, b.tone);
    if (b.type === 'list') return b.items.length ? this.list(b.items) : null;
    if (b.type === 'kv') return b.rows.length ? this.kv(b.rows) : null;
    if (b.type === 'table') return b.rows.length ? this.table(b.columns, b.rows) : null;
  }
}

// One display string for any value: dates in UTC, booleans as Yes/No, arrays joined, objects as key: value pairs.
export function display(v) {
  if (v === null || v === undefined || v === '') return '-';
  if (typeof v === 'boolean') return v ? 'Yes' : 'No';
  if (typeof v === 'number') return String(v);
  if (Array.isArray(v)) return v.length ? v.map(display).join('; ') : '-';
  if (typeof v === 'object') return Object.entries(v).filter(([, x]) => x !== null && x !== undefined && x !== '').map(([k, x]) => `${k}: ${display(x)}`).join(', ') || '-';
  const s = String(v);
  if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]00:00)$/.test(s)) return s.startsWith('0001-01-01') ? '-' : `${s.slice(0, 10)} ${s.slice(11, 16)} UTC`;
  return s;
}

export function renderPdf(doc) {
  const L = new Layout(doc);
  // Title block.
  L.y -= 6;
  L.text(PAGE.margin, L.y, winAnsi(doc.eyebrow || 'ENTITY 360 REPORT'), { font: 'F2', size: 8, color: COLOR.accent }); L.y -= 24;
  for (const l of wrap(winAnsi(doc.title), 'F2', 20, L.width)) { L.text(PAGE.margin, L.y, l, { font: 'F2', size: 20 }); L.y -= 24; }
  if (doc.subtitle) L.paragraph(doc.subtitle, { size: 10, color: COLOR.muted, gap: 8 });
  if (doc.meta?.length) L.kv(doc.meta);
  if (doc.intro) for (const t of [].concat(doc.intro)) L.callout(t, 'info');
  // Contents with each section's status.
  if (doc.sections.length > 1) {
    L.heading('Contents');
    L.table([{ label: '#', w: 0.4 }, { label: 'Section', w: 4 }, { label: 'Status', w: 3 }], doc.sections.map((s, i) => [String(i + 1), s.title, s.summary || statusText(s)]));
  }
  doc.sections.forEach((s, i) => {
    if (i === 0) L.newPage();
    L.sectionTitle(s, i + 1);
    if (s.reason) L.callout(`${s.status === 'unavailable' ? 'Could not be read' : 'Incomplete'}: ${s.reason}`, 'warn');
    for (const b of s.blocks || []) L.block(b);
  });
  return assemble(L, doc);
}
const statusText = s => s.status === 'unavailable' ? 'Could not be read' : s.status === 'partial' ? 'Partial' : s.status === 'empty' ? 'Nothing found' : 'Read';

function assemble(L, doc) {
  const objects = []; // index i holds object number i + 1
  const add = body => { objects.push(body); return objects.length; };
  const catalog = add(null), pagesObj = add(null), f1 = add('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>'), f2 = add('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>');
  const total = L.pages.length, pageIds = [];
  const footer = winAnsi(doc.footer || 'Entity 360');
  L.pages.forEach((ops, i) => {
    const n = winAnsi(`Page ${i + 1} of ${total}`), y = 30;
    const foot = [`${COLOR.rule} RG 0.5 w ${PAGE.margin} ${y + 10} m ${PAGE.w - PAGE.margin} ${y + 10} l S`,
      `BT /F1 7.5 Tf ${COLOR.muted} rg ${PAGE.margin} ${y} Td ${pdfString(wrap(footer, 'F1', 7.5, PAGE.w - 2 * PAGE.margin - 70)[0])} Tj ET`,
      `BT /F1 7.5 Tf ${COLOR.muted} rg ${(PAGE.w - PAGE.margin - textWidth(n, 'F1', 7.5)).toFixed(2)} ${y} Td ${pdfString(n)} Tj ET`];
    const data = deflateSync(Buffer.from([...ops, ...foot].join('\n'), 'latin1'));
    const stream = add({ stream: data });
    pageIds.push(add(`<< /Type /Page /Parent ${pagesObj} 0 R /MediaBox [0 0 ${PAGE.w} ${PAGE.h}] /Resources << /Font << /F1 ${f1} 0 R /F2 ${f2} 0 R >> >> /Contents ${stream} 0 R >>`));
  });
  objects[pagesObj - 1] = `<< /Type /Pages /Kids [${pageIds.map(p => `${p} 0 R`).join(' ')}] /Count ${total} >>`;
  // Bookmarks: one per section, so a PDF reader's sidebar jumps straight to it.
  let outlines = null;
  if (L.outline.length) {
    outlines = add(null);
    const ids = L.outline.map(() => add(null));
    L.outline.forEach((o, i) => { objects[ids[i] - 1] = `<< /Title ${pdfString(o.title)} /Parent ${outlines} 0 R${i ? ` /Prev ${ids[i - 1]} 0 R` : ''}${i < ids.length - 1 ? ` /Next ${ids[i + 1]} 0 R` : ''} /Dest [${pageIds[o.page]} 0 R /XYZ 0 ${o.y.toFixed(0)} 0] >>`; });
    objects[outlines - 1] = `<< /Type /Outlines /First ${ids[0]} 0 R /Last ${ids[ids.length - 1]} 0 R /Count ${ids.length} >>`;
  }
  objects[catalog - 1] = `<< /Type /Catalog /Pages ${pagesObj} 0 R${outlines ? ` /Outlines ${outlines} 0 R /PageMode /UseOutlines` : ''} >>`;
  const stamp = new Date().toISOString().replace(/[-:T]/g, '').slice(0, 14);
  const info = add(`<< /Title ${pdfString(winAnsi(doc.title))} /Producer (Entity 360) /Creator (Entity 360) /CreationDate (D:${stamp}Z) >>`);
  const chunks = [Buffer.from('%PDF-1.4\n%\xe2\xe3\xcf\xd3\n', 'latin1')];
  let offset = chunks[0].length;
  const offsets = [];
  objects.forEach((body, i) => {
    offsets.push(offset);
    const parts = body && body.stream
      ? [Buffer.from(`${i + 1} 0 obj\n<< /Length ${body.stream.length} /Filter /FlateDecode >>\nstream\n`, 'latin1'), body.stream, Buffer.from('\nendstream\nendobj\n', 'latin1')]
      : [Buffer.from(`${i + 1} 0 obj\n${body}\nendobj\n`, 'latin1')];
    for (const p of parts) { chunks.push(p); offset += p.length; }
  });
  const xref = `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n${offsets.map(o => `${String(o).padStart(10, '0')} 00000 n \n`).join('')}trailer\n<< /Size ${objects.length + 1} /Root ${catalog} 0 R /Info ${info} 0 R >>\nstartxref\n${offset}\n%%EOF\n`;
  chunks.push(Buffer.from(xref, 'latin1'));
  return Buffer.concat(chunks);
}
