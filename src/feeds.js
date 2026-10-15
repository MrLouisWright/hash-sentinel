import { readFileSync, statSync, readdirSync, existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { join, basename } from 'node:path';
import { createHash } from 'node:crypto';
import { homedir } from 'node:os';
import { fuzzyType } from './fuzzy.js';

export const HASH_TYPES = { 32: 'md5', 40: 'sha1', 64: 'sha256', 128: 'sha512' };
export const hashType = (h) => (/^[0-9a-f]+$/i.test(h) ? HASH_TYPES[h.length] || null : null);
const HASH_RE = /\b(?:[0-9a-f]{128}|[0-9a-f]{64}|[0-9a-f]{40}|[0-9a-f]{32})\b/gi;

/** In-memory index: hash -> [{ feed, label, malicious, source }] */
export class HashIndex {
  constructor() { this.map = new Map(); this.feeds = []; this.fuzzy = []; }
  /** Add a fuzzy hash (ssdeep or TLSH) entry. */
  addFuzzy(type, value, entry) { const v = type === 'tlsh' ? String(value).toUpperCase().replace(/^(?!T1)/, 'T1') : String(value); if (!this.fuzzy.some((f) => f.value === v && f.entry.feed === entry.feed)) this.fuzzy.push({ type, value: v, entry }); }
  add(hash, entry) { const h = hash.toLowerCase(); if (!hashType(h)) return; const a = this.map.get(h); if (a) { if (!a.some((x) => x.feed === entry.feed && x.label === entry.label)) a.push(entry); } else this.map.set(h, [entry]); }
  get(h) { return this.map.get(h.toLowerCase()) || []; }
  get size() { return this.map.size; }
}

function splitCsv(line, d = ',') {
  const out = []; let cur = ''; let q = false;
  for (let i = 0; i < line.length; i++) { const c = line[i]; if (q) { if (c === '"' && line[i + 1] === '"') { cur += '"'; i++; } else if (c === '"') q = false; else cur += c; } else if (c === '"') q = true; else if (c === d) { out.push(cur); cur = ''; } else cur += c; }
  out.push(cur); return out.map((s) => s.trim());
}

const MISP_HASH = /^(md5|sha1|sha256|sha512|sha224|sha384|filename\|(md5|sha1|sha256|sha512)|malware-sample)$/;
function mispAttributes(ev, out, ctx) {
  const e = ev.Event || ev;
  const info = e.info || ctx.info;
  const threat = { 1: 'high', 2: 'medium', 3: 'low', 4: 'undefined' }[e.threat_level_id] || undefined;
  const tags = (e.Tag || []).map((t) => t.name);
  const take = (a, objName) => {
    if (!a || !MISP_HASH.test(a.type || '')) return;
    let v = String(a.value || ''); let file;
    if (v.includes('|')) { [file, v] = v.split('|'); }
    out.push({ hash: v, label: [info, a.comment, objName, file].filter(Boolean).join(' / ') || undefined, malicious: a.to_ids === true || a.to_ids === '1' || a.to_ids === 1, meta: { event: e.uuid || e.id, category: a.category, threat, tags: tags.length ? tags : undefined } });
  };
  for (const a of e.Attribute || []) take(a);
  for (const o of e.Object || []) for (const a of o.Attribute || []) take(a, o.name);
}

/**
 * Parse feed content. Formats: plain list (hash [label]), sha256sum output, CSV/TSV with a hash column
 * (MalwareBazaar exports, MISP hashes.csv), MISP event JSON / REST search results, JSON arrays.
 * @returns {{hash:string,label?:string,malicious:boolean,meta?:object}[]}
 */
export function parseFeed(text, { name = 'feed', format = 'auto', malicious = true } = {}) {
  const t = String(text).replace(/^\uFEFF/, ''); const out = [];
  const head = t.split(/\r?\n/).filter((l) => l.trim()).slice(0, 50);
  const looksCsv = head.some((l) => /[,;\t]/.test(l) && (/(sha256|sha1|md5|hash)/i.test(l) || splitCsv(l.replace(/^#\s*/, ''), l.includes('\t') ? '\t' : l.includes(';') && !l.includes(',') ? ';' : ',').some((c) => hashType(c))));
  const fmt = format !== 'auto' ? format : /^\s*[[{]/.test(t) ? 'json' : looksCsv ? 'csv' : 'text';
  if (fmt === 'json') {
    let j; try { j = JSON.parse(t); } catch (e) { throw new Error(`${name}: invalid JSON (${e.message})`); }
    const visit = (x) => {
      if (Array.isArray(x)) { for (const y of x) visit(y); return; }
      if (typeof x === 'string') { if (hashType(x)) out.push({ hash: x, malicious }); return; }
      if (!x || typeof x !== 'object') return;
      if (x.Event || x.Attribute || x.Object) { mispAttributes(x, out, {}); return; }
      if (x.response) { visit(x.response); return; }
      if (x.data && Array.isArray(x.data)) { visit(x.data); return; }
      const keys = ['sha256', 'sha256_hash', 'sha1', 'sha1_hash', 'md5', 'md5_hash', 'sha512', 'hash'];
      for (const k of keys) if (typeof x[k] === 'string' && hashType(x[k])) out.push({ hash: x[k], label: x.signature || x.name || x.file_name || x.label || x.description || undefined, malicious: x.malicious ?? malicious });
      for (const k of ['ssdeep', 'tlsh']) if (typeof x[k] === 'string' && fuzzyType(x[k]) === k) out.push({ hash: x[k], fuzzy: k, label: x.signature || x.name || x.file_name || x.label || undefined, malicious: x.malicious ?? malicious });
    };
    visit(j);
    return out;
  }
  if (fmt === 'csv') {
    const lines = t.split(/\r?\n/);
    let header = null; let delim = ',';
    for (const raw of lines) {
      let line = raw.trim(); if (!line) continue;
      if (line.startsWith('#')) { const h = line.replace(/^#\s*/, ''); if (!header && /(sha256|sha1|md5|hash)/i.test(h) && /[,;\t]/.test(h)) { delim = h.includes('\t') ? '\t' : h.includes(';') && !h.includes(',') ? ';' : ','; header = splitCsv(h, delim).map((x) => x.toLowerCase().replace(/"/g, '')); } continue; }
      if (!header && /(sha256|sha1|md5|hash)/i.test(line) && !line.match(HASH_RE)) { delim = line.includes('\t') ? '\t' : line.includes(';') && !line.includes(',') ? ';' : ','; header = splitCsv(line, delim).map((x) => x.toLowerCase()); continue; }
      const cells = splitCsv(line, delim);
      const labelIdx = header ? ['signature', 'malware', 'family', 'name', 'file_name', 'filename', 'label', 'comment', 'tags', 'eventuuid', 'event'].map((k) => header.indexOf(k)).find((i) => i >= 0) : -1;
      cells.forEach((c, i) => { const ft = fuzzyType(c); if (ft && (!header || /ssdeep|tlsh|fuzzy|hash/.test(header[i] || 'hash'))) { out.push({ hash: c, fuzzy: ft, label: labelIdx >= 0 && cells[labelIdx] && cells[labelIdx] !== 'n/a' ? cells[labelIdx] : undefined, malicious }); return; } if (hashType(c) && (!header || /sha|md5|hash/.test(header[i] || 'hash'))) out.push({ hash: c, label: labelIdx >= 0 && cells[labelIdx] && cells[labelIdx] !== 'n/a' ? cells[labelIdx] : undefined, malicious }); });
    }
    return out;
  }
  for (const raw of t.split(/\r?\n/)) {
    const line = raw.replace(/\s+#.*$/, '').trim(); if (!line || line.startsWith('#') || line.startsWith(';')) continue;
    const fz = line.split(/[\s,]+/)[0].replace(/^"|"$/g, '');
    if (fuzzyType(fz)) { out.push({ hash: fz, fuzzy: fuzzyType(fz), label: line.slice(fz.length).replace(/^[\s,"]+|"$/g, '').trim() || undefined, malicious }); continue; }
    if (/^ssdeep,\d/.test(line)) continue; // ssdeep -l header
    const bsd = line.match(/^(?:MD5|SHA1|SHA256|SHA512)\s*\((.+)\)\s*=\s*([0-9a-f]+)$/i);
    if (bsd) { if (hashType(bsd[2])) out.push({ hash: bsd[2], label: bsd[1], malicious }); continue; }
    const sum = line.match(/^\\?([0-9a-f]{32,128})(?:\s+\*?(.*))?$/i);
    if (sum && hashType(sum[1])) { out.push({ hash: sum[1], label: sum[2]?.trim() || undefined, malicious }); continue; }
    for (const h of line.match(HASH_RE) || []) out.push({ hash: h, label: line.replace(h, '').replace(/[,;|\t]+/g, ' ').trim() || undefined, malicious });
  }
  return out;
}

export function cacheDir() { return process.env.HASH_SENTINEL_CACHE || join(process.env.XDG_CACHE_HOME || join(homedir(), '.cache'), 'hash-sentinel'); }

/**
 * Load feeds into an index. A feed is a path (file or MISP feed directory), a URL (cached), or { path|url, name, malicious, format, ttl }.
 */
export async function loadFeeds(feeds, { index = new HashIndex(), fetchImpl = globalThis.fetch, cache = cacheDir(), ttl = 6 * 3600, offline = false, errors = [] } = {}) {
  for (const f0 of feeds) {
    const f = typeof f0 === 'string' ? (/^https?:\/\//.test(f0) ? { url: f0 } : { path: f0 }) : f0;
    const name = f.name || basename(f.path || f.url);
    const opts = { name, format: f.format || 'auto', malicious: f.malicious !== false };
    const before = index.size;
    try {
      let entries = [];
      if (f.url) {
        const key = createHash('sha256').update(f.url).digest('hex').slice(0, 24); const file = join(cache, `${key}.feed`);
        let text = null;
        const fresh = existsSync(file) && (Date.now() - statSync(file).mtimeMs) / 1000 < (f.ttl ?? ttl);
        if (fresh || offline) { if (existsSync(file)) text = readFileSync(file, 'utf8'); else throw new Error('not cached and --offline is set'); }
        else {
          try {
            const res = await fetchImpl(f.url, { signal: AbortSignal.timeout(30000), headers: { 'user-agent': 'hash-sentinel' } });
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            text = await res.text();
            mkdirSync(cache, { recursive: true }); writeFileSync(file, text);
          } catch (e) { if (existsSync(file)) { text = readFileSync(file, 'utf8'); errors.push(`${name}: download failed (${e.message}); using stale cache`); } else throw e; }
        }
        entries = parseFeed(text, opts);
      } else if (statSync(f.path).isDirectory()) {
        for (const e of readdirSync(f.path).sort()) {
          const p = join(f.path, e);
          if (e === 'manifest.json' || !statSync(p).isFile()) continue;
          if (/\.(json|csv|txt|tsv)$/i.test(e)) entries.push(...parseFeed(readFileSync(p, 'utf8'), { ...opts, name: `${name}/${e}`, malicious: e === 'hashes.csv' ? opts.malicious : opts.malicious }));
        }
      } else entries = parseFeed(readFileSync(f.path, 'utf8'), opts);
      for (const e of entries.filter((x) => x.fuzzy)) index.addFuzzy(e.fuzzy, e.hash, { feed: name, label: e.label, malicious: e.malicious });
      for (const e of entries.filter((x) => !x.fuzzy)) index.add(e.hash, { feed: name, label: e.label, malicious: e.malicious, ...(e.meta ? { meta: e.meta } : {}) });
      index.feeds.push({ name, entries: entries.length, unique: index.size - before });
    } catch (e) { errors.push(`${name}: ${e.code === 'ENOENT' ? 'not found' : e.message}`); index.feeds.push({ name, entries: 0, error: e.message }); }
  }
  return index;
}
