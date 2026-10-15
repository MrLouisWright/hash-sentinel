import { readFileSync, statSync, readdirSync, createReadStream } from 'node:fs';
import { join, relative } from 'node:path';
import { createHash } from 'node:crypto';
import { buildReport, exceeds, exitCode, formatText, formatJson, formatSarif, formatMarkdown, SEVERITIES, ConfigError, validateConfig } from './core.js';
import { RULES } from './rules.js';
import { parseFeed, loadFeeds, HashIndex, hashType, cacheDir } from './feeds.js';
import { lookup, SOURCES, ENDPOINTS, DEFAULT_RATES, createLimiter, bulkCircl } from './online.js';
import { ssdeep, tlsh, compareSsdeep, compareTlsh, fuzzyType, parseSsdeep, parseTlsh } from './fuzzy.js';
import { LookupCache } from './lookupcache.js';

export { ssdeep, tlsh, compareSsdeep, compareTlsh, fuzzyType, parseSsdeep, parseTlsh, DEFAULT_RATES, createLimiter, bulkCircl, LookupCache };
export { parseFeed, loadFeeds, HashIndex, hashType, cacheDir, lookup, SOURCES, ENDPOINTS, RULES, exceeds, exitCode, formatText, formatJson, formatSarif, formatMarkdown, SEVERITIES, ConfigError };
export const VERSION = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version;
export const TOOL = { name: 'hash-sentinel', version: VERSION, rules: RULES, title: 'hash-sentinel', emoji: '#️⃣', defaultFailOn: 'high' };

/**
 * All hashes of an in-memory buffer: md5, sha1, sha256, sha512 plus fuzzy ssdeep and tlsh (null if too small/uniform).
 * Reusable by other tools (e.g. malware-report-sentinel).
 * @param {Uint8Array} buf
 * @param {{ fuzzy?: boolean }} [opts]
 * @returns {{ md5: string, sha1: string, sha256: string, sha512: string, ssdeep?: string, tlsh?: string|null }}
 */
export function hashBuffer(buf, { fuzzy = true } = {}) {
  const out = Object.fromEntries(['md5', 'sha1', 'sha256', 'sha512'].map((a) => [a, createHash(a).update(buf).digest('hex')]));
  if (fuzzy) { out.ssdeep = ssdeep(buf); out.tlsh = tlsh(buf); }
  return out;
}

const FUZZY_MAX = 256 * 1024 * 1024;
/**
 * Match fuzzy hashes against an index's fuzzy entries.
 * @param {{ ssdeep?: string, tlsh?: string|null }} hashes
 * @param {{ fuzzy: {type: string, value: string, entry: object}[] }} index
 * @param {{ ssdeepThreshold?: number, tlshThreshold?: number }} [opts]  defaults 60 (score ≥) and 50 (distance ≤)
 */
export function fuzzyMatches(hashes, index, { ssdeepThreshold = 60, tlshThreshold = 50 } = {}) {
  const out = [];
  for (const f of index.fuzzy || []) {
    if (f.type === 'ssdeep' && hashes.ssdeep) { const score = compareSsdeep(hashes.ssdeep, f.value); if (score >= ssdeepThreshold) out.push({ ...f.entry, type: 'ssdeep', value: f.value, score }); }
    if (f.type === 'tlsh' && hashes.tlsh) { const distance = compareTlsh(hashes.tlsh, f.value); if (distance <= tlshThreshold) out.push({ ...f.entry, type: 'tlsh', value: f.value, distance }); }
  }
  return out.sort((a, b) => (b.score ?? 0) - (a.score ?? 0) || (a.distance ?? 0) - (b.distance ?? 0));
}

/** MD5, SHA1, SHA256 and SHA512 of a file, streamed. */
export function hashFile(path) {
  return new Promise((resolve, reject) => {
    const hs = ['md5', 'sha1', 'sha256', 'sha512'].map((a) => [a, createHash(a)]);
    createReadStream(path).on('data', (c) => { for (const [, h] of hs) h.update(c); }).on('error', reject).on('end', () => resolve(Object.fromEntries(hs.map(([a, h]) => [a, h.digest('hex')]))));
  });
}
function walk(p, out = []) { const st = statSync(p); if (st.isDirectory()) { for (const e of readdirSync(p).sort()) if (e !== '.git' && e !== 'node_modules') walk(join(p, e), out); } else if (st.isFile()) out.push(p); return out; }
async function pool(items, n, fn) { const out = new Array(items.length); let i = 0; await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => { while (i < items.length) { const k = i++; out[k] = await fn(items[k]); } })); return out; }

/**
 * Check hashes and/or files.
 * @param {string[]} inputs  hashes, file paths or directories
 * @param {object} opts  feeds, knownGood, online (['circl', ...]), offline, endpoints, keys, fetchImpl, allow, severity
 */
export async function check(inputs, opts = {}) {
  validateConfig({ allow: opts.allow, severity: opts.severity });
  const online = opts.online || [];
  const bad = online.filter((s) => !SOURCES.includes(s)); if (bad.length) throw new ConfigError(`Unknown online source(s): ${bad.join(', ')} (have ${SOURCES.join(', ')})`);
  const errors = [];
  const index = await loadFeeds(opts.feeds || [], { ...opts, errors });
  const goodSrc = [...(opts.knownGood || []), ...(opts.nsrl || []).map((p) => ({ ...(typeof p === 'string' ? (/^https?:/.test(p) ? { url: p } : { path: p }) : p), name: 'NSRL', format: 'csv' }))];
  const good = await loadFeeds(goodSrc.map((f) => (typeof f === 'string' ? { ...(/^https?:/.test(f) ? { url: f } : { path: f }), malicious: false } : { ...f, malicious: false })), { ...opts, errors });
  const items = [];
  for (const inp of inputs) {
    const s = String(inp).trim();
    if (hashType(s)) { items.push({ target: s.toLowerCase(), hashes: { [hashType(s)]: s.toLowerCase() } }); continue; }
    if (fuzzyType(s)) { items.push({ target: s, hashes: { [fuzzyType(s)]: fuzzyType(s) === 'tlsh' ? s.toUpperCase().replace(/^(?!T1)/, 'T1') : s }, fuzzyOnly: true }); continue; }
    let files; try { files = walk(s); } catch (e) {
      if (/^[0-9a-f]+$/i.test(s)) { items.push({ target: s, invalid: true }); continue; }
      items.push({ target: s, fatal: `Cannot read ${s}: ${e.code || e.message}` }); continue;
    }
    for (const f of files) items.push({ target: relative(process.cwd(), f) || f, file: f });
  }
  // phase 1: hash files (in parallel)
  await pool(items, opts.concurrency || 4, async (it) => {
    if (!it.file) return;
    it.hashes = await hashFile(it.file);
    if (opts.fuzzy !== false) { try { if (statSync(it.file).size <= FUZZY_MAX) { const buf = readFileSync(it.file); it.hashes.ssdeep = ssdeep(buf); const t = tlsh(buf); if (t) it.hashes.tlsh = t; } } catch {} }
  });
  // phase 2: online lookups — cached, batched (CIRCL bulk) and rate-limited per source
  const cache = new LookupCache(opts.offline || opts.lookupCache === false || (opts.endpoints && !opts.cache) ? null : (opts.cache || cacheDir()), opts.lookupTtl ?? 24 * 3600, opts.now ? () => new Date(opts.now).getTime() : Date.now);
  const rates = { ...DEFAULT_RATES, ...(opts.rates || {}) };
  const limiters = Object.fromEntries(online.map((src) => [src, createLimiter(rates[src], opts.clock)]));
  const primary = (h) => (h.sha256 ? ['sha256', h.sha256] : Object.entries(h).find(([k]) => hashType(k === 'md5' ? 'a'.repeat(32) : k === 'sha1' ? 'a'.repeat(40) : k === 'sha512' ? 'a'.repeat(128) : k === 'sha256' ? 'a'.repeat(64) : '')) || []);
  const ready = items.filter((it) => it.hashes && !it.fuzzyOnly);
  const lookupsOf = new Map(ready.map((it) => [it, []]));
  let requests = 0;
  if (online.length && !opts.offline) {
    for (const src of online) {
      const pending = [];
      for (const it of ready) { const [type, h] = primary(it.hashes); if (!h) continue; const c = cache.get(src, h); if (c) lookupsOf.get(it).push(c); else pending.push({ it, type, h }); }
      if (src === 'circl' && pending.length > 1 && opts.batch !== false) {
        const byType = {}; for (const p of pending) (byType[p.type] ||= []).push(p);
        for (const [type, ps] of Object.entries(byType)) {
          for (let i = 0; i < ps.length; i += 1000) {
            const chunk = ps.slice(i, i + 1000);
            await limiters[src].wait(); requests++;
            let res; try { res = await bulkCircl([...new Set(chunk.map((p) => p.h))], type, opts); } catch { res = null; }
            if (!res) { for (const p of chunk) { const r = await lookup(src, p.h, p.type, opts); cache.set(src, p.h, r); lookupsOf.get(p.it).push(r); } continue; }
            for (const p of chunk) { const r = res.get(p.h) || { source: src, found: false }; cache.set(src, p.h, r); lookupsOf.get(p.it).push(r); }
          }
        }
        continue;
      }
      for (const p of pending) {
        await limiters[src].wait(); requests++;
        const r = await lookup(src, p.h, p.type, opts);
        cache.set(src, p.h, r); lookupsOf.get(p.it).push(r);
      }
    }
    cache.save();
  }
  const results = items.map((it) => {
    if (it.fatal) return { target: it.target, fatal: true, raw: [], errors: [it.fatal] };
    if (it.invalid) return { target: it.target, raw: [{ rule: 'invalid-hash', message: `"${it.target}" is ${it.target.length} hex characters, not an MD5/SHA1/SHA256/SHA512`, fix: 'Check for truncation or copy/paste errors.' }], errors: [] };
    const hashes = it.hashes;
    const matches = []; const goods = [];
    for (const [k, h] of Object.entries(hashes)) { if (k === 'ssdeep' || k === 'tlsh') continue; matches.push(...index.get(h).map((m) => ({ ...m, hash: h }))); goods.push(...good.get(h).map((m) => ({ ...m, hash: h }))); }
    const fuzzy = fuzzyMatches(hashes, index, opts).filter((m) => m.malicious !== false || true);
    const lookups = lookupsOf.get(it) || [];
    const raw = []; const errs = [];
    const mal = [...matches.filter((m) => m.malicious).map((m) => `${m.feed}${m.label ? `: ${m.label}` : ''}`), ...lookups.filter((l) => l.malicious).map((l) => `${l.source}: ${l.label}`)];
    const soft = matches.filter((m) => !m.malicious).map((m) => `${m.feed}${m.label ? `: ${m.label}` : ''}`);
    const goodHits = [...goods.map((g) => `${g.feed}${g.label ? `: ${g.label}` : ''}`), ...lookups.filter((l) => l.knownGood).map((l) => `${l.source}: ${l.label}`)];
    const display = hashes.sha256 || Object.values(hashes)[0];
    if (mal.length) raw.push({ rule: 'known-malicious', message: `Known malicious: ${[...new Set(mal)].slice(0, 5).join('; ')}`, evidence: display, fix: 'Quarantine the file, block the hash and investigate where it came from.' });
    else if (soft.length) raw.push({ rule: 'feed-match', message: `Listed in ${[...new Set(soft)].slice(0, 5).join('; ')}`, evidence: display, fix: 'Review the feed context (MISP event / watchlist) before acting.' });
    if (!mal.length && fuzzy.length) raw.push({ rule: 'fuzzy-match', message: `Similar to ${fuzzy.slice(0, 3).map((m) => `${m.feed}${m.label ? `: ${m.label}` : ''} (${m.type} ${m.score != null ? `score ${m.score}` : `distance ${m.distance}`})`).join('; ')}`, evidence: hashes.ssdeep || hashes.tlsh || display, fix: 'A near-duplicate of a listed sample (repacked or patched variant?). Analyse before trusting it.' });
    if (goodHits.length && (mal.length || soft.length || fuzzy.length)) raw.push({ rule: 'known-good-conflict', message: `Also on a known-good list (${goodHits.slice(0, 3).join('; ')}): possible false positive or a trojanised copy of a legitimate file`, evidence: display });
    else if (goodHits.length) raw.push({ rule: 'known-good', message: `Known good: ${goodHits.slice(0, 3).join('; ')}`, evidence: display });
    for (const l of lookups.filter((x) => x.error)) raw.push({ rule: 'lookup-error', message: `${l.source} lookup failed: ${l.error}` });
    for (const l of lookups.filter((x) => x.skipped)) errs.push(`${l.source} skipped: ${l.skipped}`);
    const status = mal.length ? 'malicious' : soft.length ? 'listed' : fuzzy.length ? 'similar' : goodHits.length ? 'known-good' : 'unknown';
    return { target: it.target, raw, errors: errs, summary: { status, sha256: hashes.sha256, ...(it.file ? {} : { type: Object.keys(hashes)[0] }) }, data: { hashes, status, matches, fuzzy, knownGood: goods, online: lookups } };
  });
  if (errors.length) results.push({ target: 'feeds', raw: errors.map((e) => ({ rule: 'lookup-error', message: e, fix: 'Check the feed path/URL; stale cached copies are used when available.' })), errors: [] });
  const report = buildReport(TOOL, results, { ...opts, meta: { feeds: [...index.feeds, ...good.feeds.map((f) => ({ ...f, knownGood: true }))], indexed: index.size, fuzzyIndexed: index.fuzzy.length, online, feedErrors: errors, lookups: { requests, cacheHits: cache.hits } } });
  return report;
}

/** Compact table: one line per input with status and best label. */
export function formatTable(report) {
  const rows = report.targets.map((t) => [t.data?.status || (t.fatal ? 'error' : 'invalid'), t.target, (t.findings[0]?.message || t.errors[0] || '').replace(/^Known (malicious|good): /, '')]);
  return rows.map((r) => `${r[0].padEnd(11)} ${r[1]}${r[2] ? `  ${r[2]}` : ''}`).join('\n') + (rows.length ? '\n' : '');
}
