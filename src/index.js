import { readFileSync, statSync, readdirSync, createReadStream } from 'node:fs';
import { join, relative } from 'node:path';
import { createHash } from 'node:crypto';
import { buildReport, exceeds, exitCode, formatText, formatJson, formatSarif, formatMarkdown, SEVERITIES, ConfigError, validateConfig } from './core.js';
import { RULES } from './rules.js';
import { parseFeed, loadFeeds, HashIndex, hashType, cacheDir } from './feeds.js';
import { lookup, SOURCES, ENDPOINTS } from './online.js';

export { parseFeed, loadFeeds, HashIndex, hashType, cacheDir, lookup, SOURCES, ENDPOINTS, RULES, exceeds, exitCode, formatText, formatJson, formatSarif, formatMarkdown, SEVERITIES, ConfigError };
export const VERSION = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version;
export const TOOL = { name: 'hash-sentinel', version: VERSION, rules: RULES, title: 'hash-sentinel', emoji: '#️⃣', defaultFailOn: 'high' };

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
  const good = await loadFeeds((opts.knownGood || []).map((f) => (typeof f === 'string' ? { ...(/^https?:/.test(f) ? { url: f } : { path: f }), malicious: false } : { ...f, malicious: false })), { ...opts, errors });
  const items = [];
  for (const inp of inputs) {
    const s = String(inp).trim();
    if (hashType(s)) { items.push({ target: s.toLowerCase(), hashes: { [hashType(s)]: s.toLowerCase() } }); continue; }
    let files; try { files = walk(s); } catch (e) {
      if (/^[0-9a-f]+$/i.test(s)) { items.push({ target: s, invalid: true }); continue; }
      items.push({ target: s, fatal: `Cannot read ${s}: ${e.code || e.message}` }); continue;
    }
    for (const f of files) items.push({ target: relative(process.cwd(), f) || f, file: f });
  }
  const results = await pool(items, opts.concurrency || 4, async (it) => {
    if (it.fatal) return { target: it.target, fatal: true, raw: [], errors: [it.fatal] };
    if (it.invalid) return { target: it.target, raw: [{ rule: 'invalid-hash', message: `"${it.target}" is ${it.target.length} hex characters, not an MD5/SHA1/SHA256/SHA512`, fix: 'Check for truncation or copy/paste errors.' }], errors: [] };
    const hashes = it.file ? await hashFile(it.file) : it.hashes;
    const matches = []; const goods = [];
    for (const h of Object.values(hashes)) { matches.push(...index.get(h).map((m) => ({ ...m, hash: h }))); goods.push(...good.get(h).map((m) => ({ ...m, hash: h }))); }
    const lookups = [];
    if (online.length && !opts.offline) {
      const [type, h] = hashes.sha256 ? ['sha256', hashes.sha256] : Object.entries(hashes)[0];
      for (const src of online) lookups.push(await lookup(src, h, type, opts));
    }
    const raw = []; const errs = [];
    const mal = [...matches.filter((m) => m.malicious).map((m) => `${m.feed}${m.label ? `: ${m.label}` : ''}`), ...lookups.filter((l) => l.malicious).map((l) => `${l.source}: ${l.label}`)];
    const soft = matches.filter((m) => !m.malicious).map((m) => `${m.feed}${m.label ? `: ${m.label}` : ''}`);
    const goodHits = [...goods.map((g) => `${g.feed}${g.label ? `: ${g.label}` : ''}`), ...lookups.filter((l) => l.knownGood).map((l) => `${l.source}: ${l.label}`)];
    const display = hashes.sha256 || Object.values(hashes)[0];
    if (mal.length) raw.push({ rule: 'known-malicious', message: `Known malicious: ${[...new Set(mal)].slice(0, 5).join('; ')}`, evidence: display, fix: 'Quarantine the file, block the hash and investigate where it came from.' });
    else if (soft.length) raw.push({ rule: 'feed-match', message: `Listed in ${[...new Set(soft)].slice(0, 5).join('; ')}`, evidence: display, fix: 'Review the feed context (MISP event / watchlist) before acting.' });
    if (goodHits.length && (mal.length || soft.length)) raw.push({ rule: 'known-good-conflict', message: `Also on a known-good list (${goodHits.slice(0, 3).join('; ')}): possible false positive or a trojanised copy of a legitimate file`, evidence: display });
    else if (goodHits.length) raw.push({ rule: 'known-good', message: `Known good: ${goodHits.slice(0, 3).join('; ')}`, evidence: display });
    for (const l of lookups.filter((x) => x.error)) raw.push({ rule: 'lookup-error', message: `${l.source} lookup failed: ${l.error}` });
    for (const l of lookups.filter((x) => x.skipped)) errs.push(`${l.source} skipped: ${l.skipped}`);
    const status = mal.length ? 'malicious' : soft.length ? 'listed' : goodHits.length ? 'known-good' : 'unknown';
    return { target: it.target, raw, errors: errs, summary: { status, sha256: hashes.sha256, ...(it.file ? {} : { type: Object.keys(hashes)[0] }) }, data: { hashes, status, matches, knownGood: goods, online: lookups } };
  });
  if (errors.length) results.push({ target: 'feeds', raw: errors.map((e) => ({ rule: 'lookup-error', message: e, fix: 'Check the feed path/URL; stale cached copies are used when available.' })), errors: [] });
  const report = buildReport(TOOL, results, { ...opts, meta: { feeds: [...index.feeds, ...good.feeds.map((f) => ({ ...f, knownGood: true }))], indexed: index.size, online, feedErrors: errors } });
  return report;
}

/** Compact table: one line per input with status and best label. */
export function formatTable(report) {
  const rows = report.targets.map((t) => [t.data?.status || (t.fatal ? 'error' : 'invalid'), t.target, (t.findings[0]?.message || t.errors[0] || '').replace(/^Known (malicious|good): /, '')]);
  return rows.map((r) => `${r[0].padEnd(11)} ${r[1]}${r[2] ? `  ${r[2]}` : ''}`).join('\n') + (rows.length ? '\n' : '');
}
