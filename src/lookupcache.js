// Local cache for online lookup results (per source JSON file), so repeated CI runs don't re-query.
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';

export class LookupCache {
  /** @param {string|null} dir  cache directory (null = memory only) @param {number} ttl seconds */
  constructor(dir, ttl = 24 * 3600, now = Date.now) { this.dir = dir; this.ttl = ttl; this.now = now; this.data = {}; this.dirty = new Set(); this.hits = 0; }
  file(src) { return join(this.dir, 'lookups', `${src}.json`); }
  load(src) { if (this.data[src]) return this.data[src]; let d = {}; if (this.dir && existsSync(this.file(src))) { try { d = JSON.parse(readFileSync(this.file(src), 'utf8')); } catch { d = {}; } } return (this.data[src] = d); }
  get(src, hash) { const e = this.load(src)[hash]; if (!e || (this.now() - e.t) / 1000 > this.ttl) return null; this.hits++; return { ...e.r, cached: true }; }
  set(src, hash, r) { if (r.error || r.skipped) return; this.load(src)[hash] = { t: this.now(), r }; this.dirty.add(src); }
  save() { if (!this.dir) return; for (const s of this.dirty) { mkdirSync(join(this.dir, 'lookups'), { recursive: true }); writeFileSync(this.file(s), JSON.stringify(this.data[s])); } this.dirty.clear(); }
}
