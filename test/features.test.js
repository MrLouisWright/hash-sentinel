import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { check, hashBuffer, ssdeep, tlsh, compareSsdeep, compareTlsh, fuzzyMatches, createLimiter, LookupCache, bulkCircl, parseFeed } from '../src/index.js';

const tmp = () => mkdtempSync(join(tmpdir(), 'hs-f-'));
const BIN = new URL('../bin/hash-sentinel.js', import.meta.url).pathname;
function sample(seed = 1, n = 20000) { const parts = []; for (let i = 0; i * 32 < n; i++) parts.push(createHash('sha256').update(`${seed}:${i}`).digest()); return Buffer.concat(parts).subarray(0, n); }
const variant = (b) => { const c = Buffer.from(b); for (let i = 0; i < 5; i++) c[1000 + i * 3000] ^= 0xff; return c; };

test('hashBuffer and fuzzy hashes', () => {
  const h = hashBuffer(Buffer.from('hello'));
  assert.equal(h.sha256, '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824');
  assert.equal(h.tlsh, null); assert.match(h.ssdeep, /^3:/);
  const a = sample(); const b = variant(a); const c = sample(99);
  assert.ok(compareSsdeep(ssdeep(a), ssdeep(b)) >= 60);
  assert.equal(compareSsdeep(ssdeep(a), ssdeep(c)), 0);
  assert.equal(compareSsdeep(ssdeep(a), ssdeep(a)), 100);
  assert.ok(compareTlsh(tlsh(a), tlsh(b)) < 50); assert.ok(compareTlsh(tlsh(a), tlsh(c)) > 100);
  assert.equal(hashBuffer(a, { fuzzy: false }).ssdeep, undefined);
});

test('fuzzy feed entries, fuzzy-match rule and fuzzy hash inputs', async () => {
  const d = tmp(); const a = sample(); writeFileSync(join(d, 'variant.exe'), variant(a)); writeFileSync(join(d, 'other.exe'), sample(7));
  writeFileSync(join(d, 'fz.txt'), `${ssdeep(a)} emotet-sample\n`);
  writeFileSync(join(d, 'fz.csv'), `tlsh,label\n${tlsh(a)},qakbot\n`);
  const idx = parseFeed(`ssdeep,1.1--blocksize:hash:hash,filename\n${ssdeep(a)},"x.exe"\n`, { name: 'ss' });
  assert.equal(idx.length, 1); assert.equal(idx[0].fuzzy, 'ssdeep');
  const rep = await check([d], { feeds: [join(d, 'fz.txt'), join(d, 'fz.csv')] });
  const by = Object.fromEntries(rep.targets.map((t) => [t.target.replace(/^.*[\\/]/, ''), t]));
  assert.equal(by['variant.exe'].data.status, 'similar'); assert.equal(by['variant.exe'].findings[0].rule, 'fuzzy-match');
  assert.deepEqual(by['variant.exe'].data.fuzzy.map((m) => m.type).sort(), ['ssdeep', 'tlsh']);
  assert.equal(by['other.exe'].data.status, 'unknown');
  const strict = await check([join(d, 'variant.exe')], { feeds: [join(d, 'fz.txt')], ssdeepThreshold: 101 });
  assert.equal(strict.findings.length, 0);
  const none = await check([join(d, 'variant.exe')], { feeds: [join(d, 'fz.txt')], fuzzy: false });
  assert.equal(none.findings.length, 0);
  const s = await check([ssdeep(variant(a))], { feeds: [join(d, 'fz.txt')] });
  assert.equal(s.targets[0].data.status, 'similar');
  assert.deepEqual(fuzzyMatches({ tlsh: tlsh(sample(5)) }, { fuzzy: [{ type: 'tlsh', value: tlsh(a), entry: {} }] }), []);
});

test('NSRL known-good', async () => {
  const d = tmp(); writeFileSync(join(d, 'f.bin'), 'hello');
  writeFileSync(join(d, 'NSRLFile.txt'), `"SHA-1","MD5","CRC32","FileName","FileSize","ProductCode","OpSystemCode","SpecialCode"\n"AAF4C61DDCC5E8A2DABEDE0F3B482CD9AEA9434D","5D41402ABC4B2A76B9719D911017C592","3610A686","hello.txt",5,1,"WIN",""\n`);
  const rep = await check([join(d, 'f.bin')], { nsrl: [join(d, 'NSRLFile.txt')] });
  assert.equal(rep.targets[0].data.status, 'known-good');
  assert.match(rep.targets[0].findings[0]?.message || JSON.stringify(rep.targets[0].data.knownGood), /NSRL/);
});

test('rate limiter, lookup cache, CIRCL bulk batching', async () => {
  let t = 0; const slept = [];
  const lim = createLimiter(4, { now: () => t, sleep: async (ms) => { slept.push(ms); t += ms; } });
  await lim.wait(); await lim.wait(); await lim.wait();
  assert.deepEqual(slept, [15000, 15000]);
  const d = tmp(); let now = 0;
  const c = new LookupCache(d, 10, () => now); c.set('circl', 'h', { source: 'circl', found: true }); c.set('circl', 'e', { error: 'x' }); c.save();
  const c2 = new LookupCache(d, 10, () => now); assert.equal(c2.get('circl', 'h').cached, true); assert.equal(c2.get('circl', 'e'), null);
  now = 11000; assert.equal(c2.get('circl', 'h'), null);
  const calls = [];
  const fetchImpl = async (url, init) => { calls.push(url); const body = JSON.parse(init.body); return { ok: true, json: async () => [{ MD5: body.hashes[0].toUpperCase(), FileName: 'a.dll', KnownMalicious: 'test' }] }; };
  const m = await bulkCircl(['aa'.repeat(16), 'bb'.repeat(16)], 'md5', { fetchImpl, endpoints: { circl: 'http://x' } });
  assert.equal(calls[0], 'http://x/bulk/md5'); assert.equal(m.get('aa'.repeat(16)).malicious, true); assert.equal(m.get('bb'.repeat(16)).found, false);
  const files = tmp(); writeFileSync(join(files, '1'), 'a'); writeFileSync(join(files, '2'), 'b'); writeFileSync(join(files, '3'), 'c');
  calls.length = 0;
  const cache = tmp();
  const rep = await check([files], { online: ['circl'], fetchImpl, endpoints: { circl: 'http://x' }, cache });
  assert.equal(calls.length, 1); assert.equal(rep.lookups.requests, 1);
  const rep2 = await check([files], { online: ['circl'], fetchImpl, endpoints: { circl: 'http://x' }, cache });
  assert.equal(calls.length, 1); assert.equal(rep2.lookups.cacheHits, 3);
});

test('CLI fuzzy/NSRL flags', () => {
  const d = tmp(); const a = sample(); writeFileSync(join(d, 'v.exe'), variant(a)); writeFileSync(join(d, 'fz.txt'), `${ssdeep(a)} fam\n`);
  const run = (args) => spawnSync(process.execPath, [BIN, ...args], { encoding: 'utf8' });
  let r = run([join(d, 'v.exe'), '--feed', join(d, 'fz.txt')]); assert.equal(r.status, 1); assert.match(r.stdout, /Similar to/);
  r = run([join(d, 'v.exe'), '--feed', join(d, 'fz.txt'), '--no-fuzzy']); assert.equal(r.status, 0);
  r = run([join(d, 'v.exe'), '--feed', join(d, 'fz.txt'), '--ssdeep-threshold', '101', '--tlsh-threshold', '0']); assert.equal(r.status, 0);
  assert.match(run(['--help']).stdout, /--nsrl/);
});
