import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { writeFileSync, mkdtempSync, mkdirSync, utimesSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { parseFeed, loadFeeds, check, hashFile, hashType, lookup, formatTable, exitCode } from '../src/index.js';

const BIN = new URL('../bin/hash-sentinel.js', import.meta.url).pathname;
const EICAR_MD5 = '44d88612fea8a8f36de82e1278abb02f';
const SHA256 = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f';
const SHA1 = '3395856ce81f2b7382dee72602f798b642f14140';
const GOOD = '8ed4b4ed952526d89899e723f3488de4';
let server; let base; let feedHits = 0;
before(async () => {
  server = createServer((req, res) => {
    let body = ''; req.on('data', (c) => (body += c)); req.on('end', () => {
      const send = (code, obj) => { res.writeHead(code, { 'content-type': 'application/json' }); res.end(typeof obj === 'string' ? obj : JSON.stringify(obj)); };
      if (req.url === `/circl/lookup/md5/${EICAR_MD5}`) return send(200, { FileName: 'eicar.com', KnownMalicious: 'malshare.com' });
      if (req.url === `/circl/lookup/md5/${GOOD}`) return send(200, { FileName: 'kernel32.dll', ProductCode: { ProductName: 'Windows' } });
      if (req.url.startsWith('/circl/')) return send(404, { message: 'Non existing' });
      if (req.url === '/mb') { if (req.headers['auth-key'] !== 'k') return send(401, { error: 'Unauthorized' }); return new URLSearchParams(body).get('hash') === SHA256 ? send(200, { query_status: 'ok', data: [{ signature: 'AgentTesla', file_type: 'exe', tags: ['rat'] }] }) : send(200, { query_status: 'hash_not_found' }); }
      if (req.url === `/vt/files/${SHA256}`) return req.headers['x-apikey'] === 'v' ? send(200, { data: { attributes: { last_analysis_stats: { malicious: 40, undetected: 20 }, popular_threat_classification: { suggested_threat_label: 'trojan.agenttesla' } } } }) : send(401, {});
      if (req.url.startsWith('/vt/')) return send(404, {});
      if (req.url === '/feed.txt') { feedHits++; return send(200, `${SHA1} url-feed-family\n`); }
      if (req.url.startsWith('/slow')) return setTimeout(() => send(200, {}), 3000);
      send(500, 'boom');
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${server.address().port}`;
});
after(() => server.close());
const endpoints = () => ({ circl: `${base}/circl`, malwarebazaar: `${base}/mb`, virustotal: `${base}/vt` });
const tmp = () => mkdtempSync(join(tmpdir(), 'hs-'));

test('hashType', () => {
  assert.equal(hashType(EICAR_MD5), 'md5'); assert.equal(hashType(SHA1), 'sha1'); assert.equal(hashType(SHA256), 'sha256'); assert.equal(hashType('a'.repeat(128)), 'sha512');
  assert.equal(hashType('xyz'), null); assert.equal(hashType('abc'), null);
});

test('parseFeed: text, sha256sum, BSD, CSV with header, MalwareBazaar export, JSON, MISP', () => {
  assert.deepEqual(parseFeed(`# list\n${EICAR_MD5} eicar  # comment\n\n${SHA1}`).map((e) => [e.hash, e.label]), [[EICAR_MD5, 'eicar'], [SHA1, undefined]]);
  assert.equal(parseFeed(`${SHA256} *dropper.exe`)[0].label, 'dropper.exe');
  assert.equal(parseFeed(`SHA256 (a b.exe) = ${SHA256}`)[0].label, 'a b.exe');
  const csv = parseFeed(`name,sha256,first_seen\nEmotet,${SHA256},2026-01-01\nQakbot,${SHA1},2026-01-02`);
  assert.deepEqual(csv.map((e) => e.label), ['Emotet', 'Qakbot']);
  const mb = parseFeed(`################\n# "first_seen_utc","sha256_hash","md5_hash","sha1_hash","reporter","file_name","file_type_guess","mime_type","signature"\n"2026-10-01 10:00:00", "${SHA256}", "${EICAR_MD5}", "${SHA1}", "abuse_ch", "a.exe", "exe", "x", "AgentTesla"\n`);
  assert.equal(mb.length, 3); assert.ok(mb.every((e) => e.label === 'AgentTesla'));
  assert.deepEqual(parseFeed(JSON.stringify([SHA256, { md5: EICAR_MD5, signature: 'X' }])).map((e) => e.label), [undefined, 'X']);
  const misp = parseFeed(JSON.stringify({ response: [{ Event: { info: 'Phishing wave', uuid: 'e1', threat_level_id: '1', Tag: [{ name: 'tlp:amber' }], Attribute: [{ type: 'sha256', value: SHA256, to_ids: true }, { type: 'filename|md5', value: `inv.doc|${EICAR_MD5}`, to_ids: false }, { type: 'url', value: 'http://x' }], Object: [{ name: 'file', Attribute: [{ type: 'sha1', value: SHA1, to_ids: true, comment: 'payload' }] }] } }] }));
  assert.equal(misp.length, 3);
  assert.equal(misp[0].malicious, true); assert.equal(misp[1].malicious, false); assert.equal(misp[1].label, 'Phishing wave / inv.doc');
  assert.equal(misp[0].meta.threat, 'high'); assert.deepEqual(misp[0].meta.tags, ['tlp:amber']);
  assert.throws(() => parseFeed('{bad', { name: 'f' }), /invalid JSON/);
});

test('loadFeeds: MISP feed directory, URL feed with cache, missing feed', async () => {
  const d = tmp(); mkdirSync(join(d, 'misp'));
  writeFileSync(join(d, 'misp', 'manifest.json'), JSON.stringify({ e1: { info: 'x' } }));
  writeFileSync(join(d, 'misp', 'e1.json'), JSON.stringify({ Event: { info: 'Campaign', Attribute: [{ type: 'md5', value: EICAR_MD5, to_ids: true }] } }));
  writeFileSync(join(d, 'misp', 'hashes.csv'), `${SHA256},e1\n`);
  const cache = join(d, 'cache'); const errors = [];
  const idx = await loadFeeds([join(d, 'misp'), `${base}/feed.txt`, join(d, 'nope.txt')], { cache, errors });
  assert.equal(idx.get(EICAR_MD5)[0].label, 'Campaign'); assert.equal(idx.get(SHA256).length, 1); assert.equal(idx.get(SHA1)[0].label, 'url-feed-family');
  assert.equal(errors.length, 1); assert.match(errors[0], /nope\.txt: not found/);
  const hits = feedHits;
  await loadFeeds([`${base}/feed.txt`], { cache }); assert.equal(feedHits, hits, 'served from cache');
  const off = await loadFeeds([`${base}/other.txt`], { cache, offline: true, errors: [] }); assert.equal(off.size, 0);
  const e2 = []; await loadFeeds([`${base}/broken`], { cache, errors: e2 }); assert.match(e2[0], /HTTP 500/);
});

test('online lookups (mock): CIRCL, MalwareBazaar, VirusTotal, errors and missing keys', async () => {
  const o = { endpoints: endpoints() };
  let r = await lookup('circl', EICAR_MD5, 'md5', o); assert.equal(r.malicious, true);
  r = await lookup('circl', GOOD, 'md5', o); assert.equal(r.knownGood, true); assert.match(r.label, /kernel32\.dll from Windows/);
  r = await lookup('circl', SHA1, 'sha1', o); assert.equal(r.found, false);
  assert.match((await lookup('circl', 'a'.repeat(128), 'sha512', o)).skipped, /not supported/);
  assert.match((await lookup('malwarebazaar', SHA256, 'sha256', o)).skipped, /ABUSECH_AUTH_KEY/);
  r = await lookup('malwarebazaar', SHA256, 'sha256', { ...o, keys: { malwarebazaar: 'k' } }); assert.equal(r.malicious, true); assert.match(r.label, /AgentTesla/);
  r = await lookup('malwarebazaar', SHA1, 'sha1', { ...o, keys: { malwarebazaar: 'k' } }); assert.equal(r.found, false);
  r = await lookup('malwarebazaar', SHA256, 'sha256', { ...o, keys: { malwarebazaar: 'wrong' } }); assert.match(r.error, /401/);
  r = await lookup('virustotal', SHA256, 'sha256', { ...o, keys: { virustotal: 'v' } }); assert.equal(r.malicious, true); assert.match(r.label, /40\/60/);
  r = await lookup('circl', EICAR_MD5, 'md5', { endpoints: { circl: `${base}/slow` }, timeout: 200 }); assert.equal(r.error, 'timeout');
});

test('check: files, hashes, feeds, known-good, online, statuses and rules', async () => {
  const d = tmp(); writeFileSync(join(d, 'a.bin'), 'hello'); writeFileSync(join(d, 'b.bin'), 'other');
  const h = await hashFile(join(d, 'a.bin'));
  assert.equal(h.sha256, '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824');
  writeFileSync(join(d, 'feed.txt'), `${h.md5} test-family\n${SHA1} other\n`);
  writeFileSync(join(d, 'good.txt'), `${SHA1}\n`);
  const rep = await check([d, SHA1, EICAR_MD5, 'abc', join(d, 'missing.bin')], { feeds: [join(d, 'feed.txt')], knownGood: [join(d, 'good.txt')], online: ['circl'], endpoints: endpoints(), now: '2026-10-14' });
  const by = Object.fromEntries(rep.targets.map((t) => [t.target.replace(/^.*[\\/]/, ''), t]));
  assert.equal(by['a.bin'].data.status, 'malicious'); assert.equal(by['a.bin'].findings[0].rule, 'known-malicious');
  assert.equal(by['b.bin'].data.status, 'unknown'); assert.equal(by['b.bin'].findings.length, 0);
  assert.deepEqual(by[SHA1].findings.map((f) => f.rule).sort(), ['known-good-conflict', 'known-malicious']);
  assert.equal(by[EICAR_MD5].data.status, 'malicious');
  assert.equal(by.abc.findings[0].rule, 'invalid-hash');
  assert.ok(by['missing.bin'].fatal);
  assert.equal(exitCode(rep, 'high'), 2);
  assert.match(formatTable(rep), /^malicious\s+.*a\.bin\s+feed\.txt: test-family/m);
  await assert.rejects(check([SHA1], { online: ['nope'] }), /Unknown online source/);
  const misp = await check([SHA1], { feeds: [{ path: join(d, 'feed.txt'), malicious: false, name: 'watch' }] });
  assert.equal(misp.findings[0].rule, 'feed-match');
  const allowed = await check([join(d, 'a.bin')], { feeds: [join(d, 'feed.txt')], allow: [{ rule: 'known-malicious', match: h.sha256, reason: 'test fixture', expires: '2099-01-01' }], now: '2026-10-14' });
  assert.equal(allowed.findings.length, 0);
  const offline = await check([EICAR_MD5], { online: ['circl'], offline: true, endpoints: endpoints() });
  assert.equal(offline.targets[0].data.online.length, 0);
});

test('CLI', () => {
  const d = tmp(); writeFileSync(join(d, 'feed.txt'), `${SHA1} fam\n`);
  const run = (args, input) => spawnSync(process.execPath, [BIN, ...args], { encoding: 'utf8', input });
  let r = run([SHA1, '--feed', join(d, 'feed.txt')]); assert.equal(r.status, 1); assert.match(r.stdout, /Known malicious/);
  r = run(['-', '--feed', join(d, 'feed.txt'), '-f', 'table'], `${SHA1}\n${SHA256}\n`); assert.equal(r.status, 1); assert.match(r.stdout, /unknown\s+275a/);
  r = run([SHA256, '--feed', join(d, 'feed.txt')]); assert.equal(r.status, 0);
  r = run([SHA1, '--feed', join(d, 'feed.txt'), '-f', 'sarif']); assert.equal(JSON.parse(r.stdout).runs[0].results[0].ruleId, 'known-malicious');
  assert.equal(run([]).status, 2); assert.equal(run([SHA1, '--online', 'x']).status, 2);
  assert.match(run(['--help']).stdout, /circl/);
});
