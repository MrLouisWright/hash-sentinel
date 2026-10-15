#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { runCli, list, UsageError } from '../src/cli-core.js';
import { check, formatTable, TOOL, SOURCES } from '../src/index.js';

const HELP = `hash-sentinel {VERSION} — look up file hashes in self-hosted feeds and optional public sources

Usage: hash-sentinel <hash|file|dir|-> [...] [options]

Inputs are MD5/SHA1/SHA256/SHA512 values, files (hashed locally, never uploaded) or directories.
"-" reads hashes or paths from stdin, one per line.

Feeds (offline, self-hosted)
      --feed <src>           Hash list, CSV (e.g. MalwareBazaar export), MISP event JSON, MISP feed
                             directory, or an http(s) URL (cached; repeatable or comma-separated)
      --known-good <src>     Known-good hash list(s) (e.g. your golden images)
      --nsrl <src>           NSRL RDS CSV/hash list (file or URL), treated as known-good
      --no-fuzzy             Skip ssdeep/TLSH fuzzy hashing of files
      --ssdeep-threshold <n> Minimum ssdeep similarity score for fuzzy-match (default 60)
      --tlsh-threshold <n>   Maximum TLSH distance for fuzzy-match (default 50)
      --lookup-ttl <s>       Cache online lookup results for s seconds (default 86400; 0 disables)
      --rate <src=n>         Requests per minute for an online source (default virustotal=4, circl=120, malwarebazaar=60)
      --ttl <seconds>        URL feed cache lifetime (default 21600)
      --offline              Never touch the network (cached URL feeds only)
Online (opt-in; only the hash is sent)
      --online <list>        ${SOURCES.join(', ')}
                               circl: CIRCL hashlookup, no key (NSRL known-good + KnownMalicious)
                               malwarebazaar: needs ABUSECH_AUTH_KEY (free at auth.abuse.ch)
                               virustotal: needs VT_API_KEY
  -f table                   One line per input: status, target, label
{COMMON}`;

process.exitCode = await runCli(TOOL, {
  help: HELP,
  formats: ['table'],
  options: { feed: { type: 'string', multiple: true }, 'known-good': { type: 'string', multiple: true }, nsrl: { type: 'string', multiple: true }, 'no-fuzzy': { type: 'boolean' }, 'ssdeep-threshold': { type: 'string' }, 'tlsh-threshold': { type: 'string' }, 'lookup-ttl': { type: 'string' }, rate: { type: 'string', multiple: true }, ttl: { type: 'string' }, offline: { type: 'boolean' }, online: { type: 'string' } },
  async run(o, pos, cfg, ctx) {
    let inputs = [...pos];
    if (inputs.includes('-')) { inputs = inputs.filter((x) => x !== '-'); inputs.push(...readFileSync(0, 'utf8').split(/\r?\n/).map((l) => l.replace(/#.*$/, '').trim()).filter(Boolean)); }
    if (!inputs.length) throw new UsageError('No hash, file or directory given');
    const online = o.online ? list(o.online) : cfg.online || [];
    for (const s of online) if (!SOURCES.includes(s)) throw new UsageError(`Unknown --online source ${s}`);
    const report = await check(inputs, { feeds: [...(cfg.feeds || []), ...list(o.feed)], knownGood: [...(cfg.knownGood || []), ...list(o['known-good'])], ttl: o.ttl ? Number(o.ttl) : cfg.ttl, offline: o.offline ?? cfg.offline, online, nsrl: [...(cfg.nsrl || []), ...list(o.nsrl)], fuzzy: o['no-fuzzy'] ? false : cfg.fuzzy, ssdeepThreshold: o['ssdeep-threshold'] ? Number(o['ssdeep-threshold']) : cfg.ssdeepThreshold, tlshThreshold: o['tlsh-threshold'] ? Number(o['tlsh-threshold']) : cfg.tlshThreshold, lookupTtl: o['lookup-ttl'] ? Number(o['lookup-ttl']) : cfg.lookupTtl, lookupCache: o['lookup-ttl'] === '0' ? false : undefined, rates: { ...(cfg.rates || {}), ...Object.fromEntries(list(o.rate).map((r) => { const [k, v] = r.split('='); return [k, Number(v)]; })) }, allow: cfg.allow, severity: cfg.severity });
    return ctx.format === 'table' ? { report, output: formatTable(report) } : report;
  },
});
