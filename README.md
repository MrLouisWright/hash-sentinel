# hash-sentinel

[![npm version](https://img.shields.io/npm/v/hash-sentinel.svg)](https://www.npmjs.com/package/hash-sentinel) [![CI](https://github.com/MrLouisWright/hash-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/MrLouisWright/hash-sentinel/actions/workflows/ci.yml) [![Node](https://img.shields.io/node/v/hash-sentinel.svg)](https://nodejs.org) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> Check file hashes against your own threat feeds, MISP and optional public lookups, offline-first.

`hash-sentinel` takes MD5/SHA1/SHA256/SHA512 values, or files and directories that it hashes locally, and checks them against **self-hosted feeds** you control: plain hash lists, `sha256sum` output, CSV exports (such as MalwareBazaar's), **MISP events, MISP REST search results and MISP feed directories**, and URL feeds that are cached locally. Optionally it asks **CIRCL hashlookup** (no API key; it knows millions of good files from NSRL and flags known-malicious ones), **MalwareBazaar** (free abuse.ch Auth-Key) and **VirusTotal** (API key).

CLI, library and GitHub Action. Node.js 18+, **zero runtime dependencies**. Files are hashed locally and never uploaded. Online lookups are opt-in and send only the hash.

## Features

- **Inputs**: hashes, files, directories (recursive), or stdin (`-`). Files are hashed with MD5, SHA1, SHA256 and SHA512 in one streaming pass, and all four are matched.
- **Feed formats** (auto-detected):
  - Text: one hash per line with an optional label, `# comments`, `sha256sum`/`md5sum` output (`hash *file`), BSD `SHA256 (file) = hash`.
  - CSV/TSV with a header: any `sha256`/`sha1`/`md5`/`hash` column, labelled from `signature`, `malware`, `family`, `name`, `file_name`, `tags`… Commented MalwareBazaar export headers (`# "first_seen_utc","sha256_hash",…`) are understood.
  - JSON: arrays of hashes or objects with `sha256`/`md5`/… fields.
  - **MISP**: single events, `{"response": [...]}` search results, and feed directories (`manifest.json` + `<uuid>.json` + `hashes.csv`). Hash attributes include `md5`, `sha1`, `sha256`, `sha512`, `filename|sha256` and `malware-sample`, plus file-object attributes. Attributes with `to_ids: true` count as **known malicious**; others count as **listed** (context, not proof). Labels carry the event info, attribute comment and file name; event threat level and tags are kept.
  - **URL feeds** (`--feed https://…`) are cached in `~/.cache/hash-sentinel` (or `$HASH_SENTINEL_CACHE`) for 6 hours (`--ttl`). If a download fails, the stale cache is used and a warning is reported. `--offline` never touches the network.
- **Known-good lists** (`--known-good`) for golden images or allow-listed tools. A hash that is both known-good and on a malicious feed raises `known-good-conflict` (a false positive, or a trojanised copy).
- **Online sources** (`--online circl,malwarebazaar,virustotal`): CIRCL hashlookup needs no key and returns NSRL known-good data plus a `KnownMalicious` flag. MalwareBazaar uses `ABUSECH_AUTH_KEY` (free at auth.abuse.ch). VirusTotal uses `VT_API_KEY` and counts 3 or more engines as malicious. Missing keys are reported as skipped, not failures. Lookups run 4 at a time with a 15 s timeout.
- `-f table` prints one compact line per input: `malicious | listed | known-good | unknown | invalid`.

## Rules

| Rule | Default | Meaning |
|---|---|---|
| `known-malicious` | critical | Malicious feed entry, MISP IDS attribute, MalwareBazaar hit, CIRCL KnownMalicious or VirusTotal ≥ 3 engines |
| `feed-match` | high | Listed in a feed without the malicious flag (MISP non-IDS attribute, or a feed declared `"malicious": false`) |
| `known-good-conflict` | medium | Known good and listed as malicious at the same time |
| `lookup-error` | low | Feed missing or unparseable, download or API failure |
| `invalid-hash` | low | Hex input with the wrong length |
| `known-good` | info | NSRL / known-good list match |

## Install and run

```bash
npx hash-sentinel 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f --feed intel/hashes.txt
npx hash-sentinel ./downloads --feed misp-feed/ --feed https://intel.example.net/sha256.txt --online circl
sha256sum /usr/bin/* | cut -d' ' -f1 | npx hash-sentinel - --known-good golden.txt --online circl -f table
```

Config (`.hash-sentinel.json`) can declare feeds with options:

```json
{
  "feeds": ["intel/blocklist.txt", { "url": "https://intel.example.net/misp/hashes.csv", "name": "corp-misp", "ttl": 3600 }, { "path": "watch.txt", "malicious": false }],
  "knownGood": ["golden-image.sha256"],
  "online": ["circl"]
}
```

## Library

```js
import { check, parseFeed, hashFile, lookup } from 'hash-sentinel';

const report = await check(['./suspicious.exe'], { feeds: ['misp-feed/'], online: ['circl'] });
report.targets[0].data.status;   // 'malicious' | 'listed' | 'known-good' | 'unknown'
report.targets[0].data.matches;  // [{ feed, label, malicious, hash, meta }]
```

## Configuration

Put a `.hash-sentinel.json` in the working directory (or pass `--config <file>`). Every key is optional; CLI flags override the file.

```json
{
  "failOn": "high",
  "severity": { "known-malicious": "high" },
  "allow": [
    { "rule": "known-malicious", "match": "e3b0c442*", "reason": "Accepted risk, ticket SEC-123", "expires": "2027-03-31" }
  ]
}
```

- **`severity`** changes the severity of any rule, or turns it `off`.
- **`allow`** suppresses findings. Each entry needs a `rule` (globs such as `known-*` work) and a `reason`, and can be narrowed with `target` and `match` (a glob tested against the target, location and value). Suppressed findings are listed in the JSON report. When `expires` (YYYY-MM-DD) has passed, the finding comes back together with an `allow-expired` finding, so exceptions can't be forgotten. Entries that match nothing are reported as `allow-unused` (info).

## Output and exit codes

- `--format text|json|sarif|markdown` for stdout, plus `--json`, `--sarif` and `--markdown <file>` to write extra copies in one run. SARIF 2.1.0 works with GitHub code scanning.
- `--fail-on critical|high|medium|low|info|none` (default `high`).
- Exit code **0**: passed. **1**: at least one finding at or above `--fail-on`. **2**: usage or config error, or a target could not be checked.
- `--list-rules` prints every rule with its default severity.

## GitHub Action

```yaml
permissions:
  contents: read
  security-events: write   # only for the SARIF upload
steps:
  - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
    with: { persist-credentials: false }
  - uses: MrLouisWright/hash-sentinel@v1
    with:
      targets: 'downloads/'
      fail-on: high
      sarif: hash-sentinel.sarif
  - uses: github/codeql-action/upload-sarif@v3
    if: always()
    with: { sarif_file: hash-sentinel.sarif }
```

Inputs: `targets`, `fail-on`, `config`, `sarif`, `json`, `job-summary` (Markdown report in the job summary, default `true`), `args` (extra CLI flags), `feeds`, `online`. Outputs: `markdown-file`, `exit-code`.

## Requirements

Node.js 18 or newer. No runtime dependencies.

## Support

If this project is useful to you, you can support its development with a donation: [Buy me a coffee](https://donate.stripe.com/aFa00lek3cvX4Ds2Fk9EI0b). It helps keep these tools maintained, documented and free for everyone.

## License

MIT © Louis Wright ([Louis Wright](https://github.com/MrLouisWright))
