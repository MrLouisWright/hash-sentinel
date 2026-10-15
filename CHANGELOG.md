# Changelog

## 1.1.0 (2026-10-15)

- Fuzzy hashing: ssdeep and TLSH computed for every file; ssdeep/tlsh entries in feeds (text, CSV, JSON) and a new `fuzzy-match` rule (ssdeep score >= 60, TLSH distance <= 50, configurable). Fuzzy hash strings are accepted as inputs.
- `--nsrl` loads NSRL RDS / hash lists as known-good.
- Online lookups are cached locally (`--lookup-ttl`, default 24h), rate limited per source (`--rate`, VirusTotal 4/min by default) and CIRCL lookups are batched through the bulk endpoint.
- New reusable API: `hashBuffer`, `ssdeep`, `tlsh`, `compareSsdeep`, `compareTlsh`, `fuzzyMatches`, `createLimiter`, `LookupCache`, `bulkCircl`.
- Dual ESM + CommonJS build with generated type declarations.

## 1.0.0 (2026-10-14)

First release, by Louis Wright.

- Lookup of MD5/SHA1/SHA256/SHA512 values, files and directories (streamed local hashing).
- Self-hosted feeds: text lists, sha256sum/BSD output, CSV/TSV (incl. MalwareBazaar exports), JSON, MISP events, MISP search results and MISP feed directories; cached URL feeds with TTL, stale-cache fallback and offline mode.
- Known-good lists and conflict detection.
- Optional online sources: CIRCL hashlookup (no key), MalwareBazaar (abuse.ch Auth-Key) and VirusTotal.
- Allowlist with expiry, per-rule severity, text/table/JSON/SARIF/Markdown output, `--fail-on` and exit codes 0/1/2; composite GitHub Action.
