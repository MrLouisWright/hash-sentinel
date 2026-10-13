# Changelog

## 1.0.0 (2026-10-14)

First release, by Louis Wright.

- Lookup of MD5/SHA1/SHA256/SHA512 values, files and directories (streamed local hashing).
- Self-hosted feeds: text lists, sha256sum/BSD output, CSV/TSV (incl. MalwareBazaar exports), JSON, MISP events, MISP search results and MISP feed directories; cached URL feeds with TTL, stale-cache fallback and offline mode.
- Known-good lists and conflict detection.
- Optional online sources: CIRCL hashlookup (no key), MalwareBazaar (abuse.ch Auth-Key) and VirusTotal.
- Allowlist with expiry, per-rule severity, text/table/JSON/SARIF/Markdown output, `--fail-on` and exit codes 0/1/2; composite GitHub Action.
