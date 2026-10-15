export const RULES = {
  'known-malicious': { severity: 'critical', title: 'Hash is known malicious (feed, MISP IDS attribute or online source)', group: 'match' },
  'feed-match': { severity: 'high', title: 'Hash appears in a feed (non-IDS MISP attribute or a watchlist feed)', group: 'match' },
  'fuzzy-match': { severity: 'high', title: 'File is similar to a listed sample (ssdeep / TLSH near match)', group: 'match' },
  'known-good-conflict': { severity: 'medium', title: 'Hash is on a known-good list and on a malicious feed', group: 'match' },
  'known-good': { severity: 'info', title: 'Hash is a known-good file (NSRL / known-good list)', group: 'reputation' },
  'lookup-error': { severity: 'low', title: 'An online lookup or feed download failed', group: 'error' },
  'invalid-hash': { severity: 'low', title: 'Input is not a valid MD5/SHA1/SHA256/SHA512', group: 'error' },
};
