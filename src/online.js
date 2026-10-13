// Optional online lookups. Off unless requested; only hashes are sent, never files.
export const ENDPOINTS = { circl: 'https://hashlookup.circl.lu', malwarebazaar: 'https://mb-api.abuse.ch/api/v1/', virustotal: 'https://www.virustotal.com/api/v3' };
export const SOURCES = ['circl', 'malwarebazaar', 'virustotal'];

/** @returns {Promise<{source:string,found:boolean,malicious?:boolean,knownGood?:boolean,label?:string,detail?:object,error?:string,skipped?:string}>} */
export async function lookup(source, hash, type, { fetchImpl = globalThis.fetch, endpoints = {}, keys = {}, timeout = 15000 } = {}) {
  const ep = { ...ENDPOINTS, ...endpoints }[source];
  const signal = AbortSignal.timeout(timeout);
  try {
    if (source === 'circl') {
      if (!['md5', 'sha1', 'sha256'].includes(type)) return { source, found: false, skipped: `${type} not supported` };
      const r = await fetchImpl(`${ep}/lookup/${type}/${hash}`, { signal, headers: { accept: 'application/json', 'user-agent': 'hash-sentinel' } });
      if (r.status === 404) return { source, found: false };
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const j = await r.json();
      const mal = !!j.KnownMalicious;
      return { source, found: true, malicious: mal, knownGood: !mal, label: mal ? `known malicious (${j.KnownMalicious})` : `${j.FileName || 'known file'}${j.ProductCode?.ProductName ? ` from ${j.ProductCode.ProductName}` : ''} (NSRL/known-good)`, detail: { fileName: j.FileName, fileSize: j.FileSize, source: j['hashlookup:trust'] !== undefined ? `trust ${j['hashlookup:trust']}` : undefined, knownMalicious: j.KnownMalicious } };
    }
    if (source === 'malwarebazaar') {
      const key = keys.malwarebazaar || process.env.ABUSECH_AUTH_KEY || process.env.MALWAREBAZAAR_API_KEY;
      if (!key) return { source, found: false, skipped: 'set ABUSECH_AUTH_KEY (free key from auth.abuse.ch)' };
      const r = await fetchImpl(ep, { method: 'POST', signal, headers: { 'Auth-Key': key, 'content-type': 'application/x-www-form-urlencoded', 'user-agent': 'hash-sentinel' }, body: new URLSearchParams({ query: 'get_info', hash }).toString() });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const j = await r.json();
      if (j.query_status === 'hash_not_found' || j.query_status === 'no_results') return { source, found: false };
      if (j.query_status !== 'ok') throw new Error(`query_status ${j.query_status}`);
      const d = j.data?.[0] || {};
      return { source, found: true, malicious: true, label: [d.signature, d.file_type, ...(d.tags || []).slice(0, 4)].filter(Boolean).join(', ') || 'MalwareBazaar sample', detail: { firstSeen: d.first_seen, fileName: d.file_name, signature: d.signature, tags: d.tags, sha256: d.sha256_hash } };
    }
    if (source === 'virustotal') {
      const key = keys.virustotal || process.env.VT_API_KEY;
      if (!key) return { source, found: false, skipped: 'set VT_API_KEY' };
      const r = await fetchImpl(`${ep}/files/${hash}`, { signal, headers: { 'x-apikey': key, accept: 'application/json' } });
      if (r.status === 404) return { source, found: false };
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const a = (await r.json()).data?.attributes || {}; const st = a.last_analysis_stats || {};
      const total = Object.values(st).reduce((x, y) => x + y, 0);
      return { source, found: true, malicious: (st.malicious || 0) >= 3, knownGood: (st.malicious || 0) === 0 && total > 0 ? undefined : undefined, label: `${st.malicious || 0}/${total} engines${a.popular_threat_classification?.suggested_threat_label ? `, ${a.popular_threat_classification.suggested_threat_label}` : ''}`, detail: { stats: st, names: (a.names || []).slice(0, 5) } };
    }
    throw new Error(`unknown source ${source}`);
  } catch (e) { return { source, found: false, error: e.name === 'TimeoutError' ? 'timeout' : e.message }; }
}
