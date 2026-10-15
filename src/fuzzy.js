// Fuzzy hashes for near-duplicate matching, dependency-free:
//  - ssdeep (context-triggered piecewise hashing, SpamSum by Andrew Tridgell; algorithm as in ssdeep/ppdeep)
//  - TLSH (Trend Micro Locality Sensitive Hash, 128 buckets / 1-byte checksum, "T1" version prefix)

// ---------------------------------------------------------------- ssdeep
const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const MIN_BS = 3; const SPAMSUM_LENGTH = 64; const HASH_INIT = 0x27; const WIN = 7;
const F_TABLE = [0x00, 0x13, 0x26, 0x39, 0x0c, 0x1f, 0x32, 0x05, 0x18, 0x2b, 0x3e, 0x11, 0x24, 0x37, 0x0a, 0x1d, 0x30, 0x03, 0x16, 0x29, 0x3c, 0x0f, 0x22, 0x35, 0x08, 0x1b, 0x2e, 0x01, 0x14, 0x27, 0x3a, 0x0d, 0x20, 0x33, 0x06, 0x19, 0x2c, 0x3f, 0x12, 0x25, 0x38, 0x0b, 0x1e, 0x31, 0x04, 0x17, 0x2a, 0x3d, 0x10, 0x23, 0x36, 0x09, 0x1c, 0x2f, 0x02, 0x15, 0x28, 0x3b, 0x0e, 0x21, 0x34, 0x07, 0x1a, 0x2d];
// partial FNV over 6 bits: next = F_TABLE[h] ^ (byte & 63)
const step = (h, b) => F_TABLE[h] ^ (b & 0x3f);

/**
 * ssdeep fuzzy hash of a buffer, e.g. "3:AXGBicFlgVNhBGcL6wCrFQEv:AXGHsNhxLsr2C".
 * @param {Uint8Array} buf
 * @returns {string}
 */
export function ssdeep(buf) {
  const data = buf instanceof Uint8Array ? buf : Buffer.from(buf);
  let bs = MIN_BS; while (bs * SPAMSUM_LENGTH < data.length) bs *= 2;
  for (;;) {
    const win = new Uint8Array(WIN); let h1 = 0; let h2 = 0; let h3 = 0; let n = 0; let rh = 0;
    let b1 = HASH_INIT; let b2 = HASH_INIT; let s1 = ''; let s2 = ''; let last1 = ''; let last2 = '';
    for (let i = 0; i < data.length; i++) {
      const c = data[i];
      b1 = step(b1, c); b2 = step(b2, c);
      h2 = (h2 - h1 + WIN * c) >>> 0; h1 = (h1 + c - win[n]) >>> 0; win[n] = c; n = (n + 1) % WIN;
      h3 = ((h3 << 5) ^ c) >>> 0;
      rh = (h1 + h2 + h3) >>> 0;
      if (rh % bs === bs - 1) {
        last1 = B64[b1];
        if (s1.length < SPAMSUM_LENGTH - 1) { s1 += B64[b1]; b1 = HASH_INIT; last1 = ''; }
        if (rh % (bs * 2) === bs * 2 - 1) {
          last2 = B64[b2];
          if (s2.length < SPAMSUM_LENGTH / 2 - 1) { s2 += B64[b2]; b2 = HASH_INIT; last2 = ''; }
        }
      }
    }
    if (bs > MIN_BS && s1.length < SPAMSUM_LENGTH / 2) { bs /= 2; continue; }
    if (rh !== 0) { s1 += B64[b1]; s2 += B64[b2]; } else { s1 += last1; s2 += last2; }
    return `${bs}:${s1}:${s2}`;
  }
}

// ssdeep's weighted edit distance: insert/delete 1, substitute 2
function editDistance(s, t) {
  if (s === t) return 0;
  let prev = Array.from({ length: t.length + 1 }, (_, i) => i);
  for (let i = 1; i <= s.length; i++) {
    const cur = [i];
    for (let j = 1; j <= t.length; j++) cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (s[i - 1] === t[j - 1] ? 0 : 2));
    prev = cur;
  }
  return prev[t.length];
}
function hasCommonSubstring(a, b) {
  if (a.length < WIN || b.length < WIN) return false;
  const seen = new Set(); for (let i = 0; i + WIN <= a.length; i++) seen.add(a.slice(i, i + WIN));
  for (let i = 0; i + WIN <= b.length; i++) if (seen.has(b.slice(i, i + WIN))) return true;
  return false;
}
function scoreStrings(a, b, bs) {
  if (!hasCommonSubstring(a, b)) return 0;
  let score = Math.floor((editDistance(a, b) * SPAMSUM_LENGTH) / (a.length + b.length));
  score = 100 - Math.floor((100 * score) / SPAMSUM_LENGTH);
  const cap = Math.floor(bs / MIN_BS) * Math.min(a.length, b.length);
  return Math.max(0, Math.min(score, cap));
}
const stripSeq = (s) => s.replace(/(.)\1{3,}/g, '$1$1$1');
/** Parse "blocksize:s1:s2" or null. */
export function parseSsdeep(h) {
  const m = /^(\d+):([A-Za-z0-9+/]*):([A-Za-z0-9+/]*)(?:,.*)?$/.exec(String(h).trim());
  return m ? { bs: Number(m[1]), s1: m[2], s2: m[3] } : null;
}
/**
 * Compare two ssdeep hashes: 0 (no similarity) … 100 (identical).
 * @param {string} a
 * @param {string} b
 */
export function compareSsdeep(a, b) {
  const x = parseSsdeep(a); const y = parseSsdeep(b);
  if (!x || !y) throw new Error('Invalid ssdeep hash');
  if (x.bs !== y.bs && x.bs !== y.bs * 2 && y.bs !== x.bs * 2) return 0;
  const [a1, a2, b1, b2] = [x.s1, x.s2, y.s1, y.s2].map(stripSeq);
  if (x.bs === y.bs && a1 === b1) return 100;
  if (x.bs === y.bs) return Math.max(scoreStrings(a1, b1, x.bs), scoreStrings(a2, b2, x.bs * 2));
  if (x.bs === y.bs * 2) return scoreStrings(a1, b2, x.bs);
  return scoreStrings(a2, b1, y.bs);
}

// ---------------------------------------------------------------- TLSH
const V = [1, 87, 49, 12, 176, 178, 102, 166, 121, 193, 6, 84, 249, 230, 44, 163, 14, 197, 213, 181, 161, 85, 218, 80, 64, 239, 24, 226, 236, 142, 38, 200, 110, 177, 104, 103, 141, 253, 255, 50, 77, 101, 81, 18, 45, 96, 31, 222, 25, 107, 190, 70, 86, 237, 240, 34, 72, 242, 20, 214, 244, 227, 149, 235, 97, 234, 57, 22, 60, 250, 82, 175, 208, 5, 127, 199, 111, 62, 135, 248, 174, 169, 211, 58, 66, 154, 106, 195, 245, 171, 17, 187, 182, 179, 0, 243, 132, 56, 148, 75, 128, 133, 158, 100, 130, 126, 91, 13, 153, 246, 216, 219, 119, 68, 223, 78, 83, 88, 201, 99, 122, 11, 92, 32, 136, 114, 52, 10, 138, 30, 48, 183, 156, 35, 61, 26, 143, 74, 251, 94, 129, 162, 63, 152, 170, 7, 115, 167, 241, 206, 3, 150, 55, 59, 151, 220, 90, 53, 23, 131, 125, 173, 15, 238, 79, 95, 89, 16, 105, 137, 225, 224, 217, 160, 37, 123, 118, 73, 2, 157, 46, 116, 9, 145, 134, 228, 207, 212, 202, 215, 69, 229, 27, 188, 67, 124, 168, 252, 42, 4, 29, 108, 21, 247, 19, 205, 39, 203, 233, 40, 186, 147, 198, 192, 155, 33, 164, 191, 98, 204, 165, 180, 117, 76, 140, 36, 210, 172, 41, 54, 159, 8, 185, 232, 113, 196, 231, 47, 146, 120, 51, 65, 28, 144, 254, 221, 93, 189, 194, 139, 112, 43, 71, 109, 184, 209];
const pearson = (salt, a, b, c) => V[V[V[V[salt] ^ a] ^ b] ^ c];
const swap = (x) => ((x & 0x0f) << 4) | ((x & 0xf0) >> 4);
const hex2 = (x) => x.toString(16).toUpperCase().padStart(2, '0');
export const TLSH_MIN_LENGTH = 50;

function lCapture(len) {
  if (len <= 656) return Math.floor(Math.log(len) / 0.4054651) % 256;
  if (len <= 3199) return Math.floor(Math.log(len) / 0.26236426 - 8.72777) % 256;
  return Math.floor(Math.log(len) / 0.095310180 - 62.5472) % 256;
}

/**
 * TLSH digest ("T1" + 70 hex chars), or null when the input is too short (< 50 bytes) or too uniform.
 * @param {Uint8Array} buf
 * @returns {string | null}
 */
export function tlsh(buf) {
  const data = buf instanceof Uint8Array ? buf : Buffer.from(buf);
  if (data.length < TLSH_MIN_LENGTH) return null;
  const buckets = new Uint32Array(256); const w = new Uint8Array(5); let checksum = 0;
  for (let i = 0; i < data.length; i++) {
    const j = i % 5; w[j] = data[i];
    if (i >= 4) {
      const j1 = (j + 4) % 5; const j2 = (j + 3) % 5; const j3 = (j + 2) % 5; const j4 = (j + 1) % 5;
      checksum = pearson(0, w[j], w[j1], checksum);
      buckets[pearson(2, w[j], w[j1], w[j2])]++;
      buckets[pearson(3, w[j], w[j1], w[j3])]++;
      buckets[pearson(5, w[j], w[j2], w[j3])]++;
      buckets[pearson(7, w[j], w[j2], w[j4])]++;
      buckets[pearson(11, w[j], w[j1], w[j4])]++;
      buckets[pearson(13, w[j], w[j3], w[j4])]++;
    }
  }
  const eff = Array.from(buckets.subarray(0, 128));
  const sorted = [...eff].sort((a, b) => a - b);
  const q1 = sorted[31]; const q2 = sorted[63]; const q3 = sorted[95];
  if (q3 === 0) return null;
  if (eff.filter((x) => x > 0).length <= 64) return null;
  const body = new Array(32);
  for (let i = 0; i < 32; i++) {
    let h = 0;
    for (let k = 0; k < 4; k++) { const v = eff[4 * i + k]; h += (q3 < v ? 3 : q2 < v ? 2 : q1 < v ? 1 : 0) << (k * 2); }
    body[i] = h;
  }
  const lv = lCapture(data.length);
  const q1r = Math.floor((q1 * 100) / q3) % 16; const q2r = Math.floor((q2 * 100) / q3) % 16;
  const qb = (q1r & 0x0f) | ((q2r & 0x0f) << 4);
  let out = 'T1' + hex2(swap(checksum)) + hex2(swap(lv)) + hex2(swap(qb));
  for (let i = 31; i >= 0; i--) out += hex2(body[i]);
  return out;
}

/** Parse a TLSH string (with or without the "T1" prefix). */
export function parseTlsh(h) {
  const s = String(h).trim().toUpperCase().replace(/^T1/, '');
  if (!/^[0-9A-F]{70}$/.test(s)) return null;
  const b = s.match(/../g).map((x) => parseInt(x, 16));
  return { checksum: swap(b[0]), lvalue: swap(b[1]), q1: swap(b[2]) & 0x0f, q2: (swap(b[2]) & 0xf0) >> 4, body: b.slice(3).reverse() };
}
const modDiff = (a, b, r) => { const d = Math.abs(a - b); return Math.min(d, r - d); };
const BITPAIR = (() => { const t = new Uint8Array(65536); for (let a = 0; a < 256; a++) for (let b = 0; b < 256; b++) { let d = 0; for (let k = 0; k < 4; k++) { const x = Math.abs(((a >> (2 * k)) & 3) - ((b >> (2 * k)) & 3)); d += x === 3 ? 6 : x; } t[a * 256 + b] = d; } return t; })();
/**
 * TLSH distance: 0 = identical; < ~50 very similar; > ~200 unrelated.
 * @param {string} a
 * @param {string} b
 * @param {{ lengthDiff?: boolean }} [opts]
 */
export function compareTlsh(a, b, { lengthDiff = true } = {}) {
  const x = parseTlsh(a); const y = parseTlsh(b);
  if (!x || !y) throw new Error('Invalid TLSH digest');
  let d = 0;
  if (lengthDiff) { const l = modDiff(x.lvalue, y.lvalue, 256); d += l === 0 ? 0 : l === 1 ? 1 : l * 12; }
  for (const [p, q] of [[x.q1, y.q1], [x.q2, y.q2]]) { const qd = modDiff(p, q, 16); d += qd <= 1 ? qd : (qd - 1) * 12; }
  if (x.checksum !== y.checksum) d += 1;
  for (let i = 0; i < 32; i++) d += BITPAIR[x.body[i] * 256 + y.body[i]];
  return d;
}

/** Recognise a fuzzy hash string: 'ssdeep' | 'tlsh' | null. */
export function fuzzyType(s) {
  const v = String(s).trim();
  if (/^T1[0-9A-Fa-f]{70}$/.test(v) || /^[0-9A-Fa-f]{70}$/.test(v)) return 'tlsh';
  if (/^\d+:[A-Za-z0-9+/]{1,64}:[A-Za-z0-9+/]{0,32}$/.test(v)) return 'ssdeep';
  return null;
}
