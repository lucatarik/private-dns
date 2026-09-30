// Blocklist parsing, compact hashed storage and lookup.
//
// A blocklist is stored as one Float64Array blob: [stamp, h1, h2, ...] where the
// hashes are sorted, unique 53-bit domain hashes. A lookup is a binary search
// (~20 steps for 500k domains) with no per-domain string allocation.

export const DEFAULT_LISTS = [
  'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro-onlydomains.txt',
  'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',
  'https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt',
];

export const PASS = 0;
export const BLOCK = 1;
export const ALLOW = 2;

/** 53-bit hash of s.slice(from) (exactly representable as a double). */
export function hashDomain(s, from = 0) {
  let h1 = 0x811c9dc5;
  let h2 = 0x9747b28c;
  for (let i = from; i < s.length; i++) {
    const c = s.charCodeAt(i);
    h1 = Math.imul(h1 ^ c, 16777619);
    h2 = Math.imul(h2 ^ c, 0x5bd1e995);
    h2 ^= h2 >>> 15;
  }
  return (h1 & 0x1fffff) * 4294967296 + (h2 >>> 0);
}

const HOST_RE = /^[a-z0-9_]([a-z0-9_.-]*[a-z0-9])?$/;
const IPISH_RE = /^[0-9.]+$/;
const HOSTS_IP_RE = /^(?:0\.0\.0\.0|127\.\d+\.\d+\.\d+|::1?|0)$/;

/** Normalises a user/list supplied domain; returns null if it is not a usable domain. */
export function normalizeDomain(d) {
  d = d.trim().toLowerCase();
  if (d.startsWith('*.')) d = d.slice(2);
  if (d.endsWith('.')) d = d.slice(0, -1);
  if (d.length > 253 || !d.includes('.') || IPISH_RE.test(d) || !HOST_RE.test(d)) return null;
  return d;
}

/** Parses hosts / plain-domain / AdGuard (||domain^) lists, calling add(domain) for each. */
export function parseList(text, add) {
  const len = text.length;
  let pos = 0;
  while (pos < len) {
    let end = text.indexOf('\n', pos);
    if (end < 0) end = len;
    let line = text.slice(pos, end).trim();
    pos = end + 1;
    if (!line) continue;
    const c = line.charCodeAt(0);
    if (c === 35 || c === 33 || c === 91 || c === 64) continue; // # ! [ @
    if (c === 124) {
      // ||example.com^  (optionally followed by $important)
      const caret = line.indexOf('^');
      if (line.charCodeAt(1) !== 124 || caret < 0) continue;
      const rest = line.slice(caret + 1);
      if (rest && rest !== '$important') continue;
      const d = normalizeDomain(line.slice(2, caret));
      if (d) add(d);
      continue;
    }
    const hash = line.indexOf('#');
    if (hash > 0) line = line.slice(0, hash).trim();
    const parts = line.split(/\s+/);
    if (parts.length === 1) {
      const d = normalizeDomain(parts[0]);
      if (d) add(d);
    } else if (HOSTS_IP_RE.test(parts[0])) {
      for (let i = 1; i < parts.length; i++) {
        const d = normalizeDomain(parts[i]);
        if (d) add(d);
      }
    }
  }
}

export class HashSink {
  constructor() {
    this.arr = new Float64Array(1 << 20);
    this.n = 0;
  }
  add(h) {
    if (this.n === this.arr.length) {
      const bigger = new Float64Array(this.arr.length * 2);
      bigger.set(this.arr);
      this.arr = bigger;
    }
    this.arr[this.n++] = h;
  }
}

/** Sorts + dedupes the sink into a blob: [stamp, ...sortedUniqueHashes]. */
export function buildBlob(sink, stamp) {
  const sorted = sink.arr.subarray(0, sink.n).sort();
  const out = new Float64Array(sorted.length + 1);
  out[0] = stamp;
  let n = 1;
  let prev = -1;
  for (let i = 0; i < sorted.length; i++) {
    if (sorted[i] !== prev) out[n++] = prev = sorted[i];
  }
  return out.slice(0, n);
}

export function hasHash(list, h) {
  let lo = 0;
  let hi = list.length - 1;
  while (lo <= hi) {
    const m = (lo + hi) >> 1;
    const v = list[m];
    if (v === h) return true;
    if (v < h) lo = m + 1;
    else hi = m - 1;
  }
  return false;
}

export class Filter {
  /**
   * @param list  sorted Float64Array of hashes (without stamp header)
   * @param rules { block: string[], allow: string[] } custom rules
   */
  constructor(list, rules, stamp = 0) {
    this.list = list;
    this.stamp = stamp;
    this.block = new Set(rules?.block || []);
    this.allow = new Set(rules?.allow || []);
  }

  /** Most specific match wins, walking from the full name up to the registrable suffix. */
  check(name) {
    let i = 0;
    for (;;) {
      const sfx = i === 0 ? name : name.slice(i);
      if (this.allow.has(sfx)) return ALLOW;
      if (this.block.has(sfx) || hasHash(this.list, hashDomain(name, i))) return BLOCK;
      const dot = name.indexOf('.', i);
      if (dot < 0 || name.indexOf('.', dot + 1) < 0) return PASS; // never test a bare TLD
      i = dot + 1;
    }
  }
}
