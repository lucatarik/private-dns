// Minimal, allocation-light DNS wire-format helpers (RFC 1035 / 6891).

const u16 = (b, o) => (b[o] << 8) | b[o + 1];
const w16 = (b, o, v) => {
  b[o] = v >> 8;
  b[o + 1] = v & 255;
};
const u32 = (b, o) => b[o] * 16777216 + (b[o + 1] << 16) + (b[o + 2] << 8) + b[o + 3];
const w32 = (b, o, v) => {
  b[o] = (v >>> 24) & 255;
  b[o + 1] = (v >>> 16) & 255;
  b[o + 2] = (v >>> 8) & 255;
  b[o + 3] = v & 255;
};

const T_A = 1;
const T_CNAME = 5;
const T_AAAA = 28;
const T_OPT = 41;

/** Returns the offset just after the (possibly compressed) name at `p`, or -1. */
export function skipName(b, p) {
  for (;;) {
    if (p >= b.length) return -1;
    const l = b[p];
    if (l === 0) return p + 1;
    if ((l & 0xc0) === 0xc0) return p + 2 <= b.length ? p + 2 : -1;
    if (l & 0xc0) return -1;
    p += l + 1;
  }
}

/** Decodes a (possibly compressed) name into a lowercase dotted string, or null. */
export function readName(b, p) {
  let out = '';
  let hops = 0;
  for (;;) {
    if (p >= b.length) return null;
    const l = b[p];
    if (l === 0) return out;
    if ((l & 0xc0) === 0xc0) {
      if (p + 1 >= b.length || ++hops > 8) return null;
      p = ((l & 0x3f) << 8) | b[p + 1];
      continue;
    }
    if (l & 0xc0 || p + 1 + l > b.length) return null;
    if (out) out += '.';
    for (let i = 1; i <= l; i++) {
      let c = b[p + i];
      if (c >= 65 && c <= 90) c += 32;
      out += String.fromCharCode(c);
    }
    p += l + 1;
  }
}

/** Calls cb(type, ttlOffset, rdataOffset, rdataLen, index) for `count` RRs starting at `p`. */
export function walkRRs(b, p, count, cb) {
  for (let i = 0; i < count; i++) {
    p = skipName(b, p);
    if (p < 0 || p + 10 > b.length) return false;
    const rdLen = u16(b, p + 8);
    if (p + 10 + rdLen > b.length) return false;
    cb(u16(b, p), p + 4, p + 10, rdLen, i);
    p += 10 + rdLen;
  }
  return true;
}

/**
 * Parses a DNS query. Returns null if malformed.
 * edns: 0 = no OPT record, 1 = OPT without DO, 2 = OPT with DO.
 */
export function parseQuery(b) {
  if (b.length < 17) return null;
  const flags = u16(b, 2);
  if (flags & 0x8000 || u16(b, 4) !== 1) return null;
  let p = 12;
  let name = '';
  for (;;) {
    if (p >= b.length) return null;
    const l = b[p];
    if (l === 0) {
      p++;
      break;
    }
    if (l & 0xc0 || p + 1 + l > b.length) return null;
    if (name) name += '.';
    for (let i = 1; i <= l; i++) {
      let c = b[p + i];
      if (c >= 65 && c <= 90) c += 32;
      name += String.fromCharCode(c);
    }
    p += l + 1;
    if (name.length > 253) return null;
  }
  if (p + 4 > b.length) return null;
  const q = {
    raw: b,
    id: u16(b, 0),
    opcode: (flags >> 11) & 15,
    rd: !!(flags & 0x100),
    cd: !!(flags & 0x10),
    name,
    qnameEnd: p,
    qtype: u16(b, p),
    qclass: u16(b, p + 2),
    end: p + 4,
    edns: 0,
  };
  walkRRs(b, q.end, u16(b, 6) + u16(b, 8) + u16(b, 10), (type, ttlOff) => {
    if (type === T_OPT) q.edns = b[ttlOff + 2] & 0x80 ? 2 : 1;
  });
  return q;
}

/**
 * Builds a clean upstream query: id 0 (cache friendly), RD=1, lowercase name,
 * and a bare OPT record. Client EDNS options (ECS, cookies, padding) are dropped.
 */
export function buildUpstreamQuery(q) {
  const nameLen = q.qnameEnd - 12;
  const out = new Uint8Array(12 + nameLen + 4 + (q.edns ? 11 : 0));
  w16(out, 2, 0x0100 | (q.cd ? 0x10 : 0));
  w16(out, 4, 1);
  w16(out, 10, q.edns ? 1 : 0);
  for (let i = 0; i < nameLen; i++) {
    const c = q.raw[12 + i];
    out[12 + i] = c >= 65 && c <= 90 ? c + 32 : c;
  }
  let p = 12 + nameLen;
  w16(out, p, q.qtype);
  w16(out, p + 2, q.qclass);
  p += 4;
  if (q.edns) {
    w16(out, p + 1, T_OPT);
    w16(out, p + 3, 1232);
    if (q.edns === 2) out[p + 7] = 0x80;
  }
  return out;
}

/**
 * Inspects an upstream response: clamps every TTL into [minTtl, maxTtl] in place and
 * returns { rcode, ttl (min over answer+authority), cnames (answer CNAME targets) }.
 */
export function inspectResponse(b, qEnd, minTtl, maxTtl) {
  const an = u16(b, 6);
  const ns = u16(b, 8);
  let ttl = Infinity;
  const cnames = [];
  walkRRs(b, qEnd, an + ns + u16(b, 10), (type, ttlOff, rdOff, _len, idx) => {
    if (type === T_OPT) return;
    const t = Math.min(Math.max(u32(b, ttlOff), minTtl), maxTtl);
    w32(b, ttlOff, t);
    if (idx < an + ns && t < ttl) ttl = t;
    if (type === T_CNAME && idx < an) {
      const n = readName(b, rdOff);
      if (n) cnames.push(n);
    }
  });
  return { rcode: b[3] & 15, ttl: ttl === Infinity ? 60 : ttl, cnames };
}

/**
 * Turns stored upstream bytes into a response for query `q`: restores the client's
 * id / question casing and ages every TTL (or pins it to 30s when serving stale).
 */
export function renderResponse(up, q, ageSecs, stale) {
  const out = up.slice();
  w16(out, 0, q.id);
  if (!q.rd) out[2] &= 0xfe;
  out.set(q.raw.subarray(12, q.qnameEnd), 12);
  walkRRs(out, q.end, u16(out, 6) + u16(out, 8) + u16(out, 10), (type, ttlOff) => {
    if (type === T_OPT) return;
    w32(out, ttlOff, stale ? 30 : Math.max(1, u32(out, ttlOff) - ageSecs));
  });
  return out;
}

/** Sinkhole answer. mode: 'null' (0.0.0.0 / ::), 'nxdomain' or 'refused'. */
export function buildBlocked(q, mode, ttl = 300) {
  const rcode = mode === 'nxdomain' ? 3 : mode === 'refused' ? 5 : 0;
  const addr = mode !== 'nxdomain' && mode !== 'refused' ? (q.qtype === T_A ? 4 : q.qtype === T_AAAA ? 16 : 0) : 0;
  const qLen = q.end - 12;
  const out = new Uint8Array(12 + qLen + (addr ? 12 + addr : 0));
  w16(out, 0, q.id);
  w16(out, 2, 0x8080 | (q.rd ? 0x100 : 0) | rcode);
  w16(out, 4, 1);
  w16(out, 6, addr ? 1 : 0);
  out.set(q.raw.subarray(12, q.end), 12);
  if (addr) {
    const p = 12 + qLen;
    w16(out, p, 0xc00c);
    w16(out, p + 2, q.qtype);
    w16(out, p + 4, 1);
    w32(out, p + 6, ttl);
    w16(out, p + 10, addr);
  }
  return out;
}

export function buildServfail(q) {
  const out = new Uint8Array(q.end);
  out.set(q.raw.subarray(0, q.end));
  w16(out, 2, 0x8080 | (q.rd ? 0x100 : 0) | 2);
  w16(out, 6, 0);
  w16(out, 8, 0);
  w16(out, 10, 0);
  return out;
}
