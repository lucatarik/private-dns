import { ALLOW, BLOCK, Filter, normalizeDomain } from './blocklist.js';
import { buildBlocked, buildServfail, buildUpstreamQuery, inspectResponse, parseQuery, renderResponse } from './dns.js';
import { refreshLists } from './update.js';

const DNS_MSG = 'application/dns-message';
const RELOAD_MS = 120_000; // how often an isolate re-checks KV for new lists/rules
const MIN_TTL = 15;
const MAX_TTL = 3600;
const STALE_MS = 3_600_000; // serve-stale window while refreshing in the background
const MAX_ENTRIES = 20_000;

// ---------------------------------------------------------------- filter state

let state = null; // Filter
let stateRules = '';
let lastCheck = 0;
let loading = null;

async function reload(env) {
  try {
    const [meta, rulesTxt] = await Promise.all([
      env.DNS_KV.get('meta', { type: 'json', cacheTtl: 60 }),
      env.DNS_KV.get('rules', { cacheTtl: 60 }),
    ]);
    let list = state?.list;
    let stamp = state?.stamp;
    if (!state || (meta && meta.updatedAt !== stamp)) {
      const buf = await env.DNS_KV.get('blocklist', { type: 'arrayBuffer', cacheTtl: 60 });
      if (buf && buf.byteLength >= 8) {
        const all = new Float64Array(buf);
        stamp = all[0];
        list = all.subarray(1);
      } else if (!state) {
        list = new Float64Array(0);
        stamp = 0;
      }
    }
    const rt = rulesTxt || '';
    if (!state || list !== state.list || rt !== stateRules) {
      state = new Filter(list, rt ? JSON.parse(rt) : {}, stamp);
      stateRules = rt;
    }
  } catch {
    if (!state) state = new Filter(new Float64Array(0), {}, 0); // fail open, retry soon
    lastCheck = Date.now() - RELOAD_MS + 15_000;
  }
}

function getFilter(env, ctx) {
  const now = Date.now();
  if (state && now - lastCheck < RELOAD_MS) return state;
  lastCheck = now;
  const p = loading || (loading = reload(env).finally(() => (loading = null)));
  if (state) {
    ctx.waitUntil(p);
    return state;
  }
  return p.then(() => state);
}

// ---------------------------------------------------------------- DNS cache

const cache = new Map(); // key -> entry
const inflight = new Map();

function store(key, entry) {
  cache.delete(key);
  cache.set(key, entry);
  if (cache.size > MAX_ENTRIES) cache.delete(cache.keys().next().value);
}

async function queryUpstream(wire, env) {
  const urls = (env.UPSTREAMS || 'https://cloudflare-dns.com/dns-query').split(/[\s,]+/).filter(Boolean);
  for (const url of urls) {
    try {
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'content-type': DNS_MSG, accept: DNS_MSG },
        body: wire,
        signal: AbortSignal.timeout(2500),
      });
      if (!res.ok) continue;
      const b = new Uint8Array(await res.arrayBuffer());
      if (b.length >= 12 && b[2] & 0x80) return b;
    } catch {
      /* try next upstream */
    }
  }
  return null;
}

async function fetchEntry(key, q, env) {
  const up = await queryUpstream(buildUpstreamQuery(q), env);
  if (!up) return null;
  const info = inspectResponse(up, q.end, MIN_TTL, MAX_TTL);
  const at = Date.now();
  const cacheable = (info.rcode === 0 || info.rcode === 3) && !(up[2] & 0x02);
  const entry = { bytes: up, at, ttl: cacheable ? info.ttl : 0, exp: at + (cacheable ? info.ttl * 1000 : 0), cnames: info.cnames };
  if (cacheable) store(key, entry);
  return entry;
}

function fetchCoalesced(key, q, env) {
  let p = inflight.get(key);
  if (!p) {
    p = fetchEntry(key, q, env).finally(() => inflight.delete(key));
    inflight.set(key, p);
  }
  return p;
}

/** Returns { entry, stale } or null when every upstream failed. */
async function resolve(q, env, ctx) {
  const key = `${q.name}|${q.qtype}|${q.qclass}|${q.edns}|${q.cd ? 1 : 0}`;
  const now = Date.now();
  const hit = cache.get(key);
  if (hit) {
    if (now < hit.exp) return { entry: hit, stale: false };
    if (now < hit.exp + STALE_MS) {
      ctx.waitUntil(fetchCoalesced(key, q, env).catch(() => {}));
      return { entry: hit, stale: true };
    }
  }
  const entry = await fetchCoalesced(key, q, env);
  return entry && { entry, stale: false };
}

// ---------------------------------------------------------------- HTTP

const dnsResponse = (bytes, maxAge) =>
  new Response(bytes, {
    headers: { 'content-type': DNS_MSG, 'cache-control': `max-age=${maxAge}`, 'access-control-allow-origin': '*' },
  });
const text = (body, status = 200) => new Response(body, { status, headers: { 'content-type': 'text/plain; charset=utf-8' } });
const json = (obj, status = 200) => new Response(JSON.stringify(obj, null, 2), { status, headers: { 'content-type': 'application/json' } });

function b64uDecode(s) {
  try {
    const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/'));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

function safeEq(a, b) {
  let d = a.length ^ b.length;
  for (let i = 0, n = Math.max(a.length, b.length); i < n; i++) d |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  return d === 0;
}

const tokenOk = (list, tok) => !!tok && (list || '').split(',').some((t) => (t = t.trim()) && safeEq(t, tok));

async function doh(request, url, env, ctx) {
  let wire;
  if (request.method === 'GET') {
    const p = url.searchParams.get('dns');
    wire = p && b64uDecode(p);
    if (!wire) return text('bad request', 400);
  } else if (request.method === 'POST') {
    if (+request.headers.get('content-length') > 4096) return text('too large', 413);
    wire = new Uint8Array(await request.arrayBuffer());
    if (wire.length > 4096) return text('too large', 413);
  } else {
    return text('method not allowed', 405);
  }

  const q = parseQuery(wire);
  if (!q || q.opcode !== 0) return text('bad request', 400);

  const mode = env.BLOCK_MODE || 'null';
  const filter = await getFilter(env, ctx);
  const verdict = filter.check(q.name);
  if (verdict === BLOCK) return dnsResponse(buildBlocked(q, mode), 300);

  const r = await resolve(q, env, ctx);
  if (!r) return dnsResponse(buildServfail(q), 0);
  const { entry, stale } = r;

  // CNAME-cloaking protection: a first-party name aliasing to a tracker is blocked too.
  if (verdict !== ALLOW && entry.cnames.some((c) => filter.check(c) === BLOCK)) {
    return dnsResponse(buildBlocked(q, mode), 300);
  }

  const now = Date.now();
  const age = Math.floor((now - entry.at) / 1000);
  const maxAge = stale ? 30 : entry.ttl ? Math.max(1, entry.ttl - age) : 0;
  return dnsResponse(renderResponse(entry.bytes, q, age, stale), maxAge);
}

function mobileconfig(host, token) {
  const id = host.replace(/[^a-z0-9.-]/gi, '');
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>PayloadContent</key><array><dict>
    <key>DNSSettings</key><dict>
      <key>DNSProtocol</key><string>HTTPS</string>
      <key>ServerURL</key><string>https://${host}/${token}/dns-query</string>
    </dict>
    <key>PayloadDisplayName</key><string>Private DNS</string>
    <key>PayloadIdentifier</key><string>com.apple.dnsSettings.managed.${id}</string>
    <key>PayloadType</key><string>com.apple.dnsSettings.managed</string>
    <key>PayloadUUID</key><string>${crypto.randomUUID().toUpperCase()}</string>
    <key>PayloadVersion</key><integer>1</integer>
  </dict></array>
  <key>PayloadDisplayName</key><string>Private DNS (${id})</string>
  <key>PayloadIdentifier</key><string>private-dns.${id}</string>
  <key>PayloadRemovalDisallowed</key><false/>
  <key>PayloadType</key><string>Configuration</string>
  <key>PayloadUUID</key><string>${crypto.randomUUID().toUpperCase()}</string>
  <key>PayloadVersion</key><integer>1</integer>
</dict></plist>`;
}

async function admin(request, url, env, ctx, seg) {
  const bearer = (request.headers.get('authorization') || '').replace(/^Bearer\s+/i, '');
  if (!env.ADMIN_TOKEN || !safeEq(env.ADMIN_TOKEN, bearer)) return text('not found', 404);

  const route = seg[1];
  const forceReload = async () => {
    lastCheck = Date.now();
    await reload(env);
  };

  if (route === 'status') {
    await forceReload();
    return json({
      meta: await env.DNS_KV.get('meta', 'json'),
      blocked_domains_loaded: state.list.length,
      custom_block: state.block.size,
      custom_allow: state.allow.size,
      cache_entries: cache.size,
    });
  }
  if (route === 'check') {
    await forceReload();
    const d = normalizeDomain(url.searchParams.get('domain') || '');
    if (!d) return json({ error: 'invalid domain' }, 400);
    const v = state.check(d);
    return json({ domain: d, verdict: v === BLOCK ? 'blocked' : v === ALLOW ? 'allowed' : 'not listed' });
  }
  if (route === 'update' && request.method === 'POST') {
    const meta = await refreshLists(env);
    await forceReload();
    return json(meta);
  }
  if (route === 'rules') {
    const rules = JSON.parse((await env.DNS_KV.get('rules')) || '{"block":[],"allow":[]}');
    rules.block ||= [];
    rules.allow ||= [];
    if (request.method === 'GET') return json(rules);
    if (request.method === 'POST') {
      let body;
      try {
        body = await request.json();
      } catch {
        return json({ error: 'invalid JSON' }, 400);
      }
      const domains = (body.domains || []).map((d) => normalizeDomain(String(d))).filter(Boolean);
      if (!domains.length) return json({ error: 'no valid domains' }, 400);
      const set = (k) => new Set(rules[k]);
      const block = set('block');
      const allow = set('allow');
      for (const d of domains) {
        if (body.action === 'remove') {
          block.delete(d);
          allow.delete(d);
        } else if (body.action === 'block') {
          allow.delete(d);
          block.add(d);
        } else if (body.action === 'allow') {
          block.delete(d);
          allow.add(d);
        } else {
          return json({ error: 'action must be block | allow | remove' }, 400);
        }
      }
      const out = { block: [...block].sort(), allow: [...allow].sort() };
      await env.DNS_KV.put('rules', JSON.stringify(out));
      await forceReload();
      return json(out);
    }
  }
  return text('not found', 404);
}

async function route(request, env, ctx) {
  const url = new URL(request.url);
  const seg = url.pathname.split('/').filter(Boolean);
  if (!seg.length) return text('private-dns: ok\n');
  if (seg[0] === 'admin') return admin(request, url, env, ctx, seg);
  if (!tokenOk(env.ACCESS_TOKENS, seg[0])) return text('not found', 404);
  if (seg.length === 1 || (seg.length === 2 && seg[1] === 'dns-query')) return doh(request, url, env, ctx);
  if (seg.length === 2 && seg[1] === 'apple.mobileconfig') {
    return new Response(mobileconfig(url.host, seg[0]), {
      headers: { 'content-type': 'application/x-apple-aspen-config', 'content-disposition': 'attachment; filename="private-dns.mobileconfig"' },
    });
  }
  return text('not found', 404);
}

export default {
  async fetch(request, env, ctx) {
    try {
      return await route(request, env, ctx);
    } catch {
      return text('internal error', 500);
    }
  },

  async scheduled(_event, env, ctx) {
    ctx.waitUntil(refreshLists(env));
  },
};
