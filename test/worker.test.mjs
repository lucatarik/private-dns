import test from 'node:test';
import assert from 'node:assert/strict';
import worker from '../src/worker.js';
import { HashSink, buildBlob, hashDomain, parseList, Filter, BLOCK, PASS, ALLOW } from '../src/blocklist.js';

const enc = (name, type = 1, { edns = 0, id = 0x1234 } = {}) => {
  const labels = name.split('.').filter(Boolean);
  const body = [];
  for (const l of labels) body.push(l.length, ...Buffer.from(l));
  body.push(0, type >> 8, type & 255, 0, 1);
  const hdr = [id >> 8, id & 255, 1, 0, 0, 1, 0, 0, 0, 0, 0, edns ? 1 : 0];
  const opt = edns ? [0, 0, 41, 16, 0, 0, 0, edns === 2 ? 0x80 : 0, 0, 0, 0] : [];
  return new Uint8Array([...hdr, ...body, ...opt]);
};

// Fake upstream: name -> CNAME ads.tracker.net (cloaked) or A 93.184.216.34
let upstreamCalls = 0;
globalThis.fetch = async (_url, init) => {
  upstreamCalls++;
  const q = new Uint8Array(init.body);
  let end = 12;
  while (q[end]) end += q[end] + 1;
  end += 5;
  const question = q.slice(12, end);
  const name = Buffer.from(question.slice(0, -5)).toString('latin1');
  const cloaked = name.includes('metrics');
  const rr = cloaked
    ? [0xc0, 12, 0, 5, 0, 1, 0, 0, 1, 44, 0, 13, 3, ...Buffer.from('ads'), 7, ...Buffer.from('tracker'), 3, ...Buffer.from('net'), 0]
    : [0xc0, 12, 0, 1, 0, 1, 0, 0, 1, 44, 0, 4, 93, 184, 216, 34];
  const out = new Uint8Array([0, 0, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, ...question, ...rr]);
  return new Response(out, { status: 200 });
};

const sink = new HashSink();
parseList('0.0.0.0 ads.example.com\n||tracker.net^\n# c\nbad.org\n@@||ok.bad.org^\n', (d) => sink.add(hashDomain(d)));
const blob = buildBlob(sink, 42);

const kvData = new Map([
  ['blocklist', blob.buffer],
  ['meta', JSON.stringify({ updatedAt: 42, count: 3 })],
  ['rules', JSON.stringify({ block: [], allow: ['x.bad.org'] })],
]);
const env = {
  ACCESS_TOKENS: 'tok1, tok2',
  ADMIN_TOKEN: 'adm',
  DNS_KV: {
    get: async (k, o) => {
      const v = kvData.get(k);
      if (v == null) return null;
      const t = typeof o === 'string' ? o : o?.type;
      return t === 'json' ? JSON.parse(v) : v;
    },
    put: async (k, v) => void kvData.set(k, v),
  },
};
const ctx = { waitUntil() {} };
const doh = (bytes, tok = 'tok1') => worker.fetch(new Request(`https://h/${tok}/dns-query`, { method: 'POST', body: bytes }), env, ctx);
const rd = async (r) => new Uint8Array(await r.arrayBuffer());

test('filter matching', () => {
  const f = new Filter(blob.subarray(1), { block: ['custom.io'], allow: ['x.bad.org'] });
  assert.equal(f.check('ads.example.com'), BLOCK);
  assert.equal(f.check('a.b.ads.example.com'), BLOCK);
  assert.equal(f.check('example.com'), PASS);
  assert.equal(f.check('com'), PASS);
  assert.equal(f.check('www.custom.io'), BLOCK);
  assert.equal(f.check('x.bad.org'), ALLOW);
  assert.equal(f.check('y.bad.org'), BLOCK);
});

test('rejects bad token, serves landing', async () => {
  assert.equal((await doh(enc('a.com'), 'nope')).status, 404);
  assert.equal((await worker.fetch(new Request('https://h/'), env, ctx)).status, 200);
});

test('blocked A / AAAA / HTTPS', async () => {
  let r = await rd(await doh(enc('Ads.Example.com', 1)));
  assert.deepEqual([...r.slice(0, 4)], [0x12, 0x34, 0x81, 0x80]);
  assert.deepEqual([...r.slice(-4)], [0, 0, 0, 0]);
  assert.equal(r[7], 1);
  r = await rd(await doh(enc('ads.example.com', 28)));
  assert.equal(r.length, 12 + 21 + 12 + 16);
  r = await rd(await doh(enc('ads.example.com', 65)));
  assert.equal(r[7], 0);
  assert.equal(r[3] & 15, 0);
});

test('allowed query is forwarded, cached, TTL aged', async () => {
  upstreamCalls = 0;
  const a = await rd(await doh(enc('www.good.com', 1, { edns: 2, id: 7 })));
  assert.equal(a[0], 0);
  assert.equal(a[1], 7);
  assert.equal(a[7], 1);
  const b = await rd(await doh(enc('WWW.good.com', 1, { edns: 2, id: 9 })));
  assert.equal(b[1], 9);
  assert.equal(upstreamCalls, 1);
});

test('CNAME cloaking is blocked', async () => {
  const r = await rd(await doh(enc('metrics.site.com', 1)));
  assert.deepEqual([...r.slice(-4)], [0, 0, 0, 0]);
  assert.equal(r[7], 1);
});

test('GET ?dns= works', async () => {
  const b64 = Buffer.from(enc('www.good.com')).toString('base64url');
  const res = await worker.fetch(new Request(`https://h/tok2?dns=${b64}`), env, ctx);
  assert.equal(res.headers.get('content-type'), 'application/dns-message');
});

test('admin rules + check', async () => {
  const h = { authorization: 'Bearer adm' };
  let res = await worker.fetch(new Request('https://h/admin/rules', { method: 'POST', headers: h, body: JSON.stringify({ action: 'block', domains: ['www.good.com'] }) }), env, ctx);
  assert.deepEqual((await res.json()).block, ['www.good.com']);
  res = await worker.fetch(new Request('https://h/admin/check?domain=www.good.com', { headers: h }), env, ctx);
  assert.equal((await res.json()).verdict, 'blocked');
  assert.equal((await worker.fetch(new Request('https://h/admin/status'), env, ctx)).status, 404);
});
