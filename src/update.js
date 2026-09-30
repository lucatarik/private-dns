import { DEFAULT_LISTS, HashSink, buildBlob, hashDomain, parseList } from './blocklist.js';

export function listUrls(env) {
  const custom = (env?.BLOCKLISTS || '').split(/[\s,]+/).filter(Boolean);
  return custom.length ? custom : DEFAULT_LISTS;
}

/** Downloads and compiles every list. Returns { blob: Float64Array, meta }. */
export async function buildFromLists(urls) {
  const sink = new HashSink();
  const sources = [];
  await Promise.all(
    urls.map(async (url) => {
      try {
        const res = await fetch(url);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        let count = 0;
        parseList(await res.text(), (d) => {
          sink.add(hashDomain(d));
          count++;
        });
        sources.push({ url, count });
      } catch (e) {
        sources.push({ url, error: String(e?.message || e) });
      }
    }),
  );
  if (!sink.n) throw new Error('no domains fetched: ' + JSON.stringify(sources));
  const stamp = Date.now();
  const blob = buildBlob(sink, stamp);
  return { blob, meta: { updatedAt: stamp, count: blob.length - 1, sources } };
}

/** Rebuilds the blocklist and publishes it to KV (blob first, then meta). */
export async function refreshLists(env) {
  const { blob, meta } = await buildFromLists(listUrls(env));
  await env.DNS_KV.put('blocklist', blob.buffer);
  await env.DNS_KV.put('meta', JSON.stringify(meta));
  return meta;
}
