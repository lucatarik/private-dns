#!/usr/bin/env node
// Builds the compiled blocklist locally (no Worker CPU limits) into <outdir>/blocklist.bin + meta.json.
// Usage: node tools/build-blocklist.mjs [outdir]   (env BLOCKLISTS overrides the default sources)
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { buildFromLists, listUrls } from '../src/update.js';

const out = process.argv[2] || 'build';
mkdirSync(out, { recursive: true });
const { blob, meta } = await buildFromLists(listUrls(process.env));
writeFileSync(join(out, 'blocklist.bin'), Buffer.from(blob.buffer, blob.byteOffset, blob.byteLength));
writeFileSync(join(out, 'meta.json'), JSON.stringify(meta));
for (const s of meta.sources) console.error(s.error ? `  ✗ ${s.url} (${s.error})` : `  ✓ ${s.url} (${s.count} domini)`);
console.error(`  → ${meta.count} domini unici compilati (${(blob.byteLength / 1048576).toFixed(1)} MiB)`);
