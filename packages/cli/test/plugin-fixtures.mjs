/**
 * Fixtures for the plugin tests: zip bundles and a local server standing in
 * for downloads.omnodex.com.
 */

import { createHash } from "node:crypto";
import * as http from "node:http";
import { crc32 } from "node:zlib";

export const sha = (b) => createHash("sha256").update(b).digest("hex");

/** A stored (uncompressed) zip archive from { name: content } pairs. */
export function makeZip(files) {
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const [name, content] of Object.entries(files)) {
    const nameBuf = Buffer.from(name);
    const data = Buffer.from(content);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt32LE(crc32(data), 14);
    local.writeUInt32LE(data.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(nameBuf.length, 26);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt32LE(crc32(data), 16);
    central.writeUInt32LE(data.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(nameBuf.length, 28);
    central.writeUInt32LE(offset, 42);
    locals.push(local, nameBuf, data);
    centrals.push(central, nameBuf);
    offset += 30 + nameBuf.length + data.length;
  }
  const cd = Buffer.concat(centrals);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  const count = Object.keys(files).length;
  eocd.writeUInt16LE(count, 8);
  eocd.writeUInt16LE(count, 10);
  eocd.writeUInt32LE(cd.length, 12);
  eocd.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, cd, eocd]);
}

const MANIFEST = {
  cowork: ".claude-plugin/plugin.json",
  codex: ".codex-plugin/plugin.json",
  antigravity: ".antigravity-plugin/plugin.json",
};

export function bundle(platform, version, extra = {}) {
  return makeZip({
    [MANIFEST[platform]]: JSON.stringify({ name: `omnodex-${platform}`, version }),
    "bin/launch-proxy.js": "// proxy launcher\n",
    LICENSE: "license\n",
    ...extra,
  });
}

/** A downloads site: bundles per platform and version, with checksums and indexes. */
export async function downloadsServer(t, published) {
  const files = new Map();
  const latest = { plugins: {} };
  for (const [platform, versions] of Object.entries(published)) {
    const index = { platform, versions: [] };
    for (const [version, bytes] of Object.entries(versions)) {
      const name = `omnodex-${platform}.plugin`;
      files.set(`/plugins/${platform}/${version}/${name}`, bytes);
      files.set(`/plugins/${platform}/${version}/${name}.sha256`, Buffer.from(`${sha(bytes)}  ${name}\n`));
      index.versions.push({ version, sha256: sha(bytes), size: bytes.length });
      latest.plugins[platform] = { version, sha256: sha(bytes), size: bytes.length };
    }
    files.set(`/plugins/${platform}/versions.json`, Buffer.from(JSON.stringify(index)));
  }
  files.set("/plugins/latest.json", Buffer.from(JSON.stringify(latest)));
  const requests = [];
  const server = http.createServer((req, res) => {
    const url = req.url.split("?")[0];
    requests.push(url);
    const body = files.get(url);
    res.writeHead(body ? 200 : 404);
    res.end(body ?? "not found");
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  return { url: `http://127.0.0.1:${server.address().port}`, files, requests };
}

