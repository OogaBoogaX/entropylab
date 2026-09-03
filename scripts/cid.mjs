// CIDv1 raw sha2-256 of a file. Same digest SHA256SUMS already publishes;
// this is a self-describing name for those bytes, not a second hash.
// No network, no node, no gateway, no IPNS.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { basename, resolve } from "node:path";
import { pathToFileURL } from "node:url";

// CIDv1 (0x01) + raw codec (0x55) + sha2-256 multihash (0x12 0x20) + digest.
const RAW_SHA256_PREFIX = Buffer.from([0x01, 0x55, 0x12, 0x20]);
const BASE32 = "abcdefghijklmnopqrstuvwxyz234567";

export function base32Encode(bytes) {
  let bits = 0, value = 0, out = "";
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += BASE32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += BASE32[(value << (5 - bits)) & 31];
  return out;
}

export function cidV1RawSha256FromDigest(digest) {
  const bytes = digest instanceof Uint8Array ? digest : Buffer.from(digest);
  if (bytes.length !== 32) throw new Error("SHA-256 digest must be 32 bytes");
  return "b" + base32Encode(Buffer.concat([RAW_SHA256_PREFIX, bytes]));
}

export function cidV1RawSha256FromBytes(bytes) {
  return cidV1RawSha256FromDigest(createHash("sha256").update(bytes).digest());
}

export function cidLineForFile(path) {
  const cid = cidV1RawSha256FromBytes(readFileSync(path));
  return `${cid}  ${basename(path)}\n`;
}

function main() {
  const path = process.argv[2];
  if (!path) {
    process.stderr.write("usage: node scripts/cid.mjs <file>\n");
    process.exit(1);
  }
  process.stdout.write(cidLineForFile(path));
}

const entry = process.argv[1];
if (entry && pathToFileURL(resolve(entry)).href === import.meta.url) main();
