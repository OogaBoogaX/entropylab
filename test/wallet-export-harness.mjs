// Shared test harness for the wallet.dat export suites: an independent,
// dependency-free reference implementation of the crypto the module consumes
// (secp256k1/BIP32/base58/checksums over BigInt and node:crypto — the vendor
// bundle is not used), plus the module loader and the real-SQLite read-back.
// Used by wallet-export.test.mjs (fixed Bitcoin Core ground-truth fixtures)
// and wallet-export-fuzz.test.mjs (seeded randomized wallets).
import { createHash, createHmac } from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export const root = dirname(dirname(fileURLToPath(import.meta.url)));
export const read = (path) => readFileSync(join(root, path), "utf8");

export const loadModule = () => new Function(`${read("src/js/sqlite-writer.js")}\n${read("src/js/wallet-export.js")}\nreturn hodlWalletExport;`)();

export const hexToBytes = (text) => Uint8Array.from(Buffer.from(text, "hex"));
export const bytesToHex = (bytes) => Buffer.from(bytes).toString("hex");

// --- independent reference crypto (test-local, no application code) --------

export const FIELD_P = BigInt("0x" + "f".repeat(55) + "efffffc2f");
export const ORDER_N = BigInt("0x" + "f".repeat(31) + "ebaaedce6af48a03bbfd25e8cd0364141");
export const BASE_G = [
  BigInt("0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
  BigInt("0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"),
];
export const modPow = (base, exp, mod) => {
  let result = 1n;
  base %= mod;
  while (exp) {
    if (exp & 1n) result = (result * base) % mod;
    base = (base * base) % mod;
    exp >>= 1n;
  }
  return result;
};
export const pointAdd = (p, q) => {
  if (p === null) return q;
  if (q === null) return p;
  if (p[0] === q[0] && (p[1] + q[1]) % FIELD_P === 0n) return null;
  const inv = (a) => modPow(((a % FIELD_P) + FIELD_P) % FIELD_P, FIELD_P - 2n, FIELD_P);
  const l = p[0] === q[0] && p[1] === q[1]
    ? (3n * p[0] * p[0] * inv(2n * p[1])) % FIELD_P
    : ((q[1] - p[1]) * inv(q[0] - p[0])) % FIELD_P;
  const x = ((l * l - p[0] - q[0]) % FIELD_P + FIELD_P) % FIELD_P;
  return [x, ((l * (p[0] - x) - p[1]) % FIELD_P + FIELD_P) % FIELD_P];
};
export const pointMul = (scalar) => {
  let k = ((scalar % ORDER_N) + ORDER_N) % ORDER_N;
  let result = null;
  let point = BASE_G;
  while (k) {
    if (k & 1n) result = pointAdd(result, point);
    point = pointAdd(point, point);
    k >>= 1n;
  }
  return result;
};
export const serPub = (point) => Uint8Array.from([point[1] & 1n ? 3 : 2, ...bigintBytes(point[0], 32)]);
export const unserPub = (bytes) => {
  const x = BigInt("0x" + bytesToHex(bytes.slice(1)));
  let y = modPow((x * x * x + 7n) % FIELD_P, (FIELD_P + 1n) / 4n, FIELD_P);
  if ((y & 1n) !== BigInt(bytes[0] & 1)) y = FIELD_P - y;
  return [x, y];
};
export const bigintBytes = (value, length) => {
  const out = new Uint8Array(length);
  for (let i = length - 1; i >= 0; i--) { out[i] = Number(value & 0xffn); value >>= 8n; }
  return out;
};

export const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
export const b58encode = (bytes) => {
  let n = BigInt("0x" + (bytes.length ? bytesToHex(bytes) : "0"));
  let out = "";
  while (n > 0n) { out = B58[Number(n % 58n)] + out; n /= 58n; }
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
  return "1".repeat(zeros) + out;
};
export const b58checkDecode = (text) => {
  let n = 0n;
  for (const char of text) n = n * 58n + BigInt(B58.indexOf(char));
  let raw = bigintBytes(n, Math.max(1, Math.ceil(n.toString(2).length / 8)));
  if (n === 0n) raw = new Uint8Array(0);
  let zeros = 0;
  while (zeros < text.length && text[zeros] === "1") zeros++;
  raw = Uint8Array.from([...new Array(zeros).fill(0), ...raw]);
  const data = raw.slice(0, -4);
  const check = raw.slice(-4);
  const digest = createHash("sha256").update(createHash("sha256").update(data).digest()).digest();
  if (Buffer.from(check).compare(digest.subarray(0, 4)) !== 0) throw new Error("bad base58 checksum in test helper");
  return data;
};
export const b58checkEncode = (data) => {
  const digest = createHash("sha256").update(createHash("sha256").update(data).digest()).digest();
  return b58encode(Uint8Array.from([...data, ...digest.subarray(0, 4)]));
};

export const sha256 = (bytes) => new Uint8Array(createHash("sha256").update(bytes).digest());
export const ripemd160 = (bytes) => new Uint8Array(createHash("ripemd160").update(bytes).digest());

// Descriptor checksum: the reference algorithm from Bitcoin Core's
// doc/descriptors.md (NOT the app's implementation).
export const INPUT_CHARSET =
  "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`JKLMNOPQRSTUVWXYZ";
export const CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
export const descriptorChecksum = (body) => {
  const GEN = [0xf5dee51989n, 0xa9fdca3312n, 0x1bab10e32dn, 0x3706b1677an, 0x644d626ffdn];
  const groups = [];
  const symbols = [];
  for (const character of body) {
    const index = INPUT_CHARSET.indexOf(character);
    symbols.push(index & 31);
    groups.push(index >> 5);
    if (groups.length === 3) {
      symbols.push(groups[0] * 9 + groups[1] * 3 + groups[2]);
      groups.length = 0;
    }
  }
  if (groups.length === 1) symbols.push(groups[0]);
  else if (groups.length === 2) symbols.push(groups[0] * 9 + groups[1] * 3);
  let chk = 1n;
  for (const value of [...symbols, 0, 0, 0, 0, 0, 0, 0, 0]) {
    const top = chk >> 35n;
    chk = ((chk & 0x7ffffffffn) << 5n) ^ BigInt(value);
    for (let i = 0; i < 5; i++) if ((top >> BigInt(i)) & 1n) chk ^= GEN[i];
  }
  chk ^= 1n;
  let out = "";
  for (let i = 0; i < 8; i++) out += CHECKSUM_CHARSET[Number((chk >> BigInt(5 * (7 - i))) & 31n)];
  return out;
};

// BIP32 public derivation of the account branch xpub, packed as the 74-byte
// cache body (depth, parent fingerprint, child number, chaincode, pubkey).
export const deriveBranchBody = (xpubText, branch) => {
  const raw = b58checkDecode(xpubText);
  const depth = raw[4];
  const chaincode = raw.slice(13, 45);
  const pubkey = raw.slice(45, 78);
  const indexBytes = Uint8Array.from([(branch >>> 24) & 0xff, (branch >>> 16) & 0xff, (branch >>> 8) & 0xff, branch & 0xff]);
  const I = createHmac("sha512", chaincode).update(Buffer.concat([Buffer.from(pubkey), Buffer.from(indexBytes)])).digest();
  const tweak = BigInt("0x" + I.subarray(0, 32).toString("hex"));
  const childPoint = pointAdd(pointMul(tweak), unserPub(pubkey));
  const fingerprint = ripemd160(sha256(pubkey)).subarray(0, 4);
  return Uint8Array.from([
    depth + 1,
    ...fingerprint,
    ...indexBytes,
    ...new Uint8Array(I.subarray(32)),
    ...serPub(childPoint),
  ]);
};
export const publicKeyForPrivate = (secret) => serPub(pointMul(BigInt("0x" + bytesToHex(secret))));

// Reference for the module's deriveExtendedPrivateChild dep: one hardened
// CKDpriv step below the decoded extended key, re-serialized with the same
// version bytes. The module only requests hardened children (branch steps).
export const deriveExtendedPrivateChild = (xprvText, index) => {
  const raw = b58checkDecode(xprvText);
  const child = hdDeriveHardened(
    { secret: raw.slice(46, 78), chaincode: raw.slice(13, 45), depth: raw[4] },
    index - 0x80000000,
  );
  return serializeExtendedKey(child, Buffer.from(raw.slice(0, 4)).readUInt32BE(0), true);
};

export const deps = { sha256, checksum: descriptorChecksum, base58Decode: b58checkDecode, deriveBranchBody, deriveExtendedPrivateChild, publicKeyForPrivate };

// BIP32 private derivation from a seed, for generating fuzz account keys.
// Hardened steps only — that is all a wallet.dat account path uses.
export const hdMasterFromSeed = (seed32) => {
  const I = createHmac("sha512", "Bitcoin seed").update(seed32).digest();
  return { secret: new Uint8Array(I.subarray(0, 32)), chaincode: new Uint8Array(I.subarray(32)), depth: 0, parentFingerprint: 0, index: 0 };
};
export const hdDeriveHardened = (node, index) => {
  const hardened = index + 0x80000000;
  const data = Buffer.concat([Buffer.from([0]), Buffer.from(node.secret), Buffer.from([hardened >>> 24, (hardened >>> 16) & 0xff, (hardened >>> 8) & 0xff, hardened & 0xff])]);
  const I = createHmac("sha512", node.chaincode).update(data).digest();
  const secret = (BigInt("0x" + I.subarray(0, 32).toString("hex")) + BigInt("0x" + bytesToHex(node.secret))) % ORDER_N;
  return {
    secret: bigintBytes(secret, 32),
    chaincode: new Uint8Array(I.subarray(32)),
    depth: node.depth + 1,
    parentFingerprint: Buffer.from(ripemd160(sha256(publicKeyForPrivate(node.secret))).subarray(0, 4)).readUInt32BE(0),
    index: hardened,
  };
};
export const serializeExtendedKey = (node, version, isPrivate) => {
  const body = Uint8Array.from([
    (version >>> 24) & 0xff, (version >>> 16) & 0xff, (version >>> 8) & 0xff, version & 0xff,
    node.depth,
    (node.parentFingerprint >>> 24) & 0xff, (node.parentFingerprint >>> 16) & 0xff, (node.parentFingerprint >>> 8) & 0xff, node.parentFingerprint & 0xff,
    (node.index >>> 24) & 0xff, (node.index >>> 16) & 0xff, (node.index >>> 8) & 0xff, node.index & 0xff,
    ...node.chaincode,
    ...(isPrivate ? [0, ...node.secret] : publicKeyForPrivate(node.secret)),
  ]);
  return b58checkEncode(body);
};

// Stand-in for the vendor HDKey shape hodlWalletDatDeps() reads, backed by
// the reference CKDpub above.
export const hdNodeFrom = (raw) => ({
  depth: raw[4],
  parentFingerprint: Buffer.from(raw.slice(5, 9)).readUInt32BE(0),
  index: Buffer.from(raw.slice(9, 13)).readUInt32BE(0),
  chainCode: raw.slice(13, 45),
  publicKey: raw.slice(45, 78),
  privateKey: raw[45] === 0 ? raw.slice(46, 78) : null,
  deriveChild(index) {
    const body = deriveBranchBody(b58checkEncode(Uint8Array.from([...raw.slice(0, 4), this.depth, ...raw.slice(5)])), index);
    return hdNodeFrom(Uint8Array.from([...raw.slice(0, 4), ...body]));
  },
});

// --- records and real-SQLite read-back --------------------------------------

export const asMap = (records) => new Map(records.map(([key, value]) => [key, value]));
// creationTime is the descriptor birthday written into every descriptor
// record; fixture comparisons must pass the fixture's REF_CREATION_TIME.
export const moduleRecords = (wallet, includePrivate, creationTime) =>
  asMap(
    loadModule()
      .buildWalletRecords(wallet, includePrivate, deps, creationTime)
      .map(([key, value]) => [bytesToHex(key), bytesToHex(value)]),
  );

export const PYTHON_SQLITE = (() => {
  const probe = spawnSync("python3", ["-c", "import sqlite3"], { stdio: "pipe" });
  return probe.status === 0;
})();

// Reads a generated database with the real SQLite library and returns its
// integrity check plus every row of the `main` table.
export const sqliteReadBack = (dbBytes) => {
  const dir = mkdtempSync(join(tmpdir(), "entropylab-walletdat-"));
  const file = join(dir, "wallet.dat");
  writeFileSync(file, dbBytes);
  try {
    const out = execFileSync(
      "python3",
      [
        "-c",
        `
import sqlite3, json, sys
con = sqlite3.connect(sys.argv[1])
result = {
  "integrity": con.execute("PRAGMA integrity_check").fetchone()[0],
  "app_id": con.execute("PRAGMA application_id").fetchone()[0] & 0xFFFFFFFF,
  "user_version": con.execute("PRAGMA user_version").fetchone()[0],
  "rows": [[k.hex(), v.hex()] for k, v in con.execute("SELECT key, value FROM main")],
}
con.close()
print(json.dumps(result))
`,
        file,
      ],
      { encoding: "utf8", maxBuffer: 1 << 26 },
    );
    return JSON.parse(out);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
};
