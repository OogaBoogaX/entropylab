// Tests for src/js/wallet-export.js (Bitcoin Core wallet.dat export) using
// Node's built-in test runner.
//
// The gold standard: REF_WATCH_ONLY_RECORDS / REF_PRIVATE_RECORDS in
// wallet-export-reference.mjs are the exact rows of wallet.dat `main` tables
// produced by Bitcoin Core v28.3.0 (regtest) via createwallet +
// importdescriptors of the reference descriptors. The tests rebuild those
// rows with the module and an independent, dependency-free reference
// implementation of the crypto (secp256k1/BIP32/checksums over BigInt and
// node:crypto — the vendor bundle is not used), then verify the generated
// database files with Python's sqlite3 (the real SQLite C library).
//
// The same generated file shapes were also validated by loading them with
// bitcoind (loadwallet) and spending from the private variant on regtest.
//
// Run with `npm run test:wallet-export` or `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  REF_ACCOUNT_TPUB,
  REF_CREATION_TIME,
  REF_PRIVATE_DESCRIPTORS,
  REF_PRIVATE_RECORDS,
  REF_PUBLIC_DESCRIPTORS,
  REF_WATCH_ONLY_RECORDS,
} from "./wallet-export-reference.mjs";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const read = (path) => readFileSync(join(root, path), "utf8");
const sqliteSrc = read("src/js/sqlite-writer.js");
const walletSrc = read("src/js/wallet-export.js");
const app = read("src/js/app.js");

const loadModule = () => new Function(`${sqliteSrc}\n${walletSrc}\nreturn hodlWalletExport;`)();

const hexToBytes = (text) => Uint8Array.from(Buffer.from(text, "hex"));
const bytesToHex = (bytes) => Buffer.from(bytes).toString("hex");

// --- independent reference crypto (test-local, no application code) --------

const FIELD_P = BigInt("0x" + "f".repeat(55) + "efffffc2f");
const ORDER_N = BigInt("0x" + "f".repeat(31) + "ebaaedce6af48a03bbfd25e8cd0364141");
const BASE_G = [
  BigInt("0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
  BigInt("0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"),
];
const modPow = (base, exp, mod) => {
  let result = 1n;
  base %= mod;
  while (exp) {
    if (exp & 1n) result = (result * base) % mod;
    base = (base * base) % mod;
    exp >>= 1n;
  }
  return result;
};
const pointAdd = (p, q) => {
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
const pointMul = (scalar) => {
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
const serPub = (point) => Uint8Array.from([point[1] & 1n ? 3 : 2, ...bigintBytes(point[0], 32)]);
const unserPub = (bytes) => {
  const x = BigInt("0x" + bytesToHex(bytes.slice(1)));
  let y = modPow((x * x * x + 7n) % FIELD_P, (FIELD_P + 1n) / 4n, FIELD_P);
  if ((y & 1n) !== BigInt(bytes[0] & 1)) y = FIELD_P - y;
  return [x, y];
};
const bigintBytes = (value, length) => {
  const out = new Uint8Array(length);
  for (let i = length - 1; i >= 0; i--) { out[i] = Number(value & 0xffn); value >>= 8n; }
  return out;
};

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const b58encode = (bytes) => {
  let n = BigInt("0x" + (bytes.length ? bytesToHex(bytes) : "0"));
  let out = "";
  while (n > 0n) { out = B58[Number(n % 58n)] + out; n /= 58n; }
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
  return "1".repeat(zeros) + out;
};
const b58checkDecode = (text) => {
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
const b58checkEncode = (data) => {
  const digest = createHash("sha256").update(createHash("sha256").update(data).digest()).digest();
  return b58encode(Uint8Array.from([...data, ...digest.subarray(0, 4)]));
};

const sha256 = (bytes) => new Uint8Array(createHash("sha256").update(bytes).digest());
const ripemd160 = (bytes) => new Uint8Array(createHash("ripemd160").update(bytes).digest());

// Descriptor checksum: the reference algorithm from Bitcoin Core's
// doc/descriptors.md (NOT the app's implementation).
const INPUT_CHARSET =
  "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`JKLMNOPQRSTUVWXYZ";
const CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const descriptorChecksum = (body) => {
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
const deriveBranchBody = (xpubText, branch) => {
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
const publicKeyForPrivate = (secret) => serPub(pointMul(BigInt("0x" + bytesToHex(secret))));

const deps = { sha256, checksum: descriptorChecksum, base58Decode: b58checkDecode, deriveBranchBody, publicKeyForPrivate };

// --- reference wallets ------------------------------------------------------

// refD descriptors all share one account key (m/44'/1'/0'); its public form:
const publicFormOf = (privateDescriptor) => {
  const body = privateDescriptor
    .slice(0, privateDescriptor.lastIndexOf("#"))
    .replace(/tprv[1-9A-HJ-NP-Za-km-z]{90,}/, REF_ACCOUNT_TPUB);
  return `${body}#${descriptorChecksum(body)}`;
};
const REF_PRIVATE_PUBLIC_FORMS = REF_PRIVATE_DESCRIPTORS.map(publicFormOf);

const SCRIPT_DEFS = [
  { id: "bip44", bip: "BIP44", label: "Legacy", script: "p2pkh" },
  { id: "bip49", bip: "BIP49", label: "Nested SegWit", script: "p2sh-p2wpkh" },
  { id: "bip86", bip: "BIP86", label: "Taproot", script: "p2tr" },
  { id: "bip84", bip: "BIP84", label: "Native SegWit", script: "p2wpkh" },
];
const makeAccounts = (publics, privates) =>
  SCRIPT_DEFS.map((def, i) => ({
    def,
    accountPath: `m/${def.id.slice(3)}'/1'/0'`,
    receiveDescriptor: publics[i * 2],
    changeDescriptor: publics[i * 2 + 1],
    receiveDescriptorPriv: privates[i * 2],
    changeDescriptorPriv: privates[i * 2 + 1],
  }));

const WATCH_ONLY_WALLET = {
  kind: "hd",
  network: "regtest",
  accounts: makeAccounts(REF_PUBLIC_DESCRIPTORS, new Array(8).fill(null)),
};
const PRIVATE_WALLET = {
  kind: "hd",
  network: "regtest",
  accounts: makeAccounts(REF_PRIVATE_PUBLIC_FORMS, REF_PRIVATE_DESCRIPTORS),
};

const asMap = (records) => new Map(records.map(([key, value]) => [key, value]));
const moduleRecords = (wallet, includePrivate) =>
  asMap(
    loadModule()
      .buildWalletRecords(wallet, includePrivate, deps, REF_CREATION_TIME)
      .map(([key, value]) => [bytesToHex(key), bytesToHex(value)]),
  );

const PYTHON_SQLITE = (() => {
  const probe = spawnSync("python3", ["-c", "import sqlite3"], { stdio: "pipe" });
  return probe.status === 0;
})();

// Reads a generated database with the real SQLite library and returns its
// integrity check plus every row of the `main` table.
const sqliteReadBack = (dbBytes) => {
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

// --- tests ------------------------------------------------------------------

test("never generates network traffic", () => {
  for (const source of [sqliteSrc, walletSrc]) {
    assert.doesNotMatch(source, /\bfetch\b|XMLHttpRequest|WebSocket|RTCPeerConnection|sendBeacon|WebTransport/);
  }
});

test("reference implementations agree with the fixture", () => {
  // every fixture descriptor carries the checksum its body must produce
  for (const descriptor of [...REF_PUBLIC_DESCRIPTORS, ...REF_PRIVATE_DESCRIPTORS]) {
    const [body, checksum] = descriptor.split("#");
    assert.equal(descriptorChecksum(body), checksum, `checksum mismatch: ${descriptor.slice(0, 40)}`);
  }
  // account branch-0 cache body as Core wrote it in refB2/refD
  const cache = REF_WATCH_ONLY_RECORDS.find(([key]) => key.startsWith("15" + "77616c6c657464657363726970746f726361636865"));
  const body = deriveBranchBody(REF_ACCOUNT_TPUB, 0);
  assert.equal("4a" + bytesToHex(body), cache[1]);
  // secp256k1 generator sanity
  assert.equal(
    bytesToHex(publicKeyForPrivate(Uint8Array.from([...new Array(31).fill(0), 1]))),
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
  );
});

test("watch-only records are byte-identical to a Bitcoin Core wallet", () => {
  const mine = moduleRecords(WATCH_ONLY_WALLET, false);
  const reference = asMap(REF_WATCH_ONLY_RECORDS);
  assert.equal(mine.size, reference.size);
  for (const [key, value] of reference) {
    assert.ok(mine.has(key), `missing record ${key.slice(0, 60)}`);
    assert.equal(mine.get(key), value, `record value mismatch at ${key.slice(0, 60)}`);
  }
  // no private-key records in a watch-only export
  assert.ok(![...mine.keys()].some((key) => key.includes("77616c6c657464657363726970746f726b6579")));
  // flags = DESCRIPTORS | BLANK | DISABLE_PRIVATE_KEYS
  assert.equal(mine.get("05666c616773"), "0000000007000000");
});

test("private records are byte-identical to a Bitcoin Core wallet", () => {
  const mine = moduleRecords(PRIVATE_WALLET, true);
  const reference = asMap(REF_PRIVATE_RECORDS);
  assert.equal(mine.size, reference.size);
  for (const [key, value] of reference) {
    assert.ok(mine.has(key), `missing record ${key.slice(0, 60)}`);
    assert.equal(mine.get(key), value, `record value mismatch at ${key.slice(0, 60)}`);
  }
  // 8 descriptorkey records, one per descriptor; flags = DESCRIPTORS | BLANK
  const keyRecords = [...mine.keys()].filter((key) => key.includes("77616c6c657464657363726970746f726b6579"));
  assert.equal(keyRecords.length, 8);
  assert.equal(mine.get("05666c616773"), "0000000006000000");
});

test("accounts without private material stay watch-only in a private export", () => {
  const watchOnly = moduleRecords(WATCH_ONLY_WALLET, false);
  const fallback = moduleRecords(WATCH_ONLY_WALLET, true);
  assert.deepEqual([...fallback.keys()].sort(), [...watchOnly.keys()].sort());
  for (const key of watchOnly.keys()) assert.equal(fallback.get(key), watchOnly.get(key));
});

test("generated watch-only wallet.dat verifies with real SQLite", { skip: !PYTHON_SQLITE }, () => {
  const { buildWalletDat } = loadModule();
  const bytes = buildWalletDat(WATCH_ONLY_WALLET, false, deps, REF_CREATION_TIME);
  assert.equal(new TextDecoder().decode(bytes.subarray(0, 15)), "SQLite format 3");
  const report = sqliteReadBack(bytes);
  assert.equal(report.integrity, "ok");
  assert.equal(report.app_id, 0xfabfb5da); // regtest magic
  assert.equal(report.user_version, 0);
  assert.deepEqual(asMap(report.rows), asMap(REF_WATCH_ONLY_RECORDS));
});

test("generated private wallet.dat verifies with real SQLite", { skip: !PYTHON_SQLITE }, () => {
  const { buildWalletDat } = loadModule();
  const bytes = buildWalletDat(PRIVATE_WALLET, true, deps, REF_CREATION_TIME);
  const report = sqliteReadBack(bytes);
  assert.equal(report.integrity, "ok");
  assert.deepEqual(asMap(report.rows), asMap(REF_PRIVATE_RECORDS));
});

test("network selects the application id and best-block locator", () => {
  const { buildWalletRecords, buildWalletDat } = loadModule();
  const mainnetWallet = { ...WATCH_ONLY_WALLET, network: "mainnet" };
  const bytes = buildWalletDat(mainnetWallet, false, deps, REF_CREATION_TIME);
  assert.equal(bytesToHex(bytes.subarray(68, 72)), "f9beb4d9"); // mainnet magic
  const records = moduleRecords(mainnetWallet, false);
  const bestblockKey = "12" + "62657374626c6f636b5f6e6f6d65726b6c65"; // "bestblock_nomerkle"
  const mainnetGenesis = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
  const reversed = bytesToHex(hexToBytes(mainnetGenesis).reverse());
  assert.ok(records.get(bestblockKey).endsWith(reversed), "bestblock locator should name the mainnet genesis block");
  assert.throws(() => buildWalletRecords({ ...WATCH_ONLY_WALLET, network: "signet" }, false, deps, REF_CREATION_TIME), /unknown network/);
});

test("button gating: only HD wallets with descriptors", () => {
  const { hasDescriptors } = loadModule();
  assert.equal(hasDescriptors(null), false);
  assert.equal(hasDescriptors({}), false);
  assert.equal(hasDescriptors({ kind: "single", wifCompressed: "L..." }), false);
  assert.equal(hasDescriptors({ kind: "msig", receiveDescriptor: "wsh(...)#x", changeDescriptor: "wsh(...)#y" }), false);
  assert.equal(hasDescriptors({ kind: "hd", accounts: [] }), false);
  assert.equal(hasDescriptors(WATCH_ONLY_WALLET), true);
});

test("filename announces the wallet fingerprint and watch-only vs secrets", () => {
  const { walletDatFilename } = loadModule();
  const wallet = { masterFingerprint: "73C5DA0A" };
  // Unique, identifiable files: the master XFP names the wallet (issue #77).
  assert.equal(walletDatFilename(wallet, false), "entropylab-73c5da0a-watch-only-wallet.dat");
  assert.equal(walletDatFilename(wallet, true), "entropylab-73c5da0a-private-wallet-secrets.dat");
  assert.equal(walletDatFilename(wallet), "entropylab-73c5da0a-watch-only-wallet.dat");
  // Without a usable fingerprint the names fall back to the plain forms.
  assert.equal(walletDatFilename(null, false), "watch-only-wallet.dat");
  assert.equal(walletDatFilename({ masterFingerprint: "not-an-xfp" }, true), "private-wallet-secrets.dat");
  assert.equal(walletDatFilename(), "watch-only-wallet.dat");
});

test("button label follows the reveal state", () => {
  const { walletDatButtonLabel } = loadModule();
  assert.equal(walletDatButtonLabel(false), "Download watch-only wallet.dat");
  const shown = walletDatButtonLabel(true);
  assert.match(shown, /secrets/i);
  assert.match(shown, /xprv/i);
  assert.match(shown, /\.dat/);
});

test("template, build script, and app wiring ship the export", () => {
  const template = read("src/index.html");
  const build = read("scripts/build.mjs");
  const css = read("src/css/styles.css");
  assert.match(template, /\/\*@@JS_WALLET_EXPORT@@\*\//);
  assert.match(build, /wallet-export\.js/);
  assert.match(build, /JS_WALLET_EXPORT/);
  // The button renders next to #save in the wallet-data-actions row, and its
  // label is driven by the reveal flag (Ge) at render time.
  assert.match(app, /id="save"[^>]*>\$\{downloadLabel\}<\/button>\s*\$\{hodlWalletDatControl\(privateSheet\)\}/);
  assert.match(app, /hodlSaveRecoveryControl\s*\(\s*\)\s*\{\s*return\s*`<div class="wallet-data-actions no-print">[^`]*\$\{hodlWalletDatControl\(\s*(?:false|!1)\s*\)\}/);
  assert.match(app, /id="download-wallet-dat"[^>]*>\$\{hodlWalletExport\.walletDatButtonLabel\(includePrivate\)\}/);
  assert.match(app, /hodlWalletExport\.hasDescriptors\(hodlWalletResult\)/);
  assert.match(app, /hodlWalletExport\.buildWalletDat\(\s*hodlWalletResult\s*,\s*hodlRevealPrivate\s*,\s*hodlWalletDatDeps\(\s*\)\s*,\s*creationTime\s*\)/);
  assert.match(app, /hodlWalletExport\.walletDatFilename\(hodlWalletResult, hodlRevealPrivate\)/);
  assert.match(app, /document\.getElementById\("download-wallet-dat"\)/);
  assert.match(css, /\.save-wallet-dat/);
});

// --- UI wiring: the real app.js controls rendered against stubbed globals ---

const extract = (startNeedle, endNeedle) => {
  const start = app.indexOf(startNeedle);
  const end = app.indexOf(endNeedle, start);
  if (start < 0 || end < 0) throw new Error(`extract failed: ${startNeedle}`);
  return app.slice(start, end);
};

// Stand-in for the vendor HDKey shape hodlWalletDatDeps() reads, backed by
// the reference CKDpub above.
const hdNodeFrom = (raw) => ({
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

// The UI harness executes the real app.js controls and download handler in a
// module scope where the vendor globals they read (tr, Cs, sr, le, Gt, xe,
// cr) are backed by the reference implementations above.
const harnessSource = `
import { createHash, createHmac } from "node:crypto";
const FIELD_P = ${FIELD_P.toString()}n;
const ORDER_N = ${ORDER_N.toString()}n;
const BASE_G = [${BASE_G[0].toString()}n, ${BASE_G[1].toString()}n];
const B58 = ${JSON.stringify(B58)};
const INPUT_CHARSET = ${JSON.stringify(INPUT_CHARSET)};
const CHECKSUM_CHARSET = ${JSON.stringify(CHECKSUM_CHARSET)};
${[modPow, pointAdd, pointMul, serPub, unserPub, bigintBytes, b58encode, b58checkDecode, b58checkEncode, sha256, ripemd160, bytesToHex, descriptorChecksum, deriveBranchBody, publicKeyForPrivate, hdNodeFrom].map((fn) => `const ${fn.name} = ${fn.toString()};`).join("\n")}
const captured = { blob: null, name: "" };
const elements = new Map();
const URL = {
  createObjectURL: (blob) => { captured.blob = blob; return "blob:mock"; },
  revokeObjectURL: () => {},
};
class Blob {
  constructor(parts, options) { this.parts = parts; this.type = options?.type ?? ""; }
}
const document = {
  createElement: () => ({ click() { captured.name = this.download; } }),
  getElementById: (id) => elements.get(id) ?? null,
  querySelectorAll: (selector) => [...elements.values()].filter((element) => element.matches?.(selector)),
};
let hodlWalletResult = null, hodlRevealPrivate = false, hodlWalletDatBirthday = "genesis";
const hodlSha256 = (bytes) => sha256(bytes);
const hodlDescriptorChecksum = descriptorChecksum;
const hodlBase58Check = { decode: b58checkDecode };
const hodlReversionExtendedKey = (text, version) => {
  const raw = b58checkDecode(text).slice();
  raw[0] = (version >>> 24) & 255; raw[1] = (version >>> 16) & 255; raw[2] = (version >>> 8) & 255; raw[3] = version & 255;
  return b58checkEncode(raw);
};
const hodlExtendedKeyVersions = { mainnet: { x: { pub: 0x0488b21e } } };
const hodlHDKey = { fromExtendedKey: (text) => hdNodeFrom(b58checkDecode(text)) };
const hodlSecp256k1 = { getPublicKey: (secret) => publicKeyForPrivate(secret) };
function hodlBindAddressMatch(){}
${extract("function hodlPrivateDataControls", "function hodlWalletMessages")}
${extract("function hodlWalletDatDeps", "function hodlFocusWalletResult")}
${sqliteSrc}
${walletSrc}
const setResult = (value, flag) => { hodlWalletResult = value; hodlRevealPrivate = flag; };
const setWalletDatBirthday = (value) => { hodlWalletDatBirthday = value; };
export { captured, elements, hodlPrivateDataControls, hodlSaveRecoveryControl, hodlDownloadWalletDat, hodlBindWalletResultActions, setResult, setWalletDatBirthday };
`;

// Keep the transient harness out of test/ so parallel suites that list the
// directory (e.g. the parse check) never see it.
const harnessDir = mkdtempSync(join(tmpdir(), "entropylab-harness-"));
const harnessPath = join(harnessDir, "wallet-export-harness.mjs");
writeFileSync(harnessPath, harnessSource);
const ui = await import(pathToFileURL(harnessPath).href);
rmSync(harnessDir, { recursive: true });

test("controls render the wallet.dat button next to #save only when descriptors exist", () => {
  ui.setResult(WATCH_ONLY_WALLET, false);
  const watchHtml = ui.hodlPrivateDataControls("wallet-private-description");
  assert.match(watchHtml, /id="save"/);
  assert.match(watchHtml, /id="download-wallet-dat"[^>]*>Download watch-only wallet\.dat<\/button>/);

  ui.setResult(WATCH_ONLY_WALLET, true);
  const privateHtml = ui.hodlPrivateDataControls("wallet-private-description");
  assert.match(privateHtml, /id="download-wallet-dat"[^>]*>Download wallet\.dat with secrets \(xprvs\)<\/button>/);

  ui.setResult({ kind: "single", wifCompressed: "L..." }, false);
  assert.doesNotMatch(ui.hodlPrivateDataControls("single-private-description", "single"), /download-wallet-dat/);

  ui.setResult(WATCH_ONLY_WALLET, false);
  assert.match(ui.hodlSaveRecoveryControl(), /id="download-wallet-dat"[^>]*>Download watch-only wallet\.dat<\/button>/);
});

test("download handler emits a real wallet.dat through the app code path", { skip: !PYTHON_SQLITE }, () => {
  ui.setResult(PRIVATE_WALLET, true);
  ui.hodlDownloadWalletDat();
  assert.equal(ui.captured.name, "private-wallet-secrets.dat");
  assert.equal(ui.captured.blob.type, "application/octet-stream");
  const bytes = new Uint8Array(ui.captured.blob.parts[0]);
  assert.equal(new TextDecoder().decode(bytes.subarray(0, 15)), "SQLite format 3");
  const report = sqliteReadBack(bytes);
  assert.equal(report.integrity, "ok");
  // the only nondeterminism is creation_time; read it back and rebuild
  const descriptorRow = report.rows.find(([key]) => key.startsWith("10" + "77616c6c657464657363726970746f72"));
  const value = Buffer.from(descriptorRow[1], "hex");
  const creationTime = Number(value.readBigUInt64LE(1 + value[0]));
  const expected = asMap(
    loadModule()
      .buildWalletRecords(PRIVATE_WALLET, true, deps, creationTime)
      .map(([key, val]) => [bytesToHex(key), bytesToHex(val)]),
  );
  assert.deepEqual(asMap(report.rows), expected);
});

// Issue #95: a recovered wallet exported with the export time as its
// descriptor birthday is not rescanned back to its real history by Bitcoin
// Core. The download defaults to a genesis birthday (creation time 0) so
// recovery discovers older transactions; "now" is written only on request.
const readBackCreationTime = (bytes) => {
  const report = sqliteReadBack(bytes);
  const descriptorRow = report.rows.find(([key]) => key.startsWith("10" + "77616c6c657464657363726970746f72"));
  const value = Buffer.from(descriptorRow[1], "hex");
  return Number(value.readBigUInt64LE(1 + value[0]));
};

test("wallet.dat download defaults to a genesis birthday for recovery", { skip: !PYTHON_SQLITE }, () => {
  ui.setResult(WATCH_ONLY_WALLET, false);
  ui.setWalletDatBirthday("genesis");
  ui.hodlDownloadWalletDat();
  assert.equal(readBackCreationTime(new Uint8Array(ui.captured.blob.parts[0])), 0);
});

test("wallet.dat download writes the current time only for keys confirmed new", { skip: !PYTHON_SQLITE }, () => {
  ui.setResult(PRIVATE_WALLET, true);
  ui.setWalletDatBirthday("now");
  const before = Math.floor(Date.now() / 1000) - 1;
  ui.hodlDownloadWalletDat();
  const after = Math.floor(Date.now() / 1000) + 1;
  const creationTime = readBackCreationTime(new Uint8Array(ui.captured.blob.parts[0]));
  assert.ok(creationTime >= before && creationTime <= after, `creation time ${creationTime} is not the export time`);
  ui.setWalletDatBirthday("genesis");
});

test("the wallet.dat control offers the birthday choice with genesis as the safe default", () => {
  ui.setResult(WATCH_ONLY_WALLET, false);
  const html = ui.hodlSaveRecoveryControl();
  assert.match(html, /data-wallet-dat-birthday/);
  assert.match(html, /<option value="genesis" selected>Recovering keys/);
  assert.match(html, /<option value="now">New keys/);
  // The tradeoff and the manual repair path are explained next to the button.
  assert.match(html, /wallet-dat-birthday-help/);
  assert.match(html, /rescanblockchain 0/);
  // The app reset keeps a stale "new keys" choice out of later derivations.
  assert.match(app, /function hodlCalculateKey\(progress\) \{\s*hodlSetWorkspaceError\("key", null\);\s*\n?[^}]*hodlWalletDatBirthday = "genesis";/);
  assert.match(app, /hodlWalletDatBirthday === "now" \? Math\.floor\(Date\.now\(\) \/ 1000\) : 0/);
});

test("binding attaches the download to #download-wallet-dat and tolerates missing elements", () => {
  ui.setResult(WATCH_ONLY_WALLET, false);
  assert.doesNotThrow(() => ui.hodlBindWalletResultActions());

  const button = {
    id: "download-wallet-dat",
    listeners: {},
    cloneNode() { return { ...this, id: this.id, listeners: {} }; },
    replaceWith(node) { ui.elements.set(node.id, node); },
    addEventListener(type, fn) { this.listeners[type] = fn; },
    click() { this.listeners.click?.(); },
  };
  ui.elements.set("download-wallet-dat", button);
  ui.hodlBindWalletResultActions();
  ui.captured.name = "";
  ui.elements.get("download-wallet-dat").click();
  assert.equal(ui.captured.name, "watch-only-wallet.dat");
  ui.elements.clear();
});
