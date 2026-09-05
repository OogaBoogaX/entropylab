// Seeded fuzzing of the wallet.dat export (src/js/wallet-export.js).
//
// Where wallet-export.test.mjs pins fixed Bitcoin Core ground-truth fixtures,
// this suite sweeps the input space: a deterministic PRNG generates wallets
// across networks, script types, origin shapes, SLIP-132 version prefixes,
// xpub tails (including the <digit>h corruption class), checksum presence,
// birthdays, and private/watch-only mixes. Every generated wallet is verified
// against independent reference code — nothing below calls into the module's
// own encoding to check itself:
//
//   - the record stream is decoded byte-by-byte with a separate parser and
//     must contain exactly the expected rows, no more;
//   - every descriptor record key equals the DescriptorID Bitcoin Core
//     recomputes at load (SHA-256 over the compat form + checksum) — this is
//     the check LoadDescriptorWalletRecords enforces, so matching it is what
//     "the wallet loads" means;
//   - the stored descriptor string is byte-identical to the generator's
//     input, key material untouched;
//   - descriptor cache bodies equal an independent BIP32 CKDpub derivation;
//   - private key records carry a Core-form DER key whose secret, public key,
//     and key hash all agree;
//   - the whole build is byte-for-byte deterministic;
//   - and a slice of the corpus is opened with the real SQLite C library
//     (python3): integrity_check must pass and the rows must round-trip.
//
// The seed below is fixed, so a failure reproduces exactly; the iteration
// number in each assertion message identifies the failing wallet.
//
// Run with `npm run test:wallet-export-fuzz` or `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  PYTHON_SQLITE,
  asMap,
  b58checkDecode,
  b58checkEncode,
  bytesToHex,
  deps,
  deriveBranchBody,
  descriptorChecksum,
  hdDeriveHardened,
  hdMasterFromSeed,
  hexToBytes,
  loadModule,
  publicKeyForPrivate,
  serializeExtendedKey,
  sha256,
  sqliteReadBack,
} from "./wallet-export-harness.mjs";

// --- deterministic randomness ------------------------------------------------

// Fixed seed: the corpus below is a fixed set of test vectors that happens to
// be machine-generated. Never reseed from the clock — a red run must be
// reproducible byte-for-byte.
const FUZZ_SEED = 0x5eed0001;
const mulberry32 = (seed) => {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
};
const rand = mulberry32(FUZZ_SEED);
const rint = (n) => Math.floor(rand() * n);
const pick = (items) => items[rint(items.length)];
const chance = (p) => rand() < p;

// --- account key material ----------------------------------------------------

// Extended key version bytes (BIP32 + SLIP-132), mainnet and testnet families.
const KEY_VERSIONS = {
  mainnet: { pub: { x: 0x0488b21e, y: 0x049d7cb2, z: 0x04b24746 }, prv: { x: 0x0488ade4, y: 0x049d7878, z: 0x04b2430c } },
  test: { pub: { t: 0x043587cf, u: 0x044a5262, v: 0x045f1cf6 }, prv: { t: 0x04358394, u: 0x044a4e28, v: 0x045f18bc } },
};
const TYPE_ORDER = ["bip44", "bip49", "bip84", "bip86"];
const PURPOSE = { bip44: 44, bip49: 49, bip84: 84, bip86: 86 };
// OutputType (Bitcoin Core wallet.h): pkh=0, sh(wpkh)=1, wpkh=2, tr=3.
const OUTPUT_TYPES = { bip44: 0, bip49: 1, bip84: 2, bip86: 3 };
const WRAP = {
  bip44: (inner) => `pkh(${inner})`,
  bip49: (inner) => `sh(wpkh(${inner}))`,
  bip84: (inner) => `wpkh(${inner})`,
  bip86: (inner) => `tr(${inner})`,
};
const DEFAULT_LETTER = { bip44: "x", bip49: "y", bip84: "z", bip86: "x" };

// One BIP32 account node per purpose per coin type, derived from pinned
// seeds. Elliptic-curve work is memoized downstream, so these eight nodes
// cost one derivation each no matter how many wallets reference them.
const accountNode = (purpose, coin, account) => {
  const seed = sha256(new TextEncoder().encode(`entropylab-fuzz-pool-${purpose}-${coin}-${account}`));
  let node = hdMasterFromSeed(seed);
  for (const step of [purpose, coin, account]) node = hdDeriveHardened(node, step);
  return node;
};
const POOL = Object.fromEntries(
  [0, 1].map((coin) => [
    coin,
    Object.fromEntries(TYPE_ORDER.map((type, i) => [PURPOSE[type], { node: accountNode(PURPOSE[type], coin, 3 * i + 1), account: 3 * i + 1 }])),
  ]),
);

// Real m/84'/0'/0' account xpubs ending in <digit>h — the corruption class of
// the body-wide h->' rewrite (see wallet-export.test.mjs). The third key is
// machine-found: the pinned seed below is the first of a pinned scan whose
// serialized xpub ends in <digit>h, proving the class beyond fixed vectors.
const XPUB_TAIL_4H = "xpub6DGDSTSv42ve3BBRALC4UVi3LdaoQjA9R2yV9RSDojTRKQTK5Jk73WKqm6v392eeF3Lxawf8gHiBpD5xBDx7HYvbkLoZ6e1Emu9fvW2M24h";
const XPUB_TAIL_2H = "xpub6ChZ8GTJVLpepi3oLPQUHRx6H7RkwQ6bsoqvSfwTw5jZuRithtrc75Tfq7H3sa8bXkA9d35K3CdJDY5B2aTFmdFEp19AGWT7XTXDVFvCn2h";
const SCANNED_TAIL_KEY = (() => {
  const seed = sha256(new TextEncoder().encode("entropylab-fuzz-digit-h-142"));
  let node = hdMasterFromSeed(seed);
  for (const step of [84, 0, 0]) node = hdDeriveHardened(node, step);
  const xpub = serializeExtendedKey(node, KEY_VERSIONS.mainnet.pub.x, false);
  assert.match(xpub, /[0-9]h$/, "pinned scan seed no longer yields a <digit>h xpub tail");
  return xpub;
})();

// Serialized extended keys per (node, letter, privacy), memoized: the
// expensive part is the public key, and this keeps the corpus cheap.
const serialized = new Map();
const extendedKey = (node, network, letter, isPrivate) => {
  const family = network === "mainnet" ? "mainnet" : "test";
  const cacheKey = `${family}:${letter}:${isPrivate}:${bytesToHex(node.secret)}`;
  if (!serialized.has(cacheKey)) {
    serialized.set(cacheKey, serializeExtendedKey(node, KEY_VERSIONS[family][isPrivate ? "prv" : "pub"][letter], isPrivate));
  }
  return serialized.get(cacheKey);
};

// Re-encode a key with randomized depth/parent/child header bytes: a cheap
// source of distinct base58 tails (the key material is untouched, and every
// consumer below only reads header + key material, exactly like Core).
const mutateKeyHeader = (text) => {
  const raw = b58checkDecode(text).slice();
  for (const offset of [4, 5, 9]) raw[offset + rint(4)] = rint(256);
  return b58checkEncode(raw);
};

// deps for the module under test: the harness reference implementations with
// the elliptic-curve operations memoized (behavior-neutral, shared by the
// verifier below so both sides compute each branch body exactly once).
const memoize = (fn, keyFn) => {
  const cache = new Map();
  return (...args) => {
    const key = keyFn(...args);
    if (!cache.has(key)) cache.set(key, fn(...args));
    return cache.get(key);
  };
};
const fuzzDeps = {
  ...deps,
  deriveBranchBody: memoize(deriveBranchBody, (xpub, branch) => `${xpub}:${branch}`),
  publicKeyForPrivate: memoize(publicKeyForPrivate, (secret) => bytesToHex(secret)),
};

// --- independent verification ------------------------------------------------

// Compat form, reimplemented as a character scan (the module uses a single
// regex): inside each [fingerprint/path] origin, rewrite every hardened step
// marker h to '. Anything else in the body is copied verbatim.
const referenceCompatForm = (body) => {
  let out = "";
  let cursor = 0;
  while (cursor < body.length) {
    const open = body.indexOf("[", cursor);
    if (open < 0) return out + body.slice(cursor);
    const close = body.indexOf("]", open);
    if (close < 0) return out + body.slice(cursor);
    const [fingerprint, ...steps] = body.slice(open + 1, close).split("/");
    out += body.slice(cursor, open) + "[" + fingerprint;
    for (const step of steps) out += "/" + (step.endsWith("h") ? step.slice(0, -1) + "'" : step);
    out += "]";
    cursor = close + 1;
  }
  return out;
};

const utf8 = (text) => new TextEncoder().encode(text);
const referenceDescriptorId = (stored) => {
  const hash = stored.lastIndexOf("#");
  const body = hash >= 0 ? stored.slice(0, hash) : stored;
  const compat = referenceCompatForm(body);
  return bytesToHex(sha256(utf8(`${compat}#${descriptorChecksum(compat)}`)));
};

// The cache body Core derives for a descriptor: the parent of the wildcard,
// taken from the descriptor TEXT — the branch child for "…xpub/b/*", or the
// root key itself for "…xpubBranch/*" (the hardened-branch layout). The branch
// slot the wallet assigns the descriptor to is irrelevant: Core's
// BIP32PubkeyProvider reads the path from the descriptor string.
const referenceCacheBody = (descriptor, xpub) => {
  const body = descriptor.replace(/#[a-z0-9]*$/, "");
  const tail = body.slice(body.indexOf(xpub) + xpub.length).replace(/\)+$/, "");
  if (tail === "/*") return b58checkDecode(xpub).slice(4);
  const branch = tail.match(/^\/(\d+)\/\*$/);
  assert.ok(branch, `corpus descriptor tail must be /b/* or /*: ${descriptor}`);
  return fuzzDeps.deriveBranchBody(xpub, Number(branch[1]));
};

// Bitcoin CompactSize decoding, written against the Core documentation (the
// module encodes; this suite only ever decodes).
const readCompactSize = (bytes, offset) => {
  const first = bytes[offset];
  if (first < 253) return [first, offset + 1];
  if (first === 253) return [bytes[offset + 1] | (bytes[offset + 2] << 8), offset + 3];
  if (first === 254) return [(bytes[offset + 1] | (bytes[offset + 2] << 8) | (bytes[offset + 3] << 16) | (bytes[offset + 4] << 24)) >>> 0, offset + 5];
  let value = 0n;
  for (let i = 0; i < 8; i++) value |= BigInt(bytes[offset + 1 + i]) << BigInt(8 * i);
  return [Number(value), offset + 9];
};
const decodeRecord = ([keyHex, valueHex]) => {
  const key = hexToBytes(keyHex);
  const [nameLength, offset] = readCompactSize(key, 0);
  return {
    name: new TextDecoder().decode(key.slice(offset, offset + nameLength)),
    keyPayload: key.slice(offset + nameLength),
    value: hexToBytes(valueHex),
  };
};
const u32leAt = (bytes, offset) =>
  (bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24)) >>> 0;
const u64leAt = (bytes, offset) => {
  let value = 0n;
  for (let i = 0; i < 8; i++) value |= BigInt(bytes[offset + i]) << BigInt(8 * i);
  return Number(value);
};
const XPUB_PATTERN = /((?:xpub|tpub|ypub|upub|zpub|vpub)[1-9A-HJ-NP-Za-km-z]{90,})/;

// Descriptor address ranges, from the module contract: the rows shown for a
// branch (addressBranches wins over the legacy receive/change arrays), invalid
// indexes ignored, range covering the displayed indexes plus Core's 1000-key
// lookahead, clamped to the BIP32 index space.
const RANGE_GAP = 1000;
const MAX_ADDRESS_INDEX = 0x7fffffff;
const expectedRanges = (account, branch) => {
  const branchRows = account.addressBranches?.find((entry) => entry.branch === branch)?.rows;
  const rows = Array.isArray(branchRows) ? branchRows : branch === 0 ? account.receive : account.change;
  const indexes = Array.isArray(rows)
    ? rows.map((row) => row?.index).filter((index) => Number.isSafeInteger(index) && index >= 0 && index <= MAX_ADDRESS_INDEX)
    : [];
  const low = indexes.length ? Math.min(...indexes) : 0;
  const high = indexes.length ? Math.max(...indexes) : 0;
  return {
    nextIndex: indexes.length ? Math.min(MAX_ADDRESS_INDEX, high + 1) : 0,
    rangeStart: low,
    rangeEnd: indexes.length ? Math.min(MAX_ADDRESS_INDEX, high + RANGE_GAP) : RANGE_GAP,
  };
};

// The expected export units of a wallet, mirroring the documented module
// contract (which accounts are skipped) rather than the module's code.
const expectedUnits = (wallet, includePrivate) => {
  const units = [];
  if (!wallet || wallet.kind !== "hd" || !Array.isArray(wallet.accounts)) return units;
  for (const account of wallet.accounts) {
    const type = OUTPUT_TYPES[account.def?.id];
    if (type === undefined) continue;
    for (const branch of [0, 1]) {
      const descriptor = branch === 0 ? account?.receiveDescriptor : account?.changeDescriptor;
      // Per-branch coverage (issue #366): a wallet may have derived only one
      // branch; whichever branches exist are exported.
      if (!descriptor) continue;
      const privateDescriptor = branch === 0 ? account.receiveDescriptorPriv : account.changeDescriptorPriv;
      units.push({
        type,
        internal: branch === 1,
        descriptor,
        privateDescriptor: includePrivate ? privateDescriptor ?? null : null,
        xpub: descriptor.match(XPUB_PATTERN)?.[1],
        xprv: includePrivate && privateDescriptor ? privateDescriptor.match(/((?:xprv|tprv|yprv|uprv|zprv|vprv)[1-9A-HJ-NP-Za-km-z]{90,})/)?.[1] : null,
        ...expectedRanges(account, branch),
      });
    }
  }
  return units;
};

const GENESIS = {
  mainnet: "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
  testnet: "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943",
  signet: "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6",
  regtest: "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
};
const APPLICATION_ID = { mainnet: 0xf9beb4d9, testnet: 0x0b110907, signet: 0x0a03cf40, regtest: 0xfabfb5da };

// Verify every byte of one wallet's record set against the reference code.
const verifyWalletRecords = (label, wallet, includePrivate, creationTime) => {
  const units = expectedUnits(wallet, includePrivate);
  assert.ok(units.length > 0, `${label}: corpus wallet must export at least one descriptor`);
  const module_ = loadModule();
  const first = module_.buildWalletRecords(wallet, includePrivate, fuzzDeps, creationTime);
  const second = loadModule().buildWalletRecords(wallet, includePrivate, fuzzDeps, creationTime);
  assert.deepEqual(
    second.map(([k, v]) => [bytesToHex(k), bytesToHex(v)]),
    first.map(([k, v]) => [bytesToHex(k), bytesToHex(v)]),
    `${label}: the build is deterministic`,
  );
  const rows = asMap(first.map(([key, value]) => [bytesToHex(key), bytesToHex(value)]));
  const records = [...first.map(([key, value]) => [bytesToHex(key), bytesToHex(value)])].map(decodeRecord);
  const singles = new Map();
  for (const record of records) {
    const key = `${record.name}:${bytesToHex(record.keyPayload)}`;
    assert.ok(!singles.has(key), `${label}: duplicate record ${record.name}`);
    singles.set(key, record);
  }

  // Global records.
  const expectSingle = (name, check) => {
    const matches = records.filter((record) => record.name === name);
    assert.equal(matches.length, 1, `${label}: exactly one ${name} record`);
    check(matches[0]);
  };
  expectSingle("version", (record) => {
    assert.equal(record.keyPayload.length, 0);
    assert.equal(u32leAt(record.value, 0), 280300, `${label}: client version`);
  });
  expectSingle("minversion", (record) => assert.equal(u32leAt(record.value, 0), 169900, `${label}: minversion`));
  expectSingle("flags", (record) => {
    const flags = BigInt(u64leAt(record.value, 0));
    const expectPrivate = includePrivate && units.some((unit) => unit.privateDescriptor);
    const expected = (1n << 34n) | (1n << 33n) | (expectPrivate ? 0n : 1n << 32n);
    assert.equal(flags, expected, `${label}: wallet flags`);
  });
  expectSingle("bestblock", (record) => {
    assert.equal(u32leAt(record.value, 0), 70016, `${label}: locator version`);
    assert.equal(record.value.length, 5, `${label}: empty best-block locator`);
  });
  expectSingle("bestblock_nomerkle", (record) => {
    assert.equal(u32leAt(record.value, 0), 70016);
    const [count, offset] = readCompactSize(record.value, 4);
    assert.equal(count, 1, `${label}: one genesis hash in the locator`);
    assert.equal(bytesToHex(record.value.slice(offset, offset + 32)), bytesToHex(hexToBytes(GENESIS[wallet.network]).reverse()), `${label}: genesis block`);
  });

  // Descriptor records.
  for (const unit of units) {
    const at = `${label} ${unit.descriptor.slice(0, 24)}…/${unit.internal ? 1 : 0}`;
    // The exact check Bitcoin Core runs at load: the record key must be the
    // DescriptorID of the compat form of the stored descriptor.
    const id = referenceDescriptorId(unit.descriptor);
    const descriptorRecord = singles.get(`walletdescriptor:${id}`);
    assert.ok(descriptorRecord, `${at}: walletdescriptor keyed by Core's DescriptorID`);
    const [textLength, textOffset] = readCompactSize(descriptorRecord.value, 0);
    const stored = new TextDecoder().decode(descriptorRecord.value.slice(textOffset, textOffset + textLength));
    assert.equal(stored, unit.descriptor, `${at}: stored descriptor is byte-identical to the input`);
    assert.ok(stored.includes(unit.xpub), `${at}: stored descriptor keeps the xpub verbatim`);
    assert.ok(!stored.includes("'"), `${at}: no apostrophe leaked into the stored descriptor`);
    let cursor = textOffset + textLength;
    assert.equal(u64leAt(descriptorRecord.value, cursor), creationTime, `${at}: creation time`);
    cursor += 8;
    assert.equal(u32leAt(descriptorRecord.value, cursor), unit.nextIndex, `${at}: next_index`);
    assert.equal(u32leAt(descriptorRecord.value, cursor + 4), unit.rangeStart, `${at}: range_start`);
    assert.equal(u32leAt(descriptorRecord.value, cursor + 8), unit.rangeEnd, `${at}: range_end`);
    assert.equal(descriptorRecord.value.length, cursor + 12, `${at}: descriptor value length`);

    const cache = singles.get(`walletdescriptorcache:${id}${"00000000"}`);
    assert.ok(cache, `${at}: cache record for position 0`);
    const [bodyLength, bodyOffset] = readCompactSize(cache.value, 0);
    assert.equal(bodyLength, 74, `${at}: cache body length`);
    assert.equal(
      bytesToHex(cache.value.slice(bodyOffset, bodyOffset + 74)),
      bytesToHex(referenceCacheBody(unit.descriptor, unit.xpub)),
      `${at}: cache body is the independently derived parent of the descriptor's wildcard`,
    );
    assert.equal(cache.value.length, bodyOffset + 74, `${at}: cache value length`);

    const keyRecord = [...singles.values()].find(
      (record) => record.name === "walletdescriptorkey" && bytesToHex(record.keyPayload.slice(0, 32)) === id,
    );
    if (unit.privateDescriptor) {
      assert.ok(keyRecord, `${at}: private key record present`);
      const [pubLength, pubOffset] = readCompactSize(keyRecord.keyPayload, 32);
      assert.equal(pubLength, 33, `${at}: record key carries a compressed pubkey`);
      const raw = b58checkDecode(unit.xprv);
      const secret = raw.slice(46, 78);
      const pubkey = keyRecord.keyPayload.slice(pubOffset, pubOffset + 33);
      assert.equal(bytesToHex(pubkey), bytesToHex(fuzzDeps.publicKeyForPrivate(secret)), `${at}: pubkey matches the xprv secret`);
      const [derLength, derOffset] = readCompactSize(keyRecord.value, 0);
      assert.equal(derLength, 214, `${at}: Core DER private key length`);
      const der = keyRecord.value.slice(derOffset, derOffset + 214);
      assert.equal(bytesToHex(der.slice(0, 3)), "3081d3", `${at}: DER sequence header`);
      assert.equal(bytesToHex(der.slice(8, 40)), bytesToHex(secret), `${at}: DER carries the xprv secret`);
      assert.equal(bytesToHex(der.slice(176)), bytesToHex(Uint8Array.from([0xa1, 0x24, 0x03, 0x22, 0x00, ...pubkey])), `${at}: DER pubkey trailer`);
      assert.equal(
        bytesToHex(keyRecord.value.slice(derOffset + 214)),
        bytesToHex(sha256(sha256(Uint8Array.from([...pubkey, ...der])))),
        `${at}: key hash`,
      );
    } else {
      assert.ok(!keyRecord, `${at}: no private key record for a watch-only descriptor`);
    }

    const active = singles.get(`${unit.internal ? "activeinternalspk" : "activeexternalspk"}:${unit.type.toString(16).padStart(2, "0")}`);
    assert.ok(active, `${at}: active spk record`);
    assert.equal(bytesToHex(active.value), id, `${at}: active spk points at the DescriptorID`);
  }

  // Exactly the expected rows, no more.
  const expectedCount = 5 + units.length * 3 + units.filter((unit) => unit.privateDescriptor).length;
  assert.equal(records.length, expectedCount, `${label}: record count`);
  return rows;
};

// --- corpus generation --------------------------------------------------------

const flavors = new Map();
const note = (flavor) => flavors.set(flavor, (flavors.get(flavor) ?? 0) + 1);

const randomFingerprint = () => bytesToHex(Uint8Array.from({ length: 4 }, () => rint(256)));
const randomOrigin = (type, coin, account) => {
  const style = pick(["standard", "standard", "standard", "uppercase", "mixed", "single", "bare", "none", "deep"]);
  const fingerprint = randomFingerprint();
  const purpose = PURPOSE[type];
  // A 60-step origin pushes the stored descriptor past 252 bytes, exercising
  // the multi-byte CompactSize encoding of the descriptor record.
  if (style === "deep") return [`[${fingerprint}/${Array.from({ length: 60 }, () => `${rint(10)}h`).join("/")}/${purpose}h]`, style];
  if (style === "none") return ["", style];
  if (style === "bare") return [`[${fingerprint}]`, style];
  if (style === "single") return [`[${fingerprint}/${purpose}h]`, style];
  if (style === "mixed") return [`[${fingerprint}/${purpose}h/${coin}h/${account}]`, style];
  if (style === "uppercase") return [`[${fingerprint.toUpperCase()}/${purpose}h/${coin}h/${account}h]`, style];
  return [`[${fingerprint}/${purpose}h/${coin}h/${account}h]`, style];
};

const corpus = [];
const CORPUS_SIZE = 72;
const CREATION_TIMES = [0, 1, 1700000000, 0xffffffff];
{
  // Iteration 0 and 1 force the <digit>h corruption class into the corpus.
  const forcedAccounts = (xpubs) => ({
    def: { id: "bip84" },
    receiveDescriptor: `wpkh([00000000/84h/0h/0h]${xpubs[0]}/0/*)#${descriptorChecksum(`wpkh([00000000/84h/0h/0h]${xpubs[0]}/0/*)`)}`,
    changeDescriptor: `wpkh([00000000/84h/0h/0h]${xpubs[1]}/0/*)#${descriptorChecksum(`wpkh([00000000/84h/0h/0h]${xpubs[1]}/0/*)`)}`,
  });
  corpus.push(
    { wallet: { kind: "hd", network: "mainnet", accounts: [forcedAccounts([XPUB_TAIL_4H, XPUB_TAIL_2H])] }, includePrivate: false, creationTime: 0, label: "iteration 0 (known digit-h vectors)" },
    { wallet: { kind: "hd", network: "mainnet", accounts: [forcedAccounts([SCANNED_TAIL_KEY, XPUB_TAIL_4H])] }, includePrivate: false, creationTime: 0, label: "iteration 1 (scanned digit-h key)" },
  );
  note("digit-h-tail");
  note("digit-h-tail");
  // Random address rows for a branch, with edge indexes (BIP32 maximum,
  // clamp boundary) and occasional invalid entries the exporter must skip.
  const randomRows = () => {
    const count = rint(4);
    if (count === 0) return chance(0.5) ? [] : null;
    const rows = [];
    for (let j = 0; j < count; j++) {
      const style = pick(["small", "small", "large", "max", "invalid"]);
      if (style === "invalid") {
        rows.push({ index: pick([-1, 0x80000000, 1.5, "7", null, undefined]) });
        note("rows:invalid-filtered");
      } else if (style === "max") {
        rows.push({ index: 0x7fffffff });
        note("rows:clamp");
      } else if (style === "large") {
        const index = 0x7fffff00 - rint(2000);
        rows.push({ index });
        if (index + RANGE_GAP > MAX_ADDRESS_INDEX) note("rows:clamp");
      } else {
        rows.push({ index: rint(10000) });
      }
    }
    return rows;
  };
  for (let i = 2; i < CORPUS_SIZE; i++) {
    const label = `iteration ${i}`;
    const network = pick(["mainnet", "testnet", "signet", "regtest"]);
    note(`network:${network}`);
    const coin = network === "mainnet" ? 0 : 1;
    const family = network === "mainnet" ? "mainnet" : "test";
    const includePrivate = chance(0.5);
    note(includePrivate ? "private-export" : "watch-only-export");
    const typeCount = 1 + rint(TYPE_ORDER.length);
    const types = [...TYPE_ORDER].sort(() => rand() - 0.5).slice(0, typeCount);
    const accounts = [];
    for (const type of types) {
      note(`type:${type}`);
      const poolEntry = POOL[coin][PURPOSE[type]];
      const defaultLetter = DEFAULT_LETTER[type] === "x" && family === "test" ? "t"
        : DEFAULT_LETTER[type] === "y" && family === "test" ? "u"
        : DEFAULT_LETTER[type] === "z" && family === "test" ? "v"
        : DEFAULT_LETTER[type];
      // Occasionally encode the same node under a different SLIP-132 prefix:
      // the version bytes are irrelevant to the records but exercise the
      // key-extraction alternation.
      const odd = chance(0.15);
      const letter = odd ? pick(Object.keys(KEY_VERSIONS[family].pub)) : defaultLetter;
      if (odd) note("odd-version-letter");
      const [origin, originStyle] = randomOrigin(type, coin, poolEntry.account);
      note(`origin:${originStyle}`);
      let xpub = extendedKey(poolEntry.node, network, letter, false);
      let xprv = extendedKey(poolEntry.node, network, letter, true);
      if (chance(0.4)) {
        xpub = mutateKeyHeader(xpub);
        xprv = mutateKeyHeader(xprv);
        note("mutated-header");
      }
      if (/[0-9]h$/.test(xpub)) note("digit-h-tail");
      const withChecksum = (body) => (chance(0.9) ? `${body}#${descriptorChecksum(body)}` : (note("no-checksum"), body));
      const account = {
        def: { id: type },
        receiveDescriptor: withChecksum(WRAP[type](`${origin}${xpub}/0/*`)),
        changeDescriptor: withChecksum(WRAP[type](`${origin}${xpub}/1/*`)),
      };
      if (includePrivate && chance(0.7)) {
        account.receiveDescriptorPriv = withChecksum(WRAP[type](`${origin}${xprv}/0/*`));
        account.changeDescriptorPriv = withChecksum(WRAP[type](`${origin}${xprv}/1/*`));
        note("private-descriptor");
      } else if (includePrivate) {
        note("private-missing");
      }
      // Address rows drive the descriptor range records. Cover the modern
      // addressBranches shape (sometimes only one branch present), the legacy
      // receive/change arrays it falls back from, and no rows at all.
      const rowsFlavor = pick(["none", "branches", "branches-partial", "legacy"]);
      if (rowsFlavor === "branches") {
        account.addressBranches = [{ branch: 0, rows: randomRows() }, { branch: 1, rows: randomRows() }];
        note("rows:branches");
      } else if (rowsFlavor === "branches-partial") {
        account.addressBranches = [{ branch: 0, rows: randomRows() }];
        note("rows:branches-partial");
      } else if (rowsFlavor === "legacy") {
        account.receive = randomRows();
        account.change = randomRows();
        note("rows:legacy");
      } else {
        note("rows:none");
      }
      accounts.push(account);
    }
    // Accounts the exporter must skip: unknown script types and accounts
    // missing one descriptor.
    if (chance(0.15)) {
      accounts.push({ def: { id: "bip999" }, receiveDescriptor: accounts[0].receiveDescriptor, changeDescriptor: accounts[0].changeDescriptor });
      note("skipped:unknown-type");
    }
    if (chance(0.15)) {
      // An account with no descriptors at all is still skipped entirely.
      accounts.push({ def: { id: types[0] }, receiveDescriptor: null, changeDescriptor: null });
      note("skipped:no-descriptors");
    }
    if (chance(0.15)) {
      // A single-branch account of a type not already present exports its one
      // branch (issue #366): partial coverage, not a hidden export.
      const spare = TYPE_ORDER.find((type) => !types.includes(type));
      if (spare) {
        const poolEntry = POOL[coin][PURPOSE[spare]];
        const letter = DEFAULT_LETTER[spare] === "x" && family === "test" ? "t"
          : DEFAULT_LETTER[spare] === "y" && family === "test" ? "u"
          : DEFAULT_LETTER[spare] === "z" && family === "test" ? "v"
          : DEFAULT_LETTER[spare];
        const xpub = extendedKey(poolEntry.node, network, letter, false);
        const origin = `[00000000/${PURPOSE[spare]}h/${coin}h/0h]`;
        accounts.push({
          def: { id: spare },
          receiveDescriptor: `${WRAP[spare](`${origin}${xpub}/0/*`)}#${descriptorChecksum(WRAP[spare](`${origin}${xpub}/0/*`))}`,
          changeDescriptor: null,
        });
        note("partial:single-branch");
      }
    }
    corpus.push({ wallet: { kind: "hd", network, accounts }, includePrivate, creationTime: pick(CREATION_TIMES), label });
  }
}

// --- tests --------------------------------------------------------------------

test("every fuzzed wallet's records independently verify (Core's load check included)", () => {
  for (const { wallet, includePrivate, creationTime, label } of corpus) {
    verifyWalletRecords(label, wallet, includePrivate, creationTime);
  }
});

test("every fuzzed wallet.dat is a well-formed SQLite database for its network", () => {
  const module_ = loadModule();
  for (const { wallet, includePrivate, creationTime, label } of corpus) {
    const bytes = module_.buildWalletDat(wallet, includePrivate, fuzzDeps, creationTime);
    assert.equal(new TextDecoder().decode(bytes.subarray(0, 15)), "SQLite format 3", `${label}: SQLite magic`);
    // The application id is the network magic stored as big-endian bytes.
    assert.equal(bytesToHex(bytes.subarray(68, 72)), APPLICATION_ID[wallet.network].toString(16).padStart(8, "0"), `${label}: application id is the network magic`);
  }
});

test("a slice of the corpus verifies with the real SQLite C library", { skip: !PYTHON_SQLITE }, () => {
  const module_ = loadModule();
  for (let i = 0; i < corpus.length; i += 6) {
    const { wallet, includePrivate, creationTime, label } = corpus[i];
    const bytes = module_.buildWalletDat(wallet, includePrivate, fuzzDeps, creationTime);
    const report = sqliteReadBack(bytes);
    assert.equal(report.integrity, "ok", `${label}: integrity_check`);
    assert.equal(report.app_id, APPLICATION_ID[wallet.network], `${label}: application id`);
    const expected = asMap(
      loadModule().buildWalletRecords(wallet, includePrivate, fuzzDeps, creationTime).map(([key, value]) => [bytesToHex(key), bytesToHex(value)]),
    );
    assert.deepEqual(asMap(report.rows), expected, `${label}: every row round-trips through real SQLite`);
  }
});

test("the corpus covers every generator flavor", () => {
  for (const flavor of [
    "network:mainnet", "network:testnet", "network:signet", "network:regtest",
    "type:bip44", "type:bip49", "type:bip84", "type:bip86",
    "origin:standard", "origin:none", "origin:bare", "origin:single", "origin:mixed", "origin:uppercase", "origin:deep",
    "odd-version-letter", "mutated-header", "no-checksum",
    "private-export", "watch-only-export", "private-descriptor", "private-missing",
    "skipped:unknown-type", "skipped:no-descriptors", "partial:single-branch",
    "rows:branches", "rows:branches-partial", "rows:legacy", "rows:none", "rows:invalid-filtered", "rows:clamp",
    "digit-h-tail",
  ]) {
    assert.ok((flavors.get(flavor) ?? 0) > 0, `corpus never exercised flavor ${flavor}`);
  }
});

test("defensive guards reject corrupted crypto dependencies", () => {
  const module_ = loadModule();
  const wallet = corpus[2].wallet;
  const privateWallet = corpus.find(({ wallet: candidate, includePrivate }) =>
    includePrivate && expectedUnits(candidate, true).some((unit) => unit.privateDescriptor));
  assert.ok(privateWallet, "corpus fixture: at least one wallet carries private descriptors");
  assert.throws(
    () => module_.buildWalletRecords(wallet, false, { ...fuzzDeps, sha256: () => new Uint8Array(31) }, 0),
    /sha256 must return 32 bytes/,
  );
  assert.throws(
    () => module_.buildWalletRecords(wallet, false, { ...fuzzDeps, deriveBranchBody: () => new Uint8Array(73) }, 0),
    /branch xpub body must be 74 bytes/,
  );
  assert.throws(
    () => module_.buildWalletRecords(privateWallet.wallet, true, { ...fuzzDeps, base58Decode: () => new Uint8Array(77) }, 0),
    /unexpected extended private key payload/,
  );
  assert.throws(
    () => module_.buildWalletRecords(privateWallet.wallet, true, { ...fuzzDeps, base58Decode: () => Uint8Array.from([1, ...new Array(44).fill(0), 1, ...new Array(32).fill(0)]) }, 0),
    /unexpected extended private key payload/,
  );
  assert.throws(
    () => module_.buildWalletRecords(privateWallet.wallet, true, { ...fuzzDeps, publicKeyForPrivate: () => new Uint8Array(32) }, 0),
    /public key must be 33 bytes/,
  );
});

test("malformed wallet inputs fail loudly instead of writing a bad file", () => {
  const module_ = loadModule();
  const wallet = corpus[2].wallet;
  assert.throws(() => module_.buildWalletRecords({ kind: "hd", network: "mainnet", accounts: [] }, false, fuzzDeps, 0), /no descriptors to export/);
  assert.throws(() => module_.buildWalletRecords({ kind: "hd", network: "mainnet", accounts: [{ ...wallet.accounts[0], def: { id: "bip999" } }] }, false, fuzzDeps, 0), /no descriptors to export/);
  const duplicate = { kind: "hd", network: "mainnet", accounts: [wallet.accounts[0], wallet.accounts[0]] };
  assert.throws(() => module_.buildWalletRecords(duplicate, false, fuzzDeps, 0), /duplicate script type/);
  const noKey = {
    kind: "hd",
    network: "mainnet",
    accounts: [{ def: { id: "bip84" }, receiveDescriptor: "wpkh([00000000/84h/0h/0h]/0/*)", changeDescriptor: "wpkh([00000000/84h/0h/0h]/1/*)" }],
  };
  assert.throws(() => module_.buildWalletRecords(noKey, false, fuzzDeps, 0), /no extended key found in watch-only descriptor/);
  assert.throws(
    () => module_.buildWalletRecords({ ...wallet, accounts: [{ ...wallet.accounts[0], receiveDescriptorPriv: "wpkh(none)/0/*", changeDescriptorPriv: "wpkh(none)/1/*" }] }, true, fuzzDeps, 0),
    /no extended key found in spending descriptor/,
  );
});

test("buildWalletDat defaults the birthday to the export time", { skip: !PYTHON_SQLITE }, () => {
  const module_ = loadModule();
  const before = Math.floor(Date.now() / 1000) - 1;
  const bytes = module_.buildWalletDat(corpus[2].wallet, false, fuzzDeps);
  const after = Math.floor(Date.now() / 1000) + 1;
  assert.equal(new TextDecoder().decode(bytes.subarray(0, 15)), "SQLite format 3");
  const report = sqliteReadBack(bytes);
  const row = report.rows.find(([key]) => key.startsWith("10" + "77616c6c657464657363726970746f72"));
  const value = Buffer.from(row[1], "hex");
  const creationTime = Number(value.readBigUInt64LE(1 + value[0]));
  assert.ok(creationTime >= before && creationTime <= after, `default birthday ${creationTime} is the export time`);
});

test("button label uses the translator when one is registered", () => {
  const module_ = loadModule();
  globalThis.hodlT = (source) => `T:${source}`;
  try {
    assert.equal(module_.walletDatButtonLabel(false), "T:Download watch-only wallet.dat");
    assert.equal(module_.walletDatButtonLabel(true), "T:Download wallet.dat with secrets (xprvs)");
  } finally {
    delete globalThis.hodlT;
  }
});
