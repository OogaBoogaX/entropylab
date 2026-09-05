// Tests for the vanity grinder: the WASM module (src/js/vanity-wasm-b64.js,
// built from vanity-wasm/), the pool helpers (src/js/vanity.js), and the
// shipped worker source (src/js/vanity-worker.js) executed under
// node:worker_threads. Run with `npm test` (part of the default and CI
// suites).
//
// Assurance comes from independent re-derivation: every candidate is
// recomputed from the same words, passphrase, and path with @scure/bip39,
// @scure/bip32, and @scure/btc-signer and matched against the record the WASM
// produced, so the counter → passphrase (or account index) → seed → path →
// address chain is checked at each hop. Nothing here is secret; the mnemonic
// is the BIP39 test vector and the counters are fixed test inputs.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Worker } from "node:worker_threads";
import { mnemonicToSeedSync } from "@scure/bip39";
import { HDKey } from "@scure/bip32";
import { bech32m } from "@scure/base";
import { NETWORK, p2pkh, p2sh, p2tr, p2wpkh } from "@scure/btc-signer";
import { VANITY_WASM_B64 } from "../src/js/vanity-wasm-b64.js";
import { VANITY_WORKER_SOURCE } from "../src/js/vanity-worker.js";
import {
  VANITY_ALPHABET,
  VANITY_BENCHMARK_SAMPLES,
  VANITY_HARDENED,
  VANITY_MAX_INDEX,
  VANITY_MAX_MNEMONIC_LEN,
  VANITY_MAX_SALT_LEN,
  VANITY_METHODS,
  VANITY_SCRIPTS,
  VanityGrinder,
  estimateVanityWork,
  validateVanityIndexRange,
  validateVanityMnemonic,
  validateVanityPassphrase,
  validateVanityPrefix,
  validateVanityRange,
  vanityBenchmark,
  vanityAddressFromRecord,
  vanityBuckets,
  vanityPathIndexes,
  vanityPathString,
} from "../src/js/vanity.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const H = VANITY_HARDENED;
const MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const PASSPHRASE = "TREZOR";
const encoder = new TextEncoder();

// Independent derivation: the BIP39 seed and BIP32 path via scure, the
// address encoders via @scure/btc-signer (or bech32m for Silent Payments).
const masterFor = (passphrase) => HDKey.fromMasterSeed(mnemonicToSeedSync(MNEMONIC, passphrase));
const addressFor = (node, script) => {
  const pubkey = node.publicKey;
  if (script === "p2sh-p2wpkh") return p2sh(p2wpkh(pubkey, NETWORK), NETWORK).address;
  if (script === "p2wpkh") return p2wpkh(pubkey, NETWORK).address;
  if (script === "p2tr") return p2tr(pubkey.slice(1), undefined, NETWORK).address;
  return p2pkh(pubkey, NETWORK).address;
};
// BIP-352: scan m/352'/0'/account'/1'/0, spend m/352'/0'/account'/0'/0.
const silentPaymentFor = (master, account) => {
  const payload = new Uint8Array(66);
  payload.set(master.derive(`m/352'/0'/${account}'/1'/0`).publicKey, 0);
  payload.set(master.derive(`m/352'/0'/${account}'/0'/0`).publicKey, 33);
  return bech32m.encode("sp", [0, ...bech32m.toWords(payload)], 1023);
};
const expectedAddress = (passphrase, script, path = "m/84'/0'/0'/0/0") => {
  const master = masterFor(passphrase);
  return script === "sp" ? silentPaymentFor(master, 0) : addressFor(master.derive(path), script);
};
const nodeBytes = (node) => {
  const bytes = new Uint8Array(64);
  bytes.set(node.privateKey, 0);
  bytes.set(node.chainCode, 32);
  return bytes;
};

// ── Direct WASM bindings ────────────────────────────────────────────────────

const wasmBytes = (() => {
  const binary = atob(VANITY_WASM_B64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
})();
const wasm = new WebAssembly.Instance(new WebAssembly.Module(wasmBytes), {}).exports;
const heap = () => new Uint8Array(wasm.memory.buffer);
const RECORD_LEN = 106;
const NO_SLOT = 0xffffffff;

// Runs one vanity_grind call and decodes the out buffer into records.
// Defaults describe a passphrase grind over the test mnemonic at
// m/84'/0'/0'/0/0.
const grind = ({ mode = 0, key = encoder.encode(MNEMONIC), salt = encoder.encode(PASSPHRASE), path = [84 + H, H, H, 0, 0], counterSlot = NO_SLOT, prefix, passLen = mode === 0 ? 1 : 0, start = 0n, count, script = "p2wpkh", recordCap = 1 << 12, outCap = null }) => {
  const prefixBytes = encoder.encode(prefix);
  const prefixPtr = wasm.vanity_alloc(Math.max(1, prefixBytes.length));
  heap().set(prefixBytes, prefixPtr);
  const keyPtr = wasm.vanity_alloc(Math.max(1, key.length));
  heap().set(key, keyPtr);
  const saltPtr = wasm.vanity_alloc(Math.max(1, salt.length));
  heap().set(salt, saltPtr);
  const pathPtr = wasm.vanity_alloc(Math.max(4, path.length * 4));
  const pathView = new DataView(wasm.memory.buffer, pathPtr, Math.max(4, path.length * 4));
  path.forEach((value, i) => pathView.setUint32(i * 4, value >>> 0, true));
  const cap = outCap ?? 12 + RECORD_LEN * recordCap;
  const outPtr = wasm.vanity_alloc(cap);
  try {
    const status = wasm.vanity_grind(mode, keyPtr, key.length, saltPtr, salt.length, pathPtr, path.length, counterSlot, prefixPtr, prefixBytes.length, passLen, BigInt(start), BigInt(count), outPtr, cap, VANITY_SCRIPTS[script].code);
    // On invalid arguments (-1) the WASM writes nothing to the out buffer, so
    // there is no header to decode.
    if (status === -1) return { status, processed: 0n, matches: 0, records: [] };
    const header = new DataView(wasm.memory.buffer, outPtr, 12);
    const processed = header.getBigUint64(0, true);
    const matches = header.getUint32(8, true);
    const records = [];
    for (let i = 0; i < matches; i++) {
      const at = outPtr + 12 + i * RECORD_LEN;
      records.push({
        counter: new DataView(wasm.memory.buffer, at, 8).getBigUint64(0, true),
        passphrase: new TextDecoder().decode(heap().slice(at + 8, at + 8 + passLen)),
        payload: heap().slice(at + 40, at + 106),
      });
    }
    return { status, processed, matches, records };
  } finally {
    wasm.vanity_free(prefixPtr, Math.max(1, prefixBytes.length));
    wasm.vanity_free(keyPtr, Math.max(1, key.length));
    wasm.vanity_free(saltPtr, Math.max(1, salt.length));
    wasm.vanity_free(pathPtr, Math.max(4, path.length * 4));
    wasm.vanity_free(outPtr, cap);
  }
};

test("vanity_free zeroes and vanity_alloc zero-fills; the grind leaves no seed or mnemonic behind (issues #327, #356)", () => {
  // Allocator hygiene: freed buffers are wiped and fresh ones start at zero.
  const ptr = wasm.vanity_alloc(64);
  heap().fill(0x5a, ptr, ptr + 64);
  wasm.vanity_free(ptr, 64);
  assert.deepEqual([...heap().slice(ptr, ptr + 64)], new Array(64).fill(0), "freed buffer was not wiped");
  const fresh = wasm.vanity_alloc(64);
  assert.deepEqual([...heap().slice(fresh, fresh + 64)], new Array(64).fill(0), "fresh buffer was not zero-filled");
  wasm.vanity_free(fresh, 64);
  // A passphrase grind over the whole 1-character odometer (prefix "b" matches
  // every bc1q address): the candidate seeds and the mnemonic are working
  // secrets of the loop and must not survive it.
  const run = grind({ prefix: "b", count: 62n, passLen: 1 });
  assert.equal(run.processed, 62n);
  const memory = () => Buffer.from(heap().buffer);
  for (const candidate of ["a", "9", "z"]) {
    const seed = Buffer.from(mnemonicToSeedSync(MNEMONIC, PASSPHRASE + candidate));
    assert.equal(memory().indexOf(seed), -1, `the candidate seed for ${JSON.stringify(candidate)} survived the grind`);
  }
  const mnemonicBytes = Buffer.from(new TextEncoder().encode(MNEMONIC));
  assert.equal(memory().indexOf(mnemonicBytes), -1, "the mnemonic survived the grind (freed key buffer was not wiped)");
});

test("committed vanity WASM artifact is intact (sha256 in module header matches payload)", () => {
  const source = readFileSync(join(root, "src/js/vanity-wasm-b64.js"), "utf8");
  const declared = source.match(/wasm sha256: ([0-9a-f]{64})/);
  assert.ok(declared, "module header carries the wasm sha256");
  const b64 = source.match(/export const VANITY_WASM_B64 =\s*"([A-Za-z0-9+/=]+)";/);
  assert.ok(b64, "module exports the base64 payload");
  const actual = createHash("sha256").update(Buffer.from(b64[1], "base64")).digest("hex");
  assert.equal(actual, declared[1]);
});

test("committed vanity WASM carries no build-host paths (remapped at build time)", () => {
  const payload = Buffer.from(VANITY_WASM_B64, "base64").toString("latin1");
  for (const banned of ["/home/", "/Users/", ".cargo/", ".rustup/"]) {
    assert.equal(payload.includes(banned), false, `build fingerprints the build host: ${banned}`);
  }
});

test("passphrase grind: counter → odometer → BIP39 passphrase → path address, for every address type", () => {
  // Counter 0 is "a", counter 61 is "9", counter 1000 (2 characters) is "qi".
  const vectors = [
    { counter: 0n, passLen: 1, odometer: "a" },
    { counter: 61n, passLen: 1, odometer: "9" },
    { counter: 1000n, passLen: 2, odometer: "qi" },
  ];
  for (const script of Object.keys(VANITY_SCRIPTS)) {
    const meta = VANITY_SCRIPTS[script];
    // Silent Payments take the account path; the engine appends scan/spend.
    const path = script === "sp" ? [352 + H, H, H] : [84 + H, H, H, 0, 0];
    for (const vector of vectors) {
      const expected = expectedAddress(PASSPHRASE + vector.odometer, script);
      const run = grind({ path, prefix: expected.slice(0, meta.prefix.length + 1), passLen: vector.passLen, start: vector.counter, count: 1n, script });
      assert.equal(run.status, 0, `${script} counter ${vector.counter}`);
      assert.equal(run.processed, 1n);
      assert.equal(run.matches, 1, `${script} counter ${vector.counter} matches its own prefix`);
      const record = run.records[0];
      assert.equal(record.counter, vector.counter);
      assert.equal(record.passphrase, vector.odometer);
      assert.equal(vanityAddressFromRecord(record, script), expected, `${script} ${vector.odometer}`);
    }
  }
});

test("the full 1-character space grinds in odometer order over a-zA-Z0-9", () => {
  // Prefix "1" matches every mainnet P2PKH address, so all 62 come back.
  const run = grind({ prefix: "1", passLen: 1, count: 62n, script: "p2pkh" });
  assert.equal(run.status, 0);
  assert.equal(run.processed, 62n);
  assert.equal(run.matches, 62);
  for (let i = 0; i < 62; i++) {
    assert.equal(run.records[i].counter, BigInt(i));
    assert.equal(run.records[i].passphrase, VANITY_ALPHABET[i], `counter ${i} is alphabet[${i}]`);
    assert.equal(vanityAddressFromRecord(run.records[i], "p2pkh"), expectedAddress(PASSPHRASE + VANITY_ALPHABET[i], "p2pkh"));
  }
});

test("the starting passphrase prefixes every candidate verbatim; an empty one leaves the bare counter string", () => {
  const bare = grind({ salt: new Uint8Array(0), prefix: "bc1q", passLen: 1, count: 1n });
  assert.equal(bare.matches, 1);
  assert.equal(vanityAddressFromRecord(bare.records[0], "p2wpkh"), expectedAddress("a", "p2wpkh"));
  // NFKD text with multi-byte characters is just bytes to the engine.
  const accented = "cörrect hörse".normalize("NFKD");
  const salted = grind({ salt: encoder.encode(accented), prefix: "bc1q", passLen: 1, count: 1n });
  assert.equal(salted.matches, 1);
  assert.equal(vanityAddressFromRecord(salted.records[0], "p2wpkh"), expectedAddress(accented + "a", "p2wpkh"));
  assert.notEqual(vanityAddressFromRecord(salted.records[0], "p2wpkh"), vanityAddressFromRecord(bare.records[0], "p2wpkh"), "the passphrase re-keys the candidate");
});

test("derivation grind: the counter is the account index below the parent node, hardened bit preserved", () => {
  const master = masterFor(PASSPHRASE);
  const parent = master.derive("m/84'/0'");
  // Hardened account slot: m/84'/0'/n'/0/0.
  const hardened = grind({ mode: 1, key: nodeBytes(parent), salt: new Uint8Array(0), path: [H, 0, 0], counterSlot: 0, prefix: "bc1q", count: 10n });
  assert.equal(hardened.status, 0);
  assert.equal(hardened.processed, 10n);
  assert.equal(hardened.matches, 10, "bc1q matches every P2WPKH address");
  for (const record of hardened.records) {
    assert.equal(record.passphrase, "", "the derivation grind carries no odometer string");
    assert.equal(vanityAddressFromRecord(record, "p2wpkh"), addressFor(master.derive(`m/84'/0'/${record.counter}'/0/0`), "p2wpkh"), `account ${record.counter}'`);
  }
  // Unhardened account slot: m/84'/0'/n/0/0.
  const plain = grind({ mode: 1, key: nodeBytes(parent), salt: new Uint8Array(0), path: [0, 0, 0], counterSlot: 0, prefix: "bc1q", start: 5n, count: 3n });
  assert.equal(plain.matches, 3);
  for (const record of plain.records) {
    assert.equal(vanityAddressFromRecord(record, "p2wpkh"), addressFor(master.derive(`m/84'/0'/${record.counter}/0/0`), "p2wpkh"), `account ${record.counter}`);
  }
  // The slot can sit deeper in the path (here: the address index).
  const deep = grind({ mode: 1, key: nodeBytes(master.derive("m/86'/0'/0'/0")), salt: new Uint8Array(0), path: [0], counterSlot: 0, prefix: "bc1p", count: 4n, script: "p2tr" });
  assert.equal(deep.matches, 4);
  for (const record of deep.records) {
    assert.equal(vanityAddressFromRecord(record, "p2tr"), addressFor(master.derive(`m/86'/0'/0'/0/${record.counter}`), "p2tr"));
  }
});

test("silent payment codes: scan and spend keys per BIP-352, bech32m over 66 bytes", () => {
  const master = masterFor(PASSPHRASE);
  const run = grind({ mode: 1, key: nodeBytes(master.derive("m/352'/0'")), salt: new Uint8Array(0), path: [H], counterSlot: 0, prefix: "sp1qq", count: 5n, script: "sp" });
  assert.equal(run.status, 0);
  assert.equal(run.matches, 5, "sp1qq matches every Silent Payment code");
  for (const record of run.records) {
    const expected = silentPaymentFor(master, Number(record.counter));
    assert.equal(expected.length, 116);
    assert.equal(vanityAddressFromRecord(record, "sp"), expected, `account ${record.counter}'`);
    assert.ok(VANITY_SCRIPTS.sp.firstFree.includes(expected[5]), "the sixth character is the scan key's parity character");
  }
  // Prefix matching reaches past the parity character.
  const wanted = silentPaymentFor(master, 3).slice(0, 8);
  const filtered = grind({ mode: 1, key: nodeBytes(master.derive("m/352'/0'")), salt: new Uint8Array(0), path: [H], counterSlot: 0, prefix: wanted, count: 5n, script: "sp" });
  assert.ok(filtered.records.some((record) => record.counter === 3n));
  for (const record of filtered.records) assert.ok(vanityAddressFromRecord(record, "sp").startsWith(wanted));
});

test("a contiguous bucket split is disjoint and equals the full range", () => {
  // Account indexes 0..199 split at 100 and compared with the single-run
  // result — the property that makes worker buckets correct.
  const parent = nodeBytes(masterFor(PASSPHRASE).derive("m/84'/0'"));
  const options = { mode: 1, key: parent, salt: new Uint8Array(0), path: [H, 0, 0], counterSlot: 0, prefix: "bc1q" };
  const full = grind({ ...options, count: 200n });
  const left = grind({ ...options, count: 100n });
  const right = grind({ ...options, start: 100n, count: 100n });
  const joined = [...left.records, ...right.records];
  assert.equal(full.matches, 200);
  assert.equal(joined.length, full.matches);
  for (let i = 0; i < joined.length; i++) {
    assert.equal(joined[i].counter, full.records[i].counter);
    assert.deepEqual(joined[i].payload, full.records[i].payload);
  }
});

test("prefix filtering returns only matching addresses", () => {
  const parent = nodeBytes(masterFor(PASSPHRASE).derive("m/84'/0'"));
  const options = { mode: 1, key: parent, salt: new Uint8Array(0), path: [H, 0, 0], counterSlot: 0 };
  const all = grind({ ...options, prefix: "bc1q", count: 64n });
  const wanted = vanityAddressFromRecord(all.records[7], "p2wpkh").slice(0, 5);
  const filtered = grind({ ...options, prefix: wanted, count: 64n });
  assert.ok(filtered.matches >= 1 && filtered.matches < 64);
  for (const record of filtered.records) assert.ok(vanityAddressFromRecord(record, "p2wpkh").startsWith(wanted));
  assert.ok(filtered.records.some((record) => record.counter === all.records[7].counter));
  const impossible = grind({ ...options, prefix: "bc1qb", count: 64n });
  assert.equal(impossible.status, 0);
  assert.equal(impossible.matches, 0);
});

test("vanity_grind rejects invalid arguments", () => {
  const parent = nodeBytes(masterFor(PASSPHRASE).derive("m/84'/0'"));
  assert.equal(grind({ mode: 2, prefix: "1", count: 1n }).status, -1, "unknown mode");
  assert.equal(grind({ prefix: "1", passLen: 0, count: 1n }).status, -1, "passphrase grind with pass length 0");
  assert.equal(grind({ prefix: "1", passLen: 33, count: 1n }).status, -1, "pass length beyond 32");
  assert.equal(grind({ prefix: "", count: 1n }).status, -1, "empty prefix");
  assert.equal(grind({ prefix: "1", path: [], count: 1n }).status, -1, "empty path");
  assert.equal(grind({ prefix: "1", path: new Array(17).fill(0), count: 1n }).status, -1, "path beyond 16 components");
  assert.equal(grind({ prefix: "1", counterSlot: 0, count: 1n }).status, -1, "passphrase grind with a counter slot");
  assert.equal(grind({ prefix: "1", key: new Uint8Array(0), count: 1n }).status, -1, "empty mnemonic");
  assert.equal(grind({ prefix: "1", key: new Uint8Array(VANITY_MAX_MNEMONIC_LEN + 1), count: 1n }).status, -1, "mnemonic beyond 1024 bytes");
  assert.equal(grind({ prefix: "1", salt: new Uint8Array(VANITY_MAX_SALT_LEN + 1), count: 1n }).status, -1, "starting passphrase beyond 256 bytes");
  assert.equal(grind({ prefix: "1", salt: new Uint8Array(VANITY_MAX_SALT_LEN).fill(120), count: 1n }).status, 0, "256-byte starting passphrase accepted");
  assert.equal(grind({ mode: 1, key: parent.slice(0, 63), salt: new Uint8Array(0), path: [H], counterSlot: 0, prefix: "1", count: 1n }).status, -1, "node must be 64 bytes");
  assert.equal(grind({ mode: 1, key: parent, salt: new Uint8Array(0), path: [H, 0, 0], counterSlot: 3, prefix: "1", count: 1n }).status, -1, "counter slot outside the path");
  assert.equal(grind({ mode: 1, key: parent, path: [H, 0, 0], counterSlot: 0, prefix: "1", count: 1n }).status, -1, "derivation grind with a starting passphrase");
  assert.equal(grind({ mode: 1, key: parent, salt: new Uint8Array(0), path: [H, 0, 0], counterSlot: 0, passLen: 1, prefix: "1", count: 1n }).status, -1, "derivation grind with an odometer length");
  // An out buffer too small even for the 12-byte header is invalid.
  assert.equal(grind({ prefix: "1", count: 1n, outCap: 8 }).status, -1, "out buffer below the header");
  // A record area too small for every match stops early with -2 and reports
  // how far it got, so the caller can resume at start + processed.
  const tight = grind({ mode: 1, key: parent, salt: new Uint8Array(0), path: [H, 0, 0], counterSlot: 0, prefix: "bc1q", count: 64n, recordCap: 10 });
  assert.equal(tight.status, -2);
  assert.equal(tight.matches, 10);
  assert.equal(tight.processed, 10n);
  // The derivation grind stops at the last BIP32 index.
  const edge = grind({ mode: 1, key: parent, salt: new Uint8Array(0), path: [H, 0, 0], counterSlot: 0, prefix: "bc1q", start: BigInt(VANITY_MAX_INDEX) - 1n, count: 10n });
  assert.equal(edge.status, 0);
  assert.equal(edge.processed, 2n, "only two indexes remain before 2^31");
});

// ── Pool helpers (src/js/vanity.js) ─────────────────────────────────────────

test("vanityBuckets partitions the range without overlap or gap", () => {
  for (const [start, count, workers] of [[0n, 3844n, 3], [10n, 1000n, 7], [0n, 5n, 8], [123n, 1n, 4], [0n, 62n ** 4n, 16]]) {
    const buckets = vanityBuckets(start, count, workers);
    assert.ok(buckets.length >= 1 && buckets.length <= workers);
    let cursor = start;
    for (const bucket of buckets) {
      assert.equal(bucket.start, cursor, "buckets are contiguous");
      assert.ok(bucket.count > 0n, "no empty buckets");
      cursor += bucket.count;
    }
    assert.equal(cursor, start + count, "buckets cover the whole range");
  }
});

test("validateVanityPrefix enforces the selected address type's prefix", () => {
  assert.equal(validateVanityPrefix("1Love", "p2pkh"), "1Love");
  assert.equal(validateVanityPrefix("3Nesting", "p2sh-p2wpkh"), "3Nesting");
  assert.equal(validateVanityPrefix("BC1QW0RD", "p2wpkh"), "bc1qw0rd");
  assert.equal(validateVanityPrefix("bc1prrr", "p2tr"), "bc1prrr");
  assert.equal(validateVanityPrefix("SP1QQG", "sp"), "sp1qqg");
  assert.throws(() => validateVanityPrefix("Love", "p2pkh"), /start with/);
  assert.throws(() => validateVanityPrefix("1", "p2pkh"), /alone matches every/);
  assert.throws(() => validateVanityPrefix("10", "p2pkh"), /Base58/); // 0 is not base58
  assert.throws(() => validateVanityPrefix("1O", "p2pkh"), /Base58/);
  assert.throws(() => validateVanityPrefix("3".repeat(35), "p2sh-p2wpkh"), /longer than a whole/);
  assert.throws(() => validateVanityPrefix("bc1q", "p2wpkh"), /alone matches every/);
  assert.throws(() => validateVanityPrefix("bc1qi", "p2wpkh"), /Bech32/); // i is not bech32 data
  assert.throws(() => validateVanityPrefix("bc1q" + "q".repeat(39), "p2wpkh"), /longer than a whole/);
  assert.throws(() => validateVanityPrefix("bc1p" + "q".repeat(59), "p2tr"), /longer than a whole/);
  // Silent Payments: "sp1qq" is fixed and the next character is one of the
  // eight parity characters.
  assert.throws(() => validateVanityPrefix("sp1qq", "sp"), /alone matches every/);
  assert.throws(() => validateVanityPrefix("sp1qqa", "sp"), /parity/);
  assert.throws(() => validateVanityPrefix("sp1qz", "sp"), /start with/);
  assert.throws(() => validateVanityPrefix("sp1qq" + "g".repeat(112), "sp"), /longer than a whole/);
});

test("validateVanityRange bounds the counter to the passphrase space (u64)", () => {
  assert.deepEqual(validateVanityRange(1, 0n, 62n), { passLen: 1, start: 0n, count: 62n });
  assert.throws(() => validateVanityRange(1, 61n, 2n), /runs past the 1-character space/); // 61 + 2 > 62^1
  assert.throws(() => validateVanityRange(0, 0n, 1n), /length is 1 to 32/);
  assert.throws(() => validateVanityRange(33, 0n, 1n), /length is 1 to 32/);
  assert.throws(() => validateVanityRange(8, 0n, 0n), /at least one candidate/);
  assert.throws(() => validateVanityRange(8, -1n, 1n), /zero or more/);
  // 62^11 exceeds u64::MAX, so the 64-bit counter is the binding limit.
  assert.deepEqual(validateVanityRange(11, 0n, (1n << 64n) - 1n).count, (1n << 64n) - 1n);
  assert.throws(() => validateVanityRange(11, 0n, 1n << 64n), /64-bit counter/);
});

test("validateVanityIndexRange bounds the account index to 2^31", () => {
  assert.deepEqual(validateVanityIndexRange(0n, 100n), { start: 0n, count: 100n });
  assert.deepEqual(validateVanityIndexRange(BigInt(VANITY_MAX_INDEX), 1n), { start: BigInt(VANITY_MAX_INDEX), count: 1n });
  assert.throws(() => validateVanityIndexRange(-1n, 1n), /zero or more/);
  assert.throws(() => validateVanityIndexRange(0n, 0n), /at least one account/);
  assert.throws(() => validateVanityIndexRange(BigInt(VANITY_MAX_INDEX) + 1n, 1n), /beyond the BIP32 index range/);
  assert.throws(() => validateVanityIndexRange(BigInt(VANITY_MAX_INDEX), 2n), /runs past the last BIP32 account/);
});

test("validateVanityPassphrase and validateVanityMnemonic bound the WASM buffers and normalize NFKD", () => {
  assert.equal(validateVanityPassphrase(""), "");
  assert.equal(validateVanityPassphrase("correct horse battery staple"), "correct horse battery staple");
  assert.equal(validateVanityPassphrase("é"), "é", "NFKD as BIP39 requires");
  assert.equal(validateVanityPassphrase("x".repeat(VANITY_MAX_SALT_LEN)), "x".repeat(VANITY_MAX_SALT_LEN));
  assert.throws(() => validateVanityPassphrase("x".repeat(VANITY_MAX_SALT_LEN + 1)), /256-byte vanity limit/);
  // The limit is UTF-8 bytes, not characters.
  assert.throws(() => validateVanityPassphrase("…".repeat(86)), /256-byte vanity limit/);
  assert.equal(validateVanityMnemonic(` ${MNEMONIC} `), MNEMONIC);
  assert.throws(() => validateVanityMnemonic(""), /no mnemonic/);
  assert.throws(() => validateVanityMnemonic("x".repeat(VANITY_MAX_MNEMONIC_LEN + 1)), /1024-byte vanity limit/);
});

test("vanityPathIndexes and vanityPathString round-trip BIP32 paths", () => {
  assert.deepEqual(vanityPathIndexes("m/84'/0'/0'"), [84 + H, H, H]);
  assert.deepEqual(vanityPathIndexes("m/84h/0H/3'/1/7"), [84 + H, H, 3 + H, 1, 7]);
  assert.deepEqual(vanityPathIndexes("m"), []);
  assert.equal(vanityPathString([84 + H, H, 3 + H, 1, 7]), "m/84'/0'/3'/1/7");
  assert.equal(vanityPathString(vanityPathIndexes("m/352'/0'/5'")), "m/352'/0'/5'");
  assert.throws(() => vanityPathIndexes("84'/0'"), /start with m/);
  assert.throws(() => vanityPathIndexes("m/x"), /whole number/);
  assert.throws(() => vanityPathIndexes("m/2147483648"), /whole number/);
  assert.throws(() => vanityPathIndexes("m" + "/0".repeat(17)), /at most 16/);
});

test("estimateVanityWork uses the selected address alphabet", () => {
  assert.equal(estimateVanityWork("1a", "p2pkh"), 58n);
  assert.equal(estimateVanityWork("1ab", "p2pkh"), 3364n);
  assert.equal(estimateVanityWork("1abc", "p2pkh"), 195112n);
  assert.equal(estimateVanityWork("bc1qz", "p2wpkh"), 32n);
  assert.equal(estimateVanityWork("bc1qzz", "p2wpkh"), 1024n);
  assert.equal(estimateVanityWork("bc1pz", "p2tr"), 32n);
  // The Silent Payment parity character has eight values, not 32.
  assert.equal(estimateVanityWork("sp1qqg", "sp"), 8n);
  assert.equal(estimateVanityWork("sp1qqgz", "sp"), 256n);
  assert.equal(estimateVanityWork("sp1qq", "sp"), 1n);
});

test("the method and script tables match the WASM contract", () => {
  assert.deepEqual(Object.keys(VANITY_METHODS), ["passphrase", "derivation"]);
  assert.equal(VANITY_METHODS.passphrase.mode, 0);
  assert.equal(VANITY_METHODS.derivation.mode, 1);
  assert.deepEqual(Object.values(VANITY_SCRIPTS).map((meta) => meta.code), [0, 1, 2, 3, 4]);
  assert.equal(VANITY_SCRIPTS.sp.max, 116);
});

// ── Worker protocol (the shipped source, under node:worker_threads) ─────────

// node:worker_threads has no `self`; the prelude adapts the Web Worker
// surface the shipped source expects, so the identical string is what runs.
const NODE_WORKER_PRELUDE = `
const { parentPort } = require("worker_threads");
globalThis.self = globalThis;
globalThis.postMessage = (message) => parentPort.postMessage(message);
parentPort.on("message", (data) => globalThis.self.onmessage({ data }));
`;

class NodeWebWorkerAdapter {
  constructor() {
    this.inner = new Worker(NODE_WORKER_PRELUDE + VANITY_WORKER_SOURCE, { eval: true });
    this.onmessage = null;
    this.onerror = null;
    this.inner.on("message", (data) => this.onmessage?.({ data }));
    this.inner.on("error", (error) => this.onerror?.(error));
  }
  postMessage(message, transfer) {
    this.inner.postMessage(message, transfer);
  }
  terminate() {
    return this.inner.terminate();
  }
}
const nodeSpawn = () => ({ worker: new NodeWebWorkerAdapter(), url: null });

const initWorker = () => new Promise((resolve, reject) => {
  const worker = new NodeWebWorkerAdapter();
  worker.onmessage = (event) => {
    if (event.data?.type === "ready") resolve(worker);
  };
  worker.onerror = (error) => reject(error);
  const copy = wasmBytes.slice().buffer;
  worker.postMessage({ type: "init", wasm: copy }, [copy]);
});

const awaitDone = (events, timeout = 60000) => new Promise((resolve, reject) => {
  const timer = setTimeout(() => reject(new Error("worker never finished")), timeout);
  const poll = setInterval(() => {
    const last = events.findLast((message) => message.type === "done" || message.type === "error");
    if (last) {
      clearInterval(poll);
      clearTimeout(timer);
      resolve(last);
    }
  }, 10);
});

test("worker source: init, passphrase grind, progress, done — with matching hits", async () => {
  const worker = await initWorker();
  try {
    const events = [];
    worker.onmessage = (event) => events.push(event.data);
    worker.postMessage({ type: "grind", mode: 0, key: encoder.encode(MNEMONIC), salt: encoder.encode(PASSPHRASE), path: [84 + H, H, H, 0, 0], counterSlot: NO_SLOT, prefix: "bc1q", passLen: 1, start: 0n, count: 62n, script: 2 });
    const done = await awaitDone(events);
    assert.equal(done.type, "done");
    assert.equal(done.done, 62n);
    assert.equal(done.stopped, false);
    const matches = events.filter((message) => message.type === "progress").flatMap((message) => message.matches);
    assert.equal(matches.length, 62);
    assert.equal(matches[0].passphrase, "a");
    assert.equal(matches[0].payload.length, 66);
    assert.equal(vanityAddressFromRecord(matches[0], "p2wpkh"), expectedAddress(PASSPHRASE + "a", "p2wpkh"));
    assert.ok(events.some((message) => message.type === "progress" && message.done === 62n));
    // An over-long starting passphrase is rejected with an error, never ground.
    const errors = [];
    worker.onmessage = (event) => errors.push(event.data);
    worker.postMessage({ type: "grind", mode: 0, key: encoder.encode(MNEMONIC), salt: new Uint8Array(257), path: [84 + H, H, H, 0, 0], prefix: "bc1q", passLen: 1, start: 0n, count: 1n, script: 2 });
    const failure = await awaitDone(errors);
    assert.equal(failure.type, "error");
    assert.match(failure.message, /passphrase/);
  } finally {
    await worker.terminate();
  }
});

test("worker source: the derivation grind takes a node and a counter slot", async () => {
  const worker = await initWorker();
  try {
    const master = masterFor(PASSPHRASE);
    const events = [];
    worker.onmessage = (event) => events.push(event.data);
    worker.postMessage({ type: "grind", mode: 1, key: nodeBytes(master.derive("m/352'/0'")), path: [H], counterSlot: 0, prefix: "sp1qq", start: 0n, count: 4n, script: 4 });
    const done = await awaitDone(events);
    assert.equal(done.type, "done");
    assert.equal(done.done, 4n);
    const matches = events.filter((message) => message.type === "progress").flatMap((message) => message.matches);
    assert.equal(matches.length, 4);
    for (const match of matches) {
      assert.equal(match.passphrase, "");
      assert.equal(vanityAddressFromRecord(match, "sp"), silentPaymentFor(master, Number(match.counter)));
    }
    // A malformed path is an error, never a grind.
    const errors = [];
    worker.onmessage = (event) => errors.push(event.data);
    worker.postMessage({ type: "grind", mode: 1, key: nodeBytes(master.derive("m/84'/0'")), path: [], counterSlot: 0, prefix: "bc1q", start: 0n, count: 1n, script: 2 });
    const failure = await awaitDone(errors);
    assert.equal(failure.type, "error");
    assert.match(failure.message, /path/);
  } finally {
    await worker.terminate();
  }
});

test("worker source: stop ends the run cooperatively", async () => {
  const worker = await initWorker();
  try {
    const events = [];
    worker.onmessage = (event) => {
      events.push(event.data);
      if (event.data?.type === "progress") worker.postMessage({ type: "stop" });
    };
    worker.postMessage({ type: "grind", mode: 1, key: nodeBytes(masterFor(PASSPHRASE).derive("m/84'/0'")), path: [H, 0, 0], counterSlot: 0, prefix: "bc1qzzzzzz", start: 0n, count: 20000000n, script: 2 });
    const done = await awaitDone(events);
    assert.equal(done.type, "done");
    assert.equal(done.stopped, true);
    assert.ok(done.done < 20000000n, `stop landed early (done=${done.done})`);
  } finally {
    await worker.terminate();
  }
});

test("VanityGrinder pool aggregates derivation-grind buckets across workers", async () => {
  const master = masterFor(PASSPHRASE);
  const matches = [];
  let progressEvents = 0;
  const result = await new Promise((resolve, reject) => {
    const grinder = new VanityGrinder({
      onMatch: (match) => matches.push(match),
      onProgress: () => {
        progressEvents += 1;
      },
      onDone: resolve,
      onError: (message) => reject(new Error(message)),
    }, nodeSpawn);
    grinder.start({ method: "derivation", script: "p2wpkh", prefix: "bc1q", start: 0n, count: 300n, workers: 3, passphrase: PASSPHRASE, node: nodeBytes(master.derive("m/84'/0'")), path: [H, 0, 0], counterSlot: 0, pathPrefix: [84 + H, H] });
  });
  assert.equal(result.done, 300n);
  assert.equal(result.stopped, false);
  assert.equal(result.found, 300);
  assert.equal(matches.length, 300);
  assert.ok(progressEvents >= 3, "every worker reported progress");
  const hit = matches.find((match) => match.counter === 7n);
  assert.equal(hit.index, 7);
  assert.equal(hit.passphrase, PASSPHRASE, "the derivation grind reports the fixed passphrase");
  assert.equal(hit.path, "m/84'/0'/7'/0/0");
  assert.equal(hit.address, addressFor(master.derive("m/84'/0'/7'/0/0"), "p2wpkh"));
});

test("VanityGrinder pool passes the selected script type to workers", async () => {
  const master = masterFor(PASSPHRASE);
  const expected = addressFor(master.derive("m/86'/0'/2'/0/0"), "p2tr");
  const matches = [];
  const result = await new Promise((resolve, reject) => {
    const grinder = new VanityGrinder({
      onMatch: (match) => matches.push(match),
      onDone: resolve,
      onError: (message) => reject(new Error(message)),
    }, nodeSpawn);
    grinder.start({ method: "derivation", script: "p2tr", prefix: expected.slice(0, 6), start: 0n, count: 8n, workers: 2, node: nodeBytes(master.derive("m/86'/0'")), path: [H, 0, 0], counterSlot: 0, pathPrefix: [86 + H, H] });
  });
  assert.equal(result.done, 8n);
  const hit = matches.find((match) => match.counter === 2n);
  assert.equal(hit.address, expected);
  assert.equal(hit.path, "m/86'/0'/2'/0/0");
});

test("VanityGrinder pool runs the passphrase grind and reports the full candidate passphrase", async () => {
  // A found passphrase reads as the starting passphrase followed by the
  // counter odometer string, on the key's own path.
  const matches = [];
  const result = await new Promise((resolve, reject) => {
    const grinder = new VanityGrinder({
      onMatch: (match) => matches.push(match),
      onDone: resolve,
      onError: (message) => reject(new Error(message)),
    }, nodeSpawn);
    grinder.start({ method: "passphrase", script: "p2pkh", prefix: "1", start: 0n, count: 62n, workers: 3, passLen: 1, mnemonic: MNEMONIC, passphrase: PASSPHRASE, path: [44 + H, H, H, 0, 0] });
  });
  assert.equal(result.done, 62n);
  assert.equal(result.stopped, false);
  const hit = matches.find((match) => match.counter === 0n);
  assert.equal(hit.passphrase, PASSPHRASE + "a");
  assert.equal(hit.index, null);
  assert.equal(hit.path, "m/44'/0'/0'/0/0");
  assert.equal(hit.address, expectedAddress(PASSPHRASE + "a", "p2pkh", "m/44'/0'/0'/0/0"));
  for (const match of matches) {
    assert.ok(match.passphrase.startsWith(PASSPHRASE));
    assert.equal(match.address, expectedAddress(match.passphrase, "p2pkh", "m/44'/0'/0'/0/0"));
  }
});

test("worker source: chunks adapt so progress arrives early and often", async () => {
  // The passphrase grind is PBKDF2-heavy, so the first chunk is tiny and the
  // rest are sized to a fraction of a second each: a 200-candidate range must
  // report progress several times rather than once at the end.
  const worker = await initWorker();
  try {
    const events = [];
    worker.onmessage = (event) => events.push(event.data);
    worker.postMessage({ type: "grind", mode: 0, key: encoder.encode(MNEMONIC), salt: encoder.encode(PASSPHRASE), path: [84 + H, H, H, 0, 0], counterSlot: NO_SLOT, prefix: "bc1qzzzzzzzz", passLen: 2, start: 0n, count: 200n, script: 2 });
    const done = await awaitDone(events);
    assert.equal(done.type, "done");
    assert.equal(done.done, 200n);
    const progress = events.filter((message) => message.type === "progress");
    assert.ok(progress.length >= 3, `progress reported ${progress.length} times`);
    assert.ok(progress[0].done <= 16n, `the first chunk is small (${progress[0].done})`);
    assert.equal(progress.at(-1).done, 200n);
  } finally {
    await worker.terminate();
  }
});

test("vanityBenchmark samples every method on fixed constants and reports candidates per second", async () => {
  assert.deepEqual(Object.keys(VANITY_BENCHMARK_SAMPLES), ["passphrase", "derivation", "sp"]);
  const rates = await vanityBenchmark(nodeSpawn);
  for (const name of Object.keys(VANITY_BENCHMARK_SAMPLES)) {
    assert.ok(Number.isFinite(rates[name]) && rates[name] > 0, `${name} rate is positive (${rates[name]})`);
  }
  // Stretching a seed per candidate is far slower than three child steps.
  assert.ok(rates.passphrase < rates.derivation, "the passphrase grind is the slow one");
  // The sample never touches session material: the constants live in the
  // module, not in the caller's arguments.
  const vanityJs = readFileSync(join(root, "src/js/vanity.js"), "utf8");
  assert.match(vanityJs, /const BENCHMARK_MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";/);
  assert.match(vanityJs, /const BENCHMARK_NODE = Uint8Array\.from\(\{ length: 64 \}, \(_, i\) => \(i < 32 \? 1 : 2\)\);/);
  assert.match(vanityJs, /export function vanityBenchmark\(spawn = spawnBlobWorker\) \{/);
});
