import { test } from "node:test";
import assert from "node:assert/strict";
import {
  hodlControlBlock,
  hodlDisasmTapscript,
  hodlIsNumsKey,
  hodlLooksOrdEnvelope,
  hodlOpcodeName,
  hodlTapInternalKey,
  hodlTapLeafScripts,
  hodlTapMerkleRoot,
  hodlTapWitnessPath,
} from "../src/js/psbt-tapscript.js";

const NUMS = Uint8Array.from(Buffer.from("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0", "hex"));
const eq = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
const find = (entries, type) => entries.filter((e) => e.type === type);

test("control block splits version, parity, key, nodes", () => {
  const raw = new Uint8Array(33 + 64);
  raw[0] = 0xc1;
  raw.set(NUMS, 1);
  const parsed = hodlControlBlock(raw);
  assert.equal(parsed.leafVersion, 0xc0);
  assert.equal(parsed.parity, 1);
  assert.equal(parsed.nodes.length, 2);
});

test("key-path vs script-path vs annex", () => {
  assert.equal(hodlTapWitnessPath([new Uint8Array(64)]).path, "key");
  const script = Uint8Array.of(0x20, ...new Uint8Array(32), 0xac);
  const cb = new Uint8Array(33);
  cb[0] = 0xc0;
  cb.set(NUMS, 1);
  const path = hodlTapWitnessPath([new Uint8Array(64), script, cb, Uint8Array.of(0x50, 1)]);
  assert.equal(path.path, "script");
  assert.equal(path.annex[0], 0x50);
});

test("disasm and ord envelope", () => {
  assert.deepEqual(hodlDisasmTapscript(Uint8Array.of(0x20, ...new Uint8Array(32), 0xba, 0xac)), ["PUSH(32)", "OP_CHECKSIGADD", "OP_CHECKSIG"]);
  assert.equal(hodlLooksOrdEnvelope(Uint8Array.of(0x00, 0x63, 0x03, 0x6f, 0x72, 0x64)), true);
});

test("control block rejects truncated and mis-sized buffers", () => {
  assert.equal(hodlControlBlock(null), null);
  assert.equal(hodlControlBlock(new Uint8Array(32)), null, "shorter than the header plus internal key");
  assert.equal(hodlControlBlock(new Uint8Array(34)), null, "(length - 33) must be a multiple of 32");
  assert.equal(hodlControlBlock(new Uint8Array(64)), null);
  const minimal = hodlControlBlock(new Uint8Array(33));
  assert.deepEqual(minimal.nodes, [], "a 33-byte control block has no merkle nodes");
  assert.equal(minimal.leafVersion, 0);
  assert.equal(minimal.parity, 0);
  const odd = new Uint8Array(33);
  odd[0] = 0xc1;
  assert.equal(hodlControlBlock(odd).parity, 1);
});

test("NUMS key comparison requires a 32-byte key and a reference", () => {
  assert.equal(hodlIsNumsKey(NUMS, NUMS, eq), true);
  assert.equal(hodlIsNumsKey(new Uint8Array(32), NUMS, eq), false);
  assert.equal(hodlIsNumsKey(NUMS.slice(0, 31), NUMS, eq), false, "wrong length");
  assert.equal(hodlIsNumsKey(null, NUMS, eq), false);
  assert.equal(hodlIsNumsKey(NUMS, null, eq), false);
});

test("taproot internal key and merkle root fields validate their length", () => {
  assert.equal(hodlTapInternalKey([], find), null, "field absent");
  assert.equal(hodlTapInternalKey([{ type: 23, keydata: Uint8Array.of(1), val: NUMS }], find), null, "keydata-bearing entry ignored");
  assert.deepEqual(hodlTapInternalKey([{ type: 23, keydata: new Uint8Array(), val: NUMS }], find), NUMS);
  assert.throws(
    () => hodlTapInternalKey([{ type: 23, keydata: new Uint8Array(), val: NUMS.slice(0, 31) }], find),
    /Taproot internal key field is malformed\./,
  );
  assert.equal(hodlTapMerkleRoot([], find), null);
  assert.deepEqual(hodlTapMerkleRoot([{ type: 24, keydata: new Uint8Array(), val: NUMS }], find), NUMS);
  assert.throws(
    () => hodlTapMerkleRoot([{ type: 24, keydata: new Uint8Array(), val: new Uint8Array(33) }], find),
    /Taproot merkle root field is malformed\./,
  );
});

test("tap leaf script fields split script and version and parse the control block", () => {
  const script = Uint8Array.of(0x20, ...new Uint8Array(32), 0xac);
  const controlBytes = new Uint8Array(33);
  controlBytes[0] = 0xc0;
  controlBytes.set(NUMS, 1);
  const [leaf] = hodlTapLeafScripts([{ type: 21, keydata: controlBytes, val: Uint8Array.of(...script, 0xc0) }], find);
  assert.deepEqual(leaf.script, script);
  assert.equal(leaf.leafVersion, 0xc0);
  assert.deepEqual(leaf.control.internalKey, NUMS, "the control block comes from the keydata");
  const [noControl] = hodlTapLeafScripts([{ type: 21, keydata: Uint8Array.of(1, 2), val: Uint8Array.of(...script, 0xc0) }], find);
  assert.equal(noControl.control, null, "a malformed control block parses to null, not a throw");
  assert.throws(
    () => hodlTapLeafScripts([{ type: 21, keydata: new Uint8Array(), val: new Uint8Array() }], find),
    /Taproot leaf script field is empty\./,
  );
});

test("opcode names cover the small-number and tapscript ranges", () => {
  assert.equal(hodlOpcodeName(0), "OP_0");
  assert.equal(hodlOpcodeName(79), "OP_1NEGATE");
  assert.equal(hodlOpcodeName(81), "OP_1");
  assert.equal(hodlOpcodeName(96), "OP_16");
  assert.equal(hodlOpcodeName(97), "OP_UNKNOWN_97");
  assert.equal(hodlOpcodeName(255), "OP_UNKNOWN_255");
});

test("disasm treats PUSHDATA opcodes as unknown and misreads their payload", () => {
  // Locked-in display behavior: PUSHDATA1/2/4 are not decoded, so the payload
  // length byte is disassembled as an opcode. This is a display-only path, but
  // the test pins it so any change is a deliberate review.
  assert.deepEqual(hodlDisasmTapscript(Uint8Array.of(0x4c, 0x01, 0x51)), ["OP_UNKNOWN_76", "PUSH(1)"]);
  assert.deepEqual(hodlDisasmTapscript(Uint8Array.of(0x02, 0x51)), ["PUSH(truncated)"], "a truncated push stops the dump");
  assert.deepEqual(hodlDisasmTapscript(new Uint8Array()), []);
});

test("BIP-341 annex rule: only with at least two witness elements may the last element be the annex", () => {
  // BIP-341: "If there are at least two witness elements, and the first byte
  // of the last element is 0x50, this last element is called annex a and is
  // removed from the witness stack." A lone 64-byte witness element starting
  // with 0x50 is a key-path Schnorr signature, not an annex — about 1 in 256
  // key-path spends. (psbt-wasm/src/verify.rs applies the same >= 2 rule.)
  const sig = new Uint8Array(64);
  sig[0] = 0x50;
  const keyPath = hodlTapWitnessPath([sig]);
  assert.equal(keyPath.path, "key", "a lone 0x50-prefixed 64-byte element is the key-path signature");
  assert.equal(keyPath.annex, null, "a single-element witness has no annex");
  assert.equal(sig.length, 64, "the signature element is not consumed");
  const withAnnex = hodlTapWitnessPath([new Uint8Array(64), Uint8Array.of(0x50, 1)]);
  assert.equal(withAnnex.path, "key");
  assert.ok(withAnnex.annex, "with two or more elements the 0x50-prefixed last element is the annex");
});

test("witness path classification handles edge stacks", () => {
  assert.deepEqual(hodlTapWitnessPath([]), { path: "empty", annex: null, control: null, script: null });
  const annexOnly = hodlTapWitnessPath([Uint8Array.of(0x50, 9)]);
  assert.equal(annexOnly.path, "unknown", "a lone 0x50-prefixed element is not a spend path");
  assert.equal(annexOnly.annex, null, "BIP-341: a single witness element is never the annex");
  assert.equal(hodlTapWitnessPath([new Uint8Array(65)]).path, "key", "65-byte signature with sighash byte");
  assert.equal(hodlTapWitnessPath([new Uint8Array(63)]).path, "unknown", "63 bytes is neither key nor script path");
  const badControl = hodlTapWitnessPath([new Uint8Array(64), Uint8Array.of(0x20, ...new Uint8Array(32)), new Uint8Array(10)]);
  assert.equal(badControl.path, "unknown", "a mis-sized control block is not a script path");
  const emptyAnnex = hodlTapWitnessPath([new Uint8Array(64), new Uint8Array(0)]);
  assert.equal(emptyAnnex.path, "unknown", "an empty final item is not an annex");
});
