// Offline payjoin signals through the WASM binding (issue #446, BIP-78/77):
// the single-file "payjoin" object psbtInspectDoc adds. Fixtures mirror the
// crate's own payjoin tests (psbt-wasm/src/payjoin.rs): a signed 1-in/2-out
// Original and a BIP-78-shaped proposal that inserts one finalized receiver
// input. The two-file sender checklist and the Inspector section come later.
import { test } from "node:test";
import assert from "node:assert/strict";
import { psbtInspectDoc } from "../src/js/psbt-wasm.js";

// --- Fixtures (the Rust test vectors, rebuilt byte for byte) ----------------

const concat = (parts) => {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
};
const le32 = (n) => {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, true);
  return b;
};
const le64 = (n) => {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(n), true);
  return b;
};
const varint = (n) => {
  assert.ok(n < 0xfd, "fixtures stay below the compact-size marker");
  return Uint8Array.of(n);
};

const PAYMENT = 0xaa, SENDER_SPK = 0xbb, CHANGE = 0xcc, RECEIVER_SPK = 0xee;
const spk = (byte) => Uint8Array.of(0x00, 0x14, ...Array(20).fill(byte));
const txin = (txidByte, vout) => concat([Uint8Array.from(Array(32).fill(txidByte)), le32(vout), varint(0), le32(0xfffffffd)]);
const txout = (sats, script) => concat([le64(sats), varint(script.length), script]);
const tx = (inputs, outputs) => concat([le32(2), varint(inputs.length), ...inputs, varint(outputs.length), ...outputs, le32(0)]);

const pair = (key, value) => concat([varint(key.length), key, varint(value.length), value]);
const witnessUtxo = (sats, script) => pair(Uint8Array.of(0x01), concat([le64(sats), varint(script.length), script]));
const finalWitness = pair(Uint8Array.of(0x08), Uint8Array.of(0x01, 0x00));
const psbt = (txBytes, inputMaps, outputCount) =>
  concat([
    Uint8Array.from([0x70, 0x73, 0x62, 0x74, 0xff]),
    pair(Uint8Array.of(0x00), txBytes),
    Uint8Array.of(0x00),
    ...inputMaps.map((map) => concat([...map, Uint8Array.of(0x00)])),
    ...Array.from({ length: outputCount }, () => Uint8Array.of(0x00)),
  ]);

// Original: one sender input (100k) paying 50k to PAYMENT and 40k change.
const originalBytes = psbt(
  tx([txin(0x11, 0)], [txout(50_000, spk(PAYMENT)), txout(40_000, spk(CHANGE))]),
  [[witnessUtxo(100_000, spk(SENDER_SPK)), finalWitness]],
  2,
);
// Clean proposal: the sender input stripped, a finalized receiver input (30k)
// inserted after it, the payment output grown, change reduced by the +1k fee.
const proposalBytes = psbt(
  tx([txin(0x11, 0), txin(0x22, 1)], [txout(80_000, spk(PAYMENT)), txout(39_000, spk(CHANGE))]),
  [[], [witnessUtxo(30_000, spk(RECEIVER_SPK)), finalWitness]],
  2,
);

// --- Single-file signals in the inspect document ----------------------------

test("a proposal-shaped PSBT carries single-file payjoin signals in the inspect document", () => {
  const signals = psbtInspectDoc(proposalBytes).payjoin;
  assert.equal(signals.proposalShape, true);
  assert.deepEqual(signals.candidateReceiverInputs, [1]);
  assert.equal(signals.signal, true);
});

test("an ordinary PSBT carries no payjoin signal", () => {
  const signals = psbtInspectDoc(originalBytes).payjoin;
  assert.equal(signals.proposalShape, false);
  assert.deepEqual(signals.candidateReceiverInputs, []);
  assert.equal(signals.multiWallet, false);
  assert.equal(signals.signal, false);
});
