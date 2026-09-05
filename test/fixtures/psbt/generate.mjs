// Deterministic PSBT v0 fixtures for exercising the PSBT editor UI (the
// mempool.space-style flow diagram and the key-value maps). Run with
// `node test/fixtures/psbt/generate.mjs` to (re)write the .b64 files next to
// this script; test/psbt-fixtures.test.mjs proves the committed files match
// this generator byte for byte and that every fixture parses cleanly.
//
// Nothing here is random, per CONTRIBUTING.md: keys are the public test
// private keys 1, 2 and 3 (their public keys are published constants used
// across Bitcoin Core's own tests), txids/hashes/signatures are fixed byte
// patterns, and the one published BIP-174 vector is embedded verbatim. The
// signatures are structurally valid DER/Schnorr byte strings so the typed
// decodes render — they sign nothing and validate nowhere.
import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { sha256 } from "@noble/hashes/sha2.js";
import { ripemd160 } from "@noble/hashes/legacy.js";
import { secp256k1 } from "../../../src/js/secp256k1.js";
import { psbtBuildBytes } from "../../../src/js/psbt-wasm.js";

const bytesToHex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
const hexToBytes = (hex) => {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
};

// Little-endian scalar and compact-size encoders (all values here are small
// enough for the one-byte compact-size form; assert rather than widen).
const le32 = (n) => bytesToHex(new Uint8Array(new Uint32Array([n >>> 0]).buffer));
const le64 = (n) => bytesToHex(new Uint8Array(new BigUint64Array([BigInt(n)]).buffer));
const varint = (n) => {
  if (n >= 0xfd) throw new Error("fixture too long for a one-byte compact size");
  return n.toString(16).padStart(2, "0");
};

const sha256Hex = (hex) => bytesToHex(sha256(hexToBytes(hex)));
const hash160 = (hex) => bytesToHex(ripemd160(sha256(hexToBytes(hex))));

// --- Keys and scripts -------------------------------------------------------
// Public test keys: secp256k1 pubkeys for the private keys 1, 2, 3.
const pub = (n) => bytesToHex(secp256k1.getPublicKey(hexToBytes(n.toString(16).padStart(64, "0"))));
const pk1 = pub(1n), pk2 = pub(2n), pk3 = pub(3n);
const xo1 = pk1.slice(2), xo2 = pk2.slice(2), xo3 = pk3.slice(2); // x-only (BIP-340) forms

const p2pkh = (pubkey) => `76a914${hash160(pubkey)}88ac`;
const p2wpkh = (pubkey) => `0014${hash160(pubkey)}`;
const p2sh = (script) => `a914${hash160(script)}87`;
const p2wsh = (script) => `0020${sha256Hex(script)}`;
const p2tr = (xonly) => `5120${xonly}`;
const opReturn = (text) => `6a${varint(text.length)}${bytesToHex(new TextEncoder().encode(text))}`;
// 2-of-3 bare multisig, the classic P2WSH witness script.
const multisig2of3 = `52${["21" + pk1, "21" + pk2, "21" + pk3].join("")}53ae`;

// --- PSBT pair values -------------------------------------------------------
const witnessUtxo = (sats, script) => le64(sats) + varint(script.length / 2) + script;
const HARD = 0x80000000;
const bip32Path = (fingerprint, path) => fingerprint + path.map((index) => le32(index)).join("");
const FP = "12345678"; // obvious test fingerprint, not a real key's
// DER-shaped ECDSA signature (fixed byte patterns) plus the sighash byte.
const ecdsaSig = (r, s, sighash = "01") => `30440220${r}0220${s}${sighash}`;
const R = (byte) => byte.repeat(32);
const tapKeySig = R("5a") + R("6b"); // 64-byte Schnorr-shaped, SIGHASH_DEFAULT

// A whole previous transaction paying `sats` to `script` on output 0, for the
// one fixture that carries a non-witness UTXO. Its input points at a fixed
// pattern — the point is the decode, not a chain.
const prevTx = (sats, script) =>
  le32(2) + "01" + R("99") + le32(0) + "00" + "ffffffff" + "01" + le64(sats) + varint(script.length / 2) + script + le32(0);
// rust-bitcoin displays txids reversed from the wire order; the editor
// document (and so this generator) uses the display form.
const displayTxid = (txHex) => bytesToHex(Uint8Array.from(hexToBytes(sha256Hex(sha256Hex(txHex)))).reverse());

// --- Editor-document assembly (the same shape psbtBuildBytes consumes) ------
const txin = (txid, vout, sequence = 4294967295) => ({ txid, vout, scriptSig: "", sequence });
const txout = (value, scriptPubKey) => ({ value, scriptPubKey });
const pair = (key, value) => ({ key, value });
const doc = (tx, globals, inputs, outputs) => ({ tx, globals, inputs, outputs });

// Hand-assembled PSBT v0 bytes for shapes the build gate refuses on purpose
// (consensus-invalid transactions, e.g. zero outputs — issues #322/#361).
// The fixture exists to prove inspection still parses and reports them.
const rawTx = (version, inputs, outputs, locktime) =>
  le32(version) +
  varint(inputs.length) + inputs.map((i) => bytesToHex(Uint8Array.from(hexToBytes(i.txid)).reverse()) + le32(i.vout) + "00" + le32(i.sequence)).join("") +
  varint(outputs.length) + outputs.map((o) => le64(o.value) + varint(o.scriptPubKey.length / 2) + o.scriptPubKey).join("") +
  le32(locktime);
const rawPsbt = (txHex, inputMaps, outputMaps = []) =>
  "70736274ff" + "01" + "00" + varint(txHex.length / 2) + txHex + "00" +
  [...inputMaps, ...outputMaps]
    .map((map) => map.map((p) => varint(p.key.length / 2) + p.key + varint(p.value.length / 2) + p.value).join("") + "00")
    .join("");

// BIP-174 valid vector 2, verbatim: two inputs (a finalized P2PKH scriptSig
// with no amount claim, and a nested P2WPKH with a 100000000-sat witness
// UTXO) and two P2PKH outputs. The one fixture that is not generated.
const BIP174_VECTOR_2_HEX =
  "70736274ff0100a00200000002ab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40000000000feffffff" +
  "ab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40100000000feffffff02603bea0b000000001976a914768a40" +
  "bbd740cbe81d988e71de2a4d5c71396b1d88ac8e240000000000001976a9146f4620b553fa095e721b9ee0efe9fa039cca459788ac00000000" +
  "0001076a47304402204759661797c01b036b25928948686218347d89864b719e1f7fcf57d1e511658702205309eabf56aa4d8891ffd111fdf133" +
  "6f3a29da866d7f8486d75546ceedaf93190121035cdc61fc7ba971c0b501a646a2a83b102cb43881217ca682dc86e2d73fa882920001012000e1" +
  "f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787010416001485d13537f2e265405a34dbafa9e3dda01fb82308000000";

// A syntactically valid xpub (version, depth, parent fingerprint, child,
// chaincode, key) around pk1 with fixed filler — exists so the global map
// has something to decode; it is nobody's account key.
const TEST_XPUB = "0488b21e" + "02" + FP + le32(HARD) + R("cc") + pk1;

const FIXTURES = [
  {
    name: "bip174-valid-vector-2",
    description: "Published BIP-174 vector: finalized no-claim input + P2SH-P2WPKH claim; two P2PKH outputs.",
    fixedHex: BIP174_VECTOR_2_HEX,
    expect: { inputs: 2, outputs: 2, fee: "unknown" },
  },
  {
    name: "p2wpkh-1in-2out",
    description: "Vanilla wallet spend: one P2WPKH input with claim, BIP-32 path, partial signature and sighash; payment + change with a global xpub.",
    doc: doc(
      { version: 2, locktime: 0, inputs: [txin(R("11"), 0)], outputs: [txout(1400000, p2wpkh(pk2)), txout(100000, p2wpkh(pk3))] },
      [pair("01" + TEST_XPUB, bip32Path(FP, [84 + HARD, 0 + HARD]))],
      [[
        pair("01", witnessUtxo(1523456, p2wpkh(pk1))),
        pair("02" + pk1, ecdsaSig(R("11"), R("22"))),
        pair("03", "01000000"),
        pair("06" + pk1, bip32Path(FP, [84 + HARD, 0 + HARD, 0 + HARD, 0, 0])),
      ]],
      [[], [pair("02" + pk3, bip32Path(FP, [84 + HARD, 0 + HARD, 0 + HARD, 1, 0]))]],
    ),
    expect: { inputs: 1, outputs: 2, fee: "known" },
  },
  {
    name: "p2tr-taproot",
    description: "BIP-371: two P2TR inputs (one key signature + tap derivation, one internal key only), P2TR output and a zero-value OP_RETURN.",
    doc: doc(
      { version: 2, locktime: 0, inputs: [txin(R("22"), 1), txin(R("33"), 0)], outputs: [txout(900000, p2tr(xo2)), txout(0, opReturn("EntropyLab fixture"))] },
      [],
      [
        [
          pair("01", witnessUtxo(500000, p2tr(xo1))),
          pair("13", tapKeySig),
          pair("16" + xo1, "00" + bip32Path(FP, [86 + HARD, 0 + HARD, 0 + HARD, 0, 0])),
        ],
        [pair("01", witnessUtxo(450000, p2tr(xo3))), pair("17", xo3)],
      ],
      [[pair("07" + xo2, "00" + bip32Path(FP, [86 + HARD, 0 + HARD, 0 + HARD, 1, 0]))], []],
    ),
    expect: { inputs: 2, outputs: 2, fee: "known" },
  },
  {
    name: "multisig-2of3-p2wsh",
    description: "2-of-3 P2WSH vault: two inputs with witness scripts, one carrying two partial signatures, paying back into the same script.",
    doc: doc(
      { version: 2, locktime: 0, inputs: [txin(R("44"), 0), txin(R("55"), 1)], outputs: [txout(85000, p2wsh(multisig2of3)), txout(5000, p2pkh(pk2))] },
      [],
      [
        [
          pair("01", witnessUtxo(60000, p2wsh(multisig2of3))),
          pair("05", multisig2of3),
          pair("02" + pk1, ecdsaSig(R("33"), R("44"))),
          pair("02" + pk2, ecdsaSig(R("55"), R("66"))),
          pair("06" + pk1, bip32Path(FP, [48 + HARD, 0 + HARD, 0 + HARD, 2 + HARD, 0, 0])),
          pair("06" + pk2, bip32Path(FP, [48 + HARD, 0 + HARD, 0 + HARD, 2 + HARD, 0, 1])),
        ],
        [
          pair("01", witnessUtxo(40000, p2wsh(multisig2of3))),
          pair("05", multisig2of3),
          pair("06" + pk3, bip32Path(FP, [48 + HARD, 0 + HARD, 0 + HARD, 2 + HARD, 0, 2])),
        ],
      ],
      [[], []],
    ),
    expect: { inputs: 2, outputs: 2, fee: "known" },
  },
  {
    name: "no-amount-claims",
    description: "Two inputs with no UTXO pairs at all: every box reads 'no amount claim' and the fee is unknown.",
    doc: doc(
      { version: 2, locktime: 0, inputs: [txin(R("66"), 0), txin(R("77"), 2)], outputs: [txout(21000, p2wpkh(pk1)), txout(42000, p2sh(p2wpkh(pk3)))] },
      [],
      [[], [pair("06" + pk2, bip32Path(FP, [49 + HARD, 0 + HARD, 0 + HARD, 0, 5]))]],
      [[], []],
    ),
    expect: { inputs: 2, outputs: 2, fee: "unknown" },
  },
  {
    name: "outputs-exceed-inputs",
    description: "One 5000-sat claim against two 3000-sat outputs: the negative-fee warning state.",
    doc: doc(
      { version: 2, locktime: 0, inputs: [txin(R("88"), 0)], outputs: [txout(3000, p2wpkh(pk2)), txout(3000, p2wpkh(pk3))] },
      [],
      [[pair("01", witnessUtxo(5000, p2wpkh(pk1)))]],
      [[], []],
    ),
    expect: { inputs: 1, outputs: 2, fee: "exceeds" },
  },
  {
    name: "mixed-many-inputs",
    description: "Five-input fan-in: P2PKH via full previous transaction, signed P2WPKH, P2TR, 2-of-3 P2WSH with an ANYONECANPAY sighash, and a finalized P2WPKH.",
    doc: (() => {
      const prev = prevTx(250000, p2pkh(pk1));
      return doc(
        {
          version: 2, locktime: 0,
          inputs: [txin(displayTxid(prev), 0), txin(R("aa"), 1), txin(R("bb"), 0), txin(R("cc"), 3), txin(R("dd"), 2)],
          outputs: [txout(500000, p2tr(xo2)), txout(50000, p2pkh(pk3))],
        },
        [],
        [
          [pair("00", prev), pair("06" + pk1, bip32Path(FP, [44 + HARD, 0 + HARD, 0 + HARD, 0, 12]))],
          [pair("01", witnessUtxo(80000, p2wpkh(pk2))), pair("02" + pk2, ecdsaSig(R("77"), R("88")))],
          [pair("01", witnessUtxo(120000, p2tr(xo1))), pair("13", tapKeySig)],
          [
            pair("01", witnessUtxo(60000, p2wsh(multisig2of3))),
            pair("05", multisig2of3),
            pair("02" + pk1, ecdsaSig(R("11"), R("99"), "81")), // SIGHASH_ALL | ANYONECANPAY: the warn tone
          ],
          [pair("01", witnessUtxo(55000, p2wpkh(pk3))), pair("08", "02" + "47" + ecdsaSig(R("33"), R("55")) + "21" + pk3)],
        ],
        [[], []],
      );
    })(),
    expect: { inputs: 5, outputs: 2, fee: "known" },
  },
  {
    name: "fan-out-6-outputs",
    description: "One input paying one of each script template plus a data-carrier: every output tag and a six-curve fan-out.",
    doc: doc(
      {
        version: 2, locktime: 0,
        inputs: [txin(R("ee"), 0)],
        outputs: [
          txout(11111111, p2pkh(pk1)),
          txout(22222222, p2wpkh(pk2)),
          txout(33333333, p2sh(p2wpkh(pk3))),
          txout(44444444, p2tr(xo1)),
          txout(55555555, p2wsh(multisig2of3)),
          txout(0, opReturn("PSBT fixture 8")),
        ],
      },
      [],
      [[pair("01", witnessUtxo(199999999, p2wpkh(pk1))), pair("02" + pk1, ecdsaSig(R("44"), R("55")))]],
      [
        [pair("02" + pk1, bip32Path(FP, [84 + HARD, 0 + HARD, 0 + HARD, 0, 0]))],
        [pair("02" + pk2, bip32Path(FP, [84 + HARD, 0 + HARD, 0 + HARD, 0, 1]))],
        [],
        [pair("07" + xo1, "00" + bip32Path(FP, [86 + HARD, 0 + HARD, 0 + HARD, 0, 2]))],
        [],
        [],
      ],
    ),
    expect: { inputs: 1, outputs: 6, fee: "known" },
  },
  {
    name: "locktime-rbf",
    description: "Version 2, locktime 850000, RBF sequence: a small timelocked payment.",
    doc: doc(
      { version: 2, locktime: 850000, inputs: [txin(R("ff"), 5, 4294967293)], outputs: [txout(40000, p2wpkh(pk1))] },
      [],
      [[pair("01", witnessUtxo(42000, p2wpkh(pk2))), pair("06" + pk2, bip32Path(FP, [84 + HARD, 0 + HARD, 0 + HARD, 0, 7]))]],
      [[]],
    ),
    expect: { inputs: 1, outputs: 1, fee: "known" },
  },
  {
    // A zero-input PSBT cannot exist: transaction consensus encoding rejects
    // it (the 0x00 input count collides with the segwit marker), so the
    // diagram's "No inputs." state is unreachable from a real file. And since
    // the build gate enforces CheckTransaction sanity (issues #322/#361), the
    // zero-output file below is hand-assembled: the editor can inspect it,
    // name it consensus-invalid, and must never emit it.
    name: "no-outputs",
    description: "One input, zero outputs, no pairs: the diagram's empty-column state.",
    fixedHex: rawPsbt(
      rawTx(2, [txin(R("ab"), 0)], [], 0),
      [[pair("01", witnessUtxo(75000, p2wpkh(pk1)))]],
    ),
    expect: { inputs: 1, outputs: 0, fee: "known" },
  },
];

export const buildFixtures = () =>
  FIXTURES.map((fixture) => {
    try {
      return { ...fixture, bytes: fixture.fixedHex ? hexToBytes(fixture.fixedHex) : psbtBuildBytes(fixture.doc) };
    } catch (exception) {
      throw new Error(`${fixture.name}: ${exception.message}`);
    }
  });

const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
  const dir = dirname(fileURLToPath(import.meta.url));
  for (const fixture of buildFixtures()) {
    writeFileSync(join(dir, `${fixture.name}.b64`), `${Buffer.from(fixture.bytes).toString("base64")}\n`);
    console.log(`${fixture.name}.b64 — ${fixture.description}`);
  }
}
