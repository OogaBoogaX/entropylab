import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { p2wpkh, NETWORK, OutScript, Address } from "@scure/btc-signer";
import { HDKey } from "@scure/bip32";
import { mnemonicToSeedSync } from "@scure/bip39";
import { parseRawTx, extractEcdsaSignatures, inscriptionHints, isPsbtMagic, scriptPushes } from "../src/js/tx.js";
import { indexHdKey, matchOwnership, addressFromPubkey, OWNERSHIP_GAP } from "../src/js/ownership.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const app = readFileSync(join(root, "src/js/app.js"), "utf8");
const template = readFileSync(join(root, "src/index.html"), "utf8");

const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let i = 0;
  for (const p of parts) { out.set(p, i); i += p.length; }
  return out;
};
const u32 = (n) => {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n >>> 0, true);
  return b;
};
const u64 = (n) => {
  const b = new Uint8Array(8);
  let v = BigInt(n);
  for (let i = 0; i < 8; i++) { b[i] = Number(v & 255n); v >>= 8n; }
  return b;
};
const varint = (n) => n < 253 ? Uint8Array.of(n) : Uint8Array.of(253, n & 255, n >> 8);
const slice = (bytes) => concat(varint(bytes.length), bytes);
const push = (bytes) => bytes.length <= 75 ? concat(Uint8Array.of(bytes.length), bytes) : concat(Uint8Array.of(0x4c, bytes.length), bytes);

const MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const seed = mnemonicToSeedSync(MNEMONIC, "");
const hd = HDKey.fromMasterSeed(seed);

test("BIP-84 test vector receive 0 is labeled receive", () => {
  const map = indexHdKey(hd, "mainnet", { gap: 5, accounts: 1 });
  const node = hd.derive("m/84'/0'/0'/0/0");
  const address = addressFromPubkey("p2wpkh", node.publicKey, "mainnet");
  assert.equal(address, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
  const hit = matchOwnership(map, address);
  assert.equal(hit.state, "ours");
  assert.equal(hit.role, "receive");
  assert.equal(hit.path, "m/84h/0h/0h/0/0");
});

test("BIP-84 first change address is labeled change", () => {
  const map = indexHdKey(hd, "mainnet", { gap: 5, accounts: 1 });
  const node = hd.derive("m/84'/0'/0'/1/0");
  const address = addressFromPubkey("p2wpkh", node.publicKey, "mainnet");
  assert.equal(address, "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el");
  const hit = matchOwnership(map, address);
  assert.equal(hit.state, "ours");
  assert.equal(hit.role, "change");
});

test("an unrelated address is external when a session key is loaded", () => {
  const map = indexHdKey(hd, "mainnet", { gap: 2, accounts: 1 });
  const hit = matchOwnership(map, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
  assert.equal(hit.state, "external");
});

test("no session key does not claim an output is foreign", () => {
  assert.equal(matchOwnership(new Map(), "bc1qcr8te4kr609gcawutmrqneffrxdt543n5s7zkt").state, "no-session");
});

test("parseRawTx reads a segwit one-in one-out transaction", () => {
  const der = Uint8Array.of(
    0x30, 0x44,
    0x02, 0x20, ...new Uint8Array(31).fill(0), 1,
    0x02, 0x20, ...new Uint8Array(31).fill(0), 1,
    0x01,
  );
  const pubkey = Uint8Array.of(2, ...new Uint8Array(32).fill(3));
  const spk = concat(Uint8Array.of(0, 20), new Uint8Array(20).fill(9));
  const tx = concat(
    u32(2),
    Uint8Array.of(0x00, 0x01),
    Uint8Array.of(1),
    new Uint8Array(32), u32(0), slice(new Uint8Array()), u32(0xfffffffd),
    Uint8Array.of(1),
    u64(1000), slice(spk),
    varint(2), slice(der), slice(pubkey),
    u32(0),
  );
  const parsed = parseRawTx(tx);
  assert.equal(parsed.segwit, true);
  assert.equal(parsed.inputs.length, 1);
  assert.equal(parsed.outputs.length, 1);
  assert.equal(parsed.outputs[0].amount, 1000n);
  assert.equal(parsed.inputs[0].sequence, 0xfffffffd);
  const sigs = extractEcdsaSignatures(parsed);
  assert.equal(sigs.length, 1);
  assert.equal(sigs[0].sighash, 1);
  assert.equal(sigs[0].pubkey.length, 33);
});

test("a bare DER signature with no sighash byte reports an unknown sighash", () => {
  const der = Uint8Array.of(
    0x30, 0x44,
    0x02, 0x20, ...new Uint8Array(31).fill(0), 1,
    0x02, 0x20, ...new Uint8Array(31).fill(0), 1,
  );
  const sigs = extractEcdsaSignatures({ inputs: [{ scriptSig: new Uint8Array(), witness: [der, Uint8Array.of(2, ...new Uint8Array(32).fill(3))] }] });
  assert.equal(sigs.length, 1);
  assert.equal(sigs[0].sighash, null, "no sighash byte present, so none may be reported");
  assert.deepEqual([...sigs[0].der], [...der], "the whole item is DER when no sighash byte trails it");
});

test("trailing bytes are rejected", () => {
  const spk = concat(Uint8Array.of(0x51));
  const tx = concat(
    u32(1),
    Uint8Array.of(1),
    new Uint8Array(32), u32(0), slice(new Uint8Array()), u32(0xffffffff),
    Uint8Array.of(1),
    u64(1), slice(spk),
    u32(0),
    Uint8Array.of(0xff),
  );
  assert.throws(() => parseRawTx(tx), /trailing/);
});

test("PSBT magic is detected", () => {
  assert.equal(isPsbtMagic(Uint8Array.of(0x70, 0x73, 0x62, 0x74, 0xff, 1)), true);
  assert.equal(isPsbtMagic(Uint8Array.of(2, 0, 0, 0, 0)), false);
});

test("inscription envelope in witness is flagged", () => {
  const envelope = concat(
    Uint8Array.of(0x00, 0x63),
    push(new TextEncoder().encode("ord")),
    push(Uint8Array.of(1)),
    push(new TextEncoder().encode("text/plain")),
    Uint8Array.of(0x00),
    push(new TextEncoder().encode("hi")),
    Uint8Array.of(0x68),
  );
  const spk = concat(Uint8Array.of(0x51));
  const tx = concat(
    u32(2),
    Uint8Array.of(0x00, 0x01),
    Uint8Array.of(1),
    new Uint8Array(32), u32(0), slice(new Uint8Array()), u32(0xffffffff),
    Uint8Array.of(1),
    u64(1), slice(spk),
    varint(3), slice(new Uint8Array(64)), slice(envelope), slice(new Uint8Array(33).fill(0xc0)),
    u32(0),
  );
  const parsed = parseRawTx(tx);
  const hints = inscriptionHints(parsed);
  assert.equal(hints.length, 1);
  assert.equal(hints[0].input, 0);
});

test("scriptPushes reads a P2PKH scriptSig", () => {
  const der = Uint8Array.of(0x30, 0x03, 0x02, 0x01, 0x01, 0x01);
  const pk = Uint8Array.of(2, ...new Uint8Array(32).fill(1));
  const script = concat(push(der), push(pk));
  const pushes = scriptPushes(script);
  assert.equal(pushes.length, 2);
  assert.equal(pushes[1].length, 33);
});

test("app inspects raw transactions and labels outputs", () => {
  assert.match(app, /hodlRenderRawTx/);
  assert.match(app, /hodlSessionOwnership/);
  assert.match(app, /addressFromScript/);
  assert.match(app, /not in this wallet/);
  assert.match(app, /No output belongs to this session wallet/);
  assert.match(app, /script " \+ hodlHex\.encode\(script\)/);
  assert.doesNotMatch(app, /debug fp=/);
  for (const markup of [app, template]) {
    assert.match(markup, /Read a PSBT or a signed transaction/);
    assert.match(markup, /raw transaction/);
  }
});

test("P2WPKH output scripts encode to the BIP-84 address", () => {
  const node = hd.derive("m/84'/0'/0'/0/0");
  const script = p2wpkh(node.publicKey, NETWORK).script;
  const decoded = OutScript.decode(script);
  const address = Address(NETWORK).encode(decoded);
  assert.equal(address, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
});

test("ownership matches a raw p2wpkh output script, not just the address string", () => {
  const map = indexHdKey(hd, "mainnet", { gap: 2, accounts: 1 });
  const script = p2wpkh(hd.derive("m/84'/0'/0'/1/0").publicKey, NETWORK).script;
  const hit = matchOwnership(map, Uint8Array.from(script));
  assert.equal(hit.state, "ours");
  assert.equal(hit.role, "change");
});

test("ownership gap is the documented window", () => {
  assert.equal(OWNERSHIP_GAP, 50);
});
