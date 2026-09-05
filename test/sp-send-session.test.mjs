// Issue #331: the Silent Payment send flow derives each eligible input's key
// from the loaded session root — never from a pasted scalar — resolving by
// explicit origin path or the session ownership index, verifying the derived
// key against the prevout script, and rejecting foreign fingerprints.
// Run with `npm test` (part of the default and CI suites).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { HDKey } from "../src/js/hdkey.js";
import { mnemonicToSeedSync } from "../src/js/bip39.js";
import { indexHdKey, matchOwnership } from "../src/js/ownership.js";
import { p2pkhScript, p2shP2wpkhScript, p2trKeyScript, p2wpkhScript } from "../src/js/addresses.js";
import {
  createSilentPaymentOutputs,
  deriveSilentPaymentKeys,
  encodeSilentPaymentAddress,
  extractInputPubKey,
  isP2pkh,
  isP2sh,
  isP2tr,
  isP2wpkh,
  scanSilentPaymentOutputs,
  taprootOutputPrivateKey,
  vinPrevoutScript,
  bytesToHex,
} from "../src/js/bip352.js";
import { secp256k1 } from "../src/js/secp256k1.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const app = readFileSync(join(root, "src/js/app.js"), "utf8");

function loadSlice(name) {
  const start = app.indexOf(`function ${name}(`);
  assert.ok(start >= 0, name);
  let depth = 0;
  for (let i = app.indexOf("{", start); i < app.length; i++) {
    if (app[i] === "{") depth++;
    else if (app[i] === "}") {
      depth--;
      if (depth === 0) return app.slice(start, i + 1);
    }
  }
  throw new Error(name);
}

// The session: the published empty-entropy test wallet on testnet.
const SEED = mnemonicToSeedSync("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "");
const SESSION = HDKey.fromMasterSeed(SEED); // fingerprint 73c5da0a
// Its own P2TR address at m/86'/1'/0'/0/0 (computed with the shipped WASM).
const OWNED_SCRIPT = "51203b82b2b2a9185315da6f80da5f06d0440d8a5e1457fa93387c2d919c86ec8786";

// Drive the app's resolver with the module globals it reads faked in.
const hodlSpDeriveVinKeys = new Function(
  "indexHdKey", "matchOwnership", "extractInputPubKey", "vinPrevoutScript",
  "isP2pkh", "isP2sh", "isP2tr", "isP2wpkh",
  "p2pkhScript", "p2shP2wpkhScript", "p2trKeyScript", "p2wpkhScript",
  "taprootOutputPrivateKey",
  `${loadSlice("hodlFingerprintHex")}; ${loadSlice("hodlSpDeriveVinKeys")}; return hodlSpDeriveVinKeys;`,
)(
  indexHdKey, matchOwnership, extractInputPubKey, vinPrevoutScript,
  isP2pkh, isP2sh, isP2tr, isP2wpkh,
  p2pkhScript, p2shP2wpkhScript, p2trKeyScript, p2wpkhScript,
  taprootOutputPrivateKey,
);

const vinOf = (scriptHex, extra = {}) => ({
  txid: "00".repeat(32),
  vout: 0,
  scriptSig: "",
  txinwitness: "01" + "40" + "5a".repeat(64), // one dummy 64-byte witness item
  prevout: { scriptPubKey: { hex: scriptHex } },
  ...extra,
});

const setup = () => {
  globalThis.hodlSpHd = SESSION;
  globalThis.document = { getElementById: (id) => (id === "sp-network" ? { value: "testnet" } : id === "sp-session" ? { textContent: "" } : null) };
  globalThis.hodlSpEnsureHd = () => {};
  globalThis.hodlSpNetwork = () => "testnet";
  globalThis.hodlSpBytesToHex = bytesToHex;
};

test("an owned input resolves through the ownership index, and the derived key matches the prevout", () => {
  setup();
  const [resolved] = hodlSpDeriveVinKeys([vinOf(OWNED_SCRIPT)]);
  assert.ok(resolved.private_key, "no key injected");
  const pub = secp256k1.getPublicKey(hexToBytes_(resolved.private_key), true);
  // The injected key is the key of the taproot OUTPUT key (BIP-341 tweaked,
  // as BIP-352 sending requires): its x-only public key is the prevout
  // program itself, which is what the recipient extracts from the input.
  assert.equal(bytesToHex(pub.slice(1)), OWNED_SCRIPT.slice(4));
  // Same result via an explicit path.
  const [byPath] = hodlSpDeriveVinKeys([vinOf(OWNED_SCRIPT, { path: "m/86'/1'/0'/0/0" })]);
  assert.equal(byPath.private_key, resolved.private_key);
  // And the fingerprint guard accepts the session's own fingerprint.
  const [byOrigin] = hodlSpDeriveVinKeys([vinOf(OWNED_SCRIPT, { path: "m/86'/1'/0'/0/0", fingerprint: "73c5da0a" })]);
  assert.equal(byOrigin.private_key, resolved.private_key);
});

test("session derivation refuses pasted scalars, foreign origins, and unowned scripts (issue #331)", () => {
  setup();
  assert.throws(() => hodlSpDeriveVinKeys([vinOf(OWNED_SCRIPT, { private_key: "01".repeat(32) })]), /derives each input's key from the loaded session/);
  assert.throws(() => hodlSpDeriveVinKeys([vinOf(OWNED_SCRIPT, { path: "m/86'/1'/0'/0/0", fingerprint: "deadbeef" })]), /not this session's 73c5da0a/);
  // A different session's P2TR output is not found under this session.
  const foreign = HDKey.fromMasterSeed(new Uint8Array(64).fill(9)).derive("m/86'/1'/0'/0/0");
  const foreignScript = bytesToHex(p2trKeyScript(foreign.publicKey.slice(1)));
  assert.throws(() => hodlSpDeriveVinKeys([vinOf(foreignScript)]), /not found under this session/);
  // A path that derives the wrong key for the script is a hard error.
  assert.throws(() => hodlSpDeriveVinKeys([vinOf(OWNED_SCRIPT, { path: "m/86'/1'/0'/0/1" })]), /does not produce the prevout's scriptPubKey/);
});

test("a session-resolved send equals the same inputs keyed by hand (vector-mode parity)", () => {
  setup();
  const [resolved] = hodlSpDeriveVinKeys([vinOf(OWNED_SCRIPT)]);
  const keys = deriveSilentPaymentKeys(SEED, { coinType: 1, account: 0 });
  const recipient = encodeSilentPaymentAddress(keys.scanPoint, keys.spendPoint, "tsp");
  const bySession = createSilentPaymentOutputs([resolved], [{ address: recipient, count: 1 }], { hrp: "tsp" });
  const byHand = createSilentPaymentOutputs([vinOf(OWNED_SCRIPT, { private_key: resolved.private_key })], [{ address: recipient, count: 1 }], { hrp: "tsp" });
  assert.deepEqual(bySession.outputs, byHand.outputs);
  assert.equal(bySession.outputs.length, 1);
});

test("a session send spending a tweaked P2TR input is detectable by the recipient", () => {
  // Regression: the injected key must be the key of the taproot OUTPUT key
  // (BIP-341 tweaked) — the raw internal key produced outputs scanning could
  // never find (silent funds loss), and the input-key match check rejects it.
  setup();
  const [resolved] = hodlSpDeriveVinKeys([vinOf(OWNED_SCRIPT)]);
  const keys = deriveSilentPaymentKeys(SEED, { coinType: 1, account: 0 });
  const recipient = encodeSilentPaymentAddress(keys.scanPoint, keys.spendPoint, "tsp");
  const send = createSilentPaymentOutputs([resolved], [{ address: recipient, count: 1 }], { hrp: "tsp" });
  assert.equal(send.outputs.length, 1);
  const scan = scanSilentPaymentOutputs({
    scanPriv: keys.scanPriv,
    spendPub: keys.spendPoint,
    vins: [resolved],
    outputs: send.outputs,
    labels: [],
  });
  assert.equal(scan.outputs.length, 1, "the recipient cannot detect the output: the input key is not the output key's");
});

// The library keeps raw private_key support for the published BIP-352
// vectors — the separation the issue asks for is the UI rejecting them.
test("the shell copy points at session-derived inputs, not pasted keys", () => {
  const shell = readFileSync(join(root, "src/shell.html"), "utf8");
  assert.doesNotMatch(shell, /Each eligible input needs its private key/);
  assert.match(shell, /derived from the loaded session key/);
});

function hexToBytes_(hex) {
  return new Uint8Array(hex.match(/../g).map((b) => parseInt(b, 16)));
}
