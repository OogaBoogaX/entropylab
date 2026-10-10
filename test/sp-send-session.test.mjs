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
  spendPrivForOutput,
  vinPrevoutScript,
  bytesToHex,
} from "../src/js/bip352.js";
import { secp256k1 } from "../src/js/secp256k1.js";
import { parseRecipientLines } from "../src/js/bip321.js";
import { decodeSilentPaymentAddress, p2trAddressFromXonly } from "../src/js/bip352.js";
import { tHtml, tAttr, t as tText } from "../src/js/i18n.js";
import { loadAppFunctions } from "./app-slice-harness.mjs";

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
const makeResolver = (tweak = taprootOutputPrivateKey) => new Function(
  "indexHdKey", "matchOwnership", "extractInputPubKey", "vinPrevoutScript",
  "isP2pkh", "isP2sh", "isP2tr", "isP2wpkh",
  "p2pkhScript", "p2shP2wpkhScript", "p2trKeyScript", "p2wpkhScript",
  "taprootOutputPrivateKey",
  `${loadSlice("hodlFingerprintHex")}; ${loadSlice("hodlSpWipeVinKeys")}; ${loadSlice("hodlSpDeriveVinKeys")}; return hodlSpDeriveVinKeys;`,
)(
  indexHdKey, matchOwnership, extractInputPubKey, vinPrevoutScript,
  isP2pkh, isP2sh, isP2tr, isP2wpkh,
  p2pkhScript, p2shP2wpkhScript, p2trKeyScript, p2wpkhScript,
  tweak,
);
const hodlSpDeriveVinKeys = makeResolver();
const hodlSpWipeVinKeys = new Function(`${loadSlice("hodlSpWipeVinKeys")}; return hodlSpWipeVinKeys;`)();

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
  assert.ok(resolved.private_key instanceof Uint8Array);
  assert.equal(resolved.private_key.length, 32);
  const pub = secp256k1.getPublicKey(resolved.private_key, true);
  // The injected key is the key of the taproot OUTPUT key (BIP-341 tweaked,
  // as BIP-352 sending requires): its x-only public key is the prevout
  // program itself, which is what the recipient extracts from the input.
  assert.equal(bytesToHex(pub.slice(1)), OWNED_SCRIPT.slice(4));
  // Same result via an explicit path.
  const [byPath] = hodlSpDeriveVinKeys([vinOf(OWNED_SCRIPT, { path: "m/86'/1'/0'/0/0" })]);
  assert.deepEqual(byPath.private_key, resolved.private_key);
  // And the fingerprint guard accepts the session's own fingerprint.
  const [byOrigin] = hodlSpDeriveVinKeys([vinOf(OWNED_SCRIPT, { path: "m/86'/1'/0'/0/0", fingerprint: "73c5da0a" })]);
  assert.deepEqual(byOrigin.private_key, resolved.private_key);
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
    vins: [vinOf(OWNED_SCRIPT)],
    outputs: send.outputs,
    labels: [],
  });
  assert.equal(scan.outputs.length, 1, "the recipient cannot detect the output: the input key is not the output key's");
  const spend = spendPrivForOutput(keys.spendPriv, scan.outputs[0].priv_key_tweak);
  try { assert.equal(bytesToHex(secp256k1.getPublicKey(spend, true).slice(1)), send.outputs[0]); }
  finally { spend.fill(0); hodlSpWipeVinKeys([resolved]); }
  // Current rock already rejects the old untweaked input. Keep that guard;
  // a pre-guard sender would use the internal public key in its ECDH sum.
  const node = SESSION.derive("m/86'/1'/0'/0/0");
  try {
    assert.throws(() => createSilentPaymentOutputs([vinOf(OWNED_SCRIPT, {private_key: node.privateKey})], [{address: recipient}], {hrp:"tsp"}), /does not match/);
    // Emulate the old sender's internal-key ECDH via a synthetic internal-key
    // prevout; scan against the REAL tweaked prevout, which must find nothing.
    const old = createSilentPaymentOutputs([vinOf("5120" + bytesToHex(node.publicKey.slice(1)), {private_key: node.privateKey})], [{address: recipient}], {hrp:"tsp"});
    assert.equal(scanSilentPaymentOutputs({scanPriv:keys.scanPriv, spendPub:keys.spendPoint, vins:[vinOf(OWNED_SCRIPT)], outputs:old.outputs}).outputs.length, 0);
  } finally { node.wipePrivateData(); }
});

// The library keeps raw private_key support for the published BIP-352
// vectors — the separation the issue asks for is the UI rejecting them.
test("the shell copy points at session-derived inputs, not pasted keys", () => {
  const shell = readFileSync(join(root, "src/shell.html"), "utf8");
  assert.doesNotMatch(shell, /Each eligible input needs its private key/);
  assert.match(shell, /derived from the loaded session key/);
});



test("partial resolution wipes earlier copies and leaves the session usable", () => {
  setup(); const copies=[];
  const resolve=makeResolver(key=>{const copy=taprootOutputPrivateKey(key);copies.push(copy);return copy;});
  assert.throws(()=>resolve([vinOf(OWNED_SCRIPT),vinOf(OWNED_SCRIPT,{fingerprint:"deadbeef"})]),/not this session/);
  assert.equal(copies.length,1);
  assert.ok(copies[0].every(b=>b===0));
  const resolved=resolve([vinOf(OWNED_SCRIPT)]);
  assert.ok(resolved[0].private_key.some(b=>b!==0));
  hodlSpWipeVinKeys(resolved);
  assert.ok(copies.every(copy=>copy.every(b=>b===0)));
});

// Issue #389: HDKey.privateKey returns a fresh copy on every read, and the
// resolver used to read it twice (existence check, then the tweak/copy for
// the resolved scalar) — node.wipePrivateData() can never reach those copies.
test("the sender-key wipe covers every privateKey getter copy (issue #389)", () => {
  setup();
  const retained = [];
  const original = Object.getOwnPropertyDescriptor(HDKey.prototype, "privateKey");
  Object.defineProperty(HDKey.prototype, "privateKey", {
    configurable: true,
    get() {
      const copy = original.get.call(this);
      if (copy) retained.push(copy);
      return copy;
    },
  });
  try {
    const [resolved] = hodlSpDeriveVinKeys([vinOf(OWNED_SCRIPT)]);
    assert.ok(resolved.private_key.some((b) => b !== 0), "the resolved scalar is live until the vin wipe");
    assert.equal(retained.length, 1, "one getter read per resolution, not one per use");
    assert.ok(retained[0].every((b) => b === 0), "the single retained copy is wiped after the tweak is built");
    hodlSpWipeVinKeys([resolved]);
    assert.ok(resolved.private_key.every((b) => b === 0));
    // Same guarantee on a non-Taproot input, where the resolved scalar is a
    // straight copy of the getter's buffer.
    retained.length = 0;
    const path = "m/84'/1'/0'/0/0", pub = SESSION.derive(path).publicKey;
    const [plain] = hodlSpDeriveVinKeys([vinOf(bytesToHex(p2wpkhScript(pub)), { path, txinwitness: "0121" + bytesToHex(pub) })]);
    assert.equal(retained.length, 1);
    assert.ok(retained[0].every((b) => b === 0), "the getter copy is wiped even though the resolved scalar outlives it");
    assert.ok(plain.private_key.some((b) => b !== 0));
    hodlSpWipeVinKeys([plain]);
  } finally {
    Object.defineProperty(HDKey.prototype, "privateKey", original);
  }
});

test("UI construction wipes byte keys on success and throw, and suppresses the scalar sum", () => {
  setup();
  for(const fail of [false,true]){
    let saved;
    const render=new Function("hodlSpParseRecipients","hodlSpHrp","decodeSilentPaymentAddress","hodlSpParseVins","hodlSpDeriveVinKeys","hodlSpWipeVinKeys","createSilentPaymentOutputs",
      `${loadSlice("hodlRenderSpSend")}; return hodlRenderSpSend;`)(
      ()=>({recipients:[]}),()=>"tsp",()=>{},()=>[vinOf(OWNED_SCRIPT)],hodlSpDeriveVinKeys,hodlSpWipeVinKeys,
      (vins,recipients,options)=>{saved=vins;assert.equal(options.includePrivateKeySum,false);if(fail)throw new Error("construction failed");return {outputs:[]};});
    const original=document.getElementById;document.getElementById=id=>id==="sp-out"?{}:original(id);
    if(fail)assert.throws(render,/construction failed/);else render();
    assert.ok(saved[0].private_key.every(b=>b===0));
  }
});

test("SP send discloses unused fallback text safely and keeps the published outputs (#399 F4)", async () => {
  const vector = JSON.parse(readFileSync(join(root, "test/fixtures/bip352-send-and-receive.json"), "utf8"))[0].sending[0];
  const sp = vector.given.recipients[0].address;
  const fallback = "175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"; // BIP-321 example
  const output = { innerHTML: "" };
  const recipients = { value: "" };
  const document = { getElementById: (id) => id === "sp-out" ? output : id === "sp-recipients" ? recipients : null };
  let actualOutputs;
  // Run the app's real renderer and parser against published BIP-352 inputs.
  // Only session-key lookup is replaced: these are fixed public test scalars.
  const readouts = await loadAppFunctions(["hodlPublicInlineHtml", "hodlSpCopyGroupHtml"]);
  const render = new Function(
    "document", "hodlSpParseRecipients", "hodlSpHrp", "hodlSpNetwork", "decodeSilentPaymentAddress",
    "hodlSpParseVins", "hodlSpDeriveVinKeys", "hodlSpWipeVinKeys", "createSilentPaymentOutputs",
    "p2trAddressFromXonly", "hodlT", "hodlTAttr", "hodlTText", "hodlPublicInlineHtml", "hodlSpCopyGroupHtml",
    `${loadSlice("hodlSpEscape")}; ${loadSlice("hodlRenderSpSend")}; return hodlRenderSpSend;`,
  )(
    document, parseRecipientLines, () => "sp", () => "mainnet", decodeSilentPaymentAddress,
    () => vector.given.vin, (vins) => vins, hodlSpWipeVinKeys,
    (vins, rows, options) => {
      const result = createSilentPaymentOutputs(vins, rows, options);
      actualOutputs = result.outputs;
      return result;
    },
    p2trAddressFromXonly, tHtml, tAttr, tText, readouts.hodlPublicInlineHtml, readouts.hodlSpCopyGroupHtml,
  );
  for (const path of ["", fallback, '<img src=x onerror="alert(1)">']) {
    recipients.value = `bitcoin:${path}?sp=${sp}`;
    render();
    assert.deepEqual(actualOutputs, vector.expected.outputs[0], "fallback metadata must not affect outputs");
    if (path) {
      assert.match(output.innerHTML, /not used/i); // Safety disclosure, not full presentation copy.
      if (path === fallback) assert.ok(output.innerHTML.includes(fallback));
      else {
        assert.ok(output.innerHTML.includes("&lt;img"), "untrusted fallback must be rendered as text");
        assert.ok(!output.innerHTML.includes("<img"), "untrusted fallback must not become markup");
      }
    } else {
      assert.doesNotMatch(output.innerHTML, /not used/i);
    }
  }
  recipients.value = `bitcoin:?sp=${sp}`;
  render();
  assert.doesNotMatch(output.innerHTML, /not used/i, "a later plain URI must not retain the fallback warning");
});

test("non-Taproot session scalars retain their exact bytes", () => {
  setup();
  const path="m/84'/1'/0'/0/0", node=SESSION.derive(path), pub=node.publicKey;
  try {
    for(const [script,scriptSig,witness] of [
      [p2pkhScript(pub),"21"+bytesToHex(pub),""],
      [p2wpkhScript(pub),"","0121"+bytesToHex(pub)],
      [p2shP2wpkhScript(pub),"16"+bytesToHex(p2wpkhScript(pub)),"0121"+bytesToHex(pub)],
    ]){
      const vins=hodlSpDeriveVinKeys([vinOf(bytesToHex(script),{path,scriptSig,txinwitness:witness})]);
      assert.deepEqual(vins[0].private_key,node.privateKey);
      hodlSpWipeVinKeys(vins);
    }
  } finally {node.wipePrivateData();}
});

test("UI send mode never returns the private scalar sum", () => {
  setup();const vins=hodlSpDeriveVinKeys([vinOf(OWNED_SCRIPT)]);
  const keys=deriveSilentPaymentKeys(SEED,{coinType:1});const address=encodeSilentPaymentAddress(keys.scanPoint,keys.spendPoint,"tsp");
  try{
    for(const count of [1,2324]){
      const result=createSilentPaymentOutputs(vins,[{address,count}],{hrp:"tsp",includePrivateKeySum:false});
      assert.equal(result.inputPrivateKeySum,null);
    }
  }finally{hodlSpWipeVinKeys(vins);}
});

test("P2TR tweak matches BIP-86 output scripts for both internal parities", () => {
  const parities = new Set();
  for (const n of [1, 6]) {
    const secret = new Uint8Array(32); secret[31] = n;
    const pub = secp256k1.getPublicKey(secret, true);
    parities.add(pub[0]);
    const tweaked = taprootOutputPrivateKey(secret);
    try {
      assert.equal(bytesToHex(secp256k1.getPublicKey(tweaked, true).slice(1)), bytesToHex(p2trKeyScript(pub.slice(1))).slice(4));
      assert.equal(secret[31], n, "tweaking must not mutate the caller's key");
    } finally { secret.fill(0); tweaked.fill(0); }
  }
  assert.deepEqual([...parities].sort(), [2, 3]);
});
