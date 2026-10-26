// Tests for the Lightning key worker (issue #653): the shipped worker
// string (scripts/ln-worker-source.mjs, which scripts/build.mjs injects as
// __LN_WORKER_SOURCE__) runs under node:worker_threads, and the page side
// (src/js/lightning.js) runs over the mini DOM against the same worker.
//
// Security contract: every Lightning derivation (LND aezeed, LDK BIP-39,
// CLN hsm_secret) runs inside the terminable worker; the worker alone holds
// the decoded entropy, salt, seeds, xprvs and the CLN mnemonic; the page
// receives public fields only (the secret text only while revealed); Clear
// and a format or network change ask the worker to scrub its secrets and
// its WebAssembly memory, then terminate it (on the "scrubbed" answer or a
// short bound); and an answer whose run id is stale is ignored.
//
// Expected values come from the pinned reference libraries (@scure/bip32,
// @scure/bip39) and the CLN v26.06.9 vectors already pinned in
// test/lightning.test.mjs and test/hsm-secret.test.mjs — never from the
// code under test.
// Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { Worker } from "node:worker_threads";
import { HDKey as ScureHDKey } from "@scure/bip32";
import { mnemonicToSeedSync as scureMnemonicToSeed } from "@scure/bip39";
import { MiniDocument } from "./mini-dom.mjs";
import * as wasmLoader from "../src/js/entropylab-wasm.js";
import * as ln from "../src/js/lightning.js";

// The published aezeed characterization mnemonic (test/aezeed-wasm.test.mjs,
// test/lightning.test.mjs): it deciphers to the entropy bytes 00..0f.
const AEZEED_WORDS =
  "ability result leisure oven shiver wedding toe broccoli exclude " +
  "mosquito kind van action waste merit bundle robust source able " +
  "advice core humor kitchen siren";
const AEZEED_ENTROPY_HEX = "000102030405060708090a0b0c0d0e0f";
// The BIP39 test vector (test/lightning.test.mjs).
const LDK_WORDS = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
// CLN v26.06.9, tests/test_wallet.py (test/hsm-secret.test.mjs).
const CLN_WORDS = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const CLN_NODE_ID = "03653e90c1ce4660fd8505dd6d643356e93cfe202af109d382787639dd5890e87d";
const CLN_DESCRIPTORS = [
  "wpkh(xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ/0/*)#hjszq0wk",
  "sh(wpkh(xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ/0/*))#u0t3u3xz",
  "tr(xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ/0/*)#8e7pq23w",
];

const hexToBytes = (text) => new Uint8Array(text.match(/.{2}/g).map((byte) => parseInt(byte, 16)));
const bytesToHex = (bytes) => [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");

// Reference values from the pinned @scure libraries (the same references
// test/lightning.test.mjs checks the derivations against).
const lndExpected = (coinType) => {
  const master = ScureHDKey.fromMasterSeed(hexToBytes(AEZEED_ENTROPY_HEX));
  return { nodePubKey: bytesToHex(master.derive(`m/1017'/${coinType}'/6'/0/0`).publicKey), rootXprv: master.privateExtendedKey };
};
const ldkExpected = () => {
  const master1 = ScureHDKey.fromMasterSeed(scureMnemonicToSeed(LDK_WORDS, ""));
  const node = ScureHDKey.fromMasterSeed(master1.privateKey).deriveChild(0x80000000);
  return { nodePubKey: bytesToHex(node.publicKey), rootXprv: master1.privateExtendedKey };
};
const clnAccount = () => ScureHDKey.fromMasterSeed(scureMnemonicToSeed(CLN_WORDS, "")).derive("m/86'/0'/0'");

const lndMainnet = lndExpected(0);
const lndTestnet = lndExpected(1);
const ldk = ldkExpected();
const clnXprv = clnAccount().privateExtendedKey;

// The test's own bech32 encoder (the one test/lightning.test.mjs validated
// against the BIP173 example), so the expected addresses do not come from
// the code under test.
const BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const bech32Polymod = (values) => {
  const generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let checksum = 1;
  for (const value of values) {
    const top = checksum >>> 25;
    checksum = ((checksum & 0x1ffffff) << 5) ^ value;
    for (let i = 0; i < 5; i++) if ((top >>> i) & 1) checksum ^= generator[i];
  }
  return checksum;
};
const bech32Encode = (hrp, data) => {
  const expanded = [];
  for (const char of hrp) expanded.push(char.charCodeAt(0) >> 5);
  expanded.push(0);
  for (const char of hrp) expanded.push(char.charCodeAt(0) & 31);
  const mod = bech32Polymod([...expanded, ...data, 0, 0, 0, 0, 0, 0]) ^ 1;
  const checksum = [];
  for (let i = 0; i < 6; i++) checksum.push((mod >>> (5 * (5 - i))) & 31);
  return `${hrp}1${[...data, ...checksum].map((value) => BECH32_CHARSET[value]).join("")}`;
};
const convertBits = (bytes, from, to, pad) => {
  let accumulator = 0;
  let bits = 0;
  const out = [];
  const maxValue = (1 << to) - 1;
  for (const byte of bytes) {
    accumulator = (accumulator << from) | byte;
    bits += from;
    while (bits >= to) {
      bits -= to;
      out.push((accumulator >> bits) & maxValue);
    }
  }
  if (pad && bits > 0) out.push((accumulator << (to - bits)) & maxValue);
  return out;
};
const hash160 = (bytes) => {
  const sha = createHash("sha256").update(bytes).digest();
  return new Uint8Array(createHash("ripemd160").update(sha).digest());
};
const p2wpkh = (publicKey, hrp) => bech32Encode(hrp, [0, ...convertBits(hash160(publicKey), 8, 5, true)]);
const clnExpectedAddresses = (network) => {
  const chain = clnAccount().deriveChild(0);
  const hrp = network === "testnet" ? "tb" : "bc";
  return Array.from({ length: 10 }, (_, index) => p2wpkh(chain.deriveChild(index).publicKey, hrp));
};

// A type-2 hsm_secret: 32 zero bytes (the "no passphrase" marker) followed by
// the mnemonic text, exactly as `lightning-hsmtool generatehsm` writes it.
const clnType2File = (mnemonic) => {
  const words = new TextEncoder().encode(mnemonic);
  const file = new Uint8Array(32 + words.length);
  file.set(words, 32);
  return file;
};

test("the test's bech32 encoder matches the BIP173 example", () => {
  const publicKey = hexToBytes("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
  assert.equal(p2wpkh(publicKey, "bc"), "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
});

// ── The shipped worker string, under node:worker_threads ────────────────────

// The worker source the build ships; absent before the key worker lands,
// which is the failure the worker tests name.
let workerSource = null;
try {
  workerSource = await (await import("../scripts/ln-worker-source.mjs")).buildLnWorkerSource();
} catch {
  // No key worker in this tree: the worker tests fail on the missing source.
}
// node:worker_threads has no `self`; the prelude adapts the Web Worker
// surface the shipped string expects, so the identical string is what runs.
const PRELUDE = `"use strict";
const { parentPort } = require("worker_threads");
globalThis.self = globalThis;
globalThis.postMessage = (message) => parentPort.postMessage(message);
parentPort.on("message", (data) => globalThis.self.onmessage && globalThis.self.onmessage({ data }));
`;
class NodeWebWorker {
  constructor() {
    this.inner = new Worker(PRELUDE + workerSource, { eval: true });
    this.onmessage = null;
    this.onerror = null;
    this.terminated = false;
    this.run = null; // the run of the last request the page sent
    this.inner.on("message", (data) => this.onmessage?.({ data }));
    this.inner.on("error", (error) => this.onerror?.(error));
  }
  postMessage(message, transfer) {
    if (message && message.run !== undefined) this.run = message.run;
    this.inner.postMessage(message, transfer);
  }
  terminate() {
    this.terminated = true;
    return this.inner.terminate();
  }
}

// One worker, one exchange: init (with the module bytes, as the page sends
// them), then the requests; resolves with the non-ready answers.
async function ask(messages) {
  assert.ok(workerSource, "the build ships no Lightning key worker");
  const worker = new NodeWebWorker();
  try {
    const answers = [];
    const done = new Promise((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error("the key worker did not answer in time")), 60000);
      worker.onmessage = ({ data }) => {
        answers.push(data);
        if (answers.filter((answer) => answer.type !== "ready").length === messages.length - 1) {
          clearTimeout(timeout);
          resolve();
        }
      };
      worker.onerror = (error) => {
        clearTimeout(timeout);
        reject(error);
      };
    });
    const wasm = wasmLoader.wasmModuleBytes();
    worker.postMessage({ type: "init", wasm: wasm.buffer }, [wasm.buffer]);
    for (const message of messages.slice(1)) worker.postMessage(message);
    await done;
    return answers.filter((answer) => answer.type !== "ready");
  } finally {
    await worker.terminate();
  }
}

test("the key worker derives the published LND node key on mainnet and testnet", async () => {
  const [mainnet] = await ask([{ type: "init" }, { type: "derive", run: 1, format: "aezeed", words: AEZEED_WORDS.split(" "), passphrase: "", coinType: 0 }]);
  assert.equal(mainnet.type, "derived");
  assert.equal(mainnet.result.nodePubKey, lndMainnet.nodePubKey);
  assert.equal(mainnet.result.path, "m/1017'/0'/6'/0/0");
  assert.deepEqual(Object.keys(mainnet.result).sort(), ["birthdayDays", "birthdayTimestamp", "coinType", "format", "internalVersion", "nodePubKey", "path"], "the derived answer carries public fields only");
  assert.ok(!JSON.stringify(mainnet).includes(lndMainnet.rootXprv), "the answer carries the root xprv");
  assert.ok(!JSON.stringify(mainnet).includes(AEZEED_ENTROPY_HEX), "the answer carries the decoded entropy");
  const [testnet] = await ask([{ type: "init" }, { type: "derive", run: 2, format: "aezeed", words: AEZEED_WORDS.split(" "), passphrase: "", coinType: 1 }]);
  assert.equal(testnet.result.nodePubKey, lndTestnet.nodePubKey);
  assert.equal(testnet.result.path, "m/1017'/1'/6'/0/0");
});

test("the key worker derives the LDK two-stage node key", async () => {
  const [derived, revealed] = await ask([{ type: "init" }, { type: "derive", run: 3, format: "bip39", words: LDK_WORDS.split(" "), passphrase: "" }, { type: "reveal", run: 3 }]);
  assert.equal(derived.result.nodePubKey, ldk.nodePubKey);
  assert.equal(derived.result.path, "m/0'");
  assert.deepEqual(Object.keys(derived.result).sort(), ["format", "nodePubKey", "path"], "the derived answer carries public fields only");
  assert.equal(revealed.secrets.rootXprv, ldk.rootXprv);
  assert.equal(revealed.secrets.entropyHex, null, "LDK has no decoded entropy to reveal");
});

test("the key worker derives the CLN node id, descriptors and addresses", async () => {
  const [derived, revealed] = await ask([{ type: "init" }, { type: "derive", run: 11, format: "cln-hsm", words: CLN_WORDS.split(" "), text: CLN_WORDS, passphrase: "", network: "bitcoin" }, { type: "reveal", run: 11 }]);
  assert.equal(derived.type, "derived");
  assert.equal(derived.result.nodePubKey, CLN_NODE_ID);
  assert.deepEqual(derived.result.descriptors, CLN_DESCRIPTORS);
  assert.equal(derived.result.path, "m/86'/0'/0'");
  assert.deepEqual(derived.result.addresses, clnExpectedAddresses("bitcoin"));
  assert.deepEqual(Object.keys(derived.result).sort(), ["addresses", "descriptors", "format", "network", "nodePubKey", "path", "xpub"], "the CLN answer carries public fields only");
  assert.ok(!JSON.stringify(derived).includes(CLN_WORDS), "the answer carries the mnemonic");
  assert.ok(!JSON.stringify(derived).includes(clnXprv), "the answer carries the account xprv");
  assert.equal(revealed.secrets.rootXprv, clnXprv, "reveal returns the BIP86 account xprv");
  assert.equal(revealed.secrets.entropyHex, null, "CLN has no decoded entropy to reveal");
  // The test network keeps the node id and changes the key version and prefix.
  const [testnet] = await ask([{ type: "init" }, { type: "derive", run: 12, format: "cln-hsm", words: CLN_WORDS.split(" "), text: CLN_WORDS, passphrase: "", network: "testnet" }]);
  assert.equal(testnet.result.nodePubKey, CLN_NODE_ID);
  assert.ok(testnet.result.descriptors.every((descriptor) => descriptor.includes("tpub")), "the testnet descriptors use tpub");
  assert.deepEqual(testnet.result.addresses, clnExpectedAddresses("testnet"));
});

test("reveal returns the secret text on request, and nothing without a derivation", async () => {
  const [derived, revealed] = await ask([{ type: "init" }, { type: "derive", run: 21, format: "aezeed", words: AEZEED_WORDS.split(" "), passphrase: "", coinType: 0 }, { type: "reveal", run: 21 }]);
  assert.equal(derived.type, "derived");
  assert.equal(revealed.type, "revealed");
  assert.equal(revealed.secrets.entropyHex, AEZEED_ENTROPY_HEX);
  assert.equal(revealed.secrets.rootXprv, lndMainnet.rootXprv);
  assert.match(revealed.secrets.saltHex, /^[0-9a-f]{10}$/);
  const [empty] = await ask([{ type: "init" }, { type: "reveal", run: 22 }]);
  assert.equal(empty.secrets, null, "a worker that never derived has no secret to reveal");
});

test("load-hsm takes the type-2 file bytes and the page never receives the mnemonic", async () => {
  const [loaded, derived] = await ask([
    { type: "init" },
    { type: "load-hsm", run: 31, bytes: clnType2File(CLN_WORDS) },
    { type: "derive", run: 31, format: "cln-hsm", words: [], text: "", passphrase: "", network: "bitcoin" },
  ]);
  assert.equal(loaded.type, "hsm-loaded");
  assert.deepEqual(Object.keys(loaded).sort(), ["request", "run", "type"], "the loaded answer carries no mnemonic");
  assert.equal(derived.result.nodePubKey, CLN_NODE_ID, "the worker derived from the file's words");
  const wire = JSON.stringify([loaded, derived]);
  assert.ok(!wire.includes("abandon"), "no word of the mnemonic reached the page");
  assert.ok(!wire.includes(clnXprv), "the account xprv reached the page");
});

test("the worker answers scrubbed after dropping its secrets and retiring its WebAssembly", async () => {
  const [derived, revealed, scrubbed, emptyReveal, after] = await ask([
    { type: "init" },
    { type: "derive", run: 51, format: "aezeed", words: AEZEED_WORDS.split(" "), passphrase: "", coinType: 0 },
    { type: "reveal", run: 51 },
    { type: "scrub" },
    { type: "reveal", run: 52 },
    { type: "derive", run: 53, format: "aezeed", words: AEZEED_WORDS.split(" "), passphrase: "", coinType: 0 },
  ]);
  assert.equal(derived.type, "derived");
  assert.equal(revealed.secrets.rootXprv, lndMainnet.rootXprv, "the worker held no secret before the scrub");
  assert.equal(scrubbed.type, "scrubbed", "the worker did not answer the scrub");
  assert.equal(emptyReveal.secrets, null, "the scrub left a secret to reveal");
  // The scrub retired the worker's own WebAssembly instance: a later derive
  // is refused, as after End Session on the page.
  assert.equal(after.type, "error");
  assert.match(after.error.message, /session has ended/);
});

test("refusals carry the same keyed codes as today", async () => {
  // A bad BIP39 checksum (LDK): today's keyed error carries no code.
  const bad = "abandon ".repeat(12).trim();
  const [checksum] = await ask([{ type: "init" }, { type: "derive", run: 41, format: "bip39", words: bad.split(" "), passphrase: "" }]);
  assert.equal(checksum.type, "error");
  assert.match(checksum.error.key, /checksum/i);
  assert.equal(checksum.error.code, undefined, "today's bad-checksum refusal carries no code");
  // CLN typed words with a bad checksum: hsm-secret.js's code.
  const [clnBad] = await ask([{ type: "init" }, { type: "derive", run: 42, format: "cln-hsm", words: bad.split(" "), text: bad, passphrase: "", network: "bitcoin" }]);
  assert.equal(clnBad.type, "error");
  assert.equal(clnBad.error.code, "hsm-secret-invalid-mnemonic");
  // A type-3 hsm_secret file: the page's own keyed refusal, now from the worker.
  const withPassphrase = clnType2File(CLN_WORDS);
  withPassphrase[0] = 0x42;
  const [refused] = await ask([{ type: "init" }, { type: "load-hsm", run: 43, bytes: withPassphrase }]);
  assert.equal(refused.type, "error");
  assert.equal(refused.request, "load-hsm");
  assert.equal(refused.error.code, "hsm-secret-passphrase");
  // A wrong aezeed passphrase: the aezeed.js taxonomy, unchanged.
  const [wrong] = await ask([{ type: "init" }, { type: "derive", run: 44, format: "aezeed", words: AEZEED_WORDS.split(" "), passphrase: "wrong", coinType: 0 }]);
  assert.equal(wrong.type, "error");
  assert.match(wrong.error.key ?? wrong.error.message, /passphrase/i);
});

// ── The page side: what the Lightning card holds ────────────────────────────

const spawned = [];
const nodeFactory = () => {
  const worker = new NodeWebWorker();
  spawned.push(worker);
  return { worker, url: null };
};

// The full Lightning card over a mini DOM (the fixture test/lightning.test.mjs
// uses), with the shipped worker string injected as the worker factory.
function lnPage() {
  const page = new MiniDocument();
  globalThis.document = page;
  page.body.innerHTML = '<select id="ln-format"><option value="aezeed" selected>aezeed · LND cipher seed</option><option value="bip39">BIP-39 · LDK (ldk-node)</option><option value="cln-hsm">Core Lightning hsm_secret</option></select>'
    + '<div id="ln-network-field"><select id="ln-network"><option value="mainnet" selected>Mainnet</option><option value="testnet">Testnet</option></select></div>'
    + '<button class="btn secondary" id="ln-hsm-upload" type="button">Choose hsm_secret</button><input type="file" id="ln-hsm-file" hidden>'
    + '<textarea id="ln-seed"></textarea><input id="ln-pass" type="password">'
    + '<button id="ln-go" type="button"></button><button id="ln-wipe" type="button"></button>'
    + '<p id="ln-session"></p><p id="ln-error"></p><div id="ln-out"></div>'
    + '<span id="ln-seed-help"></span>';
  if (ln.hodlLnSetWorkerFactory) ln.hodlLnSetWorkerFactory(nodeFactory);
  ln.hodlInitLn({ journalLog() {}, copyIcon: () => "" });
  return page;
}

const until = async (condition, what) => {
  for (let i = 0; i < 400; i++) {
    if (condition()) return;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  assert.fail(`timed out waiting for ${what}`);
};

const cleanup = async () => {
  ln.hodlLnWipeMem();
  for (const worker of spawned.splice(0)) await worker.terminate();
  delete globalThis.document;
};

test("the page derives in the worker and holds the secret text only while revealed", async () => {
  const page = lnPage();
  try {
    page.getElementById("ln-seed").value = AEZEED_WORDS;
    page.getElementById("ln-go").onclick();
    await until(() => page.getElementById("ln-out").innerHTML.includes(lndMainnet.nodePubKey), "the derived node key");
    const worker = spawned.at(-1);
    assert.ok(worker, "the derivation ran in a key worker");
    const html = page.getElementById("ln-out").innerHTML;
    assert.ok(!html.includes(lndMainnet.rootXprv), "the page shows the root xprv while hidden");
    assert.ok(!html.includes(AEZEED_ENTROPY_HEX), "the page shows the decoded entropy while hidden");
    // Reveal asks the worker for the secret text; hiding drops it again.
    const reveal = page.getElementById("ln-reveal");
    reveal.checked = true;
    reveal.dispatchEvent({ type: "change" });
    await until(() => page.getElementById("ln-root-xprv"), "the revealed xprv");
    assert.ok(page.getElementById("ln-out").innerHTML.includes(lndMainnet.rootXprv));
    assert.ok(page.getElementById("ln-out").innerHTML.includes(AEZEED_ENTROPY_HEX));
    const hide = page.getElementById("ln-reveal");
    hide.checked = false;
    hide.dispatchEvent({ type: "change" });
    assert.equal(page.getElementById("ln-root-xprv"), null, "hiding removes the secret text");
    assert.ok(!page.getElementById("ln-out").innerHTML.includes(lndMainnet.rootXprv));
    // A reveal answer that lands after the user hid again is dropped.
    worker.onmessage?.({ data: { type: "revealed", run: worker.run, secrets: { entropyHex: "00", saltHex: "00", rootXprv: lndMainnet.rootXprv } } });
    assert.equal(page.getElementById("ln-root-xprv"), null, "a reveal answer that arrived after hiding was kept");
    assert.ok(!page.getElementById("ln-out").innerHTML.includes(lndMainnet.rootXprv));
  } finally {
    await cleanup();
  }
});

test("Clear and a network change terminate the worker, and its late answers are ignored", async () => {
  const page = lnPage();
  try {
    page.getElementById("ln-seed").value = AEZEED_WORDS;
    page.getElementById("ln-go").onclick();
    await until(() => page.getElementById("ln-out").innerHTML.includes(lndMainnet.nodePubKey), "the node key");
    const first = spawned.at(-1);
    assert.ok(first, "the derivation ran in a key worker");
    const network = page.getElementById("ln-network");
    network.value = "testnet";
    network.dispatchEvent({ type: "change" });
    await until(() => first.terminated, "the network change terminating the worker");
    assert.equal(page.getElementById("ln-node-pubkey"), null, "the result survived the network change");
    // A late answer from the stopped worker must not bring the old result back.
    first.onmessage?.({ data: { type: "derived", run: first.run, result: { format: "aezeed", coinType: 0, nodePubKey: "02" + "00".repeat(32), path: "m/1017'/0'/6'/0/0", internalVersion: 0, birthdayDays: 0, birthdayTimestamp: 1231006505 } } });
    assert.equal(page.getElementById("ln-node-pubkey"), null, "a stopped worker's answer was rendered");
    // Deriving again spawns a fresh worker; Clear terminates it too.
    page.getElementById("ln-go").onclick();
    await until(() => page.getElementById("ln-out").innerHTML.includes(lndTestnet.nodePubKey), "the testnet key");
    const second = spawned.at(-1);
    assert.ok(second && second !== first, "a new worker was spawned");
    page.getElementById("ln-wipe").onclick();
    await until(() => second.terminated, "Clear terminating the worker");
    assert.equal(page.getElementById("ln-out").innerHTML, "", "Clear left the result on screen");
  } finally {
    await cleanup();
  }
});

test("the page terminates the worker on its scrubbed answer, ahead of the bound", async () => {
  const page = lnPage();
  try {
    page.getElementById("ln-seed").value = AEZEED_WORDS;
    page.getElementById("ln-go").onclick();
    await until(() => page.getElementById("ln-out").innerHTML.includes(lndMainnet.nodePubKey), "the node key");
    const worker = spawned.at(-1);
    assert.ok(worker, "the derivation ran in a key worker");
    let terminatedOnScrubbed = null;
    const pageHandler = worker.onmessage;
    worker.onmessage = (event) => {
      pageHandler(event);
      if (event.data && event.data.type === "scrubbed") terminatedOnScrubbed = worker.terminated;
    };
    page.getElementById("ln-wipe").onclick();
    assert.equal(worker.terminated, false, "the worker was terminated before it answered the scrub");
    await until(() => worker.terminated, "the scrubbed worker's termination");
    assert.equal(terminatedOnScrubbed, true, "the termination did not follow the scrubbed answer");
  } finally {
    await cleanup();
  }
});

test("the page terminates a worker that never answers the scrub after a bound", async () => {
  const page = lnPage();
  const silent = [];
  ln.hodlLnSetWorkerFactory(() => {
    const worker = {
      onmessage: null,
      onerror: null,
      terminated: false,
      postMessage() {}, // never answers: no scrubbed answer ever comes
      terminate() {
        this.terminated = true;
      },
    };
    silent.push(worker);
    spawned.push(worker);
    return { worker, url: null };
  });
  try {
    page.getElementById("ln-seed").value = AEZEED_WORDS;
    page.getElementById("ln-go").onclick();
    const worker = silent.at(-1);
    assert.ok(worker, "the derive spawned no worker");
    page.getElementById("ln-wipe").onclick();
    assert.equal(worker.terminated, false, "a worker that never answered was terminated before the bound");
    await until(() => worker.terminated, "the bound termination of the silent worker");
  } finally {
    ln.hodlLnSetWorkerFactory(nodeFactory);
    await cleanup();
  }
});

test("a crashed worker is terminated and its blob URL revoked at once", async () => {
  const page = lnPage();
  const revoked = [];
  const originalRevoke = URL.revokeObjectURL;
  URL.revokeObjectURL = (url) => {
    revoked.push(url);
  };
  ln.hodlLnSetWorkerFactory(() => {
    const worker = new NodeWebWorker();
    spawned.push(worker);
    return { worker, url: "blob:ln-key-worker-test" };
  });
  try {
    page.getElementById("ln-seed").value = AEZEED_WORDS;
    page.getElementById("ln-go").onclick();
    await until(() => page.getElementById("ln-out").innerHTML.includes(lndMainnet.nodePubKey), "the node key");
    const worker = spawned.at(-1);
    worker.onerror?.({ message: "boom" });
    assert.equal(worker.terminated, true, "the crashed worker was not terminated at once");
    assert.deepEqual(revoked, ["blob:ln-key-worker-test"], "the crashed worker's blob URL was not revoked");
    assert.equal(page.getElementById("ln-error").textContent, "boom");
  } finally {
    URL.revokeObjectURL = originalRevoke;
    ln.hodlLnSetWorkerFactory(nodeFactory);
    await cleanup();
  }
});

test("the page resets the file input after the transfer detaches the hsm_secret buffer", async () => {
  const page = lnPage();
  try {
    page.getElementById("ln-format").value = "cln-hsm";
    const fileInput = page.getElementById("ln-hsm-file");
    const bytes = clnType2File(CLN_WORDS);
    fileInput.files = [{ arrayBuffer: async () => bytes.buffer }];
    // node:worker_threads honours the transfer list: the post detaches the
    // page's view of the bytes, so wiping it would throw a TypeError and
    // skip the input reset (the browser failure this pins).
    await fileInput.onchange();
    assert.equal(bytes.byteLength, 0, "the worker did not detach the transferred buffer");
    assert.equal(fileInput.value, "", "the file input was not reset");
    await until(() => page.getElementById("ln-session").textContent.length > 0, "the hsm-loaded status");
    page.getElementById("ln-go").onclick();
    await until(() => page.getElementById("ln-out").innerHTML.includes(CLN_NODE_ID), "the derived node id");
  } finally {
    await cleanup();
  }
});

test("picking a new hsm_secret file drops a Derive queued for the earlier one", async () => {
  const page = lnPage();
  try {
    page.getElementById("ln-format").value = "cln-hsm";
    const fileInput = page.getElementById("ln-hsm-file");
    const idle = page.getElementById("ln-session").textContent;
    let finishA;
    fileInput.files = [{ arrayBuffer: () => new Promise((resolve) => { finishA = () => resolve(clnType2File(CLN_WORDS).buffer); }) }];
    const readingA = fileInput.onchange();
    page.getElementById("ln-go").onclick(); // queued behind file A's read
    fileInput.files = [{ arrayBuffer: async () => clnType2File(CLN_WORDS).buffer }];
    await fileInput.onchange();
    await until(() => page.getElementById("ln-session").textContent !== idle, "file B's loaded status");
    finishA();
    await readingA;
    await new Promise((resolve) => setTimeout(resolve, 1500));
    assert.equal(page.getElementById("ln-out").innerHTML, "", "a Derive queued for file A ran against file B without a click");
  } finally {
    await cleanup();
  }
});

test("a worker crash during an hsm_secret read does not leave Derive waiting for that read", async () => {
  const page = lnPage();
  try {
    // A live worker from an earlier derive, for the crash to retire.
    page.getElementById("ln-seed").value = AEZEED_WORDS;
    page.getElementById("ln-go").onclick();
    await until(() => page.getElementById("ln-out").innerHTML.includes(lndMainnet.nodePubKey), "the node key");
    page.getElementById("ln-format").value = "cln-hsm";
    const fileInput = page.getElementById("ln-hsm-file");
    let finishRead;
    const bytes = clnType2File(CLN_WORDS);
    fileInput.files = [{ arrayBuffer: () => new Promise((resolve) => { finishRead = () => resolve(bytes.buffer); }) }];
    const reading = fileInput.onchange();
    spawned.at(-1).onerror?.({ message: "boom" });
    finishRead();
    await reading;
    page.getElementById("ln-go").onclick();
    // The click must be answered (a keyed refusal for the dropped file), not
    // queued behind a read the crash superseded.
    await until(() => (page.getElementById("ln-error").dataset.code || "").length > 0, "an answer to the Derive click");
    assert.equal(page.getElementById("ln-out").innerHTML, "", "a derive ran from a read the crash superseded");
  } finally {
    await cleanup();
  }
});

test("a refused hsm_secret file does not leave the earlier file's read status", async () => {
  const page = lnPage();
  try {
    page.getElementById("ln-format").value = "cln-hsm";
    const fileInput = page.getElementById("ln-hsm-file");
    const idle = page.getElementById("ln-session").textContent;
    fileInput.files = [{ arrayBuffer: async () => clnType2File(CLN_WORDS).buffer }];
    await fileInput.onchange();
    await until(() => page.getElementById("ln-session").textContent !== idle, "the hsm-loaded status");
    const readStatus = page.getElementById("ln-session").textContent;
    const refused = clnType2File(CLN_WORDS);
    refused[0] = 0x42; // a type-3 (passphrase) file: the worker refuses it
    fileInput.files = [{ arrayBuffer: async () => refused.buffer }];
    await fileInput.onchange();
    await until(() => page.getElementById("ln-error").dataset.code === "hsm-secret-passphrase", "the type-3 refusal");
    assert.notEqual(page.getElementById("ln-session").textContent, readStatus, "the dropped file's read status is still shown");
  } finally {
    await cleanup();
  }
});

test("a file that cannot be read does not leave the earlier file's read status", async () => {
  const page = lnPage();
  try {
    page.getElementById("ln-format").value = "cln-hsm";
    const fileInput = page.getElementById("ln-hsm-file");
    const idle = page.getElementById("ln-session").textContent;
    fileInput.files = [{ arrayBuffer: async () => clnType2File(CLN_WORDS).buffer }];
    await fileInput.onchange();
    await until(() => page.getElementById("ln-session").textContent !== idle, "the hsm-loaded status");
    const readStatus = page.getElementById("ln-session").textContent;
    fileInput.files = [{ arrayBuffer: async () => { throw new Error("NotReadableError"); } }];
    await fileInput.onchange();
    assert.ok(page.getElementById("ln-error").textContent.length > 0, "the read failure was not reported");
    assert.notEqual(page.getElementById("ln-session").textContent, readStatus, "the dropped file's read status is still shown");
  } finally {
    await cleanup();
  }
});

test("scripts/build.mjs injects the bundled worker source as __LN_WORKER_SOURCE__", () => {
  const build = readFileSync(new URL("../scripts/build.mjs", import.meta.url), "utf8");
  assert.match(build, /__LN_WORKER_SOURCE__: JSON\.stringify\(/, "the page bundle must carry the key worker source");
});

// End Session retires the WebAssembly module for the rest of this process,
// so this test must stay last: nothing after it can derive.
test("after End Session the Lightning tool refuses to derive and terminates its live worker", async () => {
  const page = lnPage();
  try {
    page.getElementById("ln-seed").value = AEZEED_WORDS;
    page.getElementById("ln-go").onclick();
    await until(() => page.getElementById("ln-out").innerHTML.includes(lndMainnet.nodePubKey), "the node key");
    const live = spawned.at(-1);
    assert.ok(live, "the derivation ran in a key worker");
    const before = spawned.length;
    wasmLoader.retireWasm();
    assert.equal(wasmLoader.wasmRetired(), true, "the retired predicate does not report the retired session");
    assert.throws(() => wasmLoader.wasmModuleBytes(), /session has ended/, "the module bytes are still handed out after End Session");
    page.getElementById("ln-go").onclick();
    // The refusal's stable marker is its error code, not the English copy.
    assert.equal(page.getElementById("ln-error").dataset.code, "session-ended", "the refusal is not the session-ended error");
    assert.ok(page.getElementById("ln-error").textContent.length > 0, "the refusal is not shown in #ln-error");
    assert.equal(page.getElementById("ln-out").innerHTML, "", "a retired session derived a node key");
    assert.equal(spawned.length, before, "a key worker was spawned after End Session");
    await until(() => live.terminated, "the retired session's live worker was terminated");
  } finally {
    await cleanup();
  }
});
