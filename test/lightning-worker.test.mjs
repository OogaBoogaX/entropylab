// The Lightning tool derives in a key worker (src/js/ln-worker.js), not in
// the page.
//
// Security contract: the worker derives exactly the published node keys; the
// page holds the public result and, while hidden, no text of the root xprv or
// the decoded entropy; the secret text reaches the page only when revealed;
// and Clear or a format/network change terminates the worker, whose late
// answers are ignored.
//
// Expected values: the aezeed toolkit characterization vector (entropy
// 00..0f, test/aezeed-wasm.test.mjs) and the
// trezor "abandon … about" mnemonic, with node keys, root xprvs and the LDK
// two-stage key computed by @scure/bip32 and @scure/bip39 as reference
// libraries. The worker source is the string the build ships
// (scripts/ln-worker-source.mjs), run under node:worker_threads.
// Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import v8 from "node:v8";
import { createHash } from "node:crypto";
import { Worker } from "node:worker_threads";
import { HDKey as ScureHDKey } from "@scure/bip32";
import { mnemonicToSeedSync } from "@scure/bip39";
import { MiniDocument } from "./mini-dom.mjs";
import * as wasmLoader from "../src/js/entropylab-wasm.js";
import * as ln from "../src/js/lightning.js";

const AEZEED = "ability result leisure oven shiver wedding toe broccoli exclude mosquito kind van action waste merit bundle robust source able advice core humor kitchen siren";
const LDK_WORDS = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const hexOf = (bytes) => Buffer.from(bytes).toString("hex");
const digestOf = (text) => createHash("sha256").update(text).digest("hex");
// The vector's entropy is the bytes 00..0f. The test keeps it as bytes and a
// digest of its hex, never as text, so the heap check below finds only the
// page's copies.
const AEZEED_ENTROPY = Uint8Array.from({ length: 16 }, (_, i) => i);
const entropyText = (() => {
  const text = hexOf(AEZEED_ENTROPY);
  return { digest: digestOf(text), length: text.length };
})();

// Reference values, made in frames that let only digests and public keys out.
const lndReference = (coinType = 0) => {
  const master = ScureHDKey.fromMasterSeed(AEZEED_ENTROPY);
  const xprv = master.privateExtendedKey;
  return { nodePubKey: hexOf(master.derive(`m/1017'/${coinType}'/6'/0/0`).publicKey), xprv: { digest: digestOf(xprv), length: xprv.length } };
};
const ldkReference = () => {
  const master1 = ScureHDKey.fromMasterSeed(mnemonicToSeedSync(LDK_WORDS));
  const node = ScureHDKey.fromMasterSeed(master1.privateKey).deriveChild(0x80000000);
  const xprv = master1.privateExtendedKey;
  return { nodePubKey: hexOf(node.publicKey), xprv: { digest: digestOf(xprv), length: xprv.length } };
};

// ── The shipped worker string, under node:worker_threads ────────────────────

let workerSource = null;
try {
  workerSource = await (await import("../scripts/ln-worker-source.mjs")).buildLnWorkerSource();
} catch {
  // No key worker in this tree: the worker tests fail on the missing source.
}
// node:worker_threads has no `self`; the prelude adapts the Web Worker surface
// the shipped string expects, so the identical string is what runs.
const PRELUDE = `
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
    if (message?.run !== undefined) this.run = message.run;
    this.inner.postMessage(message, transfer);
  }
  terminate() { this.terminated = true; return this.inner.terminate(); }
}
const spawned = [];
const nodeFactory = () => {
  const worker = new NodeWebWorker();
  spawned.push(worker);
  return { worker, url: null };
};

// One request to a fresh worker, answered once.
async function ask(messages) {
  assert.ok(workerSource, "the build ships no Lightning key worker");
  const worker = new NodeWebWorker();
  try {
    const answers = [];
    const done = new Promise((resolve) => {
      worker.onmessage = ({ data }) => {
        answers.push(data);
        if (answers.filter((answer) => answer.type !== "ready").length === messages.length - 1) resolve();
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

test("the key worker derives the published LND node key, and reveals only on request", async () => {
  const reference = lndReference(0);
  const [derived, revealed] = await ask([{ type: "init" }, { type: "derive", run: 1, format: "aezeed", words: AEZEED.split(" "), passphrase: "", coinType: 0 }, { type: "reveal", run: 1 }]);
  assert.equal(derived.type, "derived");
  assert.equal(derived.result.nodePubKey, reference.nodePubKey);
  assert.equal(derived.result.path, "m/1017'/0'/6'/0/0");
  assert.deepEqual(Object.keys(derived.result).sort(), ["birthdayDays", "birthdayTimestamp", "coinType", "format", "internalVersion", "nodePubKey", "path"], "the derived answer carries public fields only");
  assert.equal(digestOf(revealed.secrets.entropyHex), entropyText.digest);
  assert.equal(digestOf(revealed.secrets.rootXprv), reference.xprv.digest);
});

test("the key worker derives the testnet LND key and the LDK two-stage key", async () => {
  const [testnet] = await ask([{ type: "init" }, { type: "derive", run: 2, format: "aezeed", words: AEZEED.split(" "), passphrase: "", coinType: 1 }]);
  assert.equal(testnet.result.nodePubKey, lndReference(1).nodePubKey);
  const reference = ldkReference();
  const [ldk, revealed] = await ask([{ type: "init" }, { type: "derive", run: 3, format: "bip39", words: LDK_WORDS.split(" "), passphrase: "" }, { type: "reveal", run: 3 }]);
  assert.equal(ldk.result.nodePubKey, reference.nodePubKey);
  assert.equal(ldk.result.path, "m/0'");
  assert.equal(digestOf(revealed.secrets.rootXprv), reference.xprv.digest);
});

test("the key worker names a wrong aezeed passphrase and a bad BIP-39 checksum as keyed errors", async () => {
  const [wrong] = await ask([{ type: "init" }, { type: "derive", run: 4, format: "aezeed", words: AEZEED.split(" "), passphrase: "wrong", coinType: 0 }]);
  assert.equal(wrong.type, "error");
  assert.match(wrong.error.key ?? wrong.error.message, /passphrase/i);
  const [checksum] = await ask([{ type: "init" }, { type: "derive", run: 5, format: "bip39", words: LDK_WORDS.replace(/about$/, "abandon").split(" "), passphrase: "" }]);
  assert.equal(checksum.type, "error");
  assert.match(checksum.error.key, /checksum/i);
});

// ── The page side: what the Lightning card holds ────────────────────────────

const CARD = `<select id="ln-format"><option value="aezeed" selected>aezeed</option><option value="bip39">BIP-39</option></select>
<label id="ln-network-field"><select id="ln-network"><option value="mainnet" selected>mainnet</option><option value="testnet">testnet</option></select></label>
<textarea id="ln-seed"></textarea><span id="ln-seed-help"></span><input id="ln-pass">
<button id="ln-go"></button><button id="ln-wipe"></button><p id="ln-session"></p><div id="ln-out"></div><p id="ln-error"></p>`;
function page() {
  globalThis.document = new MiniDocument();
  document.body.innerHTML = CARD;
  if (ln.hodlLnSetWorkerFactory) ln.hodlLnSetWorkerFactory(nodeFactory);
  ln.hodlInitLn({});
  return document;
}
const until = async (condition, what) => {
  for (let i = 0; i < 400; i++) {
    if (condition()) return;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  assert.fail(`timed out waiting for ${what}`);
};
// Strongly held copies of a string in this (the page's) heap: reachable from
// the roots along non-weak edges. The worker's heap is its own.
async function heldCopies({ digest, length }) {
  await new Promise((resolve) => setImmediate(resolve));
  const chunks = [];
  for await (const chunk of v8.getHeapSnapshot()) chunks.push(chunk);
  const snapshot = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  const { meta } = snapshot.snapshot, { nodes, edges, strings } = snapshot;
  const N = meta.node_fields.length, E = meta.edge_fields.length, types = meta.node_types[0], edgeTypes = meta.edge_types[0];
  const typeAt = meta.node_fields.indexOf("type"), nameAt = meta.node_fields.indexOf("name"), countAt = meta.node_fields.indexOf("edge_count");
  const edgeTypeAt = meta.edge_fields.indexOf("type"), toAt = meta.edge_fields.indexOf("to_node");
  const total = nodes.length / N, first = new Uint32Array(total);
  for (let index = 0, sum = 0; index < total; index++) {
    first[index] = sum;
    sum += nodes[index * N + countAt] * E;
  }
  const seen = new Uint8Array(total), queue = [0];
  seen[0] = 1;
  let found = 0;
  for (let head = 0; head < queue.length; head++) {
    const index = queue[head];
    if (/string/.test(types[nodes[index * N + typeAt]])) {
      const text = strings[nodes[index * N + nameAt]];
      if (text.length === length && digestOf(text) === digest) found++;
    }
    for (let edge = first[index], end = edge + nodes[index * N + countAt] * E; edge < end; edge += E) {
      if (edgeTypes[edges[edge + edgeTypeAt]] === "weak") continue;
      const to = edges[edge + toAt] / N;
      if (!seen[to]) {
        seen[to] = 1;
        queue.push(to);
      }
    }
  }
  return found;
}

test("while hidden, the page holds no text of the root xprv or the decoded entropy", async () => {
  const reference = lndReference(0);
  const document = page();
  try {
    document.getElementById("ln-seed").value = AEZEED;
    document.getElementById("ln-go").click();
    await until(() => document.getElementById("ln-node-pubkey"), "the node key");
    assert.equal(document.getElementById("ln-node-pubkey").textContent, reference.nodePubKey);
    assert.equal(await heldCopies(reference.xprv), 0, "the page holds the root xprv while it is hidden");
    assert.equal(await heldCopies(entropyText), 0, "the page holds the decoded entropy while it is hidden");
  } finally {
    ln.hodlLnWipeMem();
  }
});

test("revealing asks the worker for the secret text, and hiding drops it", async () => {
  const reference = lndReference(0);
  const document = page();
  try {
    document.getElementById("ln-seed").value = AEZEED;
    document.getElementById("ln-go").click();
    await until(() => document.getElementById("ln-reveal"), "the reveal switch");
    const reveal = document.getElementById("ln-reveal");
    reveal.checked = true;
    reveal.dispatchEvent({ type: "change" });
    await until(() => document.getElementById("ln-root-xprv"), "the revealed xprv");
    assert.equal(digestOf(document.getElementById("ln-entropy").textContent), entropyText.digest);
    assert.equal(digestOf(document.getElementById("ln-root-xprv").textContent), reference.xprv.digest);
    const hide = document.getElementById("ln-reveal");
    hide.checked = false;
    hide.dispatchEvent({ type: "change" });
    assert.equal(document.getElementById("ln-root-xprv"), null, "hiding removes the secret text");
    assert.equal(await heldCopies(reference.xprv), 0, "the page still holds the root xprv after hiding it");
    assert.equal(await heldCopies(entropyText), 0, "the page still holds the entropy after hiding it");
    // A reveal answer that lands after the user hid again is dropped. The
    // stand-in secret is made here and only its digest kept.
    const worker = spawned.at(-1);
    const late = (() => {
      const text = "xprv" + "9".repeat(107);
      worker.onmessage?.({ data: { type: "revealed", run: worker.run, secrets: { entropyHex: "", saltHex: "", rootXprv: text } } });
      return { digest: digestOf(text), length: text.length };
    })();
    assert.equal(await heldCopies(late), 0, "a reveal answer that arrived after hiding was kept");
  } finally {
    ln.hodlLnWipeMem();
  }
});

test("Clear and a network change terminate the worker, and its late answers are ignored", async () => {
  const document = page();
  try {
    spawned.length = 0;
    document.getElementById("ln-seed").value = AEZEED;
    document.getElementById("ln-go").click();
    await until(() => document.getElementById("ln-node-pubkey"), "the node key");
    const first = spawned.at(-1);
    assert.ok(first, "the derivation ran in a key worker");
    const network = document.getElementById("ln-network");
    network.value = "testnet";
    network.dispatchEvent({ type: "change" });
    assert.equal(first.terminated, true, "a network change terminates the worker");
    assert.equal(document.getElementById("ln-node-pubkey"), null);
    // A late answer from the stopped worker must not bring the old result back.
    first.onmessage?.({ data: { type: "derived", run: 1, result: { format: "aezeed", coinType: 0, nodePubKey: "02" + "00".repeat(32), path: "m/1017'/0'/6'/0/0" } } });
    assert.equal(document.getElementById("ln-node-pubkey"), null, "a stopped worker's answer was rendered");
    document.getElementById("ln-go").click();
    await until(() => document.getElementById("ln-node-pubkey"), "the testnet key");
    const second = spawned.at(-1);
    document.getElementById("ln-wipe").click();
    assert.equal(second.terminated, true, "Clear terminates the worker");
    assert.equal(document.getElementById("ln-node-pubkey"), null);
  } finally {
    ln.hodlLnWipeMem();
  }
});
