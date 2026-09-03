// Source of the vanity grinder Web Worker, shipped as a string so the build
// can spawn workers from a Blob URL inside the single self-contained
// entropylab.html (no separate script file, no network). The same string is
// executed under node:worker_threads by test/vanity-wasm.test.mjs, so what
// ships is what is tested.
//
// Protocol (structured clone; counters are BigInt):
//   main -> worker  { type: "init", wasm: ArrayBuffer }        -> { type: "ready" }
//   main -> worker  { type: "grind", mode, key, salt, path, counterSlot,
//                     prefix, passLen, start, count, script }
//   worker -> main  { type: "progress", done, matches }        per chunk
//   worker -> main  { type: "done", done, stopped }            range finished
//   main -> worker  { type: "stop" }                           cooperative stop
//   worker -> main  { type: "error", message }
// grind fields: mode 0 grinds the BIP39 passphrase — key is the NFKD mnemonic
// (Uint8Array), salt the NFKD starting passphrase (Uint8Array), path the full
// derivation path (array of u32 with the hardened bit), and the counter is
// the passLen-character odometer string appended to the passphrase. mode 1
// grinds one path component — key is a 64-byte BIP32 node (private key then
// chain code), path the components below it, and the counter replaces
// path[counterSlot]. script 0-3 are the single-signature address types,
// 4 is a BIP-352 Silent Payment code (path ends at the account node).
// Match: { counter: BigInt, passphrase: string, payload: Uint8Array(66) }.
// passphrase is the bare odometer string (empty in mode 1); the candidate
// BIP39 passphrase is salt + passphrase. payload is HASH160 (first 20 bytes)
// for hash-based scripts, the x-only output key (32 bytes) for P2TR, or the
// scan and spend compressed public keys (33 + 33 bytes) for Silent Payments.
// Private keys never leave the WASM loop.
//
// The string must stay free of backticks and "${" (it lives in a template
// literal below).
export const VANITY_WORKER_SOURCE = `
"use strict";
var wasm = null;
var stopRequested = false;
var prefixPtr = 0;
var saltPtr = 0;
var keyPtr = 0;
var pathPtr = 0;
var outPtr = 0;
var STEP_MS = 120;
var MIN_CHUNK = 8;
var MAX_CHUNK = 8192;
var RECORD_CAP = 8192;
var RECORD_LEN = 106;
var PAYLOAD_LEN = 66;
var OUT_CAP = 12 + RECORD_LEN * RECORD_CAP;
// Same limits as MAX_ADDR_LEN, MAX_SALT_LEN, MAX_KEY_LEN, and MAX_PATH_LEN in
// vanity-wasm/src/lib.rs.
var MAX_PREFIX = 116;
var MAX_SALT = 256;
var MAX_KEY = 1024;
var MAX_PATH = 16;
var NO_SLOT = 0xffffffff;
var encoder = new TextEncoder();
var decoder = new TextDecoder();

function heap() {
  return new Uint8Array(wasm.memory.buffer);
}

function drain(passLen) {
  var header = new DataView(wasm.memory.buffer, outPtr, 12);
  var processed = header.getBigUint64(0, true);
  var count = header.getUint32(8, true);
  var matches = [];
  for (var i = 0; i < count; i++) {
    var at = outPtr + 12 + i * RECORD_LEN;
    matches.push({
      counter: new DataView(wasm.memory.buffer, at, 8).getBigUint64(0, true),
      passphrase: decoder.decode(heap().slice(at + 8, at + 8 + passLen)),
      payload: heap().slice(at + 40, at + 40 + PAYLOAD_LEN)
    });
  }
  return { processed: processed, matches: matches };
}

function bytesOf(value) {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  return encoder.encode(String(value == null ? "" : value));
}

function grind(msg) {
  var mode = msg.mode === 1 ? 1 : 0;
  var prefixBytes = encoder.encode(msg.prefix);
  if (prefixBytes.length === 0 || prefixBytes.length > MAX_PREFIX) {
    postMessage({ type: "error", message: "vanity prefix is empty or longer than " + MAX_PREFIX + " characters" });
    return;
  }
  heap().set(prefixBytes, prefixPtr);
  var keyBytes = bytesOf(msg.key);
  if (keyBytes.length === 0 || keyBytes.length > MAX_KEY) {
    postMessage({ type: "error", message: "vanity key material is empty or longer than " + MAX_KEY + " bytes" });
    return;
  }
  heap().set(keyBytes, keyPtr);
  var saltBytes = mode === 1 ? new Uint8Array(0) : bytesOf(msg.salt);
  if (saltBytes.length > MAX_SALT) {
    postMessage({ type: "error", message: "vanity starting passphrase is longer than " + MAX_SALT + " bytes" });
    return;
  }
  heap().set(saltBytes, saltPtr);
  var path = Array.isArray(msg.path) ? msg.path : [];
  if (path.length === 0 || path.length > MAX_PATH) {
    postMessage({ type: "error", message: "vanity derivation path has 1 to " + MAX_PATH + " components" });
    return;
  }
  var pathView = new DataView(wasm.memory.buffer, pathPtr, MAX_PATH * 4);
  for (var i = 0; i < path.length; i++) pathView.setUint32(i * 4, Number(path[i]) >>> 0, true);
  var counterSlot = mode === 1 ? Number(msg.counterSlot) >>> 0 : NO_SLOT;
  var passLen = mode === 1 ? 0 : Number(msg.passLen);
  var total = BigInt(msg.count);
  var cursor = BigInt(msg.start);
  var done = BigInt(0);
  // Chunks adapt to the device: the first is small so progress shows within
  // a fraction of a second even for the PBKDF2-heavy passphrase grind, then
  // each step is resized to take about STEP_MS so the bar moves smoothly and
  // a queued "stop" lands promptly.
  var chunkSize = mode === 1 ? 512 : 16;
  stopRequested = false;
  var step = function () {
    if (done >= total || stopRequested) {
      postMessage({ type: "done", done: done, stopped: stopRequested });
      return;
    }
    var remaining = total - done;
    var chunk = remaining > BigInt(chunkSize) ? chunkSize : Number(remaining);
    var startedAt = Date.now();
    var status = wasm.vanity_grind(mode, keyPtr, keyBytes.length, saltPtr, saltBytes.length, pathPtr, path.length, counterSlot, prefixPtr, prefixBytes.length, passLen, cursor, BigInt(chunk), outPtr, OUT_CAP, msg.script || 0);
    if (status === -1) {
      postMessage({ type: "error", message: "vanity_grind rejected its arguments" });
      return;
    }
    var elapsed = Math.max(1, Date.now() - startedAt);
    chunkSize = Math.max(MIN_CHUNK, Math.min(MAX_CHUNK, Math.round(chunk * STEP_MS / elapsed)));
    var drained = drain(passLen);
    done += drained.processed;
    cursor += drained.processed;
    postMessage({ type: "progress", done: done, matches: drained.matches });
    // status -2 means the record area filled up; it was drained above, so the
    // loop simply continues. A short chunk means the counter space ran out.
    if (status !== -2 && drained.processed < BigInt(chunk)) {
      postMessage({ type: "done", done: done, stopped: false });
      return;
    }
    setTimeout(step, 0); // yield so a queued "stop" message lands
  };
  step();
}

self.onmessage = function (event) {
  var msg = event.data;
  if (!msg || typeof msg !== "object") return;
  if (msg.type === "init") {
    WebAssembly.instantiate(msg.wasm, {}).then(function (result) {
      wasm = result.instance.exports;
      prefixPtr = wasm.vanity_alloc(MAX_PREFIX);
      saltPtr = wasm.vanity_alloc(MAX_SALT);
      keyPtr = wasm.vanity_alloc(MAX_KEY);
      pathPtr = wasm.vanity_alloc(MAX_PATH * 4);
      outPtr = wasm.vanity_alloc(OUT_CAP);
      postMessage({ type: "ready" });
    }).catch(function (error) {
      postMessage({ type: "error", message: "vanity wasm failed to instantiate: " + (error && error.message || error) });
    });
  } else if (msg.type === "grind") {
    if (!wasm) {
      postMessage({ type: "error", message: "worker not initialized" });
      return;
    }
    try {
      grind(msg);
    } catch (error) {
      postMessage({ type: "error", message: (error && error.message) || String(error) });
    }
  } else if (msg.type === "stop") {
    stopRequested = true;
  }
};
`;
