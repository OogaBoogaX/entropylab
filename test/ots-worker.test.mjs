// OpenTimestamps verification worker tests — issue #460.
//
// Runs the shipped worker string under node:worker_threads, as
// test/qr-worker.test.mjs does, and exercises the page-side client with a
// fake Worker. The worker is bundled without the base64 module; the real
// WebAssembly bytes are handed over in the first message.

import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Worker } from "node:worker_threads";

import { wasmModuleBytes } from "../src/js/entropylab-wasm.js";
import { buildOtsWorkerSource } from "../scripts/ots-worker-source.mjs";
import { createOtsVerifier } from "../src/js/ots-verify-client.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const fixtures = join(root, "test", "fixtures", "ots");
const expected = JSON.parse(readFileSync(join(fixtures, "expected.json"), "utf8"));
const headers = JSON.parse(readFileSync(join(fixtures, "headers.json"), "utf8")).headers;

const workerSource = await buildOtsWorkerSource();

// The shipped worker string runs under node:worker_threads behind a minimal
// shim: `self` is the worker's global, and postMessage/onmessage are the
// worker_threads pair.
const WORKER_SHIM = `
const { parentPort } = require("node:worker_threads");
globalThis.self = globalThis;
self.postMessage = (data) => parentPort.postMessage(data);
parentPort.on("message", (data) => {
  if (typeof self.onmessage === "function") self.onmessage({ data });
});
`;

function startWorker() {
  const worker = new Worker(WORKER_SHIM + workerSource, { eval: true });
  const replies = [];
  const waiters = [];
  worker.on("message", (data) => {
    const waiter = waiters.shift();
    if (waiter) waiter(data);
    else replies.push(data);
  });
  const next = () =>
    new Promise((resolve, reject) => {
      if (replies.length) return resolve(replies.shift());
      const timer = setTimeout(() => reject(new Error("worker did not reply")), 5000);
      waiters.push((data) => {
        clearTimeout(timer);
        resolve(data);
      });
    });
  return { worker, next };
}

function bufferOf(bytes) {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
}

test("worker: the v1.0.0 release proof gives the verdict expected.json records", async () => {
  const releaseCase = expected.cases.find(
    (c) => c.proof === "entropylab-v1.0.0/entropylab.html.ots" && c.header === 970791,
  );
  assert.ok(releaseCase, "expected.json records the v1.0.0 case");
  const { worker, next } = startWorker();
  try {
    const wasm = wasmModuleBytes();
    worker.postMessage({ type: "init", wasm: wasm.buffer }, [wasm.buffer]);
    assert.equal((await next()).type, "ready");

    const proof = readFileSync(join(fixtures, "entropylab-v1.0.0", "entropylab.html.ots"));
    const header = Buffer.from(headers[String(releaseCase.header)].header, "hex");
    const digest = Buffer.from(releaseCase.expectedDigest, "hex");
    const proofBuffer = bufferOf(proof);
    const headerBuffer = bufferOf(header);
    const digestBuffer = bufferOf(digest);
    worker.postMessage(
      { type: "verify", run: 1, proof: proofBuffer, header: headerBuffer, expected: digestBuffer, original: null },
      [proofBuffer, headerBuffer, digestBuffer],
    );
    const reply = await next();
    assert.equal(reply.type, "verified");
    assert.equal(reply.run, 1);
    assert.equal(reply.result.result, releaseCase.result);
  } finally {
    await worker.terminate();
  }
});

// verifyOts turns a parse failure into an INVALID verdict with a parse:<code>
// reason (ots-verifier.js), so the worker answers "verified", not "error".
test("worker: a truncated proof gives an INVALID verdict with a parse reason", async () => {
  const { worker, next } = startWorker();
  try {
    const wasm = wasmModuleBytes();
    worker.postMessage({ type: "init", wasm: wasm.buffer }, [wasm.buffer]);
    await next();
    const proof = readFileSync(join(fixtures, "entropylab-v1.0.0", "entropylab.html.ots"));
    const truncated = proof.subarray(0, 10);
    const buffer = bufferOf(truncated);
    worker.postMessage({ type: "verify", run: 2, proof: buffer, header: null, expected: null, original: null }, [buffer]);
    const reply = await next();
    assert.equal(reply.type, "verified");
    assert.equal(reply.run, 2);
    assert.equal(reply.result.result, "INVALID");
    assert.match(reply.result.reason, /^parse:[A-Z_]+$/);
  } finally {
    await worker.terminate();
  }
});

test("worker: a malformed message gives BAD_MESSAGE", async () => {
  const { worker, next } = startWorker();
  try {
    const wasm = wasmModuleBytes();
    worker.postMessage({ type: "init", wasm: wasm.buffer }, [wasm.buffer]);
    await next();
    worker.postMessage({ type: "nope", run: 3 });
    const reply = await next();
    assert.equal(reply.type, "error");
    assert.equal(reply.error.name, "Error");
    assert.equal(reply.error.code, "BAD_MESSAGE");
    assert.equal(reply.error.message, "Bad message.");
  } finally {
    await worker.terminate();
  }
});

// ---- client with a fake Worker --------------------------------------------

function fakeWorkerClass() {
  const instances = [];
  class FakeWorker {
    constructor(url) {
      this.url = url;
      this.posted = [];
      this.terminated = false;
      this.onmessage = null;
      this.onerror = null;
      instances.push(this);
    }
    // Transfers detach the sender's buffers, as a real Worker does.
    postMessage(data, transfer) {
      this.posted.push({ data: transfer && transfer.length ? structuredClone(data, { transfer }) : data, transfer });
    }
    terminate() {
      this.terminated = true;
    }
    reply(data) {
      if (this.onmessage) this.onmessage({ data });
    }
  }
  return { FakeWorker, instances };
}

async function withFakeUrl(fn) {
  const originalCreate = URL.createObjectURL;
  const originalRevoke = URL.revokeObjectURL;
  const created = [];
  const revoked = [];
  URL.createObjectURL = (blob) => {
    const url = `blob:fake/${created.length}`;
    created.push({ url, blob });
    return url;
  };
  URL.revokeObjectURL = (url) => revoked.push(url);
  try {
    return await fn({ created, revoked });
  } finally {
    URL.createObjectURL = originalCreate;
    URL.revokeObjectURL = originalRevoke;
  }
}

test("client: one worker per run, terminated and its URL revoked after the reply", async () => {
  await withFakeUrl(async ({ created, revoked }) => {
    const { FakeWorker, instances } = fakeWorkerClass();
    const verifier = createOtsVerifier({ source: "s", wasmBytes: () => new Uint8Array([1]), Worker: FakeWorker, timeoutMs: 1000 });
    const promise = verifier.verify({ proofBytes: new Uint8Array([1]) });
    assert.equal(instances.length, 1);
    const worker = instances[0];
    assert.equal(worker.posted[0].data.type, "init");
    assert.equal(worker.posted[1].data.type, "verify");
    worker.reply({ type: "verified", run: worker.posted[1].data.run, result: { result: "PENDING" } });
    assert.deepEqual(await promise, { result: "PENDING" });
    assert.equal(worker.terminated, true);
    assert.deepEqual(revoked, [created[0].url]);
  });
});

test("client: the input buffers are detached after verify", async () => {
  await withFakeUrl(async () => {
    const { FakeWorker, instances } = fakeWorkerClass();
    const verifier = createOtsVerifier({ source: "s", wasmBytes: () => new Uint8Array([1]), Worker: FakeWorker, timeoutMs: 1000 });
    const proof = new Uint8Array([1, 2, 3]);
    const header = new Uint8Array(80);
    const promise = verifier.verify({ proofBytes: proof, header });
    const worker = instances[0];
    assert.equal(proof.buffer.byteLength, 0, "the proof buffer was transferred");
    assert.equal(header.buffer.byteLength, 0, "the header buffer was transferred");
    worker.reply({ type: "verified", run: worker.posted[1].data.run, result: {} });
    await promise;
  });
});

test("client: a worker that never answers gives TIME_LIMIT and is terminated", async () => {
  await withFakeUrl(async () => {
    const { FakeWorker, instances } = fakeWorkerClass();
    const verifier = createOtsVerifier({ source: "s", wasmBytes: () => new Uint8Array([1]), Worker: FakeWorker, timeoutMs: 10 });
    const promise = verifier.verify({ proofBytes: new Uint8Array([1]) });
    await assert.rejects(promise, (error) => {
      assert.equal(error.name, "OtsBudgetError");
      assert.equal(error.code, "TIME_LIMIT");
      assert.equal(error.message, "Verification incomplete: the time limit was reached. Nothing was verified.");
      return true;
    });
    assert.equal(instances[0].terminated, true);
  });
});

test("client: stop() mid-run gives CANCELLED, terminates, and ignores a late reply", async () => {
  await withFakeUrl(async ({ revoked }) => {
    const { FakeWorker, instances } = fakeWorkerClass();
    const verifier = createOtsVerifier({ source: "s", wasmBytes: () => new Uint8Array([1]), Worker: FakeWorker, timeoutMs: 1000 });
    const promise = verifier.verify({ proofBytes: new Uint8Array([1]) });
    const worker = instances[0];
    const run = worker.posted[1].data.run;
    verifier.stop();
    await assert.rejects(promise, (error) => {
      assert.equal(error.code, "CANCELLED");
      return true;
    });
    assert.equal(worker.terminated, true);
    assert.equal(revoked.length, 1);
    worker.reply({ type: "verified", run, result: { result: "PENDING" } });
    verifier.stop();
    assert.equal(revoked.length, 1);
  });
});

test("client: a second verify cancels the first", async () => {
  await withFakeUrl(async () => {
    const { FakeWorker, instances } = fakeWorkerClass();
    const verifier = createOtsVerifier({ source: "s", wasmBytes: () => new Uint8Array([1]), Worker: FakeWorker, timeoutMs: 1000 });
    const first = verifier.verify({ proofBytes: new Uint8Array([1]) });
    const firstWorker = instances[0];
    const second = verifier.verify({ proofBytes: new Uint8Array([2]) });
    await assert.rejects(first, (error) => {
      assert.equal(error.code, "CANCELLED");
      return true;
    });
    assert.equal(firstWorker.terminated, true);
    const secondWorker = instances[1];
    secondWorker.reply({ type: "verified", run: secondWorker.posted[1].data.run, result: { result: "PENDING" } });
    assert.deepEqual(await second, { result: "PENDING" });
  });
});

test("client: errors come back as RangeError / TypeError instances and OTS errors keep name and code", async () => {
  await withFakeUrl(async () => {
    const { FakeWorker, instances } = fakeWorkerClass();
    const verifier = createOtsVerifier({ source: "s", wasmBytes: () => new Uint8Array([1]), Worker: FakeWorker, timeoutMs: 1000 });
    const promise = verifier.verify({ proofBytes: new Uint8Array([1]) });
    const worker = instances[0];
    worker.reply({ type: "error", run: worker.posted[1].data.run, error: { name: "RangeError", code: null, message: "too long" } });
    await assert.rejects(promise, (error) => {
      assert.ok(error instanceof RangeError);
      assert.equal(error.message, "too long");
      return true;
    });
  });
  await withFakeUrl(async () => {
    const { FakeWorker, instances } = fakeWorkerClass();
    const verifier = createOtsVerifier({ source: "s", wasmBytes: () => new Uint8Array([1]), Worker: FakeWorker, timeoutMs: 1000 });
    const promise = verifier.verify({ proofBytes: new Uint8Array([1]) });
    const worker = instances[0];
    worker.reply({ type: "error", run: worker.posted[1].data.run, error: { name: "TypeError", code: null, message: "bad type" } });
    await assert.rejects(promise, (error) => {
      assert.ok(error instanceof TypeError);
      return true;
    });
  });
  await withFakeUrl(async () => {
    const { FakeWorker, instances } = fakeWorkerClass();
    const verifier = createOtsVerifier({ source: "s", wasmBytes: () => new Uint8Array([1]), Worker: FakeWorker, timeoutMs: 1000 });
    const promise = verifier.verify({ proofBytes: new Uint8Array([1]) });
    const worker = instances[0];
    worker.reply({ type: "error", run: worker.posted[1].data.run, error: { name: "OtsParseError", code: "TRUNCATED", message: "truncated" } });
    await assert.rejects(promise, (error) => {
      assert.equal(error.name, "OtsParseError");
      assert.equal(error.code, "TRUNCATED");
      assert.equal(error.message, "truncated");
      return true;
    });
  });
});

test("client: the Node fallback verifies in process when there is no source and no Worker", async () => {
  const verifier = createOtsVerifier({ source: null, Worker: undefined });
  const out = await verifier.verify({ proofBytes: new Uint8Array([0]) });
  assert.equal(out.result, "INVALID");
  assert.match(out.reason, /^parse:/);
});

// ---- release build --------------------------------------------------------

test("a release build ships neither the OTS worker source nor the worker bundle", () => {
  const out = mkdtempSync(join(tmpdir(), "entropylab-release-"));
  try {
    // CI checks the repository out shallow, where build-commit.mjs refuses to
    // name a commit. The footer stamp is not under test: pointing GIT_DIR at
    // a missing directory makes the build stamp "unknown" instead.
    const env = { ...process.env, GIT_DIR: join(out, "no-git") };
    execFileSync(process.execPath, [join(root, "scripts/build.mjs"), "--out", out], { cwd: root, env, stdio: "pipe" });
    const page = readFileSync(join(out, "entropylab.html"), "utf8");
    assert.ok(workerSource.includes("OtsParseError"), "the worker bundle carries the parser");
    // __OTS_WORKER_SOURCE__ is defined only in preview builds, so the worker
    // bundle cannot reach a release page. (The rest of the Verify code does,
    // as dead code: app.js declares PREVIEW with var, which esbuild does not
    // fold, so preview-gated calls stay in the bundle.) esbuild prints a string
    // literal's plain characters unchanged, so a run of plain code from the
    // bundle would appear verbatim if the define were set.
    const marker = workerSource.match(/[A-Za-z0-9_.(){}=,;:+*<>!&|? -]{60,}/g)?.sort((a, b) => b.length - a.length)[0];
    assert.ok(marker, "the worker bundle has a plain-code run to look for");
    assert.ok(!page.includes(marker), "the release build carries no OTS worker bundle");
  } finally {
    rmSync(out, { recursive: true, force: true });
  }
});
