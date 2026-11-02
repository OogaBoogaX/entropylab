// Security contract: a partial BBQr transfer cannot be replaced by another
// transport; reset releases the session and permits a new complete PSBT.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createPsbtQrReader } from "../src/js/psbt-qr-payload.js";
import { hodlUrEncodePsbt } from "../src/js/psbt-ur.js";

const source = Buffer.from(readFileSync(new URL("./fixtures/psbt/p2wpkh-1in-2out.b64", import.meta.url), "utf8").trim(), "base64");
// BBQr specification: H/P, two parts, indices 00 and 01; hex carries
// source bytes directly, independently of the implementation under test.
const hex = source.toString("hex").toUpperCase();
const cut = Math.ceil(source.length / 2) * 2;
const frames = [`B$HP0200${hex.slice(0, cut)}`, `B$HP0201${hex.slice(cut)}`];

for (const [name, other] of [
  ["UR", hodlUrEncodePsbt(new Uint8Array(source))[0]],
  ["static base64", source.toString("base64")],
]) {
  test(`a partial BBQr refuses replacement by ${name} until reset`, () => {
    const reader = createPsbtQrReader();
    assert.equal(reader.receive(frames[0]).status, "partial");
    assert.equal(reader.receive(other).status, "mismatch");
    assert.equal(reader.receive(frames[1]).status, "mismatch");
    assert.equal(reader.progress(), null);
    reader.reset();
    assert.equal(reader.receive(frames[1]).status, "partial");
    const result = reader.receive(frames[0]);
    assert.equal(result.status, "complete");
    assert.deepEqual(Buffer.from(result.bytes), source);
    result.bytes.fill(0);
    reader.reset();
  });
}

test("BBQr cannot displace a partially assembled UR", () => {
  const reader = createPsbtQrReader();
  const parts = hodlUrEncodePsbt(new Uint8Array(source), { maxBytes: 80 });
  assert.equal(reader.receive(parts[0]).status, "partial");
  assert.equal(reader.receive(frames[0]).status, "mismatch");
  assert.equal(reader.progress(), null);
  reader.reset();
});

test("unrelated text does not mutate BBQr progress; reset drops retained fragments", () => {
  const reader = createPsbtQrReader();
  assert.equal(reader.receive(frames[1]).status, "partial");
  assert.deepEqual(reader.progress(), { received: 1, total: 2 });
  assert.equal(reader.receive("not a PSBT").status, "not-psbt");
  assert.deepEqual(reader.progress(), { received: 1, total: 2 });
  reader.reset();
  assert.equal(reader.progress(), null);
  assert.equal(reader.receive(frames[0]).status, "partial");
  assert.deepEqual(reader.progress(), { received: 1, total: 2 });
  reader.reset();
});
