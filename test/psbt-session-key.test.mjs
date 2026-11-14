// The PSBT Inspector's pasted session key (red-team sweep 0eed735, part07
// #12 and part08 #2). A single key is checked before it becomes the session
// key, so a rejected one is never left behind as one. And the run stamp,
// which outlives the key field, holds a digest of the key text, not the text.
// Run with `npm test` (part of the default suite).
import { after, test } from "node:test";
import assert from "node:assert/strict";
import { loadAppFunctions } from "./app-slice-harness.mjs";

const inertDom = new Proxy(function () {}, { get: (target, key) => (key === Symbol.toPrimitive ? () => "" : key === "then" ? undefined : inertDom), apply: () => inertDom, construct: () => inertDom });
Object.assign(globalThis, { __ENTROPYLAB_TEST_HOOKS__: false, document: inertDom, window: inertDom });
after(() => {
  delete globalThis.__ENTROPYLAB_TEST_HOOKS__;
  delete globalThis.document;
  delete globalThis.window;
});

const session = await loadAppFunctions(["hodlLoadPsbtKey", "hodlPsbtWipeMem", "hodlPsbtPriv"]);

test("a rejected single key never becomes the session key", () => {
  // Zero and the group order n decode as 32 bytes but are not private keys.
  for (const hex of ["00".repeat(32), "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"]) {
    assert.throws(() => session.hodlLoadPsbtKey(hex), `${hex.slice(0, 8)}… is refused`);
    assert.equal(session.hodlPsbtPriv, null, `${hex.slice(0, 8)}…: no session key is left behind`);
  }
  // A valid key (scalar 1, the textbook example) still loads, as bytes.
  session.hodlLoadPsbtKey("00".repeat(31) + "01");
  assert.deepEqual([...session.hodlPsbtPriv], [...new Uint8Array(31), 1]);
  // Refusing the next one leaves no key at all, not the previous one.
  assert.throws(() => session.hodlLoadPsbtKey("00".repeat(32)));
  assert.equal(session.hodlPsbtPriv, null);
  session.hodlPsbtWipeMem();
});

test("the run stamp holds a digest of the key fields, not their text", async () => {
  const values = {};
  const stamp = await loadAppFunctions(["hodlPsbtRunStamp", "hodlPsbtCards"], {
    stubs: { document: { getElementById: (id) => ({ value: values[id] ?? "" }) }, hodlStationPassphraseStamp: () => "" },
  });
  const keyText = "cNotARealKeyButLooksLikeOneQ1w2e3r4t5y6u7i8o9p0asdfghjk";
  for (const card of stamp.hodlPsbtCards) {
    const keyField = card.fields.find((id) => /-key$/.test(id));
    assert.ok(keyField, `${card.go} has a key field`);
    Object.keys(values).forEach((id) => delete values[id]);
    values[card.text] = "cHNidP8BAA==";
    values[keyField] = `  ${keyText}  `;
    const first = stamp.hodlPsbtRunStamp(card);
    assert.ok(!first.includes(keyText), `${card.go}: the stamp does not hold the key text`);
    assert.ok(first.includes("cHNidP8BAA=="), `${card.go}: the payload is still stamped as it is`);
    values[keyField] = keyText;
    assert.equal(stamp.hodlPsbtRunStamp(card), first, `${card.go}: surrounding space changes nothing, as before`);
    values[keyField] = keyText.slice(0, -1) + "x";
    assert.notEqual(stamp.hodlPsbtRunStamp(card), first, `${card.go}: a changed key still changes the stamp`);
    values[keyField] = "";
    assert.notEqual(stamp.hodlPsbtRunStamp(card), first, `${card.go}: an emptied key field changes it too`);
  }
});
