// Audit M4: finalized scriptSig/witness pushes are attacker-controlled. The
// nonce-analysis path must cap script pushes and candidate keys instead of
// running an O(signatures * candidates^2) deduplication and an unbounded
// EC-verification search.
// Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { loadAppFunctions } from "./app-slice-harness.mjs";

const entries = [];
const stubs = {
  hodlFind: (_entries, type) => (type === 7 ? entries : []),
  hodlInputScriptCode: () => null,
  hodlScriptHasCodeSeparator: () => false,
  hodlSecp256k1: { verify: () => false },
  hodlBip143: () => null,
  hodlHex: { encode: (bytes) => Buffer.from(bytes).toString("hex") },
};
const { hodlFinalSigs } = await loadAppFunctions(["hodlFinalSigs"], { stubs });

const push = (bytes) => Uint8Array.from([bytes.length, ...bytes]);
const pubkey = (fill) => push(Uint8Array.from([0x02, ...new Uint8Array(32).fill(fill)]));
const signature = () => push(Uint8Array.from([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01]));

test("more than 512 script pushes are marked malformed instead of analyzed", () => {
  entries.length = 0;
  const script = Uint8Array.from(Array.from({ length: 600 }, () => pubkey(1)).flatMap((item) => [...item]));
  entries.push({ keydata: new Uint8Array(), val: script });
  const started = Date.now();
  const result = hodlFinalSigs(entries, null, { inputs: [], outputs: [] }, 0, { remaining: 0 });
  assert.equal(result.malformed, true);
  assert.ok(Date.now() - started < 2000, "the capped scan returned promptly");
});

test("more than 32 candidate keys in a witnessScript are also capped", async () => {
  // scriptCode's pushes used to bypass addCandidate, so a witnessScript with
  // 511 pubkey-shaped pushes became 511 EC-verification candidates and the
  // budget bound the stack but not this path.
  entries.length = 0;
  const parts = [];
  for (let i = 0; i < 100; i++) parts.push(...pubkey(i));
  const scriptCode = Uint8Array.from(parts);
  const { hodlFinalSigs: withScript } = await loadAppFunctions(["hodlFinalSigs"], {
    stubs: { ...stubs, hodlInputScriptCode: () => scriptCode },
  });
  const result = withScript(entries, null, { inputs: [], outputs: [] }, 0, { remaining: 64 });
  assert.equal(result.malformed, true, "the scriptCode candidate cap must block a clean verdict");
});

test("more than 32 distinct candidate keys are marked malformed", () => {
  entries.length = 0;
  const parts = [];
  for (let i = 0; i < 100; i++) parts.push(...pubkey(i));
  parts.push(...signature());
  entries.push({ keydata: new Uint8Array(), val: Uint8Array.from(parts) });
  const result = hodlFinalSigs(entries, null, { inputs: [], outputs: [] }, 0, { remaining: 0 });
  assert.equal(result.malformed, true, "the candidate cap must block a clean verdict");
  assert.ok(result.uninspected >= 1);
});
