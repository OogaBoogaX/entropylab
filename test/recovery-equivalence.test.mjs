// Wallet Recovery Equivalence Verification (issue #171) — red-first tests.
//
// Pins the shape and minimum contract of `compareRecoveryArtifacts()`:
// a thin wrapper that takes user-supplied recovery artifacts (seed, xpub,
// SLIP-132 key, descriptor, address) and reports whether they describe
// the same wallet.
//
// This file MUST FAIL on `npm test` until the function lands in
// src/js/recovery-equivalence.js. Once it lands, the structure and
// edge-case tests below should pass immediately.
//
// Concrete-fixture tests (matching vs mismatching artifact sets using
// BIP-32 vector 1 + BIP-380 spec values) will land in a follow-up once
// the function signature is stable. Per CONTRIBUTING.md "smallest
// change that works" — we don't pin behavior the implementation can't
// run yet.
//
// Run with `node --test test/recovery-equivalence.test.mjs`.
import { test } from "node:test";
import assert from "node:assert/strict";

// RED trigger: import the not-yet-implemented module.
// Until src/js/recovery-equivalence.js exists and exports
// compareRecoveryArtifacts, this whole file fails to load = clear RED
// state for reviewers, not a cryptic "no tests ran".
import { compareRecoveryArtifacts } from "../src/js/recovery-equivalence.js";

test("returns a non-null object", () => {
  const out = compareRecoveryArtifacts({}, { network: "mainnet", receiveIndex: 0 });
  assert.equal(typeof out, "object");
  assert.ok(out !== null);
});

test("result.steps is an array of { name: string, ok: boolean } objects", () => {
  const out = compareRecoveryArtifacts({}, { network: "mainnet", receiveIndex: 0 });
  assert.ok(Array.isArray(out.steps), "out.steps is an array");
  for (const step of out.steps) {
    assert.equal(typeof step.name, "string", `step.name is a string (got ${typeof step.name})`);
    assert.equal(typeof step.ok, "boolean", `step.ok is a boolean (got ${typeof step.ok})`);
  }
});

test("out.verdict is one of 'consistent' | 'inconsistent' | 'insufficient'", () => {
  const out = compareRecoveryArtifacts({}, { network: "mainnet", receiveIndex: 0 });
  assert.ok(
    ["consistent", "inconsistent", "insufficient"].includes(out.verdict),
    `verdict '${out.verdict}' is not one of: consistent, inconsistent, insufficient`,
  );
});

test("empty artifacts object → 'insufficient' verdict (no throw)", () => {
  assert.doesNotThrow(() => {
    const out = compareRecoveryArtifacts({}, { network: "mainnet", receiveIndex: 0 });
    assert.equal(out.verdict, "insufficient");
  });
});

test("only one artifact (descriptor alone) → 'insufficient' (no throw)", () => {
  assert.doesNotThrow(() => {
    const out = compareRecoveryArtifacts(
      // BIP-32 test vector 1 master xpub + fingerprint; the path does
      // not match this xpub, but the function never reaches parsing
      // for an insufficient artifact count. Well-formed input regardless.
      {
        descriptor: "wpkh([3442193e/84'/0'/0']xpub6CVKsQYXc9awxgV1tWbG4foDvdcnieK2JkbpPEBKB5WwAPkArY1ssordaRffWaMeWiST7SnxYSGPUsnnE9cj8HDRhDzykXuGAJUCC9jVy8h/0/*)#n8a2qkyc",
      },
      { network: "mainnet", receiveIndex: 0 },
    );
    assert.equal(out.verdict, "insufficient");
  });
});
