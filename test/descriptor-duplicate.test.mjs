import { test } from "node:test";
import assert from "node:assert/strict";
import { descriptorDuplicateCheck } from "../src/js/addresses.js";

const XPUB_A =
  "xpub661MyMwAqRbcFhCvdhTAfpEEDV58oqDvv65YNHC686NNs4KbH8YZQJWVmrfbve7aAVHzxw8bKFxA7MLeDK6BbLfkE3bqkvHLPgaGHHtYGeY";
const XPUB_B =
  "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw";

test("detects a duplicate that exists only in a later multipath branch", () => {
  const descriptor = `wsh(or_i(pk(${XPUB_A}/<0;1>),pk(${XPUB_A}/<2;1>)))`;
  const result = descriptorDuplicateCheck(descriptor, 0);

  assert.equal(result.isValid, true);
  assert.equal(result.expandedCount, 2);
  assert.equal(result.childIndex, 0);
  assert.equal(result.hasDuplicate, true);
  assert.equal(result.findings.length, 1);
  assert.deepEqual(
    result.findings[0].occurrences.map(({ branch, keyPosition }) => [branch, keyPosition]),
    [[1, 0], [1, 1]],
  );
});

test("detects explicit duplicate concrete keys", () => {
  const result = descriptorDuplicateCheck(
    `wsh(or_i(pk(${XPUB_A}/1),pk(${XPUB_A}/1)))`,
    0,
  );
  assert.equal(result.hasDuplicate, true);
  assert.equal(result.findings.length, 1);
});

test("detects duplicate multisig key material", () => {
  const result = descriptorDuplicateCheck(
    `wsh(multi(2,${XPUB_A}/0/0,${XPUB_A}/0/0))`,
    0,
  );
  assert.equal(result.hasDuplicate, true);
});

test("detects duplicate key material across all multipath branches", () => {
  const result = descriptorDuplicateCheck(
    `wsh(multi(2,${XPUB_A}/0/<0;1>/*,${XPUB_A}/0/<0;1>/*))`,
    0,
  );
  assert.equal(result.expandedCount, 2);
  assert.equal(result.hasDuplicate, true);
});

test("rejects invalid BIP-389 multipath expressions before scanning", () => {
  const invalid = [
    `wpkh(${XPUB_A}/<0;0>/*)`,
    `wpkh(${XPUB_A}/<0;1>/<2;3>/*)`,
    `wpkh([deadbeef/<0;1>]${XPUB_A}/0/*)`,
  ];

  for (const descriptor of invalid) {
    assert.throws(
      () => descriptorDuplicateCheck(descriptor, 0),
      /Invalid output descriptor or invalid multipath expression/,
    );
  }
});

test("does not flag distinct xpubs", () => {
  const result = descriptorDuplicateCheck(
    `wsh(multi(2,${XPUB_A}/0/<0;1>/*,${XPUB_B}/0/<0;1>/*))`,
    0,
  );
  assert.equal(result.hasDuplicate, false);
});

test("does not flag distinct paths from the same xpub", () => {
  const result = descriptorDuplicateCheck(
    `wsh(multi(2,${XPUB_A}/0/0,${XPUB_A}/0/2))`,
    0,
  );
  assert.equal(result.hasDuplicate, false);
});

test("does not flag distinct derivation paths", () => {
  const result = descriptorDuplicateCheck(
    `wsh(multi(2,${XPUB_A}/0/0,${XPUB_A}/1/0))`,
    0,
  );
  assert.equal(result.hasDuplicate, false);
});
