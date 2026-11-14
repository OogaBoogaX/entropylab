// Security contract: independently emitted, complete PSBTs must be recovered
// byte-exactly; malformed CRC frames and incomplete streams must not load bytes.
// No Python, reference checkout, network, or generator is needed by this suite.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { createHash } from "node:crypto";
import { createPsbtQrReader } from "../src/js/psbt-qr-payload.js";
import { psbtInspectDoc } from "../src/js/psbt-wasm.js";
const root = new URL("./fixtures/psbt-qr/", import.meta.url);
const manifest = JSON.parse(readFileSync(new URL("manifest.json", root), "utf8"));
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

test("the independent corpus has no missing or untracked payload files", () => {
  assert.equal(manifest.reference.revision, "e0a80d4b33b8eb7fb1e9fd14a27b7cd11c7d2cd6");
  const listed = manifest.fixtures.map((entry) => entry.file).sort();
  assert.equal(new Set(listed).size, listed.length);
  assert.deepEqual(readdirSync(root).filter((file) => file.endsWith(".txt")).sort(), listed);
});

for (const entry of manifest.fixtures) {
  test(`reference ${entry.file}: ${entry.expected.status}`, () => {
    assert.match(entry.file, /^[a-z0-9.-]+\.txt$/);
    const data = readFileSync(new URL(entry.file, root));
    assert.equal(data.length, entry.bytes);
    assert.equal(sha256(data), entry.sha256);
    const source = Buffer.from(readFileSync(new URL(`../${entry.source.path}`, import.meta.url), "utf8"), "base64");
    assert.equal(source.length, entry.source.bytes);
    assert.equal(sha256(source), entry.source.sha256);
    const reader = createPsbtQrReader();
    let result, accepted;
    try {
      const parts = data.toString("ascii").trim().split("\n");
      assert.equal(parts.length, entry.parts);
      for (const part of parts) {
        result = reader.receive(part);
        if (result.status === "complete") accepted = result.bytes;
        else if (!["partial", "done"].includes(result.status)) break;
      }
      if (entry.expected.status !== "complete") {
        assert.equal(accepted, undefined);
        assert.equal(result.status, entry.expected.status);
        return;
      }
      assert.ok(accepted instanceof Uint8Array);
      assert.equal(accepted.length, entry.expected.bytes);
      assert.equal(sha256(accepted), entry.expected.sha256);
      const doc = psbtInspectDoc(accepted);
      assert.equal(doc.rustBitcoinError, null);
      const transaction = {
        version: doc.tx.version, locktime: doc.tx.locktime,
        inputs: doc.tx.inputs.map(({ txid, vout, sequence }) => ({ txid, vout, sequence })),
        outputs: doc.tx.outputs.map(({ value, scriptPubKey }) => ({ value, scriptPubKey })),
      };
      assert.deepEqual(transaction, entry.expected.transaction);
    } finally {
      accepted?.fill(0);
      reader.reset();
    }
  });
}
