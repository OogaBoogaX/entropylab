// Multisig co-signer identity (issue #92): an extended public key's parent
// fingerprint and version bytes are unauthenticated serialization metadata.
// Mutating only those bytes must not let one account key pass as two
// distinct co-signers, and no generated script may contain a repeated public
// key.
// Run with: npm test
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { HDKey } from "@scure/bip32";
import { mnemonicToSeedSync } from "@scure/bip39";
import { createBase58check } from "@scure/base";
import { sha256 } from "@noble/hashes/sha2.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const app = readFileSync(join(root, "src/js/app.js"), "utf8");

// Extract the app's real identity functions and run them against real HDKey
// nodes, so the test exercises the shipped comparison rather than a copy.
function loadFunctionSource(name) {
  const start = app.indexOf(`function ${name}(`);
  assert.ok(start >= 0, name);
  let depth = 0;
  for (let i = app.indexOf("{", start); i < app.length; i++) {
    if (app[i] === "{") depth++;
    else if (app[i] === "}" && --depth === 0) return app.slice(start, i + 1);
  }
  throw new Error(`unterminated ${name}`);
}

function loadIdentityFn() {
  const path = join(root, "test", `.msig-identity-${Math.random().toString(16).slice(2)}.mjs`);
  writeFileSync(
    path,
    `import { hex as hodlHex } from "@scure/base";\n${loadFunctionSource("hodlMsigDerivedNode")}\n${loadFunctionSource("hodlCanonicalMultisigKey")}\nexport { hodlCanonicalMultisigKey };\n`,
  );
  return path;
}

const slicePath = loadIdentityFn();
const { hodlCanonicalMultisigKey } = await import(pathToFileURL(slicePath).href);
unlinkSync(slicePath);

const base58check = createBase58check(sha256);
const seed = mnemonicToSeedSync(
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
);
// One account node per standard the multisig flow accepts.
const ACCOUNT_PATHS = {
  "Legacy BIP45": "m/45'",
  "Legacy BIP87": "m/87'/0'/0'",
  "Nested SegWit BIP48": "m/48'/0'/0'/1'",
  "Native SegWit BIP48": "m/48'/0'/0'/2'",
  "Taproot BIP86": "m/86'/0'/0'",
};

const identityOf = (node) => hodlCanonicalMultisigKey({ node });

// Re-encode an extended key with only metadata bytes changed, then parse it
// back the way the app does before deriving an HDKey.
const remetadata = (xpub, mutate) => {
  const payload = base58check.decode(xpub);
  mutate(payload);
  return HDKey.fromExtendedKey(base58check.encode(payload));
};

test("xpubs differing only in parent-fingerprint bytes are one co-signer", () => {
  for (const [label, path] of Object.entries(ACCOUNT_PATHS)) {
    const node = HDKey.fromMasterSeed(seed).derive(path);
    const mutated = remetadata(node.publicExtendedKey, (payload) => {
      payload[5] ^= 0xff; // parent fingerprint bytes 5..8
      payload[6] ^= 0xff;
      payload[7] ^= 0xff;
      payload[8] ^= 0xff;
    });
    assert.notEqual(mutated.publicExtendedKey, node.publicExtendedKey, label);
    assert.notEqual(mutated.parentFingerprint, node.parentFingerprint, label);
    assert.equal(identityOf(mutated), identityOf(node), label);
  }
});

test("xpubs differing only in version bytes are one co-signer", () => {
  const node = HDKey.fromMasterSeed(seed).derive("m/48'/0'/0'/2'");
  // Same payload, reserialized under the mainnet Zpub version (0x02aa7ed3).
  const zpubPayload = base58check.decode(node.publicExtendedKey);
  zpubPayload.set([0x02, 0xaa, 0x7e, 0xd3], 0);
  const zpub = base58check.encode(zpubPayload);
  assert.notEqual(zpub, node.publicExtendedKey);
  // The app normalizes version bytes before parsing; do the same here.
  const reparsed = remetadata(zpub, (payload) => {
    payload.set([0x04, 0x88, 0xb2, 0x1e], 0);
  });
  assert.equal(identityOf(reparsed), identityOf(node));
});

test("legitimately distinct account keys stay distinct", () => {
  const first = HDKey.fromMasterSeed(seed).derive("m/48'/0'/0'/2'");
  const otherSeed = mnemonicToSeedSync(
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
  );
  const second = HDKey.fromMasterSeed(otherSeed).derive("m/48'/0'/0'/2'");
  assert.notEqual(identityOf(first), identityOf(second));
  // A different hardened account of the same seed is also a distinct signer.
  assert.notEqual(identityOf(first), identityOf(HDKey.fromMasterSeed(seed).derive("m/48'/0'/1'/2'")));
});

test("one account key under different appended derivation paths is distinct co-signers", () => {
  const node = HDKey.fromMasterSeed(seed).derive("m/48'/0'/0'/2'");
  // Reusing a key requires the appended path, and the same path twice is
  // still the same co-signer.
  assert.notEqual(hodlCanonicalMultisigKey({ node }), hodlCanonicalMultisigKey({ node, derivationPath: "1" }));
  assert.notEqual(hodlCanonicalMultisigKey({ node, derivationPath: "1" }), hodlCanonicalMultisigKey({ node, derivationPath: "2" }));
  assert.equal(hodlCanonicalMultisigKey({ node, derivationPath: "1" }), hodlCanonicalMultisigKey({ node, derivationPath: "1" }));
  // The identity matches the account key derived through the path directly.
  assert.equal(hodlCanonicalMultisigKey({ node, derivationPath: "1" }), identityOf(node.derive("m/1")));
  assert.equal(hodlCanonicalMultisigKey({ node, derivationPath: "1/2" }), identityOf(node.derive("m/1/2")));
});

test("both duplicate checks and the final script guard use derivation identity", () => {
  // Field-level and final validation compare hodlCanonicalMultisigKey output.
  assert.match(app, /function hodlDuplicateMultisigKey\(ta, parsed\) \{\s*let canonical = hodlCanonicalMultisigKey\(parsed\)/);
  assert.match(app, /canonical = hodlCanonicalMultisigKey\(parsed\);\s*if \(xpubs\.includes\(canonical\)\) throw new Error\(`Co-signer \$\{index \+ 1\} duplicates an earlier co-signer/);
  // Final defense: a generated script never contains a repeated public key.
  assert.match(app, /new Set\(publicKeys\.map\(hodlHex\.encode\)\)\.size !== publicKeys\.length/);
  // Identity follows the node derived through any appended co-signer path.
  assert.match(app, /let node = hodlMsigDerivedNode\(parsed\), canonical = hodlCanonicalMultisigKey\(parsed\)/);
  // Identity ignores the reserialized extended key (which carries metadata).
  const start = app.indexOf("function hodlCanonicalMultisigKey(");
  const end = app.indexOf("function hodlDuplicateMultisigKey", start);
  const body = app.slice(start, end);
  assert.match(body, /node\.publicKey/);
  assert.match(body, /node\.chainCode/);
  assert.doesNotMatch(body, /publicExtendedKey/);
});
