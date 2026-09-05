// The multisig Paste descriptor panel decomposes a full multisig descriptor:
// the wrapper picks the script type, multi/sortedmulti picks the key order,
// and the threshold plus one key expression per co-signer fill the quorum and
// the fields. The #checksum is verified, private keys are refused, and shapes
// the form cannot reproduce (a fixed derivation path, a non-NUMS Taproot
// internal key) fail with directions.
// Run with: npm test
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { HDKey } from "@scure/bip32";
import { mnemonicToSeedSync } from "@scure/bip39";
import { createBase58check } from "@scure/base";
import { sha256 } from "@noble/hashes/sha2.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const app = readFileSync(join(root, "src/js/app.js"), "utf8");
const page = readFileSync(join(root, "src/index.html"), "utf8");
const shell = readFileSync(join(root, "src/shell.html"), "utf8");

function loadSlice(name) {
  const start = app.indexOf(`function ${name}(`);
  assert.ok(start >= 0, name);
  let depth = 0;
  let end = -1;
  for (let i = app.indexOf("{", start); i < app.length; i++) {
    if (app[i] === "{") depth++;
    else if (app[i] === "}") {
      depth--;
      if (depth === 0) {
        end = i + 1;
        break;
      }
    }
  }
  assert.ok(end > start, name);
  return app.slice(start, end);
}

const source = [
  loadSlice("hodlDescriptorSymbolValues"),
  loadSlice("hodlDescriptorPolymod"),
  loadSlice("hodlDescriptorChecksum"),
  loadSlice("hodlDescriptorWithChecksum"),
  loadSlice("hodlStripDescriptorChecksum"),
  loadSlice("hodlNormalizeOriginPath"),
  loadSlice("hodlParseKeyOrigin"),
  loadSlice("hodlDescriptorKeyExpressions"),
  loadSlice("hodlParseMultisigCosigner"),
  loadSlice("hodlSplitDescriptorArgs"),
  loadSlice("hodlUnwrapDescriptor"),
  loadSlice("hodlMsigDescriptorKeyText"),
  loadSlice("hodlParseMsigDescriptor"),
].join("\n");
// Stub the extended-key decoder: these tests assert which key text the parser
// hands to it and how keys are counted and refused, not base58check itself.
// The checksum charset constants are pulled from their var declaration in
// app.js so the test tracks the real values.
const hodlParseExtendedKey = (key) => ({ receivedKey: key, isPrivate: key.slice(0, 4).toLowerCase().endsWith("prv") });
const charsets = app.match(/var hodlDescriptorInputCharset = "([^"]+)", hodlBech32Charset = "([^"]+)";/);
assert.ok(charsets, "descriptor checksum charsets");
const load = (name) => new Function("hodlParseExtendedKey", "hodlDescriptorInputCharset", "hodlBech32Charset", "hodlMsigSliderLimit", `${source}; return ${name};`)(hodlParseExtendedKey, charsets[1], charsets[2], 15);
const hodlParseMsigDescriptor = load("hodlParseMsigDescriptor");
const hodlDescriptorWithChecksum = load("hodlDescriptorWithChecksum");

const base58check = createBase58check(sha256);
const seed = mnemonicToSeedSync(
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
);
const master = HDKey.fromMasterSeed(seed);
const fingerprint = master.fingerprint.toString(16).padStart(8, "0");

// Re-encode an extended key with different version bytes (xpub -> Zpub etc.).
const reversion = (xkey, version) => {
  const payload = base58check.decode(xkey);
  payload.set([(version >>> 24) & 0xff, (version >>> 16) & 0xff, (version >>> 8) & 0xff, version & 0xff], 0);
  return base58check.encode(payload);
};
const ZPUB = 0x02aa7ed3;
const ZPRV = 0x02aa7a99;

const nodeA = master.derive("m/48'/0'/0'/2'");
const nodeB = master.derive("m/48'/0'/1'/2'");
const nodeC = master.derive("m/48'/0'/2'/2'");
const zpubA = reversion(nodeA.publicExtendedKey, ZPUB);
const zpubB = reversion(nodeB.publicExtendedKey, ZPUB);
const zpubC = reversion(nodeC.publicExtendedKey, ZPUB);
const zprvA = reversion(nodeA.privateExtendedKey, ZPRV);
const keyA = `[${fingerprint}/48h/0h/0h/2h]${zpubA}`;
const keyB = `[${fingerprint}/48h/0h/1h/2h]${zpubB}`;
const keyC = `[${fingerprint}/48h/0h/2h/2h]${zpubC}`;
const NUMS = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

test("a wsh sortedmulti descriptor decomposes into quorum, kind, order, and keys", () => {
  const descriptor = hodlDescriptorWithChecksum(`wsh(sortedmulti(2,${keyA}/0/*,${keyB}/0/*,${keyC}/0/*))`);
  const parsed = hodlParseMsigDescriptor(descriptor);
  assert.equal(parsed.m, 2);
  assert.equal(parsed.n, 3);
  assert.equal(parsed.sorted, true);
  assert.equal(parsed.kind, "p2wsh");
  assert.deepEqual(parsed.keys, [keyA, keyB, keyC], "the branch wildcard is stripped, origin and key stay intact");
});

test("sh, sh(wsh), and bare multi wrappers map to script kinds", () => {
  const nested = hodlParseMsigDescriptor(hodlDescriptorWithChecksum(`sh(wsh(multi(2,${keyA}/0/*,${keyB}/0/*)))`));
  assert.equal(nested.kind, "p2sh-p2wsh");
  assert.equal(nested.sorted, false);
  const legacy = hodlParseMsigDescriptor(hodlDescriptorWithChecksum(`sh(multi(1,${keyA}))`));
  assert.equal(legacy.kind, "p2sh");
  assert.equal(legacy.m, 1);
  assert.equal(legacy.n, 1);
  const bare = hodlParseMsigDescriptor(`sortedmulti(2,${keyA}/0/*,${keyB}/0/*)`);
  assert.equal(bare.kind, null, "no wrapper keeps the selected script type");
});

test("a present checksum is verified, not just stripped", () => {
  const descriptor = hodlDescriptorWithChecksum(`wsh(sortedmulti(2,${keyA}/0/*,${keyB}/0/*))`);
  const corrupted = descriptor.slice(0, -1) + (descriptor.endsWith("0") ? "1" : "0");
  assert.throws(() => hodlParseMsigDescriptor(corrupted), /checksum does not match/);
  assert.doesNotThrow(() => hodlParseMsigDescriptor(descriptor));
  assert.doesNotThrow(() => hodlParseMsigDescriptor(descriptor.slice(0, descriptor.lastIndexOf("#"))), "no checksum is accepted too");
});

test("multipath suffixes strip like plain branch wildcards", () => {
  const parsed = hodlParseMsigDescriptor(`wsh(sortedmulti(2,${keyA}/<0;1>/*,${keyB}/<0;1>/*))`);
  assert.deepEqual(parsed.keys, [keyA, keyB]);
});

test("an extended private key in the descriptor is refused", () => {
  assert.throws(
    () => hodlParseMsigDescriptor(`wsh(sortedmulti(1,[${fingerprint}/48h/0h/0h/2h]${zprvA}/0/*,${keyB}/0/*))`),
    /extended private key/,
  );
});

test("a fixed derivation path after a key is refused with directions", () => {
  assert.throws(
    () => hodlParseMsigDescriptor(`wsh(sortedmulti(2,${keyA}/1,${keyB}/0/*))`),
    /fixed path/,
  );
});

test("a Taproot descriptor imports only over the NUMS internal key", () => {
  const parsed = hodlParseMsigDescriptor(`tr(${NUMS},multi_a(2,${keyA}/<0;1>/*,${keyB}/<0;1>/*))`);
  assert.equal(parsed.kind, "p2tr");
  assert.equal(parsed.m, 2);
  assert.equal(parsed.sorted, false);
  assert.throws(
    () => hodlParseMsigDescriptor(`tr(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,sortedmulti_a(2,${keyA}/<0;1>/*,${keyB}/<0;1>/*))`),
    /NUMS/,
  );
});

test("single-sig wrappers and broken thresholds are refused", () => {
  assert.throws(() => hodlParseMsigDescriptor(`wpkh(${keyA}/0/*)`), /not a multisig descriptor/);
  assert.throws(() => hodlParseMsigDescriptor(`wsh(sortedmulti(4,${keyA}/0/*,${keyB}/0/*))`), /exceeds/);
  assert.throws(() => hodlParseMsigDescriptor(""), /Paste a multisig output descriptor first/);
});

test("more keys than the quorum supports are refused", () => {
  const many = Array.from({ length: 16 }, () => `${keyA}/0/*`).join(",");
  assert.throws(() => hodlParseMsigDescriptor(`wsh(sortedmulti(2,${many}))`), /at most 15/);
});

test("both markups ship the Paste descriptor panel and the app wires it", () => {
  for (const markup of [shell]) {
    assert.match(markup, /<summary[^>]*>Paste descriptor<\/summary>/, "expandable summary");
    assert.ok(markup.includes('id="msig-descriptor"'), "descriptor textarea");
    assert.ok(markup.includes('id="msig-descriptor-import"'), "import button");
    assert.ok(markup.includes('id="msig-descriptor-status"'), "status line");
    assert.ok(markup.includes('id="msig-descriptor-import" type="button" disabled aria-disabled="true"'), "the import button ships disabled — the descriptor field starts empty");
  }
  assert.ok(app.includes('addEventListener("click", hodlImportMsigDescriptor)'), "the import button is wired");
});

test("the import button disables while any co-signer field holds text", () => {
  const sync = loadSlice("hodlSyncMsigDescriptorImport");
  assert.ok(sync.includes("button.disabled = occupied || empty"), "occupied fields or an empty descriptor disable the button");
  assert.ok(sync.includes('aria-disabled'), "the disabled state is announced");
  assert.ok(sync.includes("Clear the co-signer fields to import a descriptor."), "the hint explains the disabled state");
  // The sync follows every path that changes what the co-signer fields hold:
  // a fill rebuild, typing or a session-key pick (the textarea oninput), and
  // the reset. The import itself still guards against occupied fields.
  const fill = loadSlice("hodlFillKeys");
  assert.ok(fill.includes("hodlSyncMsigDescriptorImport(true)"), "typing in a co-signer field re-syncs and drops any import result");
  assert.ok(fill.includes("hodlSyncMsigDescriptorImport();"), "rebuilding the fields re-syncs");
  const importer = loadSlice("hodlImportMsigDescriptor");
  assert.ok(importer.includes("already hold keys"), "the import refuses occupied fields even if the button state is bypassed");
  const fillAt = importer.indexOf("hodlFillKeys(imported.keys)"), pickersAt = importer.indexOf("hodlRefreshMsigSessionPickers()");
  assert.ok(fillAt >= 0 && pickersAt > fillAt, "after the fields fill, the session pickers refresh so a co-signer that matches a Key Lab key shows its lifehash and pressed chip, as if picked by hand");
});
