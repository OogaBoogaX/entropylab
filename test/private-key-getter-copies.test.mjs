// HDKey.privateKey returns a fresh copy on every read (src/js/hdkey.js). A
// truthiness check such as Boolean(node.privateKey) or !node.privateKey
// throws that copy away unzeroed, and a call that reads the getter several
// times (scanNode.privateKey.slice(), getPublicKey(node.privateKey, …))
// leaves every read but the kept one in freed heap slots. The residue audit
// measured exactly this shape of leak in freed PartitionAlloc slots after
// Wipe (issue #546).
//
// Contract: a truthiness check on an HDKey must not copy the private key,
// and every getter copy a function takes is all zero once that function
// returns, on success and on refusal. What the functions accept, refuse and
// derive is unchanged.
//
// Expected values come from published vectors, not from the code under
// test: BIP32 test vector 1 (bitcoin/bips BIP-0032) and the BIP-85
// HMAC-SHA512 test cases (bip-0085.mediawiki). Run with `npm test`.
import { after, test } from "node:test";
import assert from "node:assert/strict";
import { HDKey as ScureHDKey } from "@scure/bip32";
import { HDKey } from "../src/js/hdkey.js";
import { deriveSilentPaymentKeys } from "../src/js/bip352.js";
import { deriveBip85Entropy } from "../src/js/bip85.js";
import { hash160 } from "../src/js/hashes.js";
import { secp256k1 } from "../src/js/secp256k1.js";
import { loadAppFunctions } from "./app-slice-harness.mjs";

const hexToBytes = (hex) => new Uint8Array(hex.match(/.{2}/g).map((b) => parseInt(b, 16)));
const bytesToHex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");

// BIP32 test vector 1's seed and master keys (bitcoin/bips BIP-0032).
const SEED = hexToBytes("000102030405060708090a0b0c0d0e0f");
const XPRV = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
const XPUB = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
// BIP-85's own master root key and HMAC-SHA512 test case 1
// (bip-0085.mediawiki).
const BIP85_MASTER = "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb";
const BIP85_CASE1 = "efecfbccffea313214232d29e71563d941229afb4338c21f9517c41aaa0d16f00b83d2a09ef747e7a64e8e2bd5a14869e693da66ce94ac2da570ab7ee48618f7";

// Runs fn() with a recording wrapper on the app HDKey's privateKey getter,
// and returns fn()'s value plus every copy the getter handed out.
function recordGetterCopies(fn) {
  const copies = [];
  const original = Object.getOwnPropertyDescriptor(HDKey.prototype, "privateKey");
  Object.defineProperty(HDKey.prototype, "privateKey", {
    configurable: true,
    get() {
      const copy = original.get.call(this);
      if (copy) copies.push(copy);
      return copy;
    },
  });
  try {
    return { value: fn(), copies };
  } finally {
    Object.defineProperty(HDKey.prototype, "privateKey", original);
  }
}
function assertAllZero(copies, label, { kept = [] } = {}) {
  for (const [i, copy] of copies.entries()) {
    if (kept.includes(copy)) continue;
    assert.ok(copy.every((b) => b === 0), `${label}: getter copy ${i + 1} of ${copies.length} still holds the private key`);
  }
}

test("BIP-352 session derivation takes one getter copy per key, and hands both to the caller", () => {
  // The all-zero smoke seed and the derived path shape are pinned by the
  // existing BIP-352 suite; the recorded copies are the new assertion.
  const seed = hexToBytes("00".repeat(64));
  const { value: keys, copies } = recordGetterCopies(() => deriveSilentPaymentKeys(seed, { coinType: 0, account: 0 }));
  // The session owns scanPriv/spendPriv; every other read must be zero.
  assertAllZero(copies, "deriveSilentPaymentKeys", { kept: [keys.scanPriv, keys.spendPriv] });
  assert.equal(copies.length, 2, "exactly one getter copy per session key, no duplicates");
  assert.equal(keys.scanPath, "m/352'/0'/0'/1'/0");
  assert.equal(keys.spendPath, "m/352'/0'/0'/0'/0");
  assert.equal(keys.scanPriv.length, 32);
  assert.equal(keys.spendPriv.length, 32);
});

test("BIP-85 entropy derivation zeroes every getter copy, and the watch-only refusal takes none", () => {
  // The BIP-85 spec's master root, so the published HMAC test case applies.
  const root = HDKey.fromExtendedKey(BIP85_MASTER);
  const { value: entropy, copies } = recordGetterCopies(() => deriveBip85Entropy(root, "m/83696968'/0'/0'"));
  // The kept copy (the derived child's key) is wiped by the function; the
  // watch-only truthiness check must not add an unzeroed one.
  assertAllZero(copies, "deriveBip85Entropy");
  assert.ok(copies.length > 0, "the derived child's key is read once and wiped");
  assert.equal(bytesToHex(entropy), BIP85_CASE1);
  // A watch-only root is refused, and the refusal leaves no copy behind.
  // With no preflight, the fully-hardened path refuses inside derive()
  // ("Could not derive hardened child key") before any private key exists.
  const watch = HDKey.fromExtendedKey(XPUB);
  const { copies: refuseCopies } = recordGetterCopies(() => {
    assert.throws(() => deriveBip85Entropy(watch, "m/83696968'/0'/0'"));
  });
  assert.equal(refuseCopies.length, 0, "a watch-only refusal must not read the privateKey getter at all");
});

test("@scure/bip32 roots derive the published BIP-85 vector, and the compatibility path takes no discarded getter copy", () => {
  // The existing suites hand @scure/bip32 HDKeys to deriveBip85Entropy. The
  // pinned scure 2.4.0 getter returns a FRESH copy (Uint8Array.from), not an
  // alias of the node — so a truthiness fallback like Boolean(root.privateKey)
  // would create and discard an unzeroed copy. Record every copy scure's
  // getter hands out and prove the only ones taken are wiped, never dropped.
  const scureRoot = ScureHDKey.fromExtendedKey(BIP85_MASTER);
  const copies = [];
  const original = Object.getOwnPropertyDescriptor(ScureHDKey.prototype, "privateKey");
  Object.defineProperty(ScureHDKey.prototype, "privateKey", {
    configurable: true,
    get() {
      const copy = original.get.call(this);
      if (copy) copies.push(copy);
      return copy;
    },
  });
  let entropy;
  try {
    entropy = deriveBip85Entropy(scureRoot, "m/83696968'/0'/0'");
  } finally {
    Object.defineProperty(ScureHDKey.prototype, "privateKey", original);
  }
  assert.equal(bytesToHex(entropy), BIP85_CASE1);
  assertAllZero(copies, "deriveBip85Entropy on a scure root");
  // The node's own key material must survive untouched as well.
  const after = original.get.call(scureRoot);
  assert.notEqual(after.every((b) => b === 0), true, "the scure root must still hold its key");
  after.fill(0);
});

// ---- app.js sites, loaded through the slice harness ----

// The prefix table rows the parsed keys need stand in for the page-boot
// statements the harness does not run.
const XPRV_VERSION = 0x0488ade4, XPUB_VERSION = 0x0488b21e;
const hodlExtendedKeyPrefixTable = [
  { network: "mainnet", family: "x", scope: "singlesig", private: true, ver: XPRV_VERSION, name: "xprv" },
  { network: "mainnet", family: "x", scope: "singlesig", private: false, ver: XPUB_VERSION, name: "xpub" },
];

test("hodlParseExtendedKey's prefix check reads no private-key copy at all", async () => {
  const app = await loadAppFunctions(["hodlParseExtendedKey"], { stubs: { hodlExtendedKeyPrefixTable } });
  const { copies } = recordGetterCopies(() => {
    const parsed = app.hodlParseExtendedKey(XPRV);
    assert.equal(parsed.isPrivate, true);
    assert.equal(parsed.xkey, XPRV);
    parsed.node.wipePrivateData();
    const watch = app.hodlParseExtendedKey(XPUB);
    assert.equal(watch.isPrivate, false);
  });
  assert.equal(copies.length, 0, "the prefix check answers from hasPrivateKey, never the copying getter");
});

test("hodlRootWalletResult's multisig branch takes no unzeroed root-key copy", async () => {
  const app = await loadAppFunctions(["hodlRootWalletResult"], { stubs: {} });
  const root = HDKey.fromMasterSeed(SEED);
  const source = { entropy: null, passphraseUsed: false, notes: [], warnings: [] };
  const { value: result, copies } = recordGetterCopies(() => app.hodlRootWalletResult(root, "mainnet", source, 0, "73c5da0a", []));
  assert.equal(result.kind, "hd");
  assert.equal(result.rootXpub, XPUB);
  assert.ok(result.multisigCosignerExports.length > 0, "a private root produces multisig cosigner exports");
  result.rootNode?.wipePrivateData();
  assertAllZero(copies, "hodlRootWalletResult");
});

// ---- app.js PSBT nonce/RFC-6979 render (audit C2-B) ----
//
// The Inspector's per-signature loop resolves the session key matching each
// ECDSA signature, to recompute its RFC 6979 nonce. Both resolvers
// (hodlPrivForPub, hodlPrivFromPath) hand back either the canonical WIF/hex
// session buffer or a fresh HDKey privateKey getter copy; the copies used to
// escape unwiped for every signature row, so root/child scalars survived End
// Session in freed heap slots.
//
// Security contract: after a render returns, every private-key getter copy
// taken for it is all zero — whether its signature compared cleanly, was
// refused (invalid or non-strict DER), or left the loop early (digest budget
// spent, script not covered); a row whose r is unreadable never triggers a
// resolution at all. The canonical WIF/hex session buffer is the session's
// own and must NOT be zeroed mid-session by the render, and every
// per-signature verdict stays what it was before the fix.

// The render reads the session key from the app module's own state, exactly
// as after a real key load, and paints status into DOM nodes the slice does
// not have — the inert proxy stands in (same pattern as the copy/i18n
// suites).
const inertDom = new Proxy(function () {}, { get: (target, key) => (key === Symbol.toPrimitive ? () => "" : key === "then" ? undefined : inertDom), apply: () => inertDom, construct: () => inertDom });
Object.assign(globalThis, { __ENTROPYLAB_TEST_HOOKS__: false, document: inertDom, window: inertDom });
const psbtRender = await loadAppFunctions(
  ["hodlRenderPsbt", "hodlBip143", "hodlInputScriptCode", "hodlPsbtWipeMem", "hodlRfc6979Compare"],
  { settable: ["hodlPsbtPriv", "hodlPsbtHd", "hodlPsbtNonceHistory"] },
);
after(() => {
  delete globalThis.__ENTROPYLAB_TEST_HOOKS__;
  delete globalThis.document;
  delete globalThis.window;
});

const PSBT_CHILD_PATH = [0x80000000, 0]; // m/0'/0 under the session root
const psbtWitnessUtxoEntry = (amount, script) => ({
  type: 1,
  keydata: new Uint8Array(),
  val: Uint8Array.of(...[...Array(8)].map((_, i) => Number((BigInt(amount) >> BigInt(8 * i)) & 0xffn)), script.length, ...script),
});
// PSBT_IN_BIP32_DERIVATION: 4-byte big-endian master fingerprint, then the
// path as little-endian uint32 indexes.
const psbtBip32Entry = (pubkey, fingerprint, path) => {
  const val = new Uint8Array(4 + 4 * path.length);
  val.set([(fingerprint >>> 24) & 255, (fingerprint >>> 16) & 255, (fingerprint >>> 8) & 255, fingerprint & 255], 0);
  path.forEach((index, i) => new DataView(val.buffer).setUint32(4 + 4 * i, index >>> 0, true));
  return { type: 6, keydata: pubkey, val };
};
const psbtP2wpkh = (pubkey) => Uint8Array.of(0x00, 0x14, ...hash160(pubkey));
// A fixed, innocuous destination every synthetic PSBT pays to.
const PSBT_OUTPUT = { amount: 900n, script: Uint8Array.of(0x00, 0x14, ...new Uint8Array(20).fill(0x42)) };
// `count` distinguishable inputs; the input index alone does not separate
// BIP143 digests, so the claimed txid must differ per input.
function psbtTx(count) {
  return {
    version: 2,
    inputs: Array.from({ length: count }, (_, i) => {
      const txid = new Uint8Array(32).fill(0x11);
      txid[0] = i + 1;
      return { txid, vout: 0, sequence: 0xfffffffd };
    }),
    outputs: [PSBT_OUTPUT],
    locktime: 0,
  };
}
// Signs input `index`'s P2WPKH spend with a 32-byte private key, through the
// render's own BIP143 path (pinned against rust-bitcoin elsewhere; what this
// suite pins is which key copies survive the render). The key buffer is
// borrowed, the compact form wiped here.
function psbtSignInput(privateKey, tx, index, script) {
  const scriptCode = psbtRender.hodlInputScriptCode([psbtWitnessUtxoEntry(1000, script)], { amount: 1000n, script });
  const digest = psbtRender.hodlBip143(tx, index, scriptCode, 1000n, 1);
  const compact = secp256k1.sign(digest, privateKey, { prehash: false, extraEntropy: false });
  try {
    return { digest, compact, der: secp256k1.Signature.fromBytes(compact).toBytes("der") };
  } catch {
    return { digest, compact, der: null };
  }
}
// One input's entry set spending a P2WPKH output of the session key, signed
// per `variant`: "clean" (parses and verifies), "tweaked-s" (parses, fails
// verification), "padded-r" (strict DER rejects a non-minimal r; the loose
// reader still recovers it), "garbage" (no readable r at all).
function psbtInputEntries({ root, child, tx, index, variant = "clean", witnessUtxo = true }) {
  const pubkey = (child || root).publicKey, script = psbtP2wpkh(pubkey);
  const entries = [];
  if (witnessUtxo) entries.push(psbtWitnessUtxoEntry(1000, script));
  if (variant === "garbage") {
    entries.push({ type: 2, keydata: pubkey, val: Uint8Array.of(0xde, 0xad, 0xbe, 0xef, 1) });
  } else {
    const privCopy = (child || root).privateKey;
    let val;
    try {
      const { compact, der } = psbtSignInput(privCopy, tx, index, script);
      try {
        if (variant === "tweaked-s") {
          const broken = Uint8Array.from(der);
          broken[broken.length - 1] ^= 0x7f; // same magnitude: still strict DER, no longer verifies
          val = Uint8Array.of(...broken, 1);
        } else if (variant === "padded-r") {
          const r = compact.slice(0, 32), s = compact.slice(32);
          const body = Uint8Array.of(0x02, 33, 0x00, ...r, 0x02, s.length, ...s);
          val = Uint8Array.of(...Uint8Array.of(0x30, body.length, ...body), 1);
        } else {
          val = Uint8Array.of(...der, 1);
        }
      } finally {
        compact.fill(0);
      }
    } finally {
      privCopy.fill(0);
    }
    entries.push({ type: 2, keydata: pubkey, val });
  }
  if (child) entries.push(psbtBip32Entry(pubkey, root.fingerprint, PSBT_CHILD_PATH));
  return entries;
}
// The BIP-174 reference verdict is orthogonal here; pre-set it the way
// hodlPsbtReferenceVerdict itself caches an "incomplete" outcome, so the
// render neither shells into the reference layer nor prints its banner.
function psbtFixture(tx, inputs) {
  return { tx, inputs, outputs: tx.outputs.map(() => []), referenceVerdict: { state: "incomplete", problems: [], unlisted: 0 } };
}
// Installs the HD session root, records every privateKey getter copy while
// the render runs, then tears the session down with the app's own End
// Session path (which wipes the root node).
function renderWithHdSession(root, psbt) {
  psbtRender.__set.hodlPsbtHd(root);
  psbtRender.__set.hodlPsbtNonceHistory([]);
  try {
    return recordGetterCopies(() => psbtRender.hodlRenderPsbt(psbt, new Uint8Array(), "2026-01-01T00:00:00.000Z", "all"));
  } finally {
    psbtRender.hodlPsbtWipeMem();
    psbtRender.__set.hodlPsbtNonceHistory([]);
  }
}
// The per-signature row inside the nonce section; distinct from the earlier
// tx-input listing, whose rows read "<strong>Input N</strong> ·".
function signedRowHtml(html, index) {
  return html.split("<p class='psbt-kv'><strong>Input ").slice(1).find((piece) => piece.startsWith(index + "</strong><br>")) || "";
}

test("hodlRenderPsbt zeroes every per-signature private-key getter copy it resolves (audit C2-B)", () => {
  const session = { root: HDKey.fromMasterSeed(SEED), child: null };
  session.child = session.root.derive("m/0'/0");
  try {
    // One six-input synthetic PSBT covers the compare, refusal and early-exit
    // paths; unrelated rows share nothing but the session.
    const variants = [
      { variant: "clean", child: session.child, verdict: "Matches RFC 6979 (plain deterministic nonce)." },
      { variant: "clean", child: null, verdict: "Matches RFC 6979 (plain deterministic nonce)." }, // the session root signs directly
      { variant: "tweaked-s", child: session.child, verdict: "This signature does not verify against the reconstructed input digest." },
      { variant: "padded-r", child: session.child, verdict: "Signature is not strict DER. Its r value is still compared for nonce reuse." },
      { variant: "clean", child: session.child, witnessUtxo: false, verdict: "Matching key found, but this input script is not yet supported for RFC 6979 comparison." },
      { variant: "garbage", child: session.child, verdict: "Signature is not DER and its nonce cannot be inspected." },
    ];
    const tx = psbtTx(variants.length);
    const inputs = variants.map((spec, index) => psbtInputEntries({ root: session.root, child: spec.child, tx, index, variant: spec.variant, witnessUtxo: spec.witnessUtxo !== false }));
    const { value: html, copies } = renderWithHdSession(session.root, psbtFixture(tx, inputs));
    try {
      variants.forEach((spec, index) => {
        assert.ok(signedRowHtml(html, index).includes(spec.verdict), `row ${index}: the ${spec.variant} verdict is unchanged`);
      });
      // Resolution runs once per row whose r is readable, and every copy it
      // took is zeroed by the time the render returned.
      assert.equal(copies.length, variants.length - 1, "one key resolution per inspectable signature, none for the unreadable row");
      assertAllZero(copies, "hodlRenderPsbt signature loop");
    } finally {
      // The nonce-history records keep only digests and r values.
      assert.ok(!html.includes("Nonce history could not be updated"), "nonce history update did not fail");
    }
  } finally {
    session.child.wipePrivateData();
    if (session.root.hasPrivateKey) session.root.wipePrivateData();
  }
});

test("the rendered RFC 6979 verdict is the compare's own verdict for the same key, digest and r", () => {
  const session = { root: HDKey.fromMasterSeed(SEED), child: null };
  session.child = session.root.derive("m/0'/0");
  try {
    const tx = psbtTx(1);
    const script = psbtP2wpkh(session.child.publicKey);
    // The digest and r of the rendered signature, re-derived for the direct
    // comparison below; the key copies are wiped in place.
    const privForFixture = session.child.privateKey;
    let reference;
    let entries;
    try {
      const { digest, compact, der } = psbtSignInput(privForFixture, tx, 0, script);
      try {
        const privForCompare = session.child.privateKey;
        try {
          reference = psbtRender.hodlRfc6979Compare(digest, privForCompare, compact.slice(0, 32));
        } finally {
          privForCompare.fill(0);
        }
        entries = [
          psbtWitnessUtxoEntry(1000, script),
          { type: 2, keydata: session.child.publicKey, val: Uint8Array.of(...der, 1) },
          psbtBip32Entry(session.child.publicKey, session.root.fingerprint, PSBT_CHILD_PATH),
        ];
      } finally {
        compact.fill(0);
      }
    } finally {
      privForFixture.fill(0);
    }
    const { value: html, copies } = renderWithHdSession(session.root, psbtFixture(tx, [entries]));
    assert.ok(reference.ok, "the fixture signature really is plain RFC 6979");
    assert.ok(signedRowHtml(html, 0).includes(reference.message), "the render prints the compare's own verdict");
    assertAllZero(copies, "compare-path pin render");
  } finally {
    session.child.wipePrivateData();
    if (session.root.hasPrivateKey) session.root.wipePrivateData();
  }
});

test("an over-budget signature row leaves no private-key copy behind either (audit C2-B)", () => {
  const session = { root: HDKey.fromMasterSeed(SEED), child: null };
  session.child = session.root.derive("m/0'/0");
  try {
    // The digest-reconstruction budget is 256 per render (audit C3-3); row
    // 257 overruns it and exits before any compare, after resolution.
    const count = 257;
    const tx = psbtTx(count);
    const entries = [];
    const privCopy = session.child.privateKey;
    try {
      for (let index = 0; index < count; index++) {
        const { der, compact } = psbtSignInput(privCopy, tx, index, psbtP2wpkh(session.child.publicKey));
        compact.fill(0);
        entries.push([
          psbtWitnessUtxoEntry(1000, psbtP2wpkh(session.child.publicKey)),
          { type: 2, keydata: session.child.publicKey, val: Uint8Array.of(...der, 1) },
          psbtBip32Entry(session.child.publicKey, session.root.fingerprint, PSBT_CHILD_PATH),
        ]);
      }
    } finally {
      privCopy.fill(0);
    }
    const { value: html, copies } = renderWithHdSession(session.root, psbtFixture(tx, entries));
    assert.equal(copies.length, count, "every row resolved its matching key exactly once");
    assertAllZero(copies, "over-budget render");
    assert.ok(signedRowHtml(html, 0).includes("Matches RFC 6979 (plain deterministic nonce)."), "in-budget rows still compare");
    assert.ok(signedRowHtml(html, 256).includes("Signature not inspected: this file carries more SIGHASH_ALL signatures than the per-file check budget covers."), "the over-budget row reports the budget");
  } finally {
    session.child.wipePrivateData();
    if (session.root.hasPrivateKey) session.root.wipePrivateData();
  }
});

test("a WIF/hex session key reaches the compare and is never zeroed by the render", () => {
  // The canonical session buffer (owned by the session, cleared only by End
  // Session) must pass through the render untouched; no HD getter is read.
  // Green before and after the fix: it pins the alias contract the fix must
  // not break.
  const sessionKey = Uint8Array.from(hexToBytes("01".repeat(32)));
  const pubkey = secp256k1.getPublicKey(sessionKey, true);
  const script = psbtP2wpkh(pubkey);
  const tx = psbtTx(1);
  const { der, compact } = psbtSignInput(sessionKey, tx, 0, script);
  compact.fill(0);
  const psbt = psbtFixture(tx, [
    [psbtWitnessUtxoEntry(1000, script), { type: 2, keydata: pubkey, val: Uint8Array.of(...der, 1) }],
  ]);
  const before = Uint8Array.from(sessionKey);
  psbtRender.__set.hodlPsbtPriv(sessionKey);
  psbtRender.__set.hodlPsbtNonceHistory([]);
  try {
    const { value: html, copies } = recordGetterCopies(() => psbtRender.hodlRenderPsbt(psbt, new Uint8Array(), "2026-01-01T00:00:00.000Z", "all"));
    assert.equal(copies.length, 0, "a raw session key involves no HDKey getter");
    assert.ok(signedRowHtml(html, 0).includes("Matches RFC 6979 (plain deterministic nonce)."), "the alias reached the compare");
    assert.deepEqual([...sessionKey], [...before], "the canonical session buffer is not zeroed mid-session");
  } finally {
    psbtRender.hodlPsbtWipeMem();
    psbtRender.__set.hodlPsbtNonceHistory([]);
  }
  assert.ok(sessionKey.every((b) => b === 0), "End Session still clears the session buffer");
});

// ---- app.js hodlPrivFromPath: a path walk that throws partway (#867) ----
//
// Security contract: when a child derivation throws partway down a PSBT
// input's BIP32 path, the intermediate node the walk had reached is wiped,
// as HDKey.derive wipes its own since #843; the session root never is. The
// throw is the practically unreachable invalid-child case, so the session
// root is a stand-in around a real HDKey whose first child refuses the
// next step.
test("hodlPrivFromPath wipes the intermediate it reached when a later child derivation throws (#867)", async () => {
  const slice = await loadAppFunctions(["hodlPrivFromPath"], { settable: ["hodlPsbtHd"] });
  const root = HDKey.fromMasterSeed(SEED);
  const target = root.derive("m/0'/0");
  let reached = null, rootWiped = false;
  const sessionRoot = {
    fingerprint: root.fingerprint,
    deriveChild(index) {
      reached = root.deriveChild(index);
      reached.deriveChild = () => {
        throw new Error("invalid child");
      };
      return reached;
    },
    wipePrivateData() {
      rootWiped = true;
    },
  };
  slice.__set.hodlPsbtHd(sessionRoot);
  try {
    const found = slice.hodlPrivFromPath([psbtBip32Entry(target.publicKey, root.fingerprint, PSBT_CHILD_PATH)], target.publicKey);
    assert.equal(found, null, "a path that fails to derive yields no key");
    assert.ok(reached, "the walk reached m/0' before the next step threw");
    assert.equal(reached.hasPrivateKey, false, "the reached intermediate (m/0') is wiped");
    assert.equal(rootWiped, false, "the session root is not wiped");
  } finally {
    slice.__set.hodlPsbtHd(null);
    target.wipePrivateData();
    root.wipePrivateData();
  }
});
