// MS Station co-signer derivation specs.
//
// Contract: each co-signer card follows one derivation spec, chosen from the
// specs that serve the selected script type. A spec supplies the card's path
// template and field names: BIP48 m/48'/coin'/account'/script' with script 2'
// for Native and 1' for Nested SegWit, BIP87 m/87'/coin'/account' for every
// script type, BIP45 m/45' for Legacy only, and the single-sig account specs
// m/44'|49'|84'|86'/coin'/account' for the script type each belongs to.
// Custom serves every script type and supplies no template. A pasted origin
// pre-selects the spec its purpose names when that spec serves the script
// type, and Custom only for a purpose no spec uses: a known spec's key on the
// wrong script type (a BIP44 key in a Native SegWit wallet, say) pre-selects
// nothing, so the card stays on its standard spec and refuses it with the
// reason, unless the user chooses Custom. A wallet follows BIP45 or BIP87 only
// when every co-signer follows that spec; any Custom co-signer makes it Custom.
// Co-signers on a spec share one, and BIP45 never shares a wallet with Custom:
// BIP45 derives every co-signer through its co-signer branch, so a Custom card
// would silently change how the BIP45 cards derive. The summary says paths
// vary only when a card is Custom; a standard wallet's differing accounts read
// as accounts that vary.
//
// Expected paths are the published ones: BIP48, BIP87, BIP45, BIP44, BIP49,
// BIP84 and BIP86, independent of the app.
// Run with: npm test
import { test } from "node:test";
import assert from "node:assert/strict";
import { loadAppFunctions } from "./app-slice-harness.mjs";

const { hodlMsigSpecsFor, hodlMsigSpec, hodlMsigSpecFromOrigin, hodlMsigSpecComponents, hodlMsigSpecStepLabels, hodlMsigForeignSpecNote, hodlMsigWalletStandard, hodlMsigSpecMixError } = await loadAppFunctions([
  "hodlMsigSpecsFor", "hodlMsigSpec", "hodlMsigSpecFromOrigin", "hodlMsigSpecComponents", "hodlMsigSpecStepLabels", "hodlMsigForeignSpecNote", "hodlMsigWalletStandard", "hodlMsigSpecMixError",
]);

const ALL = { purpose: true, coinType: true, account: true, address: false };
const path = (components) => components && "m" + components.map(({ index, hardened }) => `/${index}${hardened ? "'" : ""}`).join("");
const ids = (kind) => hodlMsigSpecsFor(kind).map((spec) => spec.id);

test("each script type offers exactly the specs that serve it, Custom always", () => {
  assert.deepEqual(ids("p2wsh").sort(), ["bip48", "bip84", "bip87", "custom"]);
  assert.deepEqual(ids("p2sh-p2wsh").sort(), ["bip48", "bip49", "bip87", "custom"]);
  assert.deepEqual(ids("p2sh").sort(), ["bip44", "bip45", "bip87", "custom"]);
  assert.deepEqual(ids("p2tr").sort(), ["bip86", "bip87", "custom"]);
  assert.equal(hodlMsigSpec("custom").purpose, null);
  assert.equal(hodlMsigSpec("nope"), null);
});

test("a spec's template is its published path", () => {
  assert.equal(path(hodlMsigSpecComponents("bip48", "p2wsh", 0, 0, ALL)), "m/48'/0'/0'/2'");
  assert.equal(path(hodlMsigSpecComponents("bip48", "p2sh-p2wsh", 1, 3, ALL)), "m/48'/1'/3'/1'");
  assert.equal(path(hodlMsigSpecComponents("bip87", "p2tr", 0, 5, ALL)), "m/87'/0'/5'");
  assert.equal(path(hodlMsigSpecComponents("bip87", "p2sh", 1, 0, ALL)), "m/87'/1'/0'");
  assert.equal(path(hodlMsigSpecComponents("bip45", "p2sh", 0, 7, ALL)), "m/45'");
  assert.equal(path(hodlMsigSpecComponents("bip44", "p2sh", 0, 2, ALL)), "m/44'/0'/2'");
  assert.equal(path(hodlMsigSpecComponents("bip49", "p2sh-p2wsh", 0, 0, ALL)), "m/49'/0'/0'");
  assert.equal(path(hodlMsigSpecComponents("bip84", "p2wsh", 1, 0, ALL)), "m/84'/1'/0'");
  assert.equal(path(hodlMsigSpecComponents("bip86", "p2tr", 0, 0, ALL)), "m/86'/0'/0'");
  // The purpose, coin-type and account hardening follow the selection; the
  // BIP48 script step is hardened by the specification itself.
  assert.equal(path(hodlMsigSpecComponents("bip48", "p2wsh", 0, 0, { purpose: false, coinType: false, account: false })), "m/48/0/0/2'");
  assert.equal(hodlMsigSpecComponents("custom", "p2wsh", 0, 0, ALL), null);
});

test("a spec names one field per template step; Custom names none", () => {
  assert.equal(hodlMsigSpecStepLabels("bip48").length, 4);
  assert.equal(hodlMsigSpecStepLabels("bip87").length, 3);
  assert.equal(hodlMsigSpecStepLabels("bip84").length, 3);
  assert.equal(hodlMsigSpecStepLabels("bip45").length, 1);
  assert.deepEqual(hodlMsigSpecStepLabels("custom"), []);
  for (const id of ["bip48", "bip87", "bip45", "bip44", "bip49", "bip84", "bip86"]) {
    assert.ok(hodlMsigSpecStepLabels(id).every((label) => typeof label === "string" && label), id);
  }
});

test("a pasted origin pre-selects the spec its purpose names, where that spec serves the script type", () => {
  assert.equal(hodlMsigSpecFromOrigin({ path: "48h/0h/0h/2h" }, "p2wsh"), "bip48");
  assert.equal(hodlMsigSpecFromOrigin({ path: "48/0/0/1h" }, "p2sh-p2wsh"), "bip48");
  assert.equal(hodlMsigSpecFromOrigin({ path: "87h/1h/0h" }, "p2wsh"), "bip87");
  assert.equal(hodlMsigSpecFromOrigin({ path: "87h/0h/0h" }, "p2tr"), "bip87");
  assert.equal(hodlMsigSpecFromOrigin({ path: "45h" }, "p2sh"), "bip45");
  assert.equal(hodlMsigSpecFromOrigin({ path: "84h/0h/0h" }, "p2wsh"), "bip84");
  assert.equal(hodlMsigSpecFromOrigin({ path: "86h/0h/0h" }, "p2tr"), "bip86");
  // A purpose no spec uses is Custom.
  assert.equal(hodlMsigSpecFromOrigin({ path: "0h" }, "p2wsh"), "custom");
  assert.equal(hodlMsigSpecFromOrigin({ path: "69420h/0h/0h" }, "p2wsh"), "custom");
  assert.equal(hodlMsigSpecFromOrigin(null, "p2wsh"), "custom");
});

test("a known spec's key on the wrong script type pre-selects nothing and is named as foreign", () => {
  for (const [path, kind] of [
    ["44h/0h/0h", "p2wsh"], // BIP44 belongs to Legacy
    ["84h/0h/0h", "p2sh"], // BIP84 belongs to Native SegWit
    ["49h/0h/0h", "p2wsh"], // BIP49 belongs to Nested SegWit
    ["86h/0h/0h", "p2wsh"], // BIP86 belongs to Taproot
    ["45h", "p2wsh"], // BIP45 belongs to Legacy
    ["48h/0h/0h/2h", "p2tr"], // BIP48 belongs to the SegWit types
    ["48h/0h/0h/2h", "p2sh"],
  ]) {
    assert.equal(hodlMsigSpecFromOrigin({ path }, kind), null, `${path} on ${kind}`);
    const note = hodlMsigForeignSpecNote({ path }, kind);
    assert.equal(typeof note, "string", `${path} on ${kind}`);
    assert.ok(note && !note.includes("[object"), `${path} on ${kind}: ${note}`);
  }
  // A served purpose, an unknown purpose, or no origin is not foreign.
  for (const [path, kind] of [["48h/0h/0h/2h", "p2wsh"], ["87h/0h/0h", "p2sh"], ["45h", "p2sh"], ["69420h/0h/0h", "p2wsh"], ["0h", "p2tr"]]) {
    assert.equal(hodlMsigForeignSpecNote({ path }, kind), "", `${path} on ${kind}`);
  }
  assert.equal(hodlMsigForeignSpecNote(null, "p2wsh"), "");
});

test("a wallet follows BIP45 or BIP87 only when every co-signer does; any Custom co-signer makes it Custom", () => {
  assert.equal(hodlMsigWalletStandard(["bip45", "bip45", "bip45"]), "bip45");
  assert.equal(hodlMsigWalletStandard(["bip87", "bip87"]), "bip87");
  assert.equal(hodlMsigWalletStandard(["bip45", "custom"]), "custom");
  assert.equal(hodlMsigWalletStandard(["custom", "bip87"]), "custom");
  assert.equal(hodlMsigWalletStandard(["custom"]), "custom");
  // Specs with no Legacy address convention of their own.
  assert.equal(hodlMsigWalletStandard(["bip48", "bip48"]), "custom");
  assert.equal(hodlMsigWalletStandard(["bip44"]), "custom");
  // Mixed specs are refused before this is asked; they are never a standard.
  assert.equal(hodlMsigWalletStandard(["bip45", "bip87"]), "custom");
  assert.equal(hodlMsigWalletStandard([]), "custom");
});

test("co-signer specs that cannot share one wallet are refused, and those that can are not", () => {
  // One spec, or one spec beside Custom cards (BIP45 aside), is a wallet.
  for (const specs of [["bip48", "bip48"], ["bip87"], ["custom", "custom"], ["bip48", "custom"], ["bip87", "custom", "bip87"], ["bip45", "bip45"]]) {
    assert.equal(hodlMsigSpecMixError(specs), "", specs.join(" + "));
  }
  // Two specs never are; neither is BIP45 beside Custom, which would drop
  // BIP45's co-signer branch from the BIP45 cards.
  for (const specs of [["bip48", "bip87"], ["bip45", "bip87"], ["bip84", "bip48", "custom"], ["bip45", "custom"], ["custom", "bip45", "bip45"]]) {
    const error = hodlMsigSpecMixError(specs);
    assert.ok(typeof error === "string" && error && !error.includes("[object"), `${specs.join(" + ")}: ${error}`);
  }
});

