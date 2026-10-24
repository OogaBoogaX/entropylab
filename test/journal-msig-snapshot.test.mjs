// Contract: a Session snapshot keeps every public multisig descriptor and
// displayed address, including custom branch windows, while never exporting
// co-signer source inputs, private nodes or private row material.
import { test } from "node:test";
import assert from "node:assert/strict";
import { HDKey } from "@scure/bip32";
import { p2ms, p2wsh, TEST_NETWORK } from "@scure/btc-signer";
import { loadAppFunctions } from "./app-slice-harness.mjs";
import { descriptorChecksum } from "./wallet-export-harness.mjs";

// Existing originated 2-of-3 public fixture from descriptor.test.mjs. Only
// public child derivation is used; no wallet entropy or private key is made.
const COSIGNERS = [
  ["73c5da0a", "tpubDFH9dgzveyD8zTbPUFuLrGmCydNvxehyNdUXKJAQN8x4aZ4j6UZqGfnqFrD4NqyaTVGKbvEW54tsvPTK2UoSbCC1PJY8iCNiwTL3RWZEheQ"],
  ["b8688df1", "tpubDEfobrrtptRTbKf4gysDhoabneABDTAcdj3Vbn4XwPsLE2pmqpizSPRG6zHsbAMuiSgWmWPsYCLHTKTPpyrGJ5rAoTpKoQNZcxodiPf2tSJ"],
  ["3f635a63", "tpubDFPtPArj4GzBEFHohegg1Xatrc1Fi9oSox5LzuSRX91miwQxuUrEpBxpvDRsmZYJKYFhgdK3UStsjC8JKXfUbMinjFqiEM4uNwzVaCaHpys"],
];
const PRIVATE_MARKERS = ["private cosigner input must not appear", "private node must not appear", "private row must not appear"];
const withChecksum = body => `${body}#${descriptorChecksum(body)}`;
const descriptor = branch => withChecksum(`wsh(sortedmulti(2,${COSIGNERS.map(([fingerprint, key]) => `[${fingerprint}/48h/1h/0h/2h]${key}/${branch}/*`).join(",")}))`);
const publicNodes = COSIGNERS.map(([, key]) => HDKey.fromExtendedKey(key, { public: 0x043587cf, private: 0x04358394 }));

function fixture(branches = [0, 1], firstIndex = 0) {
  const addressBranches = branches.map(branch => ({
    branch,
    publicDescriptor: descriptor(branch),
    privateDescriptor: PRIVATE_MARKERS[1],
    rows: [firstIndex, firstIndex + 1].map(index => {
      // The expected address comes from scure's public BIP32 derivation and
      // script templates, not the app formatter or its WASM derivation.
      const keys = publicNodes.map(node => node.deriveChild(branch).deriveChild(index).publicKey).sort(Buffer.compare);
      return { index, path: `m/48'/1'/0'/2'/${branch}/${index}`, address: p2wsh(p2ms(2, keys), TEST_NETWORK).address, privateKey: PRIVATE_MARKERS[2] };
    }),
  }));
  return {
    kind: "msig", network: "testnet", m: 2, n: 3, script: "p2wsh", sorted: true,
    nodes: [{ privateExtendedKey: PRIVATE_MARKERS[1] }],
    xpubs: [PRIVATE_MARKERS[0]],
    addressBranches,
    walletDescriptor: descriptor(branches.length === 1 ? branches[0] : `<${branches.join(";")}>`),
    receiveDescriptor: addressBranches.find(branch => branch.branch === 0)?.publicDescriptor ?? null,
    changeDescriptor: addressBranches.find(branch => branch.branch === 1)?.publicDescriptor ?? null,
    receive: addressBranches.find(branch => branch.branch === 0)?.rows ?? [],
    change: addressBranches.find(branch => branch.branch === 1)?.rows ?? [],
    notes: [], warnings: [],
  };
}

const msigs = [], children = [];
const app = await loadAppFunctions(["hodlJournalSessionSnapshot"], { stubs: {
  document: { querySelector: () => null, getElementById: () => null },
  hodlKeys: [], hodlMsigs: msigs, hodlBip85Children: children, hodlSpKeys: null,
  hodlPsbtNonceInspected: false, hodlPsbtNonceVerdict: "", hodlPsbtNonceVerdictKind: "",
  hodlPsbtNonceHistory: [], hodlPsbtNonceHistoryVerdict: "",
} });

function assertPublicContent(text, wallet) {
  assert.ok(text.includes(wallet.walletDescriptor), "the wallet descriptor disappeared from the snapshot");
  for (const branch of wallet.addressBranches) {
    assert.ok(text.includes(branch.publicDescriptor), `branch ${branch.branch} descriptor disappeared`);
    for (const row of branch.rows) {
      assert.ok(text.includes(row.address), `branch ${branch.branch}, index ${row.index} address disappeared`);
      assert.ok(text.includes(row.path), `branch ${branch.branch}, index ${row.index} path disappeared`);
    }
  }
  for (const marker of PRIVATE_MARKERS) assert.ok(!text.includes(marker), "the report copied private co-signer material");
}

for (const reveal of [false, true]) {
  test(`multisig snapshot preserves public receive/change output with reveal=${reveal}`, () => {
    const wallet = fixture();
    assert.equal(Object.hasOwn(wallet, "accounts"), false, "MS Station results have branches, not HD accounts");
    msigs.splice(0, msigs.length, { name: "Known multisig", result: wallet });
    assertPublicContent(app.hodlJournalSessionSnapshot(reveal), wallet);
  });

  test(`multisig snapshot preserves custom branches without receive address zero with reveal=${reveal}`, () => {
    const wallet = fixture([2, 3], 7);
    msigs.splice(0, msigs.length, { name: "Custom multisig", result: wallet });
    assert.equal(wallet.receiveDescriptor, null);
    assertPublicContent(app.hodlJournalSessionSnapshot(reveal), wallet);
  });
}

test("an underived multisig never exports its unverified source inputs", () => {
  msigs.splice(0, msigs.length, { name: "Unverified multisig", result: null, fields: { xpubs: PRIVATE_MARKERS } });
  const text = app.hodlJournalSessionSnapshot(true);
  assert.ok(text.includes("Unverified multisig"));
  for (const marker of PRIVATE_MARKERS) assert.ok(!text.includes(marker));
});

test("compact backup snapshots retain multisig descriptors and BIP-85 secrets without address tables", () => {
  const wallet = fixture([2, 3], 7);
  msigs.splice(0, msigs.length, { name: "Custom multisig", result: wallet });
  children.splice(0, children.length, { name: "BIP-85 child", fingerprint: "12345678", result: { app: "hex", secret: "BIP-85 secret fixture must survive" } });
  const compact = app.hodlJournalSessionSnapshot(true, null, true);
  assert.ok(compact.includes(children[0].result.secret));
  assert.ok(compact.includes(wallet.walletDescriptor));
  for (const branch of wallet.addressBranches) {
    assert.ok(compact.includes(branch.publicDescriptor));
    for (const row of branch.rows) assert.ok(!compact.includes(row.address), "compact backup snapshot repeated derived addresses");
  }
  for (const marker of PRIVATE_MARKERS) assert.ok(!compact.includes(marker));
  assertPublicContent(app.hodlJournalSessionSnapshot(true), wallet);
  children.length = 0;
});

test("compact backup snapshot refuses a failed recovery formatter instead of omitting the key", async () => {
  const failure = new Error("Recovery formatter failed");
  const api = await loadAppFunctions(["hodlJournalSessionSnapshot"], { stubs: {
    document: { querySelector: () => null, getElementById: () => null },
    hodlKeys: [{ name: "Derived key", result: { masterFingerprint: "12345678" } }],
    hodlMsigs: [], hodlBip85Children: [], hodlSpKeys: null,
    hodlPsbtNonceInspected: false, hodlPsbtNonceVerdict: "", hodlPsbtNonceVerdictKind: "",
    hodlPsbtNonceHistory: [], hodlPsbtNonceHistoryVerdict: "",
    hodlRecoverySheetText() { throw failure; },
  } });
  assert.throws(() => api.hodlJournalSessionSnapshot(true, null, true), error => error === failure);
  assert.doesNotThrow(() => api.hodlJournalSessionSnapshot(false));
});
