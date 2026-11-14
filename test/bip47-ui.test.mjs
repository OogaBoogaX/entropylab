// The BIP-47 station's pure render helpers (preview only).
//
// Vector provenance: BIP-47's "Test Vectors" section links the SamouraiDev
// gist 6aad669604c5930864bd. Alice's payment code and notification address
// below are the same values pinned in test/bip47.test.mjs, independently
// recomputed there; nothing here is derived by running the code under test.
// Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { bip47OwnHtml, bip47ContactHtml, bip47ErrorHtml, bip47RowsHtml, bip47NotifyHtml, bip47NotifyInputsHtml, bip47NotifyErrorHtml } from "../src/js/bip47-ui.js";
import { Bip47Error, bip47AccountNode, bip47DecodeNotificationTx, bip47PairRows, decodePaymentCode, encodePaymentCode, hexToBytes } from "../src/js/bip47.js";
import { HDKey } from "../src/js/hdkey.js";
import { mnemonicToSeedSync } from "../src/js/bip39.js";

const ALICE_CODE = "PM8TJTLJbPRGxSbc8EJi42Wrr6QbNSaSSVJ5Y3E4pbCYiTHUskHg13935Ubb7q8tx9GVbh2UuRnBc3WSyJHhUrw8KhprKnn9eDznYGieTzFcwQRya4GA";
const ALICE_NOTIFICATION = "1JDdmqFLhpzcUwPeinhJbUPw4Co3aWLyzW";

// Alice and Bob are rebuilt from the mnemonics pinned in test/bip47.test.mjs,
// and Bob's payment code is the one pinned there. The pair rows come from
// bip47.js, whose own spec vectors are checked in that file; this file only
// checks that the renderer shows them unchanged.
const ALICE_MNEMONIC = "response seminar brave tip suit recall often sound stick owner lottery motion";
const BOB_MNEMONIC = "reward upper indicate eight swift arch injury crystal super wrestle already dentist";
const BOB_CODE = "PM8TJS2JxQ5ztXUpBBRnpTbcUXbUHy2T1abfrb3KkAAtMEGNbey4oumH7Hc578WgQJhPjBxteQ5GHHToTYHE3A1w6p7tU6KSoFmWBVbFGjKPisZDbP97";

const aliceAccount = bip47AccountNode(HDKey.fromMasterSeed(mnemonicToSeedSync(ALICE_MNEMONIC)), "mainnet");
const bobAccount = bip47AccountNode(HDKey.fromMasterSeed(mnemonicToSeedSync(BOB_MNEMONIC)), "mainnet");
const aliceChild0 = aliceAccount.deriveChild(0);
const aliceNotificationKey = aliceChild0.privateKey;
const sendResult = bip47PairRows("send", { own: aliceNotificationKey, code: decodePaymentCode(BOB_CODE) }, 0, 10, "mainnet");
aliceNotificationKey.fill(0);
aliceChild0.wipePrivateData();
aliceAccount.wipePrivateData();
const sendRows = sendResult.rows.map((row) => ({ index: row.index, address: row.address }));
const receiveResult = bip47PairRows("receive", { own: bobAccount, code: decodePaymentCode(ALICE_CODE) }, 0, 10, "mainnet");
const receiveRows = receiveResult.rows.map((row) => ({ index: row.index, address: row.address }));
for (const row of receiveResult.rows) if (row.privateKey) row.privateKey.fill(0);
bobAccount.wipePrivateData();

// The BIP-47 spec's published pair addresses (Alice to Bob, indexes 0-9), so
// the fixture is anchored to the vectors rather than to the code under test.
const PAIR_ADDRESSES = [
  "141fi7TY3h936vRUKh1qfUZr8rSBuYbVBK",
  "12u3Uued2fuko2nY4SoSFGCoGLCBUGPkk6",
  "1FsBVhT5dQutGwaPePTYMe5qvYqqjxyftc",
  "1CZAmrbKL6fJ7wUxb99aETwXhcGeG3CpeA",
  "1KQvRShk6NqPfpr4Ehd53XUhpemBXtJPTL",
  "1KsLV2F47JAe6f8RtwzfqhjVa8mZEnTM7t",
  "1DdK9TknVwvBrJe7urqFmaxEtGF2TMWxzD",
  "16DpovNuhQJH7JUSZQFLBQgQYS4QB9Wy8e",
  "17qK2RPGZMDcci2BLQ6Ry2PDGJErrNojT5",
  "1GxfdfP286uE24qLZ9YRP3EWk2urqXgC4s",
];

test("the row fixtures reproduce the BIP-47 spec's published pair addresses", () => {
  assert.deepEqual(sendRows.map((row) => row.address), PAIR_ADDRESSES);
  assert.deepEqual(sendRows.map((row) => row.index), [...Array(10).keys()]);
  assert.deepEqual(receiveRows.map((row) => row.address), PAIR_ADDRESSES);
});

// The app's private helpers are injected, so the test supplies stand-ins with
// the same contract: a shown value carrying data-private-value, and a label
// clipboard carrying data-private-copy.
const privateIcons = {
  privateValue: (value, className) => `<span class="${className}" data-private-value data-i18n-skip translate="no">${value}</span>`,
  privateCopy: ({ label }) => `<button type="button" class="copy-button boxed-copy-button" data-private-copy data-copy-label="${label}" aria-label="${label}" title="${label}"></button>`,
};
// A sample compressed WIF. The renderer shows it verbatim and never validates
// it; the engine's own WIF encoding is pinned elsewhere.
const SAMPLE_WIF = "L1aW4ubDFB7yfras2S1mN3bqg9nwySY8nkoLmJebSLD5BWv3ENZ";

// The slice of the rendered HTML that belongs to one readout or fact, from
// its data-* marker to the next one. Hooks on data attributes only.
const region = (html, attribute, name) => {
  const start = html.indexOf(`${attribute}="${name}"`);
  assert.ok(start >= 0, `missing the ${name} ${attribute} region`);
  const next = html.indexOf(`${attribute}="`, start + 1);
  return html.slice(start, next < 0 ? undefined : next);
};

test("the own-code readouts carry the full payment code and its notification address", () => {
  const html = bip47OwnHtml({ code: ALICE_CODE, notificationAddress: ALICE_NOTIFICATION, network: "mainnet", path: "m/47'/0'/0'" });
  assert.ok(region(html, "data-bip47-value", "code").includes(ALICE_CODE), "the payment code is shown in full, never shortened");
  assert.ok(region(html, "data-bip47-value", "notification-address").includes(ALICE_NOTIFICATION), "the notification address sits in its own readout");
});

test("a valid, derivable contact code is marked as both and shows its notification address", () => {
  const decoded = decodePaymentCode(ALICE_CODE);
  assert.equal(decoded.derivable, true, "the pinned vector is a plain v1 code");
  const html = bip47ContactHtml(decoded, "mainnet");
  assert.match(html, /data-bip47-fact="valid" data-bip47-status="yes"/);
  assert.match(html, /data-bip47-fact="derivable" data-bip47-status="yes"/);
  assert.ok(region(html, "data-bip47-fact", "notification-address").includes(ALICE_NOTIFICATION));
});

test("a code with a feature bit set is not derivable and shows no notification address", () => {
  const decoded = decodePaymentCode(ALICE_CODE);
  const withFeature = encodePaymentCode(decoded.publicKey, decoded.chainCode, 1);
  const parsed = decodePaymentCode(withFeature);
  assert.equal(parsed.derivable, false, "a set feature bit makes the code non-derivable");
  const html = bip47ContactHtml(parsed, "mainnet");
  assert.match(html, /data-bip47-fact="derivable" data-bip47-status="no"/);
  assert.ok(!region(html, "data-bip47-fact", "notification-address").includes(ALICE_NOTIFICATION), "a code the engine will not derive shows no address");
});

test("every rendered value is escaped, never interpreted as markup", () => {
  const hostile = "<script>alert(1)</script>";
  const own = bip47OwnHtml({ code: hostile, notificationAddress: hostile, network: "mainnet", path: "" });
  assert.ok(!own.includes("<script>"), "a value must never reach the page as markup");
  assert.ok(own.includes("&lt;script&gt;"), "the value is shown as text");
  const error = bip47ErrorHtml(hostile);
  assert.ok(!error.includes("<script>"));
  assert.ok(error.includes("&lt;script&gt;"));
});

test("send rows render ten indexed rows with the derived addresses and no key disclosure", () => {
  const html = bip47RowsHtml({ direction: "send", rows: sendRows, skipped: [], budgetExhausted: false, network: "mainnet", revealed: null });
  const indexes = [...html.matchAll(/data-row-index="(\d+)"/g)].map((match) => Number(match[1]));
  assert.deepEqual(indexes, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], "one row per index, in order");
  for (const row of sendRows) assert.ok(html.includes(row.address), `row ${row.index} shows its address`);
  assert.ok(!html.includes("data-bip47-keys"), "send rows never offer spending keys");
  assert.ok(!html.includes("data-private-value"), "send rows carry no private value");
});

test("receive rows offer one reveal control per row and no key material at rest", () => {
  const html = bip47RowsHtml({ direction: "receive", rows: receiveRows, skipped: [], budgetExhausted: false, network: "mainnet", revealed: null });
  assert.ok(html.includes("data-bip47-keys"), "receive rows offer the spending-key disclosure");
  const reveals = [...html.matchAll(/data-bip47-reveal="(\d+)"/g)].map((match) => Number(match[1]));
  assert.deepEqual(reveals, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], "one reveal control per row");
  assert.ok(!html.includes("data-private-value"), "a concealed row has no key text");
  assert.ok(!html.includes("data-private-field"), "a concealed row has no private field");
  assert.ok(!html.includes("data-private-copy"), "a concealed row has no private clipboard control");
});

test("revealing one receive row shows exactly one private field and keeps the other reveal controls", () => {
  const html = bip47RowsHtml({ direction: "receive", rows: receiveRows, skipped: [], budgetExhausted: false, network: "mainnet", revealed: { index: 3, wif: SAMPLE_WIF } }, privateIcons);
  assert.equal(html.split("data-private-field").length - 1, 1, "only one row is ever revealed");
  const field = html.slice(html.indexOf("data-private-field"));
  assert.ok(field.includes(SAMPLE_WIF), "the revealed row shows the WIF");
  assert.ok(field.includes("data-private-copy"), "the revealed row carries the private clipboard control");
  assert.ok(html.includes("data-bip47-conceal"), "the revealed row can be concealed again");
  assert.ok(!html.includes('data-bip47-reveal="3"'), "the revealed row has no reveal control");
  const reveals = [...html.matchAll(/data-bip47-reveal="(\d+)"/g)].map((match) => Number(match[1]));
  assert.deepEqual(reveals, [0, 1, 2, 4, 5, 6, 7, 8, 9], "every other row keeps its reveal control");
});

test("skipped indexes are listed and the rows keep their real indexes", () => {
  const rows = [{ index: 4, address: "1BoatSLRHtKNngkdXEeobR76b53LETtpyT" }, { index: 5, address: "1JDdmqFLhpzcUwPeinhJbUPw4Co3aWLyzW" }];
  const html = bip47RowsHtml({ direction: "send", rows, skipped: [2, 3], budgetExhausted: false, network: "mainnet" });
  assert.ok(html.includes("data-bip47-skipped"), "skipped indexes are reported");
  assert.ok(html.includes("2, 3"), "the skipped indexes are listed");
  const indexes = [...html.matchAll(/data-row-index="(\d+)"/g)].map((match) => Number(match[1]));
  assert.deepEqual(indexes, [4, 5], "rows are never renumbered");
  assert.ok(!html.includes("data-bip47-budget"), "no budget message when the run finished");
});

test("an exhausted attempt budget renders its own hook", () => {
  const html = bip47RowsHtml({ direction: "send", rows: [], skipped: [0, 1], budgetExhausted: true, network: "mainnet" });
  assert.ok(html.includes("data-bip47-budget"), "the budget failure is shown");
  assert.ok(html.includes("data-bip47-skipped"), "the skipped indexes are still listed");
});

test("row values are escaped, never interpreted as markup", () => {
  const hostile = '"><script>alert(1)</script>';
  const html = bip47RowsHtml({ direction: "send", rows: [{ index: 0, address: hostile }], skipped: [], budgetExhausted: false, network: "mainnet" });
  assert.ok(!html.includes("<script>"), "an address never reaches the page as markup");
  assert.ok(!html.includes(hostile), "the raw value never reaches the markup");
});

// The BIP-47 spec's notification vector (SamouraiDev gist 6aad669604c5930864bd,
// the link in BIP-47's "Test Vectors" section), pinned in test/bip47.test.mjs:
// Alice's notification transaction, which Bob decodes with child 0 of his
// BIP-47 account. The vector values are pinned from the spec; the decode
// results come from bip47.js, whose own tests anchor them to the vector.
const NOTIFY_TX = "010000000186f411ab1c8e70ae8a0795ab7a6757aea6e4d5ae1826fc7b8f00c597d500609c010000006b483045022100ac8c6dbc482c79e86c18928a8b364923c774bfdbd852059f6b3778f2319b59a7022029d7cc5724e2f41ab1fcfc0ba5a0d4f57ca76f72f19530ba97c860c70a6bf0a801210272d83d8a1fa323feab1c085157a0791b46eba34afb8bfbfaeb3a3fcc3f2c9ad8ffffffff0210270000000000001976a9148066a8e7ee82e5c5b9b7dc1765038340dc5420a988ac1027000000000000536a4c50010002063e4eb95e62791b06c50e1a3a942e1ecaaa9afbbeb324d16ae6821e091611fa96c0cf048f607fe51a0327f5e2528979311c78cb2de0d682c61e1180fc3d543b0000000000000000000000000000000000";
const NOTIFY_DISPLAY_TXID = "9c6000d597c5008f7bfc2618aed5e4a6ae57677aab95078aae708e1cab11f486";
const NOTIFY_DESIGNATED_PUBKEY = "0272d83d8a1fa323feab1c085157a0791b46eba34afb8bfbfaeb3a3fcc3f2c9ad8";

const bobNotifyRoot = HDKey.fromMasterSeed(mnemonicToSeedSync(BOB_MNEMONIC));
const bobNotifyChild = bobNotifyRoot.derive("m/47'/0'/0'/0");
const bobNotifyPriv = bobNotifyChild.privateKey;
const bobNotifyResult = bip47DecodeNotificationTx(NOTIFY_TX, bobNotifyPriv);
bobNotifyPriv.fill(0);
bobNotifyChild.wipePrivateData();
bobNotifyRoot.wipePrivateData();

// Alice's own notification key is the wrong key for her transaction: the
// payload is blinded to Bob, so it unblinds to garbage and recovers no code.
const aliceNotifyRoot = HDKey.fromMasterSeed(mnemonicToSeedSync(ALICE_MNEMONIC));
const aliceNotifyChild = aliceNotifyRoot.derive("m/47'/0'/0'/0");
const aliceNotifyPriv = aliceNotifyChild.privateKey;
const wrongKeyResult = bip47DecodeNotificationTx(NOTIFY_TX, aliceNotifyPriv);
aliceNotifyPriv.fill(0);
aliceNotifyChild.wipePrivateData();
aliceNotifyRoot.wipePrivateData();

test("Bob's real notification result shows the recovered code and the matching output", () => {
  assert.equal(bobNotifyResult.status, "ok", "the pinned vector decodes with Bob's notification key");
  const html = bip47NotifyHtml(bobNotifyResult, { manual: false });
  assert.match(html, /data-result="code-recovered" data-status="yes"/);
  assert.match(html, /data-result="pays-notification-address" data-status="present"/);
  assert.ok(region(html, "data-bip47-fact", "input").includes("0"), "the designated input's zero-based index");
  assert.ok(region(html, "data-bip47-fact", "outpoint").includes(`${NOTIFY_DISPLAY_TXID}:1`), "the display-order outpoint");
  assert.ok(region(html, "data-bip47-fact", "pubkey").includes(NOTIFY_DESIGNATED_PUBKEY), "the designated public key");
  assert.ok(region(html, "data-bip47-fact", "method").includes("p2pkh"), "the extraction method");
  assert.ok(html.includes(ALICE_CODE), "the recovered code is Alice's published code");
  assert.ok(html.includes("data-bip47-use-code"), "the recovered code can be transferred to the contact field");
  assert.ok(!html.includes("data-bip47-manual"), "an automatic report is not marked manual");
});

test("a different key recovers no code and offers no transfer", () => {
  const html = bip47NotifyHtml(wrongKeyResult, { manual: false });
  assert.match(html, /data-result="code-recovered" data-status="no"/);
  assert.ok(!html.includes("data-bip47-use-code"), "no code is offered for transfer");
});

test("the manual input picker lists every input by index with the txid in display order", () => {
  const internal = hexToBytes(NOTIFY_DISPLAY_TXID).reverse();
  const html = bip47NotifyInputsHtml([
    { txid: internal, vout: 1 },
    { txid: new Uint8Array(32), vout: 0 },
  ]);
  const values = [...html.matchAll(/<option value="(\d+)"/g)].map((match) => match[1]);
  assert.deepEqual(values, ["0", "1"], "one option per input, valued by its zero-based index");
  assert.ok(html.includes(`0: ${NOTIFY_DISPLAY_TXID}:1`), "the first input's outpoint in display order");
  assert.ok(html.includes(`1: ${"00".repeat(32)}:0`), "the second input's outpoint");
  const internalHex = [...internal].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  assert.ok(!html.includes(internalHex), "the txid is shown in display order, never in internal byte order");
  assert.equal(bip47NotifyInputsHtml(), "", "no inputs, no options");
  assert.equal(bip47NotifyInputsHtml(null), "", "a missing list is not a crash");
});

test("the manual-needed, manual-invalid and unsupported-version statuses render their hooks", () => {
  assert.match(bip47NotifyHtml({ status: "manual-needed" }), /data-bip47-notify-error="manual-needed"/);
  assert.match(bip47NotifyHtml({ status: "manual-invalid" }), /data-bip47-notify-error="manual-invalid"/);
  const unsupported = bip47NotifyHtml({ status: "unsupported-version", version: 2 });
  assert.match(unsupported, /data-bip47-notify-error="unsupported-version"/);
  assert.ok(unsupported.includes("2"), "the unsupported version is shown");
});

test("an ambiguous payload gets its own message and any other failure the generic one", () => {
  const ambiguous = bip47NotifyErrorHtml(new Bip47Error("AMBIGUOUS_PAYLOAD"));
  assert.match(ambiguous, /data-bip47-notify-error="AMBIGUOUS_PAYLOAD"/);
  const badIndex = bip47NotifyErrorHtml(new Bip47Error("BAD_INDEX"));
  assert.match(badIndex, /data-bip47-notify-error="BAD_INDEX"/);
  const parse = bip47NotifyErrorHtml(new Error("bad hex"));
  assert.match(parse, /data-bip47-notify-error="parse"/);
  assert.ok(!parse.includes("bad hex"), "the engine's own message is never echoed");
});

test("a manual report is marked unverified", () => {
  const html = bip47NotifyHtml(bobNotifyResult, { manual: true });
  assert.ok(html.includes("data-bip47-manual"), "every manual report carries the marker");
  assert.match(html, /data-result="code-recovered"/);
});

test("no report echoes the raw transaction", () => {
  const reports = [
    bip47NotifyHtml(bobNotifyResult, { manual: false }),
    bip47NotifyHtml(bobNotifyResult, { manual: true }),
    bip47NotifyHtml(wrongKeyResult, { manual: false }),
    bip47NotifyErrorHtml(new Bip47Error("AMBIGUOUS_PAYLOAD")),
    bip47NotifyErrorHtml(new Error(NOTIFY_TX)),
  ];
  for (const html of reports) assert.ok(!html.includes(NOTIFY_TX), "the raw transaction never reaches the page");
});

// Showing a receive key derives it again from the current session, so the
// station checks it against the address on screen. Run against the app's
// own hodlBip47RevealRow, with the engine and render calls stubbed.
test("a shown receive key must match the address on screen; stale rows are cleared instead", async () => {
  const { loadAppFunctions } = await import("./app-slice-harness.mjs");
  const calls = { rendered: 0, cleared: 0 };
  const keys = [];
  let derived = "1ShownAddress";
  const api = await loadAppFunctions(["hodlBip47RevealRow"], {
    stubs: {
      hodlBip47EnsureHd: () => {},
      hodlBip47Network: () => "mainnet",
      hodlBip47AccountNode: () => ({ wipePrivateData() {} }),
      hodlBip47ReceiveRow: () => {
        const privateKey = new Uint8Array(32).fill(7);
        keys.push(privateKey);
        return { address: derived, privateKey };
      },
      hodlEncodeWif: () => "WIF",
      hodlBip47RenderRows: () => { calls.rendered += 1; },
      hodlBip47ClearRows: () => { calls.cleared += 1; },
      hodlBip47Conceal: () => {},
    },
    settable: ["hodlBip47RowsLast", "hodlBip47Contact"],
  });
  const previous = globalThis.document;
  globalThis.document = { getElementById: () => null };
  try {
    api.__set.hodlBip47Contact({ derivable: true });
    api.__set.hodlBip47RowsLast({ direction: "receive", start: 0, rows: [{ index: 0, address: "1ShownAddress" }], skipped: [], budgetExhausted: false });
    api.hodlBip47RevealRow(0);
    assert.deepEqual(calls, { rendered: 1, cleared: 0 }, "a matching key is shown");
    derived = "1OtherAddress";
    api.hodlBip47RevealRow(0);
    assert.deepEqual(calls, { rendered: 1, cleared: 1 }, "a key for another address clears the rows and is not shown");
    for (const key of keys) assert.ok(key.every((byte) => byte === 0), "every derived private key is wiped");
  } finally {
    globalThis.document = previous;
  }
});

// Clearing or deleting a Key Station key empties a BIP-47 session that used
// it, and also the seed text copied from it after a passphrase edit made the
// session manual (Gemini red team, 10-28). Run against the app's own hook.
test("a dropped Key Station key wipes the session that used it or the text copied from it", async () => {
  const { loadAppFunctions } = await import("./app-slice-harness.mjs");
  let wipes = 0;
  const api = await loadAppFunctions(["hodlBip47ReleaseSource"], {
    stubs: { hodlBip47WipeSource: () => { wipes += 1; } },
    settable: ["hodlBip47Source", "hodlBip47Origin"],
  });
  const run = (source, origin, dropped) => {
    wipes = 0;
    api.__set.hodlBip47Source(source);
    api.__set.hodlBip47Origin(origin);
    api.hodlBip47ReleaseSource(dropped);
    return wipes;
  };
  assert.equal(run("key:a", "key:a", "key:a"), 1, "the session's own key");
  assert.equal(run("manual", "key:a", "key:a"), 1, "a passphrase edit made it manual; the copied seed still goes");
  assert.equal(run("", "key:a", "key:a"), 1, "after a wipe of the root, the copied text still goes");
  assert.equal(run("manual", "", "key:a"), 0, "text the user typed is theirs");
  assert.equal(run("key:b", "key:b", "key:a"), 0, "another key's session stays");
});

test("an engine error keeps any text a translation puts after the code", () => {
  const html = bip47ErrorHtml("BAD_VERSION");
  assert.match(html, /<code>BAD_VERSION<\/code><\/p>$/, "English ends at the code");
});
