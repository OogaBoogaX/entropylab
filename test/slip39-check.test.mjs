// The Verify tab's "Check a SLIP-39 backup" panel (src/js/slip39-check.js).
//
// Security contract: what a backup restores (master fingerprint and first
// addresses) is shown only for a set that combines; any refused set shows
// none of it and names the reason, and a share that fails to read is marked
// on its own field. Status text never repeats a typed word. The passphrase
// is only ever shown as bullets (PassphraseVault). conceal() takes every
// typed share off the page until Show my shares; clear() leaves no share,
// passphrase or result behind. A changed share or passphrase drops the
// previous result. The randomness test needs no passphrase and reports each
// finding by kind. The panel writes no storage, console, clipboard or
// network. Addresses follow the page's network.
//
// Expected fingerprints and addresses come from the official SLIP-0039
// vectors' master secrets through @scure/bip32 and @scure/btc-signer, not
// from the panel's derivation.
// Run with: npm test
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { HDKey as ScureHDKey } from "@scure/bip32";
import { TEST_NETWORK, p2wpkh } from "@scure/btc-signer";
import { MiniDocument } from "./mini-dom.mjs";
import { VAULT_MASK } from "../src/js/passphrase-vault.js";
import { mountSlip39Check } from "../src/js/slip39-check.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const vectors = JSON.parse(readFileSync(join(root, "test/fixtures/slip39/vectors.json"), "utf8"));
// The passphrase the SLIP-0039 specification gives for every valid vector.
const VECTOR_PASSPHRASE = "TREZOR";
const vector = (n) => ({ mnemonics: vectors[n - 1][1], secret: vectors[n - 1][2] });

// Signet shares testnet's encodings; regtest differs only in its bech32 HRP.
const REGTEST = { ...TEST_NETWORK, bech32: "bcrt" };
const reference = (secretHex, network = "mainnet") => {
  const master = ScureHDKey.fromMasterSeed(Buffer.from(secretHex, "hex"));
  const branch = master.derive(network === "mainnet" ? "m/84'/0'/0'/0" : "m/84'/1'/0'/0");
  const encoding = network === "mainnet" ? undefined : network === "regtest" ? REGTEST : TEST_NETWORK;
  return {
    fingerprint: master.fingerprint.toString(16).padStart(8, "0"),
    addresses: [0, 1, 2].map((i) => p2wpkh(branch.deriveChild(i).publicKey, encoding).address),
  };
};

function mount(options = {}) {
  const doc = new MiniDocument();
  const host = doc.createElement("div");
  doc.body.appendChild(host);
  const panel = mountSlip39Check(host, { doc, win: {}, ...options });
  const $ = (id) => doc.getElementById(id);
  const fields = (set) => doc.querySelectorAll(`textarea[data-slip39-set="${set}"]`);
  const statusOf = (set, n) => doc.querySelector(`[data-slip39-share-status][data-slip39-set="${set}"][data-slip39-share="${n}"]`);
  const choose = (value) => $("slip39-check-mode").querySelector(`[data-value="${value}"]`).click();
  // Types each mnemonic into its own field, adding fields as needed.
  const fill = (set, mnemonics) => {
    while (fields(set).length < mnemonics.length) $(`slip39-check-add-${set}`).click();
    for (const [i, field] of fields(set).entries()) {
      field.value = mnemonics[i] ?? "";
      field.dispatchEvent({ type: "input" });
    }
  };
  const typePassphrase = (text) => {
    const field = $("slip39-check-pass");
    field.value = text;
    field.dispatchEvent({ type: "input" });
  };
  // The readouts are the builders' markup; their values carry data-public-value.
  const addresses = () => $("slip39-check-addresses").querySelectorAll("[data-public-value]").map((item) => item.textContent);
  const fingerprint = () => $("slip39-check-fingerprint").querySelector("[data-public-value]")?.textContent ?? "";
  const findings = () => $("slip39-check-findings").querySelectorAll("li").map((item) => item.getAttribute("data-slip39-finding"));
  return { doc, host, panel, $, fields, statusOf, choose, fill, typePassphrase, addresses, fingerprint, findings, state: () => $("slip39-check-result").getAttribute("data-state") };
}

const restores = (ui, secretHex, network = "mainnet") => {
  const expected = reference(secretHex, network);
  assert.equal(ui.state(), "restored");
  assert.equal(ui.$("slip39-check-restored").hidden, false);
  assert.equal(ui.fingerprint(), expected.fingerprint);
  assert.deepEqual(ui.addresses(), expected.addresses);
};
const showsNothing = (ui) => {
  assert.equal(ui.$("slip39-check-restored").hidden, true);
  assert.equal(ui.fingerprint(), "");
  assert.equal(ui.addresses().length, 0);
};

test("the backup check starts with two empty share fields, and Add a share adds one", () => {
  const ui = mount();
  assert.equal(ui.fields("backup").length, 2);
  assert.ok(ui.fields("backup").every((field) => field.value === ""));
  ui.$("slip39-check-add-backup").click();
  assert.deepEqual(ui.fields("backup").map((field) => field.getAttribute("data-slip39-share")), ["1", "2", "3"]);
  // Each field has its own label and status line.
  for (const field of ui.fields("backup")) {
    assert.ok(ui.doc.querySelector(`label[for="${field.id}"]`), field.id);
    assert.ok(ui.statusOf("backup", field.getAttribute("data-slip39-share")));
  }
  assert.equal(ui.$("slip39-check-random-panel").hidden, true);
  assert.equal(ui.state(), "empty");
});

test("share fields opt out of the browser's text services", () => {
  const ui = mount();
  for (const field of [...ui.fields("backup"), ...ui.fields("a"), ...ui.fields("b")]) {
    for (const [name, value] of [["spellcheck", "false"], ["autocomplete", "off"], ["autocapitalize", "off"], ["autocorrect", "off"]]) assert.equal(field.getAttribute(name), value, `${field.id} ${name}`);
  }
});

test("a valid set restores: fingerprint and addresses match the reference, with the passphrase", () => {
  // Vector 4: 2-of-3, with the official vectors' passphrase.
  const v = vector(4);
  const ui = mount();
  ui.fill("backup", v.mnemonics);
  ui.typePassphrase(VECTOR_PASSPHRASE);
  ui.$("slip39-check-run").click();
  restores(ui, v.secret);
  assert.notEqual(ui.$("slip39-check-summary").textContent, "");
  for (const n of ["1", "2"]) assert.equal(ui.statusOf("backup", n).getAttribute("data-slip39-share-state"), "ok");
});

test("a two-level set with a blank field in between restores", () => {
  // Vector 17: five shares across the group threshold; blank fields are skipped.
  const v = vector(17);
  const ui = mount();
  ui.fill("backup", [v.mnemonics[0], "", ...v.mnemonics.slice(1)]);
  ui.typePassphrase(VECTOR_PASSPHRASE);
  ui.$("slip39-check-run").click();
  restores(ui, v.secret);
});

test("the readouts come from the builders the app passes, with English labels and every address's path", () => {
  // app.js passes the Key Station's field and address table builders.
  const v = vector(4);
  const calls = [];
  let network = "testnet";
  const ui = mount({
    network: () => network,
    fieldHtml: (label, value) => {
      calls.push(["field", label, value]);
      return `<span data-public-value>${value}</span>`;
    },
    addressTableHtml: (rows) => {
      calls.push(["table", rows]);
      return rows.map((row) => `<span data-public-value>${row.address}</span>`).join("");
    },
  });
  ui.fill("backup", v.mnemonics);
  ui.typePassphrase(VECTOR_PASSPHRASE);
  ui.$("slip39-check-run").click();
  restores(ui, v.secret, "testnet");
  const expected = reference(v.secret, "testnet");
  assert.deepEqual(calls[0], ["field", "Master fingerprint", expected.fingerprint]);
  assert.deepEqual(calls[1], ["table", expected.addresses.map((address, index) => ({ index, path: `m/84'/1'/0'/0/${index}`, address }))]);
  network = "mainnet";
  ui.doc.dispatchEvent({ type: "hodl:network-default" });
  assert.deepEqual(calls.at(-1)[1].map((row) => row.path), ["m/84'/0'/0'/0/0", "m/84'/0'/0'/0/1", "m/84'/0'/0'/0/2"]);
});

test("each share counts its words as it is typed; a check replaces the count with its result", () => {
  const v = vector(4);
  const ui = mount();
  const note = ui.statusOf("backup", "1");
  assert.equal(note.hidden, true);
  ui.fill("backup", [v.mnemonics[0].split(" ").slice(0, 7).join(" ")]);
  assert.equal(note.hidden, false);
  assert.ok(note.textContent.includes("7"));
  assert.equal(note.getAttribute("data-slip39-share-state"), null);
  ui.fill("backup", v.mnemonics);
  ui.$("slip39-check-run").click();
  assert.equal(note.getAttribute("data-slip39-share-state"), "ok");
  ui.fill("backup", ["", ""]);
  assert.equal(note.hidden, true);
});

test("Clear sits in the action row on show: beside Combine, beside Compare, beside Show my shares", () => {
  const ui = mount();
  const rowOf = (id) => ui.$(id).parentElement;
  assert.equal(rowOf("slip39-check-clear"), rowOf("slip39-check-run"));
  ui.choose("randomness");
  assert.equal(rowOf("slip39-check-clear"), rowOf("slip39-check-compare"));
  ui.fill("a", vector(4).mnemonics);
  ui.panel.conceal();
  assert.equal(rowOf("slip39-check-clear"), rowOf("slip39-check-unconceal"));
  ui.$("slip39-check-unconceal").click();
  assert.equal(rowOf("slip39-check-clear"), rowOf("slip39-check-compare"));
  // Only one Clear, after the row's own action.
  assert.equal(ui.doc.querySelectorAll("#slip39-check-clear").length, 1);
  const row = rowOf("slip39-check-clear").children;
  assert.ok(row.indexOf(ui.$("slip39-check-compare")) < row.indexOf(ui.$("slip39-check-clear")));
});

test("the passphrase shows only as bullets; changing it drops the result until combined again", () => {
  const v = vector(4);
  const ui = mount();
  ui.fill("backup", v.mnemonics);
  ui.typePassphrase(VECTOR_PASSPHRASE);
  const field = ui.$("slip39-check-pass");
  assert.equal(field.value, VAULT_MASK.repeat(6));
  assert.ok(!ui.host.innerHTML.includes(VECTOR_PASSPHRASE));
  ui.$("slip39-check-run").click();
  restores(ui, v.secret);
  ui.typePassphrase(`${VECTOR_PASSPHRASE}2`);
  assert.equal(ui.state(), "stale");
  showsNothing(ui);
  ui.$("slip39-check-run").click();
  assert.equal(ui.state(), "restored");
  assert.notEqual(ui.fingerprint(), reference(v.secret).fingerprint);
});

test("refused sets show no wallet and name the failing share's field", () => {
  // Vector 2: invalid checksum; 13: invalid digest; 6: different identifiers.
  const ui = mount();
  ui.fill("backup", vector(2).mnemonics);
  ui.$("slip39-check-run").click();
  assert.equal(ui.state(), "failed");
  showsNothing(ui);
  assert.equal(ui.statusOf("backup", "1").getAttribute("data-slip39-share-state"), "error");
  for (const n of [13, 6, 16]) {
    ui.fill("backup", vector(n).mnemonics);
    ui.typePassphrase(VECTOR_PASSPHRASE);
    ui.$("slip39-check-run").click();
    assert.equal(ui.state(), "failed", `vector ${n}`);
    showsNothing(ui);
    assert.notEqual(ui.$("slip39-check-status").textContent, "");
  }
});

test("no shares entered: refused, with nothing shown", () => {
  const ui = mount();
  ui.$("slip39-check-run").click();
  assert.equal(ui.state(), "failed");
  showsNothing(ui);
});

test("status text never repeats a typed word", () => {
  const v = vector(4);
  const words = v.mnemonics[0].split(" ");
  words[3] = "notaword";
  const ui = mount();
  ui.fill("backup", [words.join(" "), v.mnemonics[1]]);
  ui.$("slip39-check-run").click();
  assert.equal(ui.state(), "failed");
  assert.equal(ui.statusOf("backup", "1").getAttribute("data-slip39-share-state"), "error");
  assert.ok(!ui.host.innerHTML.includes("notaword"));
  // No two consecutive words of either share appear outside the fields.
  for (const mnemonic of [words.join(" "), v.mnemonics[1]]) {
    const typed = mnemonic.split(" ");
    for (let i = 1; i < typed.length; i++) assert.ok(!ui.host.innerHTML.includes(`${typed[i - 1]} ${typed[i]}`), `${typed[i - 1]} ${typed[i]}`);
  }
});

test("an iteration exponent over the panel's limit is refused before decrypting", () => {
  // Vector 42 uses exponent 3.
  const v = vector(42);
  const ui = mount({ maxIterationExponent: 2 });
  ui.fill("backup", v.mnemonics);
  ui.typePassphrase(VECTOR_PASSPHRASE);
  ui.$("slip39-check-run").click();
  assert.equal(ui.state(), "failed");
  showsNothing(ui);
});

test("a changed share drops the result", () => {
  const v = vector(4);
  const ui = mount();
  ui.fill("backup", v.mnemonics);
  ui.typePassphrase(VECTOR_PASSPHRASE);
  ui.$("slip39-check-run").click();
  assert.equal(ui.state(), "restored");
  const field = ui.fields("backup")[1];
  field.value = `${field.value} `;
  field.dispatchEvent({ type: "input" });
  assert.equal(ui.state(), "stale");
  showsNothing(ui);
  assert.equal(ui.statusOf("backup", "1").getAttribute("data-slip39-share-state"), null);
});

test("conceal() takes every typed share off the page until Show my shares", () => {
  const v = vector(4);
  const ui = mount();
  // Nothing typed: nothing to hide.
  ui.panel.conceal();
  assert.equal(ui.$("slip39-check-concealed").hidden, true);
  ui.fill("backup", v.mnemonics);
  ui.typePassphrase(VECTOR_PASSPHRASE);
  ui.$("slip39-check-run").click();
  ui.panel.conceal();
  assert.equal(ui.$("slip39-check-concealed").hidden, false);
  assert.equal(ui.$("slip39-check-backup-panel").hidden, true);
  assert.ok([...ui.fields("backup"), ...ui.fields("a"), ...ui.fields("b")].every((field) => field.value === ""));
  // The result and its public values stay.
  restores(ui, v.secret);
  ui.$("slip39-check-unconceal").click();
  assert.deepEqual(ui.fields("backup").map((field) => field.value), v.mnemonics);
  assert.equal(ui.$("slip39-check-backup-panel").hidden, false);
  assert.equal(ui.state(), "restored");
  // Clear while hidden forgets the held shares as well.
  ui.panel.conceal();
  ui.$("slip39-check-clear").click();
  assert.equal(ui.$("slip39-check-concealed").hidden, true);
  assert.ok(ui.fields("backup").every((field) => field.value === ""));
});

test("conceal() also hides the randomness test's sets, typed but not compared", () => {
  const ui = mount();
  ui.choose("randomness");
  ui.fill("a", vector(4).mnemonics);
  ui.panel.conceal();
  assert.ok(ui.fields("a").every((field) => field.value === ""));
  assert.equal(ui.$("slip39-check-random-panel").hidden, true);
  ui.$("slip39-check-unconceal").click();
  assert.deepEqual(ui.fields("a").map((field) => field.value), vector(4).mnemonics);
});

test("clear() leaves no share, passphrase or result, and two fields per set", () => {
  const v = vector(17);
  const ui = mount();
  ui.fill("backup", v.mnemonics);
  ui.typePassphrase(VECTOR_PASSPHRASE);
  ui.$("slip39-check-run").click();
  ui.fill("a", vector(4).mnemonics);
  ui.panel.clear();
  assert.equal(ui.state(), "empty");
  assert.equal(ui.fields("backup").length, 2);
  assert.ok([...ui.fields("backup"), ...ui.fields("a"), ...ui.fields("b")].every((field) => field.value === ""));
  assert.equal(ui.$("slip39-check-pass").value, "");
  showsNothing(ui);
  assert.equal(ui.$("slip39-check-status").textContent, "");
  // The panel's own Clear button runs the same clear.
  ui.fill("backup", v.mnemonics);
  ui.$("slip39-check-clear").click();
  assert.ok(ui.fields("backup").every((field) => field.value === ""));
  ui.panel.destroy();
  assert.equal(ui.host.childNodes.length, 0);
});

test("the addresses follow the page's network and change with it", () => {
  const v = vector(4);
  let network = "testnet";
  const ui = mount({ network: () => network });
  ui.fill("backup", v.mnemonics);
  ui.typePassphrase(VECTOR_PASSPHRASE);
  ui.$("slip39-check-run").click();
  restores(ui, v.secret, "testnet");
  for (network of ["regtest", "signet", "mainnet"]) {
    ui.doc.dispatchEvent({ type: "hodl:network-default" });
    assert.deepEqual(ui.addresses(), reference(v.secret, network).addresses, network);
  }
  ui.panel.destroy();
  assert.equal(ui.doc.listenerCount("hodl:network-default"), 0);
});

test("a language switch relabels the panel and keeps the shares and the result", () => {
  const v = vector(4);
  let language = "en";
  const ui = mount({ translate: (text) => (language === "en" ? text : `[${language}] ${text}`) });
  ui.fill("backup", v.mnemonics);
  ui.typePassphrase(VECTOR_PASSPHRASE);
  ui.$("slip39-check-run").click();
  const fingerprint = ui.fingerprint();
  language = "xx";
  ui.panel.retranslate();
  const translated = (text) => text.startsWith("[xx] ");
  for (const id of ["slip39-check-run", "slip39-check-add-backup", "slip39-check-clear", "slip39-check-status", "slip39-check-summary", "slip39-check-address-label", "slip39-check-compare"]) {
    assert.ok(translated(ui.$(id).textContent), id);
  }
  assert.ok(translated(ui.$("slip39-check-mode").getAttribute("aria-label")));
  assert.ok(translated(ui.doc.querySelector(`label[for="${ui.fields("backup")[0].id}"]`).textContent));
  assert.ok(translated(ui.statusOf("backup", "1").textContent));
  assert.deepEqual(ui.fields("backup").map((field) => field.value), v.mnemonics);
  assert.equal(ui.fingerprint(), fingerprint);
  assert.equal(ui.state(), "restored");
});

test("the randomness test: two different official wallets share nothing", () => {
  // Vectors 4 and 23: two 2-of-3 wallets. No passphrase is asked for.
  const ui = mount();
  ui.choose("randomness");
  assert.equal(ui.$("slip39-check-backup-panel").hidden, true);
  assert.equal(ui.$("slip39-check-random-panel").hidden, false);
  ui.fill("a", vector(4).mnemonics);
  ui.fill("b", vector(23).mnemonics);
  ui.$("slip39-check-compare").click();
  assert.equal(ui.state(), "no-repeats");
  assert.deepEqual(ui.findings(), []);
  assert.notEqual(ui.$("slip39-check-checked").textContent, "");
  showsNothing(ui);
});

test("the randomness test refuses a set that does not combine, and reports one set entered twice", () => {
  const ui = mount();
  ui.choose("randomness");
  ui.fill("a", vector(4).mnemonics);
  ui.fill("b", vector(13).mnemonics);
  ui.$("slip39-check-compare").click();
  assert.equal(ui.state(), "failed");
  assert.deepEqual(ui.findings(), []);
  // The same shares in both sets: one backup, or a device that made the
  // same wallet twice. Reported, not refused.
  ui.fill("b", vector(4).mnemonics);
  ui.$("slip39-check-compare").click();
  assert.equal(ui.state(), "repeats");
  assert.deepEqual(ui.findings(), ["same-backup"]);
  // A share that fails to read is marked on its own set's field.
  ui.fill("b", vector(2).mnemonics);
  ui.$("slip39-check-compare").click();
  assert.equal(ui.statusOf("b", "1").getAttribute("data-slip39-share-state"), "error");
});

test("every kind of finding is listed and relabelled", () => {
  const value = { level: "member", group: 0, x: 254 };
  const all = [
    { kind: "same-secret" }, { kind: "same-identifier" },
    { kind: "repeat", a: value, b: { level: "group", group: null, x: 0 }, length: 12, whole: true },
    { kind: "repeat", a: value, b: value, length: 9, whole: false },
    { kind: "repeat-within", set: "b", a: { level: "member", group: 1, x: 0 }, b: value, length: 16, whole: true },
    ...["zero", "repeated-byte", "repeated-block", "counter"].map((pattern) => ({ kind: "pattern", set: "a", value, pattern })),
  ];
  let language = "en";
  const ui = mount({
    translate: (text) => (language === "en" ? text : `[${language}] ${text}`),
    testRandomness: () => ({ ok: true, findings: all, checked: { a: { values: 1, bytes: 12 }, b: { values: 1, bytes: 12 } } }),
  });
  ui.choose("randomness");
  ui.fill("a", vector(4).mnemonics);
  ui.fill("b", vector(23).mnemonics);
  ui.$("slip39-check-compare").click();
  assert.equal(ui.state(), "repeats");
  assert.deepEqual(ui.findings(), all.map((finding) => finding.kind));
  language = "xx";
  ui.panel.retranslate();
  assert.ok(ui.$("slip39-check-findings").querySelectorAll("li").every((item) => item.textContent.startsWith("[xx] ")));
  // "Same backup" stands alone; the identifier alone is a note, not a failure.
  const only = (findings) => mount({ testRandomness: () => ({ ok: true, findings, checked: { a: { values: 1, bytes: 12 }, b: { values: 1, bytes: 12 } } }) });
  for (const [findings, state] of [[[{ kind: "same-backup" }], "repeats"], [[{ kind: "same-identifier" }], "identifier-only"]]) {
    const other = only(findings);
    other.choose("randomness");
    other.fill("a", vector(4).mnemonics);
    other.fill("b", vector(23).mnemonics);
    other.$("slip39-check-compare").click();
    assert.equal(other.state(), state);
  }
});

test("switching between the backup check and the randomness test drops the result", () => {
  const v = vector(4);
  const ui = mount();
  ui.fill("backup", v.mnemonics);
  ui.typePassphrase(VECTOR_PASSPHRASE);
  ui.$("slip39-check-run").click();
  ui.choose("randomness");
  assert.equal(ui.state(), "empty");
  showsNothing(ui);
  // The typed shares stay in their fields.
  ui.choose("backup");
  assert.deepEqual(ui.fields("backup").map((field) => field.value), v.mnemonics);
});

test("the panel's modules use no storage, console, clipboard or network API", () => {
  for (const file of ["src/js/slip39-check.js", "src/js/slip39.js", "src/js/slip39-wordlist.js"]) {
    const source = readFileSync(join(root, file), "utf8").replace(/^\s*\/\/.*$/gm, "");
    for (const api of ["localStorage", "sessionStorage", "indexedDB", "console.", "navigator.clipboard", "fetch(", "XMLHttpRequest", "WebSocket", "sendBeacon", "getUserMedia", "Math.random", "getRandomValues"]) {
      assert.ok(!source.includes(api), `${file} uses ${api}`);
    }
  }
});
