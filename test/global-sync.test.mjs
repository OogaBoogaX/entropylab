// Global entropy sync shares direct entropy bits across every input method. Hashed
// methods may publish their digest, but their original transcripts are never
// reverse-filled.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(fileURLToPath(import.meta.url));
const app = readFileSync(join(root, "..", "src/js/app.js"), "utf8");
const shell = readFileSync(join(root, "..", "src/shell.html"), "utf8");

function loadSlice(name) {
  const start = app.indexOf(`function ${name}(`);
  assert.ok(start >= 0, name);
  const body = app.indexOf("{", start);
  let depth = 0;
  for (let index = body; index < app.length; index++) {
    if (app[index] === "{") depth++;
    else if (app[index] === "}" && --depth === 0) return app.slice(start, index + 1);
  }
  throw new Error(`Could not extract ${name}`);
}

const formats = {
  bin: { id: "bin", bitsPerDigit: 1, alphabet: "01" },
  base4: { id: "base4", bitsPerDigit: 2, alphabet: "0123" },
  base8: { id: "base8", bitsPerDigit: 3, alphabet: "01234567" },
  hex: { id: "hex", bitsPerDigit: 4, alphabet: "0123456789ABCDEF" },
  base32: { id: "base32", bitsPerDigit: 5, alphabet: "qpzry9x8gf2tvdw0s3jn54khce6mua7l" },
  base64: { id: "base64", bitsPerDigit: 6, alphabet: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" },
};

const numberValue = new Function("formats", `
  function hodlEntropyFormatConfig(format) {
    return { ...formats[format], fullDigits: Math.floor(128 / formats[format].bitsPerDigit), remainderBits: 128 % formats[format].bitsPerDigit, binaryRemainder: format === "base64", seed: { bits: 128 } };
  }
  function hodlGroupedBinary(value) { return value.match(/.{1,11}/g)?.join(" ") || ""; }
  ${loadSlice("hodlGlobalSyncNumberValue")}
  return hodlGlobalSyncNumberValue;
`)(formats);

test("global sync emits only complete destination symbols", () => {
  const bits = "10101";
  assert.equal(numberValue(bits, "bin", 12), "10101");
  assert.equal(numberValue(bits, "base4", 12), "22");
  assert.equal(numberValue(bits, "base8", 12), "5");
  assert.equal(numberValue(bits, "hex", 12), "A");
  assert.equal(numberValue(bits, "base32", 12), "4");
  assert.equal(numberValue(bits, "base64", 12), "");
});

test("global sync replaces the old workspace and number-base-only sync features", () => {
  assert.match(shell, /id="global-sync-host"/);
  assert.doesNotMatch(app, /global-sync-hash-host/);
  assert.match(app, /id="global-entropy-sync"/);
  assert.match(app, /globalSync: false/);
  assert.match(app, /Sync entropy across methods/);
  assert.match(app, /Hashed inputs update them one way and are never overwritten/);
  assert.doesNotMatch(app, /workspace-sync|WorkspaceSync|Sync this key to other workspaces/);
  assert.doesNotMatch(app, /sync-number-bases|syncNumberBases|numberBaseSync/);
});

test("hashed methods publish one way without being overwritten", () => {
  const classify = loadSlice("hodlGlobalSyncIsHashedMode");
  assert.match(classify, /hodlDiceMethod === "coldcard" \|\| hodlDiceMethod === "coleman"/);
  assert.match(classify, /hodlCardMethod === "hashed"/);
  assert.match(classify, /kind === "minikey" \|\| kind === "brain"/);
  const current = loadSlice("hodlGlobalSyncCurrentBits");
  assert.match(current, /hodlDiceEntropy\(value, hodlDiceMethod, config\.words\)/);
  assert.match(current, /hodlCardsEntropy\(value, config\.words, hodlCardColemanSymbols\)/);
  assert.match(current, /hodlBrainWalletPrivateKey\(value, hodlBrainWalletTrimEnabled\(\)\)/);
  const apply = loadSlice("hodlApplyGlobalSync");
  assert.doesNotMatch(apply, /fields\.dice\s*=/);
  assert.doesNotMatch(apply, /fields\.cards\s*=/);
  assert.doesNotMatch(apply, /privateKeys\.minikey\s*=/);
  assert.doesNotMatch(apply, /privateKeys\.brain\s*=/);
  const render = loadSlice("hodlRenderGlobalSyncControl");
  assert.match(render, /document\.getElementById\("global-sync-host"\)/);
  assert.doesNotMatch(render, /global-sync-hash-host/);
  // Hashed methods never disable the switch; only Secure entry does.
  const markup = loadSlice("hodlGlobalSyncControlMarkup");
  assert.equal(markup.match(/disabled/g)?.length, 1);
  assert.match(markup, /secure = hodlSecureEntryOn/);
});

test("each dice method has an isolated transcript", () => {
  const fieldName = loadSlice("hodlDiceFieldName");
  assert.match(app, /colemanDice: ""/);
  assert.match(app, /bitboxDice: ""/);
  assert.match(app, /dplusDice: ""/);
  assert.match(fieldName, /method === "coleman"\) return "colemanDice"/);
  assert.match(fieldName, /method === "bitbox"\) return "bitboxDice"/);
  assert.match(fieldName, /method === "dplus"\) return "dplusDice"/);
  assert.match(fieldName, /return "dice"/);
  const storedValue = loadSlice("hodlStoredDiceValue");
  assert.match(storedValue, /method === "coleman"/);
  assert.match(storedValue, /hasOwnProperty\.call\(fields \|\| \{\}, name\)/);
  const importedState = loadSlice("hodlKeyManagerImportedState");
  assert.match(importedState, /!Object\.prototype\.hasOwnProperty\.call\(entry\.fields, "colemanDice"\)/);
  assert.match(importedState, /state\.fields\.colemanDice = legacyColemanDice/);
});

test("pads and pickers that skip bubbling input events still trigger the sync", () => {
  // [data-d] writes the dice textarea without dispatching a bubbling "input"
  // event, #card-undo trims the card transcript the same way, and [data-lw]
  // only picks a word — the delegated click handler must re-run the sync for
  // all of them. Seed-length buttons stay excluded: they never edit input,
  // and re-syncing from an empty active method there would wipe destinations.
  assert.match(app, /target\.matches\("\[data-lw\], \[data-d\], #card-undo"\)\) hodlGlobalSyncFromCurrentInput\(\)/);
  // The final word picked from a select fires "change", not "click", so the
  // change listener re-runs the sync for it (#1458 gate, MiniMax).
  assert.match(app, /target\.matches\("select\[data-last-word-select\]"\)\) hodlGlobalSyncFromCurrentInput\(\)/);
});

test("a brain wallet reports unknown strength instead of a green tick", () => {
  // A brain wallet publishes a 256-bit SHA-256 digest however guessable the
  // text behind it was, so the digest length must never be reported as if it
  // were counted entropy. Its own answer is required, and it has to stay
  // distinct from the null that means "this method's published count IS its
  // entropy" — number bases and typed seeds rely on that null to read healthy.
  const source = loadSlice("hodlGlobalSyncSourceBits");
  assert.match(source, /if \(kind === "brain"\) return hodlGlobalSyncUnknownBits;/);
  assert.doesNotMatch(source, /kind === "brain" \? null/);
  assert.match(app, /const hodlGlobalSyncUnknownBits = "unknown"/);

  const markup = loadSlice("hodlGlobalSyncControlMarkup");
  assert.match(markup, /syncUnknown = Boolean\(syncBits\) && reported === hodlGlobalSyncUnknownBits/);
  // The unknown case must not be folded into the numeric shortfall test, and
  // must not be able to satisfy the healthy branch.
  assert.match(markup, /syncShort = Boolean\(syncBits\) && !syncUnknown && effectiveBits < minimumBits/);
  assert.match(loadSlice("hodlGlobalSyncKeyCautions"), /minimumBits: state\?\.globalSyncSource === "key:hex-key" \? 256 : hodlGlobalSyncMinimumBits\(\)/);
  assert.match(markup, /syncShort \|\| syncUnknown \?/);
  assert.match(markup, /entropy unknown/);
});

test("an over-long hex key goes invalid in sync instead of being truncated", () => {
  // Publishing the first 64 characters of a 65+-character key would mirror a
  // key the private-key field itself rejects; every other source publishes
  // null when its input is invalid.
  const source = loadSlice("hodlGlobalSyncCurrentBits");
  assert.match(source, /if \(digits\.length > 64\) return null;/);
  assert.doesNotMatch(source, /\.slice\(0, 64\)/);
});

test("a hex key with a non-hex character goes invalid in sync instead of being cut off", () => {
  // Stopping at the first non-hex character published the digits before it:
  // a shorter key the private-key field rejects (the bitcoinjs/bip39
  // GHSA-726r-qj3q-vrxm pattern). The whole key must be hex or nothing goes.
  const source = loadSlice("hodlGlobalSyncCurrentBits");
  const hexBranch = source.slice(source.indexOf('if (kind === "hex-key")'), source.indexOf('if (kind === "wif")'));
  assert.match(hexBranch, /if \(!\/\^\[0-9a-fA-F\]\*\$\/\.test\(digits\)\) return null;/);
  assert.doesNotMatch(hexBranch, /\bbreak\b/);
  // Run the branch as written: a stray "g" yields null, a clean key all 256 bits.
  const body = hexBranch.replace(/^if \(kind === "hex-key"\) \{/, "").replace(/\}\s*$/, "");
  const run = new Function("value", "hodlHex", "hodlAssertPrivateKey", `${body}\nreturn undefined;`);
  const key = "1f".repeat(32);
  const hex = { decode: (text) => Uint8Array.from(Buffer.from(text, "hex")) };
  const assertKey = (bytes) => {
    const scalar = BigInt("0x" + Buffer.from(bytes).toString("hex"));
    if (scalar === 0n || scalar >= ORDER) throw new Error("not a private key");
  };
  assert.equal(run(key.slice(0, 10) + "g" + key.slice(11), hex, assertKey), null);
  assert.equal(run(`0x${key}`, hex, assertKey).length, 256);
  assert.equal(run(key.slice(0, 40), hex, assertKey).length, 160);
  // A complete key that is not a private key publishes nothing either
  // (red-team sweep 0eed735, part04 #8): zero, the group order, and above it.
  for (const bad of ["00".repeat(32), ORDER.toString(16), "ff".repeat(32)]) {
    assert.equal(run(bad, hex, assertKey), null, bad.slice(0, 8));
  }
  assert.equal(run((ORDER - 1n).toString(16), hex, assertKey).length, 256, "n - 1 is still a key");
});
const ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

test("a minikey reports its payload keyspace, not its 256-bit digest", () => {
  // A minikey is SHA-256(text) exactly like a brain wallet, format-constrained
  // to S plus 21 or 29 base58 characters, so the accepted 22-character form
  // tops out near 123 bits — under the feature's own 128-bit floor. Reporting
  // 256 for it would be the digest-length misreport the badge exists to catch.
  const source = loadSlice("hodlGlobalSyncSourceBits");
  assert.match(source, /if \(kind === "minikey"\) \{\s*let payload = String\(value\)\.trim\(\)\.length - 1;\s*return payload > 0 \? payload \* Math\.log2\(58\) : null;/);
  // The remaining private-key formats carry a full-length key.
  assert.match(source, /return 256;/);
  // 21 payload characters must land under the floor, 29 above it.
  assert.ok(Math.floor(21 * Math.log2(58)) < 128);
  assert.ok(Math.floor(29 * Math.log2(58)) >= 128);
});

test("cloning a derived key keeps the synced entropy verdict", () => {
  // The badge reads globalSyncSourceBits; a clone that drops it falls back to
  // reporting the published digest length as counted entropy, so the
  // shortfall and unknown cautions would vanish on every commit or edit.
  const clone = loadSlice("hodlCloneDerivedKey");
  assert.match(clone, /globalSyncBitCount: source\.globalSyncBitCount,/);
  assert.match(clone, /globalSyncSourceBits: source\.globalSyncSourceBits,/);
  // So does the raised-length caution (#1459 gate, Gemini).
  assert.match(clone, /globalSyncLengthRaised: source\.globalSyncLengthRaised,/);
});

// Red-team sweep of 0eed735 (highs #5): a 256-bit private key synced into a
// 12-word seed filled the words from its first 128 bits and still said "Key
// synced". The panel agreed (Claude, Astra, Fable, Grok; owner OK 11-05): a
// sync from a private key always uses 24 words, the status says when it
// raised the hidden length, and a red note says the words are not a backup of
// the key.
const keyHex = "1f".repeat(32);
const keyBits = [...Buffer.from(keyHex, "hex")].map((byte) => byte.toString(2).padStart(8, "0")).join("");

// The sync's closure reaches app.js's top-level element lookups (the
// declaration of hodlTargetWordCount also looks up #modes and the rest), so
// the slice loads and runs against the tests' small DOM, which creates any
// element looked up by id.
async function withDocument(run) {
  const { MiniDocument } = await import("./mini-dom.mjs");
  const saved = globalThis.document;
  const document = new MiniDocument(), lookup = document.getElementById.bind(document);
  document.getElementById = (id) => lookup(id) ?? Object.assign(document.body.appendChild(document.createElement("div")), { id });
  globalThis.document = document;
  try {
    return await run();
  } finally {
    if (saved === undefined) delete globalThis.document;
    else globalThis.document = saved;
  }
}

async function loadApply() {
  const { loadAppFunctions } = await import("./app-slice-harness.mjs");
  return loadAppFunctions(["hodlApplyGlobalSync"], {
    stubs: { hodlGlobalSyncCurrentValue: () => "", hodlGlobalSyncSourceBits: () => 256 },
    settable: ["hodlKeys", "hodlActiveKey", "hodlSecureEntryOn", "hodlTargetWordCount"],
  });
}

test("a private key always syncs into 24 words, never a cut", async () => {
  await withDocument(async () => {
    const { mnemonicToEntropy } = await import("../src/js/bip39.js");
    const slice = await loadApply();
    const state = { targetWords: 12, fields: {}, seedZeroIndexed: false };
    slice.__set.hodlKeys([state]);
    slice.__set.hodlActiveKey(0);
    slice.__set.hodlSecureEntryOn(false);
    slice.__set.hodlTargetWordCount(12);
    assert.equal(slice.hodlApplyGlobalSync(keyBits, "key:wif"), true);
    assert.equal(state.targetWords, 24, "the length is raised to hold the whole key");
    assert.equal(state.globalSyncLengthRaised, true);
    const words = state.fields.seed.split(" ");
    assert.equal(words.length, 24);
    assert.equal(Buffer.from(mnemonicToEntropy(state.fields.seed)).toString("hex"), keyHex, "the words carry every bit of the key");
    assert.equal(state.fields.privateKeys["hex-key"], keyHex, "the hex-key copy is the whole 64-digit key");
    // The fit applies on every sync: a shorter length set later is raised again.
    state.targetWords = 12;
    state.globalSyncLengthRaised = false;
    slice.hodlApplyGlobalSync(keyBits, "key:hex-key");
    assert.equal(state.targetWords, 24);
    assert.equal(state.globalSyncLengthRaised, true);
  });
});

test("a source under 256 bits leaves no half-length hex-key copy", async () => {
  await withDocument(async () => {
    const slice = await loadApply();
    const state = { targetWords: 12, globalSyncLengthRaised: true, fields: {}, seedZeroIndexed: false };
    slice.__set.hodlKeys([state]);
    slice.__set.hodlActiveKey(0);
    slice.__set.hodlSecureEntryOn(false);
    slice.__set.hodlTargetWordCount(12);
    // A number-base source: its own field keeps the typed value, every other
    // field gets the synced copy.
    slice.hodlApplyGlobalSync(keyBits.slice(0, 128), "number:hex");
    assert.equal(state.targetWords, 12, "only a private key raises the length");
    assert.equal(state.globalSyncLengthRaised, false, "syncing from another source ends the raised-length caution");
    assert.equal(state.fields.privateKeys["hex-key"], "", "128 bits are not a private key");
    assert.equal(state.fields.seed.split(" ").length, 12);
  });
});

test("the key-sync cautions follow the synced source, the raised length and Secure entry", async () => {
  const { loadAppFunctions } = await import("./app-slice-harness.mjs");
  const slice = await loadAppFunctions(["hodlGlobalSyncKeyCautions"], { settable: ["hodlSecureEntryOn"] });
  slice.__set.hodlSecureEntryOn(false);
  const synced = { globalSync: true, globalSyncBitCount: 256, globalSyncSourceBits: 256 };
  assert.deepEqual(
    { ...slice.hodlGlobalSyncKeyCautions({ ...synced, globalSyncSource: "key:wif", globalSyncLengthRaised: true }), minimumBits: undefined },
    { minimumBits: undefined, keySynced: true, lengthRaised: true },
  );
  const kept = slice.hodlGlobalSyncKeyCautions({ ...synced, globalSyncSource: "key:wif", globalSyncLengthRaised: false });
  assert.equal(kept.keySynced, true, "the note shows whenever a private key is the source");
  assert.equal(kept.lengthRaised, false, "no raised-length caution when the length was already 24");
  const seed = slice.hodlGlobalSyncKeyCautions({ ...synced, globalSyncSource: "seed:words", globalSyncLengthRaised: false });
  assert.equal(seed.keySynced || seed.lengthRaised, false, "other sources get neither");
  // A part-typed hex key is short of a whole key (#1459 gate, Gemini).
  assert.equal(slice.hodlGlobalSyncKeyCautions({ ...synced, globalSyncSource: "key:hex-key" }).minimumBits, 256);
  assert.notEqual(kept.minimumBits, 256, "a WIF is whole or invalid, so it keeps the usual floor");
  assert.equal(slice.hodlGlobalSyncKeyCautions({ ...synced, globalSync: false, globalSyncSource: "key:wif" }).keySynced, false, "not with sync off");
  slice.__set.hodlSecureEntryOn(true);
  assert.equal(slice.hodlGlobalSyncKeyCautions({ ...synced, globalSyncSource: "key:wif", globalSyncLengthRaised: true }).keySynced, false, "not while Secure entry is on");
});

// An emptied or invalid source publishes nothing: the copies it made go, the
// field being typed in keeps its text, and the status no longer counts bits
// (red-team sweep 0eed735, part04 #18).
async function loadFromInput(stubs) {
  const { loadAppFunctions } = await import("./app-slice-harness.mjs");
  return loadAppFunctions(["hodlGlobalSyncFromCurrentInput"], {
    stubs: { hodlRenderGlobalSyncControl: () => {}, ...stubs },
    settable: ["hodlKeys", "hodlActiveKey", "hodlSecureEntryOn"],
  });
}
const mirroredState = () => ({
  globalSync: true, globalSyncSource: "number:hex", globalSyncBitCount: 256, globalSyncLengthRaised: true, targetWords: 24, lastWord: "about",
  fields: { hex: "12zz", bin: "0101", seed: "abandon abandon about", seedNumbers: "1 1 4", dplusDice: "1A2", directCards: "AS", bitboxDice: "123", privateKeys: { wif: "a-wif-copy", "hex-key": "ab".repeat(32), minikey: "", brain: "" } },
});

test("an invalid source drops the copies it made and keeps the text being typed", async () => {
  await withDocument(async () => {
    const slice = await loadFromInput({ hodlGlobalSyncCurrentBits: () => null, hodlGlobalSyncCurrentValue: () => "12zz", hodlGlobalSyncSourceId: () => "number:hex", hodlGlobalSyncIsHashedMode: () => false });
    const state = mirroredState();
    slice.__set.hodlKeys([state]);
    slice.__set.hodlActiveKey(0);
    slice.__set.hodlSecureEntryOn(false);
    assert.equal(slice.hodlGlobalSyncFromCurrentInput(), false);
    for (const name of ["bin", "seed", "seedNumbers", "dplusDice", "directCards", "bitboxDice"]) assert.equal(state.fields[name], "", `${name} copy dropped`);
    assert.equal(state.fields.privateKeys.wif, "", "WIF copy dropped");
    assert.equal(state.fields.privateKeys["hex-key"], "", "hex-key copy dropped");
    assert.equal(state.fields.hex, "12zz", "the source field keeps what was typed");
    assert.equal(state.globalSyncBitCount, 0, "no bits are counted");
    assert.equal(state.globalSyncLengthRaised, true, "the caution stays with the length it describes");
    assert.equal(state.globalSync, true, "sync stays on");
    assert.equal(state.lastWord, "", "the old phrase's last word goes too");
  });
});

test("an emptied hashed source drops its copies and its count", async () => {
  await withDocument(async () => {
    const slice = await loadFromInput({ hodlGlobalSyncCurrentBits: () => { throw new Error("not reached"); }, hodlGlobalSyncCurrentValue: () => "", hodlGlobalSyncSourceId: () => "dice:coldcard", hodlGlobalSyncIsHashedMode: () => true });
    const state = mirroredState();
    state.globalSyncSource = "dice:coldcard";
    slice.__set.hodlKeys([state]);
    slice.__set.hodlActiveKey(0);
    slice.__set.hodlSecureEntryOn(false);
    slice.hodlGlobalSyncFromCurrentInput();
    assert.equal(state.fields.seed, "");
    assert.equal(state.fields.hex, "", "a number field is a copy for a dice source");
    assert.equal(state.globalSyncBitCount, 0, "no \"Key synced\" over an empty field");
  });
});

test("a private-key source that goes invalid keeps its own field", async () => {
  await withDocument(async () => {
    const slice = await loadFromInput({ hodlGlobalSyncCurrentBits: () => null, hodlGlobalSyncCurrentValue: () => "5Hue", hodlGlobalSyncSourceId: () => "key:wif", hodlGlobalSyncIsHashedMode: () => false });
    const state = mirroredState();
    state.globalSyncSource = "key:wif";
    state.fields.privateKeys.wif = "5Hue";
    slice.__set.hodlKeys([state]);
    slice.__set.hodlActiveKey(0);
    slice.__set.hodlSecureEntryOn(false);
    slice.hodlGlobalSyncFromCurrentInput();
    assert.equal(state.fields.privateKeys.wif, "5Hue", "the WIF being typed stays");
    assert.equal(state.fields.privateKeys["hex-key"], "", "its hex-key copy goes");
    assert.equal(state.fields.seed, "");
  });
});

// The bytes a sync decodes are zeroed once read (red-team sweep 0eed735,
// part04 #4 and #5).
test("the sync zeroes the key bytes it decodes and the key bytes it writes from", async () => {
  await withDocument(async () => {
    const { loadAppFunctions } = await import("./app-slice-harness.mjs");
    const decoded = [];
    const read = await loadAppFunctions(["hodlGlobalSyncCurrentBits"], {
      stubs: {
        hodlGlobalSyncCurrentValue: () => "a-wif",
        hodlGlobalSyncIsHashedMode: () => false,
        hodlNormalizePrivateKeyKind: () => "wif",
        hodlDecodeWif: () => { const priv = new Uint8Array(32).fill(0x11); decoded.push(priv); return { priv }; },
      },
      settable: ["hodlKeyMode"],
    });
    read.__set.hodlKeyMode("key");
    assert.equal(read.hodlGlobalSyncCurrentBits(24), "00010001".repeat(32), "the bits are read before the wipe");
    assert.ok(decoded.length === 1 && decoded[0].every((byte) => byte === 0), "the decoded key is zeroed");
    const written = [];
    const apply = await loadAppFunctions(["hodlApplyGlobalSync"], {
      stubs: {
        hodlGlobalSyncCurrentValue: () => "",
        hodlGlobalSyncSourceBits: () => 256,
        hodlBytesFromBits: (bits) => { const bytes = Uint8Array.from(bits.match(/.{8}/g), (byte) => parseInt(byte, 2)); written.push(bytes); return bytes; },
      },
      settable: ["hodlKeys", "hodlActiveKey", "hodlSecureEntryOn", "hodlTargetWordCount"],
    });
    const state = { targetWords: 24, fields: {}, seedZeroIndexed: false };
    apply.__set.hodlKeys([state]);
    apply.__set.hodlActiveKey(0);
    apply.__set.hodlSecureEntryOn(false);
    apply.__set.hodlTargetWordCount(24);
    apply.hodlApplyGlobalSync("00010001".repeat(32), "number:hex");
    assert.ok(state.fields.privateKeys.wif.length > 0, "the WIF copy is still written");
    // Zero entropy is no private key: no hex-key or WIF copy (#1480 gate, GLM).
    apply.hodlApplyGlobalSync("0".repeat(256), "number:hex");
    assert.equal(state.fields.privateKeys["hex-key"], "", "no hex-key copy of a zero key");
    assert.equal(state.fields.privateKeys.wif, "", "no WIF copy of a zero key");
    assert.ok(written.length > 0 && written.every((bytes) => bytes.every((byte) => byte === 0)), "the key bytes are zeroed");
  });
});
