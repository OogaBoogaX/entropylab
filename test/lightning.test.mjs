// Tests for the Lightning node identity tool (src/js/lightning.js): the LND
// and LDK (ldk-node) derivations, their differential checks against
// @scure/bip32 + @scure/bip39 (pinned dev dependencies, previously the
// app's implementation), and the tool's wiring into the shell and app.
// Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { HDKey as ScureHDKey } from "@scure/bip32";
import { mnemonicToSeedSync as scureMnemonicToSeed } from "@scure/bip39";
import { deriveLndNode, deriveLdkNode, isKnownInternalVersion, hodlInitLn, hodlLnWipeMem, hodlLnSetWorkerFactory } from "../src/js/lightning.js";
import { createLnKeyHandler } from "../src/js/lightning-derive.js";
import { aezeedDecode } from "../src/js/aezeed.js";
import { hashesReady } from "../src/js/hashes.js";
import { secp256k1Ready } from "../src/js/secp256k1.js";
import { MiniDocument } from "./mini-dom.mjs";

await Promise.all([secp256k1Ready, hashesReady]);

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const read = (path) => readFileSync(join(root, path), "utf8");
const hexToBytes = (hex) => new Uint8Array(hex.match(/.{2}/g).map((b) => parseInt(b, 16)));
const bytesToHex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");

// ── LND: entropy16 is the BIP32 seed; node key at m/1017'/coin'/6'/0/0 ─────

test("LND node key differential vs @scure/bip32, both coin types", () => {
  for (const entropyHex of ["81b637d86359e6960de795e41e0b4cfd", "000102030405060708090a0b0c0d0e0f"]) {
    for (const coinType of [0, 1]) {
      const master = ScureHDKey.fromMasterSeed(hexToBytes(entropyHex));
      const path = `m/1017'/${coinType}'/6'/0/0`;
      const expected = bytesToHex(master.derive(path).publicKey);
      const derived = deriveLndNode(hexToBytes(entropyHex), coinType);
      assert.equal(derived.nodePubKey, expected, `${entropyHex} at ${path}`);
      assert.equal(derived.path, path);
      assert.equal(derived.rootXprv, master.privateExtendedKey, "root xprv matches");
    }
  }
});

test("aezeed to LND node key, end to end from the published vector", () => {
  // The toolkit characterization mnemonic (test/aezeed-wasm.test.mjs)
  // deciphers to entropy 000102030405060708090a0b0c0d0e0f; its mainnet node
  // key must equal the one @scure/bip32 derives from that entropy.
  const words = (
    "ability result leisure oven shiver wedding toe broccoli exclude " +
    "mosquito kind van action waste merit bundle robust source able " +
    "advice core humor kitchen siren"
  ).split(" ");
  const decoded = aezeedDecode(words, "");
  const derived = deriveLndNode(decoded.entropy, 0);
  const expected = ScureHDKey.fromMasterSeed(hexToBytes("000102030405060708090a0b0c0d0e0f")).derive("m/1017'/0'/6'/0/0");
  assert.equal(derived.nodePubKey, bytesToHex(expected.publicKey));
});

test("LND derivation validates its inputs", () => {
  assert.throws(() => deriveLndNode(new Uint8Array(15), 0), /16 bytes/);
  assert.throws(() => deriveLndNode(hexToBytes("000102030405060708090a0b0c0d0e0f"), 2), /Coin type/);
});

test("only known aezeed internal versions derive a node key", () => {
  // LND writes internal version 0 and rejects anything else; guggero's
  // toolkit also emits 1. Deriving from an unknown version would print a
  // node key no implementation would ever use.
  assert.ok(isKnownInternalVersion(0), "LND's version");
  assert.ok(isKnownInternalVersion(1), "the toolkit's version");
  for (const unknown of [2, 3, 255]) assert.ok(!isKnownInternalVersion(unknown), `version ${unknown} is refused`);
  const lnSource = read("src/js/lightning-derive.js");
  assert.match(lnSource, /if \(!isKnownInternalVersion\(decoded\.internalVersion\)\)/, "the tool gates on it before deriving");
  assert.match(lnSource, /code: "internal-version"/, "the refusal is a named error");
});

// ── LDK (ldk-node): seed64 -> master -> its key re-seeds -> m/0' ───────────

const ldkExpected = (mnemonic, passphrase) => {
  const seed = scureMnemonicToSeed(mnemonic, passphrase);
  const master1 = ScureHDKey.fromMasterSeed(seed);
  const master2 = ScureHDKey.fromMasterSeed(master1.privateKey);
  const node = master2.deriveChild(0x80000000);
  return { nodePubKey: bytesToHex(node.publicKey), rootXprv: master1.privateExtendedKey };
};

test("LDK node key differential vs @scure (trezor mnemonics, with and without passphrase)", () => {
  const mnemonics = [
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    "legal winner thank year wave sausage worth useful legal winner thank yellow",
    "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
  ];
  for (const mnemonic of mnemonics) {
    for (const passphrase of ["", "TREZOR"]) {
      const expected = ldkExpected(mnemonic, passphrase);
      const derived = deriveLdkNode(mnemonic, passphrase);
      assert.equal(derived.nodePubKey, expected.nodePubKey, `${mnemonic.slice(0, 20)}… pass="${passphrase}"`);
      assert.equal(derived.rootXprv, expected.rootXprv, "stage-1 root xprv matches");
      assert.equal(derived.path, "m/0'");
    }
  }
});

test("the two-stage LDK derivation is not the plain m/0' of the seed", () => {
  // Guards the subtle part: KeysManager re-seeds from the master's private
  // key. Deriving m/0' directly from the 64-byte seed must NOT match.
  const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
  const seed = scureMnemonicToSeed(mnemonic, "");
  const plain = bytesToHex(ScureHDKey.fromMasterSeed(seed).deriveChild(0x80000000).publicKey);
  assert.notEqual(deriveLdkNode(mnemonic, "").nodePubKey, plain);
});

// ── Wiring: shell markup, tab registry, show/hide, lifecycle ────────────────

const shell = read("src/shell.html");
const appSource = read("src/js/app.js");

test("the Lightning card ships in the shell with its controls", () => {
  assert.match(shell, /<div class="card no-print tool-card" id="ln-card" role="tabpanel" hidden>/);
  for (const id of ["ln-format", "ln-network", "ln-seed", "ln-pass", "ln-go", "ln-wipe", "ln-session", "ln-error", "ln-out"]) {
    assert.ok(shell.includes(`id="${id}"`), `${id} is missing from the shell`);
  }
  assert.match(shell, /id="ln-tool-intro"/);
});

test("the workspace switcher retains the held-back Lightning implementation", () => {
  for (const entry of [/\["psbt", "Transactions", "Txns"\]/, /\["journal", "Journal", "Journal"\]/]) {
    assert.match(appSource, entry);
  }
  assert.match(appSource, /getElementById\("ln-card"\)\.hidden = id !== "ln"/);
  assert.match(appSource, /\["bip85", "sp", "msig", "calc", "vanity", "ln", "core"\]\.forEach/);
  assert.match(appSource, /import \{ hodlInitLn, hodlLnWipeMem \} from "\.\/lightning\.js"/);
  assert.match(appSource, /hodlInitLn\(\{ journalLog: hodlJournalLog, copyIcon: hodlClipboardIconMarkup, qrSvg: hodlQrSvg, pageNetwork: \(\) => hodlInspectorNetwork\(\) \}\)/);
});

test("a format or network change wipes the derived result but not the invoice", () => {
  // A stale mainnet pubkey next to a flipped "Testnet" select is how a
  // correct seed looks wrong: the change handler wipes and re-renders. The
  // invoice card is not key material and must survive.
  const lnSource = read("src/js/lightning.js");
  const listener = lnSource.match(/for \(const id of \["ln-format", "ln-network"\]\) \{\s*document\.getElementById\(id\)\?\.addEventListener\("change", \(\) => \{([\s\S]*?)\}\);\s*\}/);
  assert.ok(listener, "the change listener exists");
  assert.match(listener[1], /hodlLnKeyWipeMem\(\)/, "the change wipes the derived key result");
  assert.doesNotMatch(listener[1], /hodlLnWipeMem\(\)/, "the change must not wipe the invoice card");
  assert.match(listener[1], /hodlLnRender\(\)/, "the change re-renders the empty state");
  assert.match(listener[1], /hodlLnSyncFormat\(\)/, "the change still syncs the network field");
  assert.match(listener[1], /hodlLnInvRender\(\)/, "the change re-renders the invoice card");
});

// ── Tool behaviour through the real wiring (mini DOM) ───────────────────────

// The published aezeed characterization mnemonic (see the end-to-end test
// above): it deciphers to entropy 000102030405060708090a0b0c0d0e0f.
const AEZEED_VECTOR_WORDS =
  "ability result leisure oven shiver wedding toe broccoli exclude " +
  "mosquito kind van action waste merit bundle robust source able " +
  "advice core humor kitchen siren";
const BIP39_VECTOR_WORDS = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

// The tool wired over a mini DOM: the fixture carries the ids hodlInitLn
// touches, and the derive runs through the real Derive button handler.
function lnPage() {
  const page = new MiniDocument();
  globalThis.document = page;
  // The selects carry the shell's options (shell.html #ln-card): a <select>
  // only holds a set value that matches one of its options, so without them
  // the fixture cannot switch the tool off aezeed and the BIP-39/LDK path
  // never runs.
  page.body.innerHTML = '<select id="ln-format"><option value="aezeed" selected>aezeed · LND cipher seed</option><option value="bip39">BIP-39 · LDK (ldk-node)</option><option value="cln-hsm">Core Lightning hsm_secret</option></select>'
    + '<div id="ln-network-field"><select id="ln-network"><option value="mainnet" selected>Mainnet</option><option value="testnet">Testnet</option></select></div>'
    + '<button class="btn secondary" id="ln-hsm-upload" type="button">Choose hsm_secret</button><input type="file" id="ln-hsm-file" hidden>'
    + '<textarea id="ln-seed"></textarea><input id="ln-pass" type="password">'
    + '<button id="ln-go" type="button"></button><button id="ln-wipe" type="button"></button>'
    + '<p id="ln-session"></p><p id="ln-error"></p><div id="ln-out"></div>'
    + '<span id="ln-seed-help"></span>';
  hodlInitLn({ journalLog() {}, copyIcon: () => "" });
  return page;
}

// hodlInitLn assigns the Derive button's onclick; call it (the mini DOM
// keeps it as a property), falling back to a dispatched click event.
const lnDerive = (page) => {
  const go = page.getElementById("ln-go");
  if (typeof go.onclick === "function") go.onclick();
  else go.dispatchEvent(new Event("click", { bubbles: true }));
};

// Worker factories over the real in-process protocol handler (the default
// stand-in's twin), for the tests that must control the wire. A test that
// installs one must restore the plain stand-in afterwards, and must wipe
// first: the module keeps its worker across tests, so without a wipe the
// derive would reuse a previous test's worker and never run the factory.
const standInFactory = () => {
  const worker = { onmessage: null, onerror: null, terminated: false };
  const handle = createLnKeyHandler((message) => worker.onmessage?.({ data: message }));
  worker.postMessage = (data) => {
    if (!worker.terminated) handle(data);
  };
  worker.terminate = () => {
    worker.terminated = true;
  };
  return { worker, url: null };
};

// A stand-in whose postMessage detaches the transferred buffers, as a real
// Worker does: the page's view of the hsm_secret bytes is gone once posted.
const detachingFactory = () => {
  const worker = { onmessage: null, onerror: null, terminated: false };
  const handle = createLnKeyHandler((message) => worker.onmessage?.({ data: message }));
  worker.postMessage = (data, transfer) => {
    if (!worker.terminated) handle(transfer ? structuredClone(data, { transfer }) : data);
  };
  worker.terminate = () => {
    worker.terminated = true;
  };
  return { worker, url: null };
};

// The same handler, but its replies wait for flush(): the test decides when
// an in-flight answer lands.
const queuedWorkers = [];
const queuedFactory = () => {
  const worker = { onmessage: null, onerror: null, terminated: false, queue: [] };
  const handle = createLnKeyHandler((message) => worker.queue.push(message));
  worker.postMessage = (data) => {
    if (!worker.terminated) handle(data);
  };
  worker.terminate = () => {
    worker.terminated = true;
  };
  worker.flush = () => {
    for (const message of worker.queue.splice(0)) worker.onmessage?.({ data: message });
  };
  queuedWorkers.push(worker);
  return { worker, url: null };
};

test("the shell carries the Core Lightning hsm_secret controls", () => {
  assert.match(shell, /<option value="cln-hsm">Core Lightning hsm_secret<\/option>/);
  const upload = shell.match(/<button[^>]*\bid="ln-hsm-upload"[^>]*>/)?.[0];
  assert.ok(upload, "#ln-hsm-upload is missing from the shell");
  assert.match(upload, /\btype="button"/);
  const file = shell.match(/<input[^>]*\bid="ln-hsm-file"[^>]*>/)?.[0];
  assert.ok(file, "#ln-hsm-file is missing from the shell");
  assert.match(file, /\btype="file"/);
  assert.match(file, /\bhidden\b/);
});

test("the aezeed path renders its reveal switch on a page without the CLN controls", () => {
  // The shell owns the CLN controls. A page that predates them (the LND/LDK
  // fixtures, and any shell without the markup) must still derive aezeed and
  // render #ln-reveal: the tool must not invent a format option, which would
  // flip an empty select to cln-hsm and send the aezeed words down the CLN
  // path (the round-1 regression).
  const page = new MiniDocument();
  globalThis.document = page;
  page.body.innerHTML = '<select id="ln-format"></select>'
    + '<div id="ln-network-field"><select id="ln-network"><option value="mainnet" selected>Mainnet</option><option value="testnet">Testnet</option></select></div>'
    + '<textarea id="ln-seed"></textarea><input id="ln-pass" type="password">'
    + '<button id="ln-go" type="button"></button><button id="ln-wipe" type="button"></button>'
    + '<p id="ln-session"></p><p id="ln-error"></p><div id="ln-out"></div>'
    + '<span id="ln-seed-help"></span>';
  try {
    hodlInitLn({ journalLog() {}, copyIcon: () => "" });
    assert.equal(page.getElementById("ln-format").options.length, 0, "the tool invented a format option");
    page.getElementById("ln-seed").value = AEZEED_VECTOR_WORDS;
    lnDerive(page);
    assert.equal(page.getElementById("ln-error").textContent, "", "the aezeed derive reported an error");
    assert.ok(page.getElementById("ln-reveal"), "the aezeed derive rendered no reveal switch");
  } finally {
    delete globalThis.document;
  }
});

test("the tool derives the published aezeed vector through its real wiring", () => {
  const page = lnPage();
  try {
    page.getElementById("ln-seed").value = AEZEED_VECTOR_WORDS;
    lnDerive(page);
    assert.equal(page.getElementById("ln-error").textContent, "", "the derive reported an error");
    const expected = ScureHDKey.fromMasterSeed(hexToBytes("000102030405060708090a0b0c0d0e0f")).derive("m/1017'/0'/6'/0/0");
    assert.ok(page.getElementById("ln-out").innerHTML.includes(bytesToHex(expected.publicKey)), "the derived node pubkey is not on screen");
  } finally {
    delete globalThis.document;
  }
});

test("the tool derives the LDK node key through its real wiring", () => {
  const page = lnPage();
  try {
    page.getElementById("ln-format").value = "bip39";
    page.getElementById("ln-seed").value = BIP39_VECTOR_WORDS;
    lnDerive(page);
    assert.equal(page.getElementById("ln-error").textContent, "", "the derive reported an error");
    assert.ok(page.getElementById("ln-out").innerHTML.includes(ldkExpected(BIP39_VECTOR_WORDS, "").nodePubKey), "the derived node pubkey is not on screen");
  } finally {
    delete globalThis.document;
  }
});

test("an oversized seed paste is refused before any normalizing or deriving", () => {
  // The 24-word vector plus 6 kB of punctuation noise: the normalizer would
  // strip the noise and derive, so the length refusal must come first.
  const page = lnPage();
  try {
    page.getElementById("ln-seed").value = `${AEZEED_VECTOR_WORDS} ${"1!".repeat(3000)}`;
    lnDerive(page);
    // The refusal is the keyed "seed-too-long" error; its wording is
    // translatable copy, so assert the outcome, not the text: an error is
    // shown and nothing was derived (the normalizer would have stripped the
    // noise and derived had the length check come after it).
    assert.ok(page.getElementById("ln-error").textContent.length > 0, "the oversized paste was not refused");
    assert.equal(page.getElementById("ln-out").innerHTML, "", "an oversized paste derived a node key");
  } finally {
    delete globalThis.document;
  }
});

test("the LDK tool path refuses a lone-surrogate passphrase and derives nothing", () => {
  const page = lnPage();
  try {
    page.getElementById("ln-format").value = "bip39";
    page.getElementById("ln-seed").value = BIP39_VECTOR_WORDS;
    page.getElementById("ln-pass").value = "word\uD800";
    lnDerive(page);
    // The refusal is the keyed "passphrase-utf8" error; assert the outcome,
    // not the translatable wording.
    assert.ok(page.getElementById("ln-error").textContent.length > 0, "the passphrase was not refused");
    assert.equal(page.getElementById("ln-out").innerHTML, "", "a refused passphrase derived a node key");
  } finally {
    delete globalThis.document;
  }
});

test("deriveLdkNode refuses a passphrase that is not well-formed Unicode", () => {
  // A BIP39 passphrase is UTF-8 text; a lone surrogate would silently encode
  // as U+FFFD and derive a wallet the user never typed (the station's BIP39
  // path refuses the same, #1015). Both halves of the rule: a high surrogate
  // not followed by a low one, and a low surrogate without a high one.
  for (const bad of ["\uD800", "\uDC00", "word\uD800", "word\uDC00word", "\uD800\uD800", "word\uD800A"]) {
    // The wrong side here was the test, not the derivation: the guard throws
    // the keyed refusal, but assert.throws does not hand the caught error
    // back, so the .code/.key assertions read undefined. Capture it
    // explicitly and assert on the error object itself.
    let error = null;
    try {
      deriveLdkNode(BIP39_VECTOR_WORDS, bad);
    } catch (thrown) {
      error = thrown;
    }
    assert.ok(error, `passphrase ${JSON.stringify(bad)} derived`);
    // The error's code is the stable marker; the key is translatable copy,
    // asserted only for presence (AGENTS.md).
    assert.equal(error.code, "passphrase-utf8");
    assert.ok(typeof error.key === "string" && error.key.length > 0, "the refusal carries a translation key");
  }
  // Control: a real astral character (a high+low pair) is honest UTF-8 and
  // derives exactly what the independent @scure implementation derives.
  const paired = "pass\uD83D\uDE00";
  assert.equal(deriveLdkNode(BIP39_VECTOR_WORDS, paired).nodePubKey, ldkExpected(BIP39_VECTOR_WORDS, paired).nodePubKey);
});

// ── Core Lightning hsm_secret (type 2) ──────────────────────────────────────

// CLN v26.06.9, tests/test_wallet.py: the mnemonic hsm_secret that
// `lightning-hsmtool generatehsm` writes with no passphrase.
const CLN_ABANDON = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const CLN_NODE_ID = "03653e90c1ce4660fd8505dd6d643356e93cfe202af109d382787639dd5890e87d";
const CLN_DESCRIPTORS = [
  "wpkh(xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ/0/*)#hjszq0wk",
  "sh(wpkh(xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ/0/*))#u0t3u3xz",
  "tr(xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ/0/*)#8e7pq23w",
];

// A type-2 hsm_secret: 32 zero bytes (the "no passphrase" marker) followed by
// the mnemonic text, exactly as `lightning-hsmtool generatehsm` writes it.
const clnType2File = (mnemonic) => {
  const words = new TextEncoder().encode(mnemonic);
  const file = new Uint8Array(32 + words.length);
  file.set(words, 32);
  return file;
};

// The test's own bech32 encoder, validated against the BIP173 example below,
// so the expected addresses do not come from the code under test.
const BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const bech32Polymod = (values) => {
  const generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let checksum = 1;
  for (const value of values) {
    const top = checksum >>> 25;
    checksum = ((checksum & 0x1ffffff) << 5) ^ value;
    for (let i = 0; i < 5; i++) if ((top >>> i) & 1) checksum ^= generator[i];
  }
  return checksum;
};
const bech32Encode = (hrp, data) => {
  const expanded = [];
  for (const char of hrp) expanded.push(char.charCodeAt(0) >> 5);
  expanded.push(0);
  for (const char of hrp) expanded.push(char.charCodeAt(0) & 31);
  const mod = bech32Polymod([...expanded, ...data, 0, 0, 0, 0, 0, 0]) ^ 1;
  const checksum = [];
  for (let i = 0; i < 6; i++) checksum.push((mod >>> (5 * (5 - i))) & 31);
  return `${hrp}1${[...data, ...checksum].map((value) => BECH32_CHARSET[value]).join("")}`;
};
const convertBits = (bytes, from, to, pad) => {
  let accumulator = 0;
  let bits = 0;
  const out = [];
  const maxValue = (1 << to) - 1;
  for (const byte of bytes) {
    accumulator = (accumulator << from) | byte;
    bits += from;
    while (bits >= to) {
      bits -= to;
      out.push((accumulator >> bits) & maxValue);
    }
  }
  if (pad && bits > 0) out.push((accumulator << (to - bits)) & maxValue);
  return out;
};
const hash160 = (bytes) => {
  const sha = createHash("sha256").update(bytes).digest();
  return new Uint8Array(createHash("ripemd160").update(sha).digest());
};
const p2wpkh = (publicKey, hrp) => bech32Encode(hrp, [0, ...convertBits(hash160(publicKey), 8, 5, true)]);

const clnExpectedAddresses = (mnemonic, network) => {
  const master = ScureHDKey.fromMasterSeed(scureMnemonicToSeed(mnemonic, ""));
  const chain = master.derive("m/86'/0'/0'").deriveChild(0);
  const hrp = network === "testnet" ? "tb" : "bc";
  return Array.from({ length: 10 }, (_, index) => p2wpkh(chain.deriveChild(index).publicKey, hrp));
};

test("the test's bech32 encoder matches the BIP173 example", () => {
  const publicKey = hexToBytes("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
  assert.equal(p2wpkh(publicKey, "bc"), "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
});

test("the CLN words path renders the published node id, descriptors and 10 addresses", () => {
  const page = lnPage();
  try {
    page.getElementById("ln-format").value = "cln-hsm";
    page.getElementById("ln-seed").value = CLN_ABANDON;
    lnDerive(page);
    assert.equal(page.getElementById("ln-error").textContent, "", "the derive reported an error");
    const html = page.getElementById("ln-out").innerHTML;
    assert.ok(html.includes(CLN_NODE_ID), "the CLN node id is not on screen");
    for (const descriptor of CLN_DESCRIPTORS) assert.ok(html.includes(descriptor), `descriptor ${descriptor} is not on screen`);
    for (const address of clnExpectedAddresses(CLN_ABANDON, "bitcoin")) assert.ok(html.includes(address), `address ${address} is not on screen`);
    const expectedXprv = ScureHDKey.fromMasterSeed(scureMnemonicToSeed(CLN_ABANDON, "")).derive("m/86'/0'/0'").privateExtendedKey;
    assert.ok(!html.includes(expectedXprv), "the xprv must stay hidden until revealed");
    const reveal = page.getElementById("ln-reveal");
    reveal.checked = true;
    reveal.dispatchEvent(new Event("change"));
    assert.ok(page.getElementById("ln-out").innerHTML.includes(expectedXprv), "the xprv is not shown after reveal");
  } finally {
    delete globalThis.document;
  }
});

test("a type-2 hsm_secret file derives the same node id and zeroes the bytes", async () => {
  const page = lnPage();
  try {
    page.getElementById("ln-format").value = "cln-hsm";
    const fileInput = page.getElementById("ln-hsm-file");
    const bytes = clnType2File(CLN_ABANDON);
    const snapshot = Uint8Array.from(bytes);
    fileInput.files = [{ arrayBuffer: async () => bytes.buffer }];
    await fileInput.onchange();
    assert.deepEqual([...bytes], [...new Uint8Array(snapshot.length)], "the file bytes were not zeroed");
    assert.equal(fileInput.value, "", "the file input was not reset");
    lnDerive(page);
    assert.equal(page.getElementById("ln-error").textContent, "", "the derive reported an error");
    assert.ok(page.getElementById("ln-out").innerHTML.includes(CLN_NODE_ID), "the file path did not derive the node id");
  } finally {
    delete globalThis.document;
  }
});

test("a chosen hsm_secret file wins over words typed before it", async () => {
  const page = lnPage();
  try {
    page.getElementById("ln-format").value = "cln-hsm";
    // A valid 12-word mnemonic that is not the file's: if the typed words
    // still won, the node id would be this one's, not CLN_NODE_ID.
    page.getElementById("ln-seed").value = "legal winner thank year wave sausage worth useful legal winner thank yellow";
    const fileInput = page.getElementById("ln-hsm-file");
    fileInput.files = [{ arrayBuffer: async () => clnType2File(CLN_ABANDON).buffer }];
    await fileInput.onchange();
    assert.equal(page.getElementById("ln-seed").value, "", "the file load left the typed words in #ln-seed");
    lnDerive(page);
    assert.equal(page.getElementById("ln-error").textContent, "", "the derive reported an error");
    assert.ok(page.getElementById("ln-out").innerHTML.includes(CLN_NODE_ID), "Derive used the typed words, not the chosen file");
  } finally {
    delete globalThis.document;
  }
});

test("words typed after a chosen hsm_secret file win, and the file mnemonic is dropped", async () => {
  const page = lnPage();
  try {
    page.getElementById("ln-format").value = "cln-hsm";
    const fileInput = page.getElementById("ln-hsm-file");
    fileInput.files = [{ arrayBuffer: async () => clnType2File(CLN_ABANDON).buffer }];
    await fileInput.onchange();
    assert.ok(page.getElementById("ln-session").textContent.length > 0, "the file load did not report its status");
    const seed = page.getElementById("ln-seed");
    seed.value = "legal winner thank year wave sausage worth useful legal winner thank yellow";
    seed.dispatchEvent(new Event("input"));
    assert.equal(page.getElementById("ln-session").textContent, "", "typing left the hsm_secret read status on screen");
    lnDerive(page);
    assert.equal(page.getElementById("ln-error").textContent, "", "the derive reported an error");
    const html = page.getElementById("ln-out").innerHTML;
    assert.ok(!html.includes(CLN_NODE_ID), "Derive used the file mnemonic, not the typed words");
    assert.ok(html.includes('id="ln-node-pubkey"'), "the typed words rendered no node key");
    // The held file mnemonic is gone: with the words cleared, Derive has
    // nothing to use and refuses.
    seed.value = "";
    lnDerive(page);
    assert.equal(page.getElementById("ln-error").dataset.code, "hsm-secret-missing", "the file mnemonic was still held after typing");
  } finally {
    delete globalThis.document;
  }
});

test("the CLN file path refuses type 3, encrypted, plain and invalid files with keyed errors", async () => {
  const withPassphrase = clnType2File(CLN_ABANDON);
  withPassphrase[0] = 0x42;
  const cases = [
    ["hsm-secret-passphrase", withPassphrase],
    ["hsm-secret-encrypted", new Uint8Array(73).fill(7)],
    ["hsm-secret-plain", new Uint8Array(32).fill(7)],
    ["hsm-secret-truncated", new Uint8Array(16)],
  ];
  for (const [code, bytes] of cases) {
    const page = lnPage();
    try {
      page.getElementById("ln-format").value = "cln-hsm";
      const fileInput = page.getElementById("ln-hsm-file");
      fileInput.files = [{ arrayBuffer: async () => bytes.buffer }];
      await fileInput.onchange();
      assert.equal(page.getElementById("ln-error").dataset.code, code, `expected ${code}`);
      assert.ok(page.getElementById("ln-error").textContent.length > 0, "the refusal is not on screen");
      assert.equal(page.getElementById("ln-out").innerHTML, "", "a refused file rendered a result");
    } finally {
      delete globalThis.document;
    }
  }
});

test("a passphrase with cln-hsm is refused", () => {
  const page = lnPage();
  try {
    page.getElementById("ln-format").value = "cln-hsm";
    page.getElementById("ln-seed").value = CLN_ABANDON;
    page.getElementById("ln-pass").value = "secret";
    lnDerive(page);
    assert.equal(page.getElementById("ln-error").dataset.code, "hsm-secret-passphrase-not-needed");
    assert.equal(page.getElementById("ln-out").innerHTML, "", "a refused passphrase derived a node key");
  } finally {
    delete globalThis.document;
  }
});

test("a transferred hsm_secret buffer is detached: the load still resolves and resets the input", async () => {
  // A real Worker detaches a transferred ArrayBuffer; fill() on the page's
  // view of it throws a TypeError, rejecting the handler before the input
  // reset. The detaching stand-in reproduces that wire behaviour.
  hodlLnSetWorkerFactory(detachingFactory);
  const page = lnPage();
  try {
    hodlLnWipeMem();
    page.getElementById("ln-format").value = "cln-hsm";
    const fileInput = page.getElementById("ln-hsm-file");
    const bytes = clnType2File(CLN_ABANDON);
    fileInput.files = [{ arrayBuffer: async () => bytes.buffer }];
    await fileInput.onchange();
    assert.equal(bytes.byteLength, 0, "the test double did not detach the transferred buffer");
    assert.equal(fileInput.value, "", "the file input was not reset");
    assert.equal(page.getElementById("ln-error").textContent, "", "the load reported an error");
    lnDerive(page);
    assert.ok(page.getElementById("ln-out").innerHTML.includes(CLN_NODE_ID), "the file path did not derive the node id");
  } finally {
    hodlLnWipeMem();
    hodlLnSetWorkerFactory(standInFactory);
    delete globalThis.document;
  }
});

test("a refused derive supersedes the previous run's answer still in flight", () => {
  hodlLnSetWorkerFactory(queuedFactory);
  const page = lnPage();
  try {
    hodlLnWipeMem();
    page.getElementById("ln-seed").value = AEZEED_VECTOR_WORDS;
    lnDerive(page);
    const worker = queuedWorkers.at(-1);
    // The refusal (an oversized paste) happens before anything is posted,
    // but it must still supersede the earlier run: its answer is now stale.
    page.getElementById("ln-seed").value = `${AEZEED_VECTOR_WORDS} ${"1!".repeat(3000)}`;
    lnDerive(page);
    assert.equal(page.getElementById("ln-error").dataset.code, "seed-too-long");
    worker.flush();
    assert.equal(page.getElementById("ln-out").innerHTML, "", "a stale derive answer rendered beside the refusal");
    assert.equal(page.getElementById("ln-error").dataset.code, "seed-too-long", "the stale answer cleared the refusal");
  } finally {
    hodlLnWipeMem();
    hodlLnSetWorkerFactory(standInFactory);
    delete globalThis.document;
  }
});

test("a new Derive clears the previous result and any revealed secret at once", () => {
  hodlLnSetWorkerFactory(queuedFactory);
  const page = lnPage();
  try {
    hodlLnWipeMem();
    page.getElementById("ln-seed").value = AEZEED_VECTOR_WORDS;
    lnDerive(page);
    const worker = queuedWorkers.at(-1);
    worker.flush(); // the derived answer lands
    const xprv = ScureHDKey.fromMasterSeed(hexToBytes("000102030405060708090a0b0c0d0e0f")).privateExtendedKey;
    const reveal = page.getElementById("ln-reveal");
    reveal.checked = true;
    reveal.dispatchEvent(new Event("change"));
    worker.flush(); // the revealed answer lands
    assert.ok(page.getElementById("ln-out").innerHTML.includes(xprv), "the revealed xprv is not on screen");
    // The click itself clears the screen, before the worker answers.
    lnDerive(page);
    assert.ok(!page.getElementById("ln-out").innerHTML.includes(xprv), "the old secret stayed on screen into the new derive");
    assert.equal(page.getElementById("ln-root-xprv"), null, "the old secret element survived the click");
    worker.flush();
    assert.ok(page.getElementById("ln-out").innerHTML.includes('id="ln-node-pubkey"'), "the new derive rendered no result");
  } finally {
    hodlLnWipeMem();
    hodlLnSetWorkerFactory(standInFactory);
    delete globalThis.document;
  }
});

test("a Derive clicked while an hsm_secret loads derives from the file, not the box", async () => {
  hodlLnSetWorkerFactory(queuedFactory);
  const page = lnPage();
  try {
    hodlLnWipeMem();
    page.getElementById("ln-format").value = "cln-hsm";
    // Words typed before the pick lose to the file from the moment it is
    // picked: the box is cleared before the read even starts.
    page.getElementById("ln-seed").value = "legal winner thank year wave sausage worth useful legal winner thank yellow";
    const fileInput = page.getElementById("ln-hsm-file");
    fileInput.files = [{ arrayBuffer: async () => clnType2File(CLN_ABANDON).buffer }];
    await fileInput.onchange(); // the load is posted; its reply is still in flight
    assert.equal(page.getElementById("ln-seed").value, "", "the file pick left the typed words in #ln-seed");
    // The derive must use the file the worker is loading, not the box: the
    // worker processes messages in order, so the load arrives first.
    lnDerive(page);
    const worker = queuedWorkers.at(-1);
    worker.flush(); // hsm-loaded, then the derive's answer, in wire order
    assert.ok(page.getElementById("ln-session").textContent.length > 0, "the derive dropped the hsm-loaded reply");
    assert.equal(page.getElementById("ln-error").textContent, "", "the derive reported an error");
    assert.ok(page.getElementById("ln-out").innerHTML.includes(CLN_NODE_ID), "Derive did not use the loading file's words");
  } finally {
    hodlLnWipeMem();
    hodlLnSetWorkerFactory(standInFactory);
    delete globalThis.document;
  }
});

test("words typed while the hsm_secret file is still being read win, and the read's bytes are wiped", async () => {
  const page = lnPage();
  try {
    hodlLnWipeMem();
    page.getElementById("ln-format").value = "cln-hsm";
    const bytes = clnType2File(CLN_ABANDON);
    const length = bytes.length;
    let openRead;
    const gate = new Promise((resolve) => {
      openRead = resolve;
    });
    const fileInput = page.getElementById("ln-hsm-file");
    fileInput.files = [{ arrayBuffer: () => gate.then(() => bytes.buffer) }];
    page.getElementById("ln-seed").value = "legal winner thank year wave sausage worth useful legal winner thank yellow";
    const reading = fileInput.onchange(); // the read is pending on the gate
    // The file is the latest entry from the pick: the box is cleared at once.
    assert.equal(page.getElementById("ln-seed").value, "", "the file pick left the typed words in #ln-seed");
    // Typing during the read supersedes the file.
    const seed = page.getElementById("ln-seed");
    seed.value = "legal winner thank year wave sausage worth useful legal winner thank yellow";
    seed.dispatchEvent(new Event("input"));
    openRead();
    await reading;
    assert.deepEqual([...bytes], [...new Uint8Array(length)], "the superseded read's bytes were not wiped");
    assert.equal(seed.value, "legal winner thank year wave sausage worth useful legal winner thank yellow", "the superseded read cleared the typed words");
    // The load was never posted: with the box cleared, Derive has nothing.
    seed.value = "";
    lnDerive(page);
    assert.equal(page.getElementById("ln-error").dataset.code, "hsm-secret-missing", "the superseded file was still loaded");
  } finally {
    hodlLnWipeMem();
    delete globalThis.document;
  }
});

test("words typed while an hsm_secret is still loading win over the file", async () => {
  hodlLnSetWorkerFactory(queuedFactory);
  const page = lnPage();
  try {
    hodlLnWipeMem();
    page.getElementById("ln-format").value = "cln-hsm";
    const fileInput = page.getElementById("ln-hsm-file");
    fileInput.files = [{ arrayBuffer: async () => clnType2File(CLN_ABANDON).buffer }];
    await fileInput.onchange(); // the load is posted; its reply is still in flight
    const seed = page.getElementById("ln-seed");
    seed.value = "legal winner thank year wave sausage worth useful legal winner thank yellow";
    seed.dispatchEvent(new Event("input"));
    queuedWorkers.at(-1).flush(); // the stale hsm-loaded reply lands and is ignored
    assert.equal(seed.value, "legal winner thank year wave sausage worth useful legal winner thank yellow", "the stale reply cleared the typed words");
    lnDerive(page);
    queuedWorkers.at(-1).flush();
    assert.equal(page.getElementById("ln-error").textContent, "", "the derive reported an error");
    const html = page.getElementById("ln-out").innerHTML;
    assert.ok(!html.includes(CLN_NODE_ID), "Derive used the file's words, not the typed ones");
    assert.ok(html.includes('id="ln-node-pubkey"'), "the typed words rendered no node key");
  } finally {
    hodlLnWipeMem();
    hodlLnSetWorkerFactory(standInFactory);
    delete globalThis.document;
  }
});

test("a worker error supersedes the answers the crashed worker still has in flight", () => {
  hodlLnSetWorkerFactory(queuedFactory);
  const page = lnPage();
  try {
    hodlLnWipeMem();
    page.getElementById("ln-seed").value = AEZEED_VECTOR_WORDS;
    lnDerive(page);
    const worker = queuedWorkers.at(-1);
    worker.onerror({ message: "boom" });
    assert.equal(worker.terminated, true, "the crashed worker was not terminated at once");
    worker.flush();
    assert.equal(page.getElementById("ln-out").innerHTML, "", "a crashed worker's queued answer rendered");
    assert.equal(page.getElementById("ln-error").textContent, "boom");
  } finally {
    hodlLnWipeMem();
    hodlLnSetWorkerFactory(standInFactory);
    delete globalThis.document;
  }
});

test("the worker crash fallback message goes through t()", () => {
  const lnSource = read("src/js/lightning.js");
  assert.match(lnSource, /t\("The Lightning key worker stopped\."\)/, "the crash message bypasses t()");
});

test("typed CLN words pass the same length refusal as the other formats", () => {
  const page = lnPage();
  try {
    page.getElementById("ln-format").value = "cln-hsm";
    page.getElementById("ln-seed").value = `${CLN_ABANDON} ${"1!".repeat(3000)}`;
    lnDerive(page);
    assert.equal(page.getElementById("ln-error").dataset.code, "seed-too-long");
    assert.equal(page.getElementById("ln-out").innerHTML, "", "an oversized CLN paste derived a node key");
  } finally {
    delete globalThis.document;
  }
});

test("the network field shows for aezeed and cln-hsm, not bip39", () => {
  const page = lnPage();
  try {
    const field = page.getElementById("ln-network-field");
    page.getElementById("ln-format").value = "aezeed";
    page.getElementById("ln-format").dispatchEvent(new Event("change"));
    assert.equal(field.hidden, false, "aezeed hides the network field");
    page.getElementById("ln-format").value = "bip39";
    page.getElementById("ln-format").dispatchEvent(new Event("change"));
    assert.equal(field.hidden, true, "bip39 shows the network field");
    page.getElementById("ln-format").value = "cln-hsm";
    page.getElementById("ln-format").dispatchEvent(new Event("change"));
    assert.equal(field.hidden, false, "cln-hsm hides the network field");
  } finally {
    delete globalThis.document;
  }
});

test("the CLN network field selects the test-network address prefix and key version", () => {
  const page = lnPage();
  try {
    page.getElementById("ln-format").value = "cln-hsm";
    page.getElementById("ln-network").value = "testnet";
    page.getElementById("ln-seed").value = CLN_ABANDON;
    lnDerive(page);
    assert.equal(page.getElementById("ln-error").textContent, "", "the derive reported an error");
    let html = page.getElementById("ln-out").innerHTML;
    assert.ok(html.includes("tpub"), "the testnet descriptors do not use tpub");
    for (const address of clnExpectedAddresses(CLN_ABANDON, "testnet")) assert.ok(html.includes(address), `address ${address} is not on screen`);
    // The account xprv is hidden until revealed; its version byte must be
    // testnet's (tprv), not mainnet's (xprv).
    const reveal = page.getElementById("ln-reveal");
    reveal.checked = true;
    reveal.dispatchEvent(new Event("change"));
    assert.match(page.getElementById("ln-out").innerHTML, /id="ln-root-xprv"[^>]*>tprv/, "the testnet account xprv does not use tprv");
    // Mainnet: the same seed, the other version bytes.
    page.getElementById("ln-network").value = "mainnet";
    page.getElementById("ln-network").dispatchEvent(new Event("change"));
    page.getElementById("ln-seed").value = CLN_ABANDON;
    lnDerive(page);
    html = page.getElementById("ln-out").innerHTML;
    assert.match(html, /wpkh\(xpub/, "the mainnet descriptors do not use xpub");
    const mainReveal = page.getElementById("ln-reveal");
    mainReveal.checked = true;
    mainReveal.dispatchEvent(new Event("change"));
    assert.match(page.getElementById("ln-out").innerHTML, /id="ln-root-xprv"[^>]*>xprv/, "the mainnet account xprv does not use xprv");
  } finally {
    delete globalThis.document;
  }
});

test("Clear removes the CLN result and secrets", () => {
  const page = lnPage();
  try {
    page.getElementById("ln-format").value = "cln-hsm";
    page.getElementById("ln-seed").value = CLN_ABANDON;
    lnDerive(page);
    assert.ok(page.getElementById("ln-out").innerHTML.includes(CLN_NODE_ID));
    page.getElementById("ln-wipe").onclick();
    assert.equal(page.getElementById("ln-out").innerHTML, "", "Clear left the result on screen");
    assert.equal(page.getElementById("ln-seed").value, "", "Clear left the seed on screen");
    assert.equal(page.getElementById("ln-pass").value, "", "Clear left the passphrase on screen");
  } finally {
    delete globalThis.document;
  }
});

test("hodlLnWipeMem drops the CLN result so a re-render shows nothing", () => {
  const page = lnPage();
  try {
    page.getElementById("ln-format").value = "cln-hsm";
    page.getElementById("ln-seed").value = CLN_ABANDON;
    lnDerive(page);
    assert.ok(page.getElementById("ln-out").innerHTML.includes(CLN_NODE_ID));
    hodlLnWipeMem();
    page.getElementById("ln-format").dispatchEvent(new Event("change"));
    assert.equal(page.getElementById("ln-out").innerHTML, "", "the wiped result was re-rendered");
  } finally {
    delete globalThis.document;
  }
});

test("the CLN result carries the not-a-channel-backup note", () => {
  const page = lnPage();
  try {
    page.getElementById("ln-format").value = "cln-hsm";
    page.getElementById("ln-seed").value = CLN_ABANDON;
    lnDerive(page);
    // The note's wording is translatable copy; the data attribute is the
    // stable hook (AGENTS.md: tests never assert English text).
    assert.ok(page.getElementById("ln-out").innerHTML.includes('data-ln-note="single-key"'), "the CLN result is missing its single-key note");
  } finally {
    delete globalThis.document;
  }
});
