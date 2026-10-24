// MS Station wallets checked input against output, across every descriptor
// type the station generates.
//
// Contract: from co-signer inputs (origin fingerprint and path, extended
// public key in any accepted encoding, optional public steps after it), the
// station's wallet is exactly the one those inputs define and nothing else:
//
//   - every descriptor key expression is the input's own origin, the input
//     key re-encoded as a plain xpub/tpub (never private material, never a
//     different key), the input's public steps, then the branch step —
//     BIP45 inserting its co-signer branch 0 first;
//   - the descriptor is the BIP383/386/387 form for its script type and key
//     order: sh(), sh(wsh()), wsh() around multi/sortedmulti, and
//     tr(NUMS, multi_a/sortedmulti_a) with the BIP341 unspendable internal key,
//     carrying a valid BIP380 checksum; the multipath wallet descriptor
//     expands back to each branch descriptor;
//   - the wallet descriptor re-imports through the station's own descriptor
//     import and rebuilds byte-identical branch descriptors;
//   - every address is the script built from the co-signers' public keys at
//     that branch and index, sorted per BIP67 for sortedmulti (by x-only key
//     for sortedmulti_a) and in input order for multi;
//   - BIP45's co-signer branch applies exactly when every co-signer follows
//     BIP45, as the station's own wallet-standard rule decides;
//   - unsafe inputs are refused or neutralized: a repeated public key throws
//     (for Taproot, a repeated x-only key, since multi_a compares those),
//     an extended private key is flagged and only its public half reaches
//     the descriptor, a hardened step after a public key is rejected, and an
//     origin that does not match its key is reported.
//
// The expected side is independent of the app: keys come from @scure/bip32
// (public derivation from the co-signer xpubs), scripts and addresses from
// @scure/btc-signer's own templates, the checksum from the test harness's
// BIP380 implementation. Where bitcoind is installed, Bitcoin Core's
// getdescriptorinfo and deriveaddresses check the station's descriptors too.
// The app side is its real code (app-slice-harness): parsing, key tokens,
// branch descriptors and addresses through rust-miniscript.
//
// Fixed cases pin each descriptor type; a seeded fuzz sweeps script types,
// key orders, networks, m-of-n, specs, custom paths and branch/index windows.
// Fixed seed, never reseeded; MSIG_WALLET_FUZZ_ITERATIONS widens a local run.
// Run with: npm test
import { test } from "node:test";
import assert from "node:assert/strict";
import { HDKey } from "@scure/bip32";
import { sha256 } from "@noble/hashes/sha2.js";
import { NETWORK, TEST_NETWORK, TAPROOT_UNSPENDABLE_KEY, p2ms, p2sh, p2tr, p2tr_ms, p2wsh } from "@scure/btc-signer";
import { b58checkDecode, b58checkEncode, descriptorChecksum } from "./wallet-export-harness.mjs";
import { BITCOIND, withChainNode } from "./bitcoind-harness.mjs";
import { loadAppFunctions } from "./app-slice-harness.mjs";

const app = await loadAppFunctions([
  "hodlParseMultisigCosigner",
  "hodlMultisigKeyToken",
  "hodlCanonicalMultisigKey",
  "hodlMultisigPrefixCompatible",
  "hodlOriginMatchesParsedKey",
  "hodlMsigSpecFromOrigin",
  "hodlMsigSpec",
  "hodlMsigCustomPathReason",
  "hodlMsigBranchDescriptor",
  "hodlMsigAddressRow",
  "hodlDescriptorWithChecksum",
  "hodlWatchOnlyMultipathDescriptor",
  "hodlMsigWalletStandard",
  "hodlMsigInnerDescriptor",
  "hodlParseMsigDescriptor",
]);

// --- co-signer fixtures (public test material, nothing secret) -------------

const HARDENED = 0x80000000;
const cosignerRoot = (seedIndex) => HDKey.fromMasterSeed(sha256(new TextEncoder().encode(`entropylab msig wallet output cosigner ${seedIndex}`)));
const hexFingerprint = (node) => node.fingerprint.toString(16).padStart(8, "0");
// BIP32 serialization versions: generic, then the SLIP-132 multisig families.
const VERSIONS = {
  mainnet: { x: 0x0488b21e, xprv: 0x0488ade4, Y: 0x0295b43f, Z: 0x02aa7ed3 },
  testnet: { x: 0x043587cf, xprv: 0x04358394, Y: 0x024289ef, Z: 0x02575483 },
};
const reversion = (extendedKey, version) => {
  const raw = b58checkDecode(extendedKey).slice();
  raw.set([(version >>> 24) & 255, (version >>> 16) & 255, (version >>> 8) & 255, version & 255], 0);
  return b58checkEncode(raw);
};
const originText = (path) => path.slice(2).replace(/'/g, "h");

// One co-signer input: the seed's key at `path`, encoded in `family`, with
// optional unhardened public steps after it.
function cosigner(seedIndex, path, network, { family = "x", extra = [] } = {}) {
  const root = cosignerRoot(seedIndex), node = root.derive(path);
  const generic = reversion(node.publicExtendedKey, VERSIONS[network].x);
  const encoded = family === "x" ? generic : reversion(generic, VERSIONS[network][family]);
  return {
    seedIndex,
    path,
    extra,
    fingerprint: hexFingerprint(root),
    generic,
    // Expected keys derive from the public key alone, as a watch-only wallet would.
    publicNode: HDKey.fromExtendedKey(generic, { public: VERSIONS[network].x, private: VERSIONS[network].xprv }),
    input: `[${hexFingerprint(root)}/${originText(path)}]${encoded}${extra.length ? "/" + extra.join("/") : ""}`,
  };
}

// --- the independent expectation -------------------------------------------

const bytewise = (a, b) => {
  for (let index = 0; index < Math.min(a.length, b.length); index++) if (a[index] !== b[index]) return a[index] - b[index];
  return a.length - b.length;
};
const OPS = { sorted: { tr: "sortedmulti_a", other: "sortedmulti" }, listed: { tr: "multi_a", other: "multi" } };

function expectedKeyExpression(entry, branch, bip45) {
  return `[${entry.fingerprint}/${originText(entry.path)}]${entry.generic}${entry.extra.map((step) => `/${step}`).join("")}${bip45 ? "/0" : ""}/${branch}/*`;
}
function expectedDescriptorBody(wallet, branch) {
  const op = OPS[wallet.sorted ? "sorted" : "listed"][wallet.kind === "p2tr" ? "tr" : "other"];
  const core = `${op}(${wallet.m},${wallet.cosigners.map((entry) => expectedKeyExpression(entry, branch, wallet.bip45)).join(",")})`;
  if (wallet.kind === "p2tr") return `tr(${Buffer.from(TAPROOT_UNSPENDABLE_KEY).toString("hex")},${core})`;
  if (wallet.kind === "p2wsh") return `wsh(${core})`;
  if (wallet.kind === "p2sh-p2wsh") return `sh(wsh(${core}))`;
  return `sh(${core})`;
}
function expectedAddress(wallet, branch, index) {
  const net = wallet.network === "mainnet" ? NETWORK : TEST_NETWORK;
  const keys = wallet.cosigners.map((entry) => {
    let node = entry.publicNode;
    for (const step of [...entry.extra, ...(wallet.bip45 ? [0] : []), branch, index]) node = node.deriveChild(step);
    return node.publicKey;
  });
  if (wallet.kind === "p2tr") {
    const xonly = keys.map((key) => key.slice(1));
    if (wallet.sorted) xonly.sort(bytewise);
    return p2tr(TAPROOT_UNSPENDABLE_KEY, p2tr_ms(wallet.m, xonly), net, true).address;
  }
  const ordered = wallet.sorted ? [...keys].sort(bytewise) : keys;
  const ms = p2ms(wallet.m, ordered);
  if (wallet.kind === "p2wsh") return p2wsh(ms, net).address;
  if (wallet.kind === "p2sh-p2wsh") return p2sh(p2wsh(ms, net), net).address;
  return p2sh(ms, net).address;
}

// --- the app's wallet, from the inputs -------------------------------------
//
// The same calls hodlBuildMsig makes once its inputs validate: each co-signer
// parsed and held to its card's spec, key tokens, one descriptor per branch,
// its address rows, and the multipath wallet descriptor.
const STANDARD_HARDENING = { purpose: true, coinType: true, account: true, script: true, branch: false, address: false };
function appWallet(wallet) {
  const coinType = wallet.network === "mainnet" ? 0 : 1;
  const specs = [];
  const tokens = wallet.cosigners.map((entry, position) => {
    const parsed = app.hodlParseMultisigCosigner(entry.input), where = `co-signer ${position + 1} (${entry.input.slice(0, 40)}…)`;
    assert.equal(parsed.isPrivate, false, `${where} parsed as private`);
    assert.equal(parsed.network, wallet.network, `${where} parsed for the wrong network`);
    const spec = wallet.spec === "detect" ? app.hodlMsigSpecFromOrigin(parsed.origin, wallet.kind) : wallet.spec, specPurpose = app.hodlMsigSpec(spec)?.purpose ?? null;
    assert.ok(app.hodlMultisigPrefixCompatible(parsed, wallet.kind, specPurpose), `${where}: ${parsed.prefix} refused for ${wallet.kind}`);
    assert.equal(app.hodlOriginMatchesParsedKey(parsed.origin, parsed), "", `${where}: origin does not match its key`);
    assert.ok(spec, `${where}: no spec serves its origin on ${wallet.kind}`);
    specs.push(spec);
    if (spec !== "custom") assert.equal(app.hodlMsigCustomPathReason(parsed, wallet.kind, wallet.network, specPurpose, coinType, STANDARD_HARDENING), "", `${where} departs from ${spec}`);
    return { parsed, token: app.hodlMultisigKeyToken(parsed, wallet.network) };
  });
  const canonical = tokens.map(({ parsed }) => app.hodlCanonicalMultisigKey(parsed));
  assert.equal(new Set(canonical).size, canonical.length, "two co-signers share an identity");
  // The station decides BIP45's co-signer branch from the co-signers' specs,
  // exactly as hodlBuildMsig does; the case states what BIP45 requires.
  const bip45 = wallet.kind === "p2sh" && app.hodlMsigWalletStandard(specs) === "bip45";
  assert.equal(bip45, wallet.bip45, `the station ${bip45 ? "applied" : "skipped"} BIP45's co-signer branch`);
  const branches = wallet.branches.map((branch) => {
    const descriptor = app.hodlMsigBranchDescriptor(tokens.map(({ token }) => token), wallet.kind, wallet.m, wallet.sorted, branch, bip45);
    const rows = wallet.indexes.map((index) => app.hodlMsigAddressRow(descriptor, wallet.kind, wallet.network, branch, index, bip45));
    return { branch, publicDescriptor: app.hodlDescriptorWithChecksum(descriptor), rows };
  });
  return { branches, walletDescriptor: app.hodlWatchOnlyMultipathDescriptor(branches[0].publicDescriptor, wallet.branches) };
}

function checkWallet(wallet, label) {
  const output = appWallet(wallet);
  for (const { branch, publicDescriptor, rows } of output.branches) {
    const where = `${label}, branch ${branch}`, body = expectedDescriptorBody(wallet, branch);
    assert.equal(publicDescriptor, `${body}#${descriptorChecksum(body)}`, `${where}: descriptor`);
    assert.doesNotMatch(publicDescriptor, /[xtyzuvYZUV]prv/, `${where}: private key material in the descriptor`);
    rows.forEach((row, position) => {
      const index = wallet.indexes[position];
      assert.equal(row.index, index, `${where}: row order`);
      assert.equal(row.branch, branch, `${where}: row branch`);
      assert.equal(row.path, `${wallet.bip45 ? "/0" : ""}/${branch}/${index}`, `${where}: row path`);
      assert.equal(row.address, expectedAddress(wallet, branch, index), `${where}, index ${index}: address`);
    });
  }
  // The multipath wallet descriptor is the branch descriptors folded together.
  const multipath = output.walletDescriptor, body = multipath.slice(0, multipath.lastIndexOf("#"));
  assert.equal(multipath, `${body}#${descriptorChecksum(body)}`, `${label}: wallet descriptor checksum`);
  const folded = wallet.branches.length > 1 ? `<${wallet.branches.join(";")}>` : String(wallet.branches[0]);
  assert.equal(body, expectedDescriptorBody(wallet, "\u0000").split("/\u0000/*").join(`/${folded}/*`), `${label}: wallet descriptor`);
  return output;
}

// --- fixed cases: every descriptor type the station generates --------------

const RECEIVE_CHANGE = [0, 1];
const wallet = (fields) => ({ sorted: true, bip45: false, spec: "detect", branches: RECEIVE_CHANGE, indexes: [0, 1, 7], ...fields });
const bip48 = (script) => (i, network, options) => cosigner(i, `m/48'/${network === "mainnet" ? 0 : 1}'/0'/${script}'`, network, options);
const account = (purpose) => (i, network, options) => cosigner(i, `m/${purpose}'/${network === "mainnet" ? 0 : 1}'/0'`, network, options);

function fixedCases() {
  const cases = [];
  for (const network of ["mainnet", "testnet"]) {
    for (const sorted of [true, false]) {
      const order = sorted ? "sorted" : "listed";
      cases.push([`wsh ${order} BIP48 2-of-3 xpub (${network})`, wallet({ network, sorted, kind: "p2wsh", m: 2, cosigners: [0, 1, 2].map((i) => bip48(2)(i, network)) })]);
      cases.push([`wsh ${order} BIP48 2-of-3 SLIP-132 Zpub/Vpub (${network})`, wallet({ network, sorted, kind: "p2wsh", m: 2, cosigners: [3, 4, 5].map((i) => bip48(2)(i, network, { family: "Z" })) })]);
      cases.push([`sh-wsh ${order} BIP48 2-of-2 SLIP-132 Ypub/Upub (${network})`, wallet({ network, sorted, kind: "p2sh-p2wsh", m: 2, cosigners: [0, 1].map((i) => bip48(1)(i, network, { family: "Y" })) })]);
      cases.push([`sh ${order} BIP45 2-of-3 (${network})`, wallet({ network, sorted, kind: "p2sh", m: 2, bip45: true, cosigners: [0, 1, 2].map((i) => cosigner(i, "m/45'", network)) })]);
      cases.push([`sh ${order} BIP87 1-of-2 (${network})`, wallet({ network, sorted, kind: "p2sh", m: 1, cosigners: [6, 7].map((i) => account(87)(i, network)) })]);
      cases.push([`sh ${order} BIP44 account keys 2-of-2 (${network})`, wallet({ network, sorted, kind: "p2sh", m: 2, cosigners: [8, 9].map((i) => account(44)(i, network)) })]);
      cases.push([`sh-wsh ${order} BIP49 account keys 1-of-2 (${network})`, wallet({ network, sorted, kind: "p2sh-p2wsh", m: 1, cosigners: [8, 9].map((i) => account(49)(i, network)) })]);
      cases.push([`wsh ${order} BIP84 account keys 2-of-2 (${network})`, wallet({ network, sorted, kind: "p2wsh", m: 2, cosigners: [8, 9].map((i) => account(84)(i, network)) })]);
      cases.push([`wsh ${order} BIP87 3-of-3 (${network})`, wallet({ network, sorted, kind: "p2wsh", m: 3, cosigners: [0, 1, 2].map((i) => account(87)(i, network)) })]);
      cases.push([`tr ${order} BIP87 2-of-3 (${network})`, wallet({ network, sorted, kind: "p2tr", m: 2, cosigners: [0, 1, 2].map((i) => account(87)(i, network)) })]);
      cases.push([`tr ${order} BIP86 account keys 3-of-5 (${network})`, wallet({ network, sorted, kind: "p2tr", m: 3, cosigners: [10, 11, 12, 13, 14].map((i) => account(86)(i, network)) })]);
      // Custom specs: a lone hardened step, an unhardened step before hardened
      // ones, a key deeper than its spec path, a public step after a key, and
      // one seed used twice under different paths.
      cases.push([`wsh ${order} Custom paths 2-of-4 (${network})`, wallet({ network, sorted, kind: "p2wsh", m: 2, spec: "custom", cosigners: [
        cosigner(0, "m/0'", network),
        cosigner(1, "m/48'/0/0'/0'", network),
        cosigner(2, `m/48'/${network === "mainnet" ? 0 : 1}'/0'/2'/1`, network),
        cosigner(0, "m/0'", network, { extra: [7] }),
      ] })]);
      cases.push([`tr ${order} Custom paths 2-of-2 (${network})`, wallet({ network, sorted, kind: "p2tr", m: 2, spec: "custom", cosigners: [cosigner(3, "m/1'/2/3'", network), cosigner(3, "m/1'/2/3'", network, { extra: [0, 5] })] })]);
    }
    // Quorum and window edges.
    cases.push([`wsh 1-of-1 BIP48 (${network})`, wallet({ network, kind: "p2wsh", m: 1, cosigners: [bip48(2)(0, network)] })]);
    cases.push([`sh 15-of-15 BIP87 (${network})`, wallet({ network, kind: "p2sh", m: 15, indexes: [0], cosigners: Array.from({ length: 15 }, (_, i) => account(87)(20 + i, network)) })]);
    cases.push([`tr 15-of-15 BIP87 (${network})`, wallet({ network, kind: "p2tr", m: 15, indexes: [0], cosigners: Array.from({ length: 15 }, (_, i) => account(87)(20 + i, network)) })]);
    cases.push([`wsh custom branch 5 near the last index (${network})`, wallet({ network, kind: "p2wsh", m: 2, branches: [5], indexes: [HARDENED - 3, HARDENED - 1], cosigners: [0, 1].map((i) => bip48(2)(i, network)) })]);
  }
  return cases;
}
const FIXED = fixedCases();

test("every descriptor type's wallet is exactly the one its co-signer inputs define", () => {
  for (const [label, entry] of FIXED) checkWallet(entry, label);
});

test("sortedmulti wallets ignore input order; multi wallets are defined by it", () => {
  for (const [label, entry] of FIXED.filter(([, entry]) => entry.cosigners.length > 1)) {
    const reversed = { ...entry, cosigners: [...entry.cosigners].reverse() };
    const address = (subject) => appWallet(subject).branches[0].rows[0].address;
    if (entry.sorted) assert.equal(address(reversed), address(entry), `${label}: sorted address changed with input order`);
    else assert.notEqual(address(reversed), address(entry), `${label}: listed address ignored input order`);
  }
});

test("every generated wallet re-imports through the station's own descriptor import, unchanged", () => {
  for (const [label, entry] of FIXED) {
    const output = appWallet(entry), imported = app.hodlParseMsigDescriptor(output.walletDescriptor);
    assert.deepEqual([imported.kind, imported.m, imported.n, imported.sorted], [entry.kind, entry.m, entry.cosigners.length, entry.sorted], `${label}: policy`);
    const window = Array.from({ length: imported.branchRange }, (_, step) => imported.branchStart + step);
    assert.deepEqual(window, [...entry.branches].sort((a, b) => a - b), `${label}: branch window`);
    const parsed = imported.keys.map((key) => app.hodlParseMultisigCosigner(key));
    const specs = parsed.map((key) => app.hodlMsigSpecFromOrigin(key.origin, imported.kind) || "custom");
    const bip45 = imported.kind === "p2sh" && app.hodlMsigWalletStandard(specs) === "bip45";
    const tokens = parsed.map((key) => app.hodlMultisigKeyToken(key, entry.network));
    for (const { branch, publicDescriptor } of output.branches) {
      assert.equal(app.hodlDescriptorWithChecksum(app.hodlMsigBranchDescriptor(tokens, imported.kind, imported.m, imported.sorted, branch, bip45)), publicDescriptor, `${label}, branch ${branch}: the re-imported wallet differs`);
    }
  }
});

// --- unsafe inputs ----------------------------------------------------------

test("a repeated public key is refused, however the key is encoded", () => {
  const network = "mainnet", same = bip48(2)(0, network), reencoded = bip48(2)(0, network, { family: "Z" });
  // One identity across encodings, so the station's duplicate check sees it.
  assert.equal(app.hodlCanonicalMultisigKey(app.hodlParseMultisigCosigner(same.input)), app.hodlCanonicalMultisigKey(app.hodlParseMultisigCosigner(reencoded.input)));
  // And the last defense: a script whose public keys repeat is never emitted.
  const tokens = [same, reencoded].map((entry) => app.hodlMultisigKeyToken(app.hodlParseMultisigCosigner(entry.input), network));
  for (const kind of ["p2wsh", "p2sh-p2wsh", "p2sh", "p2tr"]) {
    for (const sorted of [true, false]) {
      const descriptor = app.hodlMsigBranchDescriptor(tokens, kind, 1, sorted, 0, false);
      assert.throws(() => app.hodlMsigAddressRow(descriptor, kind, network, 0, 0, false), undefined, `${kind} ${sorted ? "sorted" : "listed"}`);
    }
  }
  // The same seed under a different path, or with a public step after it, is
  // a distinct co-signer.
  const reused = cosigner(0, "m/48'/0'/0'/2'", network, { extra: [1] });
  assert.notEqual(app.hodlCanonicalMultisigKey(app.hodlParseMultisigCosigner(reused.input)), app.hodlCanonicalMultisigKey(app.hodlParseMultisigCosigner(same.input)));
});

test("Taproot refuses two keys that share an x-only key, in either key order", () => {
  // multi_a checks x-only keys, so 02‖x and 03‖x are one signer: a signature
  // from that key would fill two slots and lower the threshold.
  const x = Buffer.from(cosignerRoot(0).derive("m/87'/0'/0'/0/0").publicKey.slice(1)).toString("hex");
  const other = Buffer.from(cosignerRoot(1).derive("m/87'/0'/0'/0/0").publicKey).toString("hex");
  for (const sorted of [true, false]) {
    const descriptor = app.hodlMsigInnerDescriptor("p2tr", 2, [`02${x}`, `03${x}`, other].join(","), sorted);
    assert.throws(() => app.hodlMsigAddressRow(descriptor, "p2tr", "mainnet", 0, 0, false), undefined, sorted ? "sortedmulti_a" : "multi_a");
  }
  // The station's own guard names the problem when the engine lets it through.
  assert.throws(() => app.hodlMsigAddressRow(app.hodlMsigInnerDescriptor("p2tr", 2, [`02${x}`, `03${x}`, other].join(","), false), "p2tr", "mainnet", 0, 0, false), /same public key/);
});

test("an extended private key is flagged and only its public half reaches the descriptor", () => {
  for (const network of ["mainnet", "testnet"]) {
    const root = cosignerRoot(0), node = root.derive("m/48'/0'/0'/2'");
    const xprv = reversion(node.privateExtendedKey, VERSIONS[network].xprv);
    const parsed = app.hodlParseMultisigCosigner(`[${hexFingerprint(root)}/48h/0h/0h/2h]${xprv}`);
    assert.equal(parsed.isPrivate, true, `${network}: an extended private key was not flagged`);
    const token = app.hodlMultisigKeyToken(parsed, network);
    assert.doesNotMatch(token, /[xtyzuv]prv/, `${network}: private key material reached the key token`);
    assert.ok(token.includes(reversion(node.publicExtendedKey, VERSIONS[network].x)), `${network}: the key token is not the key's public half`);
  }
});

test("a hardened step after a public key, or an origin that does not match its key, is refused", () => {
  const entry = bip48(2)(0, "mainnet");
  assert.throws(() => app.hodlParseMultisigCosigner(`${entry.input}/1h`));
  const parsed = app.hodlParseMultisigCosigner(entry.input);
  assert.notEqual(app.hodlOriginMatchesParsedKey({ ...parsed.origin, path: "48h/0h/0h" }, parsed), "", "a shorter origin was accepted");
  assert.notEqual(app.hodlOriginMatchesParsedKey({ ...parsed.origin, path: "48h/0h/0h/1h" }, parsed), "", "an origin ending at another child was accepted");
});

// --- seeded fuzz --------------------------------------------------------------

const FUZZ_SEED = 0x5eed0049;
const FUZZ_ITERATIONS = process.env.MSIG_WALLET_FUZZ_ITERATIONS === undefined ? 40 : Number(process.env.MSIG_WALLET_FUZZ_ITERATIONS);
const fuzzRandom = (() => {
  let a = FUZZ_SEED >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
})();
const int = (limit) => Math.floor(fuzzRandom() * limit);
const pick = (items) => items[int(items.length)];

function fuzzWallet(iteration) {
  const network = pick(["mainnet", "testnet"]), kind = pick(["p2wsh", "p2sh-p2wsh", "p2sh", "p2tr"]), coin = network === "mainnet" ? 0 : 1;
  const n = 1 + int(kind === "p2tr" ? 8 : 6), m = 1 + int(n);
  // A spec the script type serves, or Custom with a random mixed-hardening path.
  const specs = {
    "p2wsh": [["bip48", (a) => `m/48'/${coin}'/${a}'/2'`, "Z"], ["bip87", (a) => `m/87'/${coin}'/${a}'`, "x"], ["bip84", (a) => `m/84'/${coin}'/${a}'`, "x"]],
    "p2sh-p2wsh": [["bip48", (a) => `m/48'/${coin}'/${a}'/1'`, "Y"], ["bip87", (a) => `m/87'/${coin}'/${a}'`, "x"], ["bip49", (a) => `m/49'/${coin}'/${a}'`, "x"]],
    "p2sh": [["bip45", () => "m/45'", "x"], ["bip87", (a) => `m/87'/${coin}'/${a}'`, "x"], ["bip44", (a) => `m/44'/${coin}'/${a}'`, "x"]],
    "p2tr": [["bip87", (a) => `m/87'/${coin}'/${a}'`, "x"], ["bip86", (a) => `m/86'/${coin}'/${a}'`, "x"]],
  }[kind];
  const custom = int(4) === 0, [spec, template, family] = pick(specs), account = int(3);
  const cosigners = Array.from({ length: n }, (_, position) => {
    const seedIndex = 100 + iteration * 16 + position, extra = int(4) === 0 ? Array.from({ length: 1 + int(2) }, () => int(50)) : [];
    if (!custom) return cosigner(seedIndex, template(account), network, { family: int(2) ? family : "x", extra });
    const path = "m/" + Array.from({ length: 1 + int(5) }, () => `${int(100)}${int(2) ? "'" : ""}`).join("/");
    return cosigner(seedIndex, path, network, { extra });
  });
  const start = int(4) === 0 ? HARDENED - 1 - int(4) : int(1000);
  const branches = pick([[0, 1], [0], [1], [2 + int(5)]]);
  return wallet({
    network, kind, m, sorted: int(2) === 1, spec: custom ? "custom" : spec, bip45: !custom && spec === "bip45", branches,
    indexes: Array.from({ length: 1 + int(2) }, (_, step) => Math.min(HARDENED - 1, start + step)),
    cosigners,
  });
}
const FUZZ = Array.from({ length: FUZZ_ITERATIONS }, (_, iteration) => [`fuzz iteration ${iteration}`, fuzzWallet(iteration)]);

test(`fuzz: generated wallets match their inputs across types, orders, specs and windows (seed 0x${FUZZ_SEED.toString(16)}, ${FUZZ_ITERATIONS} iterations)`, () => {
  assert.ok(Number.isSafeInteger(FUZZ_ITERATIONS) && FUZZ_ITERATIONS > 0, `MSIG_WALLET_FUZZ_ITERATIONS must be a positive integer, got ${process.env.MSIG_WALLET_FUZZ_ITERATIONS}`);
  const kinds = new Set();
  for (const [label, entry] of FUZZ) {
    checkWallet(entry, `${label} (${entry.kind} ${entry.m}-of-${entry.cosigners.length} ${entry.spec} ${entry.network})`);
    kinds.add(entry.kind);
  }
  if (FUZZ_ITERATIONS >= 20) assert.equal(kinds.size, 4, `corpus too narrow: ${[...kinds].join(", ")}`);
});

// --- Bitcoin Core (skipped where bitcoind is not installed) ------------------

for (const network of ["mainnet", "testnet"]) {
  test(`Bitcoin Core derives the same addresses from the station's ${network} descriptors`, { skip: !BITCOIND, timeout: 300000 }, async () => {
    const subjects = [...FIXED, ...FUZZ].filter(([, entry]) => entry.network === network);
    await withChainNode(network, (cli) => {
      const rpc = (...args) => JSON.parse(cli(args).stdout);
      for (const [label, entry] of subjects) {
        const output = appWallet(entry);
        for (const { branch, publicDescriptor, rows } of output.branches) {
          const where = `${label}, branch ${branch}`, info = rpc("getdescriptorinfo", publicDescriptor);
          assert.equal(`${publicDescriptor.slice(0, publicDescriptor.lastIndexOf("#"))}#${info.checksum}`, publicDescriptor, `${where}: Core computes another checksum`);
          assert.equal(info.hasprivatekeys, false, `${where}: Core sees private keys`);
          assert.equal(info.isrange, true, `${where}: Core does not see a ranged descriptor`);
          for (const row of rows) {
            assert.deepEqual(rpc("deriveaddresses", publicDescriptor, JSON.stringify([row.index, row.index])), [row.address], `${where}, index ${row.index}: Core derives another address`);
          }
        }
        const info = rpc("getdescriptorinfo", output.walletDescriptor);
        assert.equal(info.hasprivatekeys, false, `${label}: Core sees private keys in the wallet descriptor`);
        assert.equal(`${output.walletDescriptor.slice(0, output.walletDescriptor.lastIndexOf("#"))}#${info.checksum}`, output.walletDescriptor, `${label}: Core computes another wallet descriptor checksum`);
      }
    });
  });
}
