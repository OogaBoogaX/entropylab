// Multisig output fuzzer: EntropyLab's multisig wallet pipeline vs an
// independent stack (@scure/bip32 + @scure/btc-signer, pinned in
// fuzzing/package.json), across the option permutation space.
//
// What is exercised, per generated wallet configuration:
//   1. Suffix tolerance (the app's real hodlFilterXpub -> hodlParseKeyOrigin,
//      sliced from src/js/app.js): decorating a co-signer's extended key with
//      a branch wildcard (/0/*, /<0;1>/*, a lone trailing slash, ...) must
//      parse to the identical origin, key, and derivation path, and every
//      site output derived from it — the branch descriptors, the multipath
//      watch-only descriptor, and every address — must be byte-identical to
//      the undecorated run.
//   2. Honored trailing paths: a numeric path after the extended key
//      (xpub…/0/20) is descriptor key derivation and IS honored — the token
//      carries it (as hodlMultisigKeyToken emits it), the branch descriptors
//      and the multipath export sit below it, and the engine output must
//      equal the scure reference derived through the same path.
//   3. Output correctness: each branch descriptor (the app's real
//      hodlMsigInnerDescriptor template) is derived by the rust-miniscript
//      WASM engine and must equal the scure-computed reference address at
//      every sampled branch/index, for script kind x standard x key order x
//      network x threshold x window permutations.
//   4. Descriptor checksums: every descriptor the app emits (its own
//      hodlDescriptorWithChecksum) is fed back through the engine, which
//      verifies the BIP380 checksum before deriving — so a checksum
//      regression fails here against real output.
//
// Deterministic: seeded xorshift64 PRNG; a CI failure reproduces locally with
// the same FUZZ_SEED (and FUZZ_ITERATIONS). The app never sees this
// randomness — the harness only feeds it test inputs, which is policy-safe
// (deterministic transformations, no key material).
//
// Run: npm --prefix fuzzing run fuzz:msig
//      FUZZ_ITERATIONS=5000 FUZZ_SEED=0x1234 node fuzzing/msig/fuzz.mjs
import { readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { HDKey } from "@scure/bip32";
import { NETWORK, TEST_NETWORK, p2sh, p2tr, p2wsh } from "@scure/btc-signer";
import { descriptorDerive } from "../../src/js/addresses.js";

const root = dirname(dirname(dirname(fileURLToPath(import.meta.url))));
const app = readFileSync(join(root, "src/js/app.js"), "utf8");

// --- Slice the app's real functions (same technique as test/descriptor.test.mjs
// and test/msig-address-kinds.test.mjs): the input filter, the origin parser,
// the descriptor checksum, and the multisig descriptor templates run from the
// shipped source, never copies.
const sliceBetween = (startNeedle, endNeedle) => {
  const start = app.indexOf(startNeedle);
  const end = app.indexOf(endNeedle, start);
  if (start < 0 || end < 0) throw new Error(`slice failed: ${startNeedle}`);
  return app.slice(start, end);
};
const sliceFn = (name) => {
  const start = app.indexOf(`function ${name}(`);
  if (start < 0) throw new Error(`slice failed: ${name}`);
  let depth = 0;
  for (let i = app.indexOf("{", start); i < app.length; i++) {
    if (app[i] === "{") depth += 1;
    else if (app[i] === "}" && --depth === 0) return app.slice(start, i + 1);
  }
  throw new Error(`slice failed at ${name}`);
};
const slicePath = join(root, "fuzzing", `.msig-slice-${process.pid}.mjs`);
writeFileSync(
  slicePath,
  "const hodlMaxPurpose = 2147483647;\nconst hodlCoinTypeFromNetwork = (network) => network === 'mainnet' ? 0 : 1;\n" +
    sliceBetween("function hodlFilterXpub", "function hodlParseMultisigCosigner") +
    "\n" +
    sliceBetween("var hodlDescriptorInputCharset", "function hodlScriptDescriptor") +
    "\n" +
    sliceFn("hodlMsigPolicyOp") +
    "\n" +
    sliceFn("hodlMsigInnerDescriptor") +
    "\n" +
    sliceBetween("function hodlStripDescriptorChecksum", "function hodlDescriptorQrSvg") +
    "\nexport { hodlFilterXpub, hodlNormalizeOriginPath, hodlParseKeyOrigin, hodlDescriptorWithChecksum, hodlMsigPolicyOp, hodlMsigInnerDescriptor, hodlWatchOnlyMultipathDescriptor };\n",
);
const app_fns = await import(pathToFileURL(slicePath).href);
unlinkSync(slicePath);
const { hodlFilterXpub, hodlParseKeyOrigin, hodlDescriptorWithChecksum, hodlMsigInnerDescriptor, hodlWatchOnlyMultipathDescriptor } = app_fns;

// --- Deterministic PRNG (xorshift64*), same conventions as the LifeHash fuzzer.
const ITERATIONS = Number.parseInt(process.env.FUZZ_ITERATIONS ?? "1000", 10);
const SEED = BigInt(process.env.FUZZ_SEED ?? "0xC0FFEE254296B10B");
let prngState = SEED & 0xffffffffffffffffn;
if (prngState === 0n) throw new Error("FUZZ_SEED must be non-zero");
const nextByte = () => {
  prngState ^= prngState << 13n; prngState &= 0xffffffffffffffffn;
  prngState ^= prngState >> 7n;
  prngState ^= prngState << 17n; prngState &= 0xffffffffffffffffn;
  return Number((prngState >> 56n) & 0xffn);
};
const nextInt = (n) => nextByte() % n;
const nextPick = (list) => list[nextInt(list.length)];
const nextBytes = (len) => Uint8Array.from({ length: len }, () => nextByte());

let checks = 0;
const fail = (message) => {
  process.stderr.write(`msig fuzz mismatch: ${message}\n  seed=0x${SEED.toString(16)} iterations=${ITERATIONS}\n`);
  process.exit(1);
};
const assertEqual = (actual, expected, what) => {
  checks += 1;
  if (actual !== expected) fail(`${what}: ours ${actual} vs reference ${expected}`);
};

// --- Independent reference leg: scure BIP32 derivation + hand-built scripts
// rendered by @scure/btc-signer. Nothing here goes through src/js/.
const HD_VERSIONS = {
  mainnet: { private: 0x0488ade4, public: 0x0488b21e },
  testnet: { private: 0x04358394, public: 0x043587cf },
};
const NETS = { mainnet: NETWORK, testnet: TEST_NETWORK };
const NUMS = Uint8Array.from(Buffer.from("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0", "hex"));
const bytewise = (a, b) => {
  for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
};
const bareMultisig = (m, keys) => new Uint8Array([0x50 + m, ...keys.flatMap((k) => [0x21, ...k]), 0x50 + keys.length, 0xae]);
const trLeafMultisig = (m, xs) => new Uint8Array([...xs.flatMap((k, i) => [0x20, ...k, i === 0 ? 0xac : 0xba]), 0x50 + m, 0x9c]);
function referenceAddress(m, listedKeys, network, kind, sorted) {
  const net = NETS[network];
  if (kind === "p2tr") {
    const xonly = listedKeys.map((k) => k.slice(1));
    if (sorted) xonly.sort(bytewise);
    return p2tr(NUMS, { script: trLeafMultisig(m, xonly), leafVersion: 0xc0 }, net).address;
  }
  const keys = sorted ? [...listedKeys].sort(bytewise) : listedKeys;
  const ms = bareMultisig(m, keys);
  if (kind === "p2sh") return p2sh({ script: ms }, net).address;
  if (kind === "p2wsh") return p2wsh({ script: ms }, net).address;
  return p2sh(p2wsh({ script: ms }, net), net).address; // p2sh-p2wsh
}

// --- Config generation over the app's option space. The shapes mirror what
// hodlOriginScriptError accepts: BIP45 is the 1-step Legacy one-off, BIP87 is
// the 3-step script-agnostic account, everything else is purpose/coin/account
// with a script-type child.
const masterFp = (node) => node.fingerprint.toString(16).padStart(8, "0");

function makeConfig(fixed = {}) {
  const kind = fixed.kind ?? nextPick(["p2sh", "p2sh-p2wsh", "p2wsh", "p2tr"]);
  const network = fixed.network ?? nextPick(["mainnet", "testnet"]);
  const coin = network === "mainnet" ? 0 : 1;
  const purpose =
    fixed.purpose ??
    (kind === "p2sh"
      ? nextPick([45, 45, 87, 44])
      : kind === "p2tr"
        ? nextPick([86, 87, 87, 69420])
        : kind === "p2sh-p2wsh"
          ? nextPick([48, 48, 87, 49])
          : nextPick([48, 48, 87, 84]));
  const account = nextInt(3);
  const bip45 = kind === "p2sh" && purpose === 45;
  const originPath = bip45
    ? "45h"
    : purpose === 87 || purpose === 44 || purpose === 49 || purpose === 84 || kind === "p2tr"
      ? `${purpose}h/${coin}h/${account}h`
      : `${purpose}h/${coin}h/${account}h/${kind === "p2sh-p2wsh" ? 1 : 2}h`;
  const n = fixed.n ?? 1 + nextInt(4);
  const m = fixed.m ?? 1 + nextInt(n);
  const sorted = fixed.sorted ?? nextByte() % 2 === 0;
  // Mostly the standard receive+change window; sometimes a single or custom branch.
  const branchStart = fixed.branchStart ?? (nextByte() % 5 === 0 ? 2 + nextInt(3) : 0);
  const branchRange = fixed.branchRange ?? (branchStart === 0 ? nextPick([1, 2, 2]) : 1);
  const addressStart = fixed.addressStart ?? nextInt(3);
  const addressCount = fixed.addressCount ?? 3;
  return { kind, network, coin, purpose, account, bip45, originPath, n, m, sorted, branchStart, branchRange, addressStart, addressCount };
}

function makeCosigners(config) {
  // One seed per cosigner from the PRNG stream; the account node sits at the
  // config's origin path, exactly like a signer export.
  const versions = HD_VERSIONS[config.network];
  return Array.from({ length: config.n }, () => {
    const root = HDKey.fromMasterSeed(nextBytes(32), versions);
    const accountPath = `m/${config.originPath.replace(/h/g, "'")}`;
    const account = root.derive(accountPath);
    return { root, account, fingerprint: masterFp(root) };
  });
}

// Random tolerated decoration: a branch wildcard step (/0/* or the multipath
// form /<a;b>/*) with an optional trailing slash, or a lone slash. These are
// the standard receive/change derivation the app rebuilds itself, so they are
// stripped and never honored. Runs through the app's field filter exactly
// like a paste into the textarea does.
function randomDecoration() {
  let roll = nextByte() % 6;
  if (roll === 0) return "";
  if (roll === 1) return "/";
  let out = nextByte() % 2 === 0 ? `/${nextInt(4)}` : `/<${nextInt(3)};${nextInt(3) + 1}>`;
  out += "/*";
  if (nextByte() % 3 === 0) out += "/";
  return out;
}

// Random honored derivation path: 1-3 unhardened numeric steps appended after
// the extended key (xpub…/0/20), sometimes carrying the branch wildcard when
// deep enough that the wildcard is not the sole step (xpub…/0/0/20/* — every
// step preserved, branches derived below). Hardened steps are rejected by the
// app's co-signer parse (covered by the unit suites), so they are not fuzzed
// here.
function randomDerivationPath() {
  if (nextByte() % 4 === 0) return "";
  let out = "";
  for (let i = 0, steps = 1 + nextInt(3); i < steps; i++) out += `/${nextInt(4)}`;
  if (out.split("/").length > 2 && nextByte() % 3 === 0) out += "/*";
  return out;
}

// One full pass over a cosigner set: parse every (possibly suffixed) token,
// build the branch descriptors with the app's template — the token carries a
// parsed derivation path exactly as hodlMultisigKeyToken emits it — derive
// each sampled address through the engine (checksum on, so the app's
// descriptor checksum is verified too), and return everything for comparison.
function runPipeline(config, cosigners, suffixFor = () => "") {
  const tokens = cosigners.map(({ account, fingerprint }, index) => {
    const pasted = `[${fingerprint}/${config.originPath}]${account.publicExtendedKey}${suffixFor(index)}`;
    const parsed = hodlParseKeyOrigin(hodlFilterXpub(pasted));
    if (!parsed.origin) fail(`suffixed parse lost the origin (config ${JSON.stringify(config)})`);
    return { parsed, token: `[${parsed.origin.fingerprint}/${parsed.origin.path}]${parsed.key}${parsed.derivationPath ? "/" + parsed.derivationPath : ""}` };
  });
  const branches = [];
  for (let branch = config.branchStart; branch < config.branchStart + config.branchRange; branch++) {
    const inner = tokens.map((t) => t.token + (config.bip45 ? "/0" : "") + `/${branch}/*`).join(",");
    const descriptor = hodlMsigInnerDescriptor(config.kind, config.m, inner, config.sorted);
    const rows = [];
    for (let index = config.addressStart; index < config.addressStart + config.addressCount; index++) {
      // The app emits hodlDescriptorWithChecksum(descriptor); the engine
      // verifies the checksum, so this leg fails if the app's checksum ever
      // diverges from BIP380.
      rows.push(descriptorDerive(hodlDescriptorWithChecksum(descriptor), index, config.network).address);
    }
    branches.push({ branch, descriptor, checksummed: hodlDescriptorWithChecksum(descriptor), rows });
  }
  const branchesList = branches.map((b) => b.branch);
  const multipath = hodlWatchOnlyMultipathDescriptor(branches[0].checksummed, branchesList);
  return { tokens: tokens.map((t) => t.token), paths: tokens.map((t) => t.parsed.derivationPath || ""), branches, multipath };
}

// Engine rows vs the independent scure leg: every cosigner's child sits below
// its honored derivation path (empty for a bare export), then the BIP45
// cosigner step, branch, and address index.
function checkAddresses(config, cosigners, run, label) {
  for (const { branch, rows } of run.branches) {
    for (let i = 0; i < rows.length; i++) {
      const index = config.addressStart + i;
      const keys = cosigners.map(({ account }, ci) => {
        const steps = [run.paths[ci], config.bip45 ? "0" : "", String(branch), String(index)].filter(Boolean).join("/");
        return account.derive(`m/${steps}`).publicKey;
      });
      assertEqual(rows[i], referenceAddress(config.m, keys, config.network, config.kind, config.sorted), `${label}: ${config.kind} m=${config.m}/${config.n} ${config.network} branch ${branch} index ${index} sorted=${config.sorted}`);
    }
  }
}

// The multipath descriptor really is the branches fused: every cosigner
// carries the <a;b> multipath form (below any honored path), and the engine
// rejects deriving it as a single output (one call = one output).
function checkMultipath(config, run, label) {
  if (config.branchStart === 0 && config.branchRange === 2) {
    const expected = `/<0;1>/*`;
    checks += 1;
    if ((run.multipath.match(/\/<0;1>\/\*/g) || []).length !== config.n) fail(`${label}: multipath descriptor lost its ${expected} branches: ${run.multipath}`);
    let rejected = false;
    try {
      descriptorDerive(run.multipath, 0, config.network);
    } catch {
      rejected = true;
    }
    checks += 1;
    if (!rejected) fail(`${label}: the engine derived a multipath descriptor as a single output`);
  }
}

function checkConfig(config) {
  const cosigners = makeCosigners(config);
  const bare = runPipeline(config, cosigners);
  const decorated = runPipeline(config, cosigners, () => randomDecoration());

  // (1) Suffix tolerance: identical canonical tokens, derivation paths,
  // descriptors, multipath, and every address.
  assertEqual(JSON.stringify(decorated.tokens), JSON.stringify(bare.tokens), `decorated tokens changed (${JSON.stringify(config)})`);
  assertEqual(JSON.stringify(decorated.paths), JSON.stringify(bare.paths), `decorated derivation paths changed (${JSON.stringify(config)})`);
  assertEqual(JSON.stringify(decorated.branches.map((b) => b.checksummed)), JSON.stringify(bare.branches.map((b) => b.checksummed)), "decorated descriptors changed");
  assertEqual(decorated.multipath, bare.multipath, "decorated multipath descriptor changed");
  assertEqual(JSON.stringify(decorated.branches.map((b) => b.rows)), JSON.stringify(bare.branches.map((b) => b.rows)), "decorated addresses changed");

  // (2) Correctness: engine output vs the independent scure leg.
  checkAddresses(config, cosigners, bare, "bare");

  // (3) The multipath descriptor really is the branches fused.
  checkMultipath(config, bare, "bare");

  // (4) Honored trailing paths: the token keeps the parsed path, every
  // address derives below it (engine vs scure at the extended path), and the
  // multipath export lands below it too.
  const honored = runPipeline(config, cosigners, () => randomDerivationPath());
  honored.paths.forEach((path, i) => {
    checks += 1;
    if (path && !honored.tokens[i].endsWith(`/${path}`)) fail(`honored path ${path} missing from token ${honored.tokens[i]}`);
  });
  checkAddresses(config, cosigners, honored, "honored");
  checkMultipath(config, honored, "honored");
}

// --- Non-vacuity guards: fixed published-key configurations whose expected
// addresses were computed once with the independent scure leg and pinned.
// A fuzzer whose comparisons silently no-op must fail here, loudly.
const GUARD_TOKENS = [
  "[73c5da0a/48h/1h/0h/2h]tpubDFH9dgzveyD8zTbPUFuLrGmCydNvxehyNdUXKJAQN8x4aZ4j6UZqGfnqFrD4NqyaTVGKbvEW54tsvPTK2UoSbCC1PJY8iCNiwTL3RWZEheQ",
  "[b8688df1/48h/1h/0h/2h]tpubDEfobrrtptRTbKf4gysDhoabneABDTAcdj3Vbn4XwPsLE2pmqpizSPRG6zHsbAMuiSgWmWPsYCLHTKTPpyrGJ5rAoTpKoQNZcxodiPf2tSJ",
  "[3f635a63/48h/1h/0h/2h]tpubDFPtPArj4GzBEFHohegg1Xatrc1Fi9oSox5LzuSRX91miwQxuUrEpBxpvDRsmZYJKYFhgdK3UStsjC8JKXfUbMinjFqiEM4uNwzVaCaHpys",
];
{
  const inner = GUARD_TOKENS.map((t) => `${t}/0/*`).join(",");
  const descriptor = hodlMsigInnerDescriptor("p2wsh", 2, inner, true);
  assertEqual(descriptorDerive(hodlDescriptorWithChecksum(descriptor), 0, "testnet").address, "tb1qmv9kucx4tjtyfwddc3698p2flxqvts89n8kllr0hvdv7qs4z476s70nuf5", "guard wsh index 0");
  assertEqual(descriptorDerive(hodlDescriptorWithChecksum(descriptor), 1, "testnet").address, "tb1q80kfzwjz9cu95wgvpd9qr8pmkasr8en00ldsy4f9fqryhug4swns0eek2a", "guard wsh index 1");
  const trInner = GUARD_TOKENS.map((t) => `${t}/1/*`).join(",");
  const trDescriptor = hodlMsigInnerDescriptor("p2tr", 2, trInner, true);
  assertEqual(descriptorDerive(hodlDescriptorWithChecksum(trDescriptor), 3, "testnet").address, "tb1pkf7g8prttef3jvmlpmsd8kfemz0rfwwk5mjadw5hgmxy29c0nz6q6kcl2m", "guard tr branch 1 index 3");
  // The reported failure mode: a trailing path used to die as "Invalid
  // Base58Check string". Every suffixed variant must now parse to the bare
  // key, the path split out (honored) or the whole suffix gone (decoration).
  const bareKey = GUARD_TOKENS[0].slice(GUARD_TOKENS[0].indexOf("]") + 1);
  for (const suffix of ["/0/1/0/", "/0/*", "/0/1/*", "/<0;1>/*", "/0h/1/2'/"]) {
    const parsed = hodlParseKeyOrigin(hodlFilterXpub(GUARD_TOKENS[0] + suffix));
    assertEqual(parsed.key, bareKey, `guard suffix ${suffix}`);
  }
  assertEqual(hodlParseKeyOrigin(hodlFilterXpub(GUARD_TOKENS[0] + "/0/1/0")).derivationPath, "0/1/0", "guard honored path");
  assertEqual(hodlParseKeyOrigin(hodlFilterXpub(GUARD_TOKENS[0] + "/<0;1>/*")).derivationPath, "", "guard decoration is not honored");
  // A deep tail keeps every step ahead of the wildcard — the wildcard form
  // and the bare path honor identically.
  assertEqual(hodlParseKeyOrigin(hodlFilterXpub(GUARD_TOKENS[0] + "/0/0/20/*")).derivationPath, "0/0/20", "guard deep wildcard path preserved");
  // Honored trailing path: a numeric path is kept in the token, branches and
  // indexes derive below it, and the multipath export lands below it —
  // xpub/0/0/20 exports as xpub/0/0/20/<0;1>/*. Expected addresses were
  // computed once with the independent scure leg.
  const pathedTokens = GUARD_TOKENS.map((t) => {
    const parsed = hodlParseKeyOrigin(hodlFilterXpub(`${t}/0/0/20`));
    assertEqual(parsed.derivationPath, "0/0/20", "guard honored path parse");
    return `[${parsed.origin.fingerprint}/${parsed.origin.path}]${parsed.key}/${parsed.derivationPath}`;
  });
  const pathedInner = (branch) => pathedTokens.map((t) => `${t}/${branch}/*`).join(",");
  const pathedReceive = hodlMsigInnerDescriptor("p2wsh", 2, pathedInner(0), true);
  assertEqual(descriptorDerive(hodlDescriptorWithChecksum(pathedReceive), 0, "testnet").address, "tb1q9eflm9vaktmn9pcpy03d8seyfeg3zm08gatdej2dsa42tfmx38aq3pfgx2", "guard honored-path wsh index 0");
  assertEqual(descriptorDerive(hodlDescriptorWithChecksum(pathedReceive), 1, "testnet").address, "tb1qeupxdgtpsyztzl9zgqw9zchst8zcqyn8ls2qd9ca9d90v9m838esv6fqts", "guard honored-path wsh index 1");
  const pathedChange = hodlMsigInnerDescriptor("p2wsh", 2, pathedInner(1), true);
  assertEqual(descriptorDerive(hodlDescriptorWithChecksum(pathedChange), 3, "testnet").address, "tb1qnet9hhcwgk9mq8l4fj4h9arrppkq6kvj34cymrwtnnx0tml9zwsq6kkn5u", "guard honored-path wsh branch 1 index 3");
  const pathedMultipath = hodlWatchOnlyMultipathDescriptor(hodlDescriptorWithChecksum(pathedReceive), [0, 1]);
  checks += 1;
  if ((pathedMultipath.match(/\/0\/0\/20\/<0;1>\/\*/g) || []).length !== 3) fail(`honored-path multipath did not land below 0/0/20: ${pathedMultipath}`);
}

// A few forced extremes beyond the PRNG distribution: 1-of-1, 15-of-15, a
// custom branch window, a custom purpose, a deep starting index.
checkConfig(makeConfig({ kind: "p2wsh", n: 1, m: 1, sorted: true }));
checkConfig(makeConfig({ kind: "p2tr", n: 15, m: 15, sorted: true, addressCount: 2 }));
checkConfig(makeConfig({ kind: "p2sh", purpose: 45, n: 3, m: 2, branchStart: 0, branchRange: 2 }));
checkConfig(makeConfig({ kind: "p2sh-p2wsh", n: 4, m: 3, sorted: false }));
checkConfig(makeConfig({ kind: "p2tr", purpose: 69420, n: 2, m: 2, sorted: false }));
checkConfig(makeConfig({ kind: "p2wsh", n: 3, m: 2, branchStart: 3, branchRange: 1, addressStart: 7, addressCount: 2 }));

for (let i = 0; i < ITERATIONS; i++) checkConfig(makeConfig());

process.stdout.write(
  `msig fuzz OK: ${checks} checks ` +
    `(${ITERATIONS} PRNG configs + fixed guards/extremes, seed=0x${SEED.toString(16)}), 0 mismatches\n`,
);
