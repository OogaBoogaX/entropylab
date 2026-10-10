// LifeHash differential fuzzer: EntropyLab's src/js/lifehash.js vs Blockchain
// Commons' C++ reference (bc-lifehash), compiled from a pinned commit.
//
// The C++ code is the LifeHash specification in practice, so this fuzzer has
// no substitutions: every input goes through both full pipelines and the
// rendered pixels must be byte-identical, float32 rounding artifacts included.
//   ours:    fromFingerprint(fp, moduleSize) -> PNG data URL -> decoded RGB
//   theirs:  make_from_data(hex_to_data(fp), version2, moduleSize, false).colors
// The reference runs as one long-lived child process (reference.cpp) speaking
// a line protocol, so per-input cost is a pipe round trip.
//
// Source: the pinned commit is fetched into fuzzing/.cache/ (git-ignored) on
// first run, or taken from BC_LIFEHASH_SRC. Either way the checkout must be at
// exactly REFERENCE_COMMIT with no local modifications. The reference is built
// with -ffp-contract=off so a compiler cannot fuse multiply-adds and round
// differently from the reference's separate operations; two upstream sources
// rely on transitive includes, supplied with -include rather than edits.
// CXX selects the compiler (default c++).
//
// Deterministic like fuzz.mjs: a failure reproduces locally with the logged
// FUZZ_SEED and FUZZ_ITERATIONS.
//
// Run: npm --prefix fuzzing run fuzz:lifehash-cpp
//      FUZZ_ITERATIONS=5000 FUZZ_SEED=0x1234 node fuzzing/lifehash/fuzz-cpp.mjs
import { execFileSync, spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import {
  ITERATIONS, MODULE_SIZES, SEED, decodePngRgb, firstDifference, nextFingerprint, ours, sha256Hex,
} from "./common.mjs";

const REFERENCE_REPO = "https://github.com/BlockchainCommons/bc-lifehash.git";
const REFERENCE_COMMIT = "0444dbed5615fbc9a98163608c6499c025b7873b";

const here = fileURLToPath(new URL(".", import.meta.url));
const git = (dir, ...args) => execFileSync("git", ["-C", dir, ...args], { encoding: "utf8" }).trim();

// --- Reference source at the pinned commit.
const referenceSource = () => {
  const dir = process.env.BC_LIFEHASH_SRC ?? join(here, "../.cache/bc-lifehash");
  if (!process.env.BC_LIFEHASH_SRC && !existsSync(join(dir, ".git"))) {
    mkdirSync(dir, { recursive: true });
    git(dir, "init", "--quiet");
    git(dir, "fetch", "--quiet", "--depth", "1", REFERENCE_REPO, REFERENCE_COMMIT);
    git(dir, "checkout", "--quiet", "--detach", "FETCH_HEAD");
  }
  const head = git(dir, "rev-parse", "HEAD");
  if (head !== REFERENCE_COMMIT) throw new Error(`bc-lifehash at ${dir} is ${head}, expected ${REFERENCE_COMMIT}`);
  if (git(dir, "status", "--porcelain", "--untracked-files=no") !== "") throw new Error(`bc-lifehash at ${dir} has local modifications`);
  return dir;
};

// --- Build the driver against the reference sources.
const buildReference = (sourceDir) => {
  const out = mkdtempSync(join(tmpdir(), "bc-lifehash-"));
  const binary = join(out, "reference");
  const srcDir = join(sourceDir, "src");
  const sources = readdirSync(srcDir).filter((f) => f.endsWith(".cpp")).map((f) => join(srcDir, f));
  execFileSync(process.env.CXX ?? "c++", [
    "-std=c++17", "-O3", "-ffp-contract=off", "-w",
    "-include", "cstring", "-include", "stdexcept",
    "-I", srcDir, ...sources, join(here, "reference.cpp"), "-o", binary,
  ], { stdio: ["ignore", "inherit", "inherit"] });
  return { binary, cleanup: () => rmSync(out, { recursive: true, force: true }) };
};

// --- Line-protocol client: one request in flight at a time.
const startReference = (binary) => {
  const child = spawn(binary, [], { stdio: ["pipe", "pipe", "inherit"] });
  const lines = createInterface({ input: child.stdout })[Symbol.asyncIterator]();
  const render = async (hex, moduleSize) => {
    child.stdin.write(`${hex} ${moduleSize}\n`);
    const { value, done } = await lines.next();
    if (done) throw new Error("bc-lifehash reference exited");
    if (value.startsWith("error ")) throw new Error(`bc-lifehash reference: ${value.slice(6)}`);
    const [width, height, rgbHex] = value.split(" ");
    return { width: Number(width), height: Number(height), rgb: Uint8Array.from(Buffer.from(rgbHex ?? "", "hex")) };
  };
  return { render, stop: () => child.stdin.end() };
};

// Non-vacuity guard: C++ reference vectors pinned in test/lifehash.test.mjs
// (SHA-256 of the raw 32x32 RGB). Both the build and the app must reproduce
// them before fuzzing starts, so a mis-built reference or a harness whose
// comparisons silently no-op fails here, loudly. The last three are float32
// boundary artifacts that the `lifehash` JS package does not reproduce.
const VECTORS = [
  { input: "73c5da0a", rgb: "09da10ffd57a4f58616a5eda313d3f0c861e79b93e1b609a012f9c3530b427b5" },
  { input: "00000000", rgb: "9003d9fd366ec3aa06f54d6797485114ec00c61bf85c0efafa91bd2e40176d5b" },
  { input: "ffffffff", rgb: "e856f1b33dfd8eef83151de7407c3d4861581ce09f11f11f2dfc6b0219a1e51b" },
  { input: "b8688df1", rgb: "d44ba038c1389003c955a6f17accfb87c98fce4e8c98c9e2a44c71067b6521fe" },
  { input: "e3aa047b", rgb: "39c5d326ab09d98cda029cb9799b5c35bdb88ab8b7b799ee6a97cf6c5d0754d6" },
  { input: "a68bbd2f", rgb: "1c8f5b3a9d49d0b2e4785a040d271e8e361fc24b42e87b504b7ecf09cc211a13" },
  { input: "a5f29c5c", rgb: "4c811efc7660757cb40aacccf38f810c0dc02732eed6ee009a3cd21db95d1958" },
];
// Edge inputs beyond the PRNG stream: boundary nibbles, repeated bytes, and
// uppercase variants (the reference's hex_to_data accepts either case).
const FIXED = [
  "00000000", "ffffffff", "01234567", "89abcdef", "deadbeef", "aaaaaaaa", "55555555", "0f0f0f0f", "f0f0f0f0",
  ...VECTORS.map((v) => v.input.toUpperCase()),
];

const { binary, cleanup } = buildReference(referenceSource());
const reference = startReference(binary);

let comparisons = 0;
const fail = (fingerprint, moduleSize, message) => {
  process.stderr.write(
    `LifeHash mismatch vs C++ reference: fingerprint=${fingerprint} moduleSize=${moduleSize} ` +
    `seed=0x${SEED.toString(16)} iterations=${ITERATIONS}\n  ${message}\n`,
  );
  reference.stop();
  cleanup();
  process.exit(1);
};

const compare = async (fingerprint, moduleSize) => {
  const oursPng = decodePngRgb(await ours.fromFingerprint(fingerprint, moduleSize));
  const theirs = await reference.render(fingerprint, moduleSize);
  const difference = firstDifference(oursPng, theirs.width, theirs.height, theirs.rgb);
  if (difference) fail(fingerprint, moduleSize, difference);
  comparisons += 1;
  return { oursPng, theirs };
};

try {
  // 1. Pinned-vector guard on both sides (module size 1, raw 32x32 RGB).
  for (const { input, rgb } of VECTORS) {
    const { oursPng, theirs } = await compare(input, 1);
    if (sha256Hex(theirs.rgb) !== rgb) fail(input, 1, "the compiled C++ reference no longer reproduces its pinned vector");
    if (sha256Hex(oursPng.rgb) !== rgb) fail(input, 1, "EntropyLab no longer reproduces the pinned C++ reference vector");
  }

  // 2. Fixed edge inputs, at every module size.
  for (const fingerprint of FIXED) {
    for (const moduleSize of MODULE_SIZES) await compare(fingerprint, moduleSize);
  }

  // 3. The PRNG stream.
  for (let i = 0; i < ITERATIONS; i += 1) {
    const fingerprint = nextFingerprint();
    for (const moduleSize of MODULE_SIZES) await compare(fingerprint, moduleSize);
  }
} finally {
  reference.stop();
  cleanup();
}

process.stdout.write(
  `LifeHash C++ fuzz OK: ${comparisons} comparisons ` +
  `(${FIXED.length} fixed + ${ITERATIONS} PRNG inputs x ${MODULE_SIZES.length} module sizes, ` +
  `seed=0x${SEED.toString(16)}, bc-lifehash ${REFERENCE_COMMIT.slice(0, 12)}), 0 mismatches\n`,
);
