// Builds the WASM artifacts from the pinned Rust sources and writes them as
// committed, importable JS modules (base64 + sha256 of the wasm bytes):
//   entropylab-wasm/ -> src/js/entropylab-wasm-b64.js
//   psbt-wasm/       -> src/js/psbt-wasm-b64.js
//   vanity-wasm/     -> src/js/vanity-wasm-b64.js
//
// The generated modules are committed so that `npm run build` keeps working
// with Node alone. CI rebuilds them from the Rust sources (pinned by each
// crate's rust-toolchain.toml and Cargo.lock) and runs the WASM test suites
// against the fresh build, so a stale committed copy cannot survive; the
// artifact job commits the runner's copy back after each merge. Byte identity
// across machines is not asserted: the secp256k1 C side compiles with the
// builder's clang. Build-host paths are remapped below so the binaries do not
// carry the builder's home directory.
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));

// Without a remap, rustc bakes the builder's absolute paths (e.g.
// /home/<user>/.cargo/...) into panicking code of registry sources, which
// both fingerprints the build host and breaks cross-machine comparisons.
const home = process.env.HOME ?? "";
const rustflags = [
  `--remap-path-prefix=${home}/.cargo/=cargo/`,
  `--remap-path-prefix=${home}/.rustup/=rustup/`,
].join(" ");

const crates = [
  {
    dir: "entropylab-wasm",
    wasm: "entropylab_wasm.wasm",
    out: "src/js/entropylab-wasm-b64.js",
    symbol: "ENTROPYLAB_WASM_B64",
    blurb: `// libsecp256k1 v0.4.1 (vendored by secp256k1-sys 0.10.1 via secp256k1 0.29.1),
// bitcoin_hashes 0.14.101, rust-bitcoin 0.32.11, rust-bip39 2.2.2,
// base58ck 0.1.101, and bech32 0.11.1 (see entropylab-wasm/Cargo.lock)
// compiled to WebAssembly from entropylab-wasm/ with the pinned Rust 1.95.0
// toolchain.
//`,
  },
  {
    dir: "psbt-wasm",
    wasm: "psbt_wasm.wasm",
    out: "src/js/psbt-wasm-b64.js",
    symbol: "PSBT_WASM_B64",
    blurb: `// rust-bitcoin 0.32.102 (see psbt-wasm/Cargo.lock) compiled to WebAssembly
// from psbt-wasm/ with the pinned Rust 1.95.0 toolchain.`,
  },
  {
    dir: "vanity-wasm",
    wasm: "vanity_wasm.wasm",
    out: "src/js/vanity-wasm-b64.js",
    symbol: "VANITY_WASM_B64",
    blurb: `// libsecp256k1 0.8.0 (vendored by secp256k1-sys 0.14.0, see
// vanity-wasm/Cargo.lock) plus sha2 0.10.9 / ripemd 0.1.3, compiled to
// WebAssembly from vanity-wasm/ with the pinned Rust 1.95.0 toolchain.`,
  },
];

for (const crate of crates) {
  const crateDir = join(root, crate.dir);
  const wasmPath = join(crateDir, `target/wasm32-unknown-unknown/release/${crate.wasm}`);
  const outPath = join(root, crate.out);

  execFileSync(
    "cargo",
    ["build", "--locked", "--release", "--target", "wasm32-unknown-unknown"],
    { cwd: crateDir, stdio: "inherit", env: { ...process.env, RUSTFLAGS: rustflags } }
  );

  const wasm = readFileSync(wasmPath);
  const sha256 = createHash("sha256").update(wasm).digest("hex");
  const b64 = wasm.toString("base64");

  const out = `// GENERATED FILE - do not edit. Rebuild with \`npm run build:wasm\`.
${crate.blurb} wasm sha256: ${sha256}
export const ${crate.symbol} =
  "${b64}";
`;

  writeFileSync(outPath, out);
  console.log(`Built ${crate.dir} WASM artifact`);
  console.log(`  ${wasm.length} bytes wasm, sha256 ${sha256}`);
  console.log(`  wrote ${outPath} (${Buffer.byteLength(out, "utf8")} bytes)`);
}
