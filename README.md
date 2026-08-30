# EntropyLab

EntropyLab is a self-contained Bitcoin key and wallet calculator designed for
offline, air-gapped use. It converts user-supplied entropy, seed phrases, and
private keys into wallet recovery information without intentionally sending
sensitive data to a server.

Current version: **v0.1.3**

Official website: [entropylab.online](https://entropylab.online)

## Features

- Accepts dice rolls, coin flips, hexadecimal entropy, BIP39 seed phrases,
  extended keys, WIF keys, raw private keys, and Casascius mini private keys.
  All five BIP39 phrase lengths (12, 15, 18, 21, and 24 words) are supported
  for every entropy entry method.
- Derives BIP39 seeds, BIP32 extended keys, wallet fingerprints, addresses,
  and Bitcoin Core-compatible descriptors. Each master fingerprint is shown
  next to its deterministic [LifeHash](https://lifehash.info) icon so two
  keys can be told apart at a glance.
- Supports legacy, nested SegWit, native SegWit, and Taproot single-signature
  address types. Script type and the hardened BIP32 purpose index are separate:
  choosing a script restores its conventional 44/49/84/86 purpose, while an
  advanced user can enter any valid hardened purpose index for a custom path.
- Supports numeric hardened coin-type indexes for single-signature and
  multisignature derivation. Coin type 0 uses Bitcoin Mainnet, coin type 1 uses
  Bitcoin Testnet, and custom indexes retain Mainnet address serialization.
  PSBT address rendering separately supports Mainnet and Testnet.
- Derives watch-only multisignature wallets from extended public keys without
  requiring private keys. Multisig script type and hardened purpose are
  separate as well; conventional script choices restore their standard purpose,
  while pasted co-signer origins auto-detect and must agree with the selected
  purpose.
- Encodes a derived BIP39 seed as a unique without-replacement card order
  (Card deck backup). On Cards, that order is shown only after you select the
  derived key and click Show stacked deck. It is not a hashed card transcript
  and will not match Ian Coleman.
- Inspects PSBT v0 transactions, reports PSBT-provided amounts and fees, checks
  for repeated ECDSA nonces from the same public key, verifies optional Jade
  anti-exfil (sign-to-contract) transcripts without a key, and can compare supported
  SegWit v0 SIGHASH_ALL signatures with RFC 6979, including Bitcoin Core-style low-r grinding, in a temporary session.
  Every input's declared sighash policy and each signature's appended sighash
  byte are decoded without a key; anything other than exact SIGHASH_ALL is a
  blocking warning.
- Runs a quick barrage of startup sanity checks on the host browser (secure
  context, CSPRNG, BigInt, UTF-8 encoding, and NFKD normalization). If any
  check fails, the page is replaced with a failure report listing the failed
  checks, because wallet output from a broken host cannot be trusted.
- Produces recovery information that can be saved or printed for offline use.
- Exports a Bitcoin Core `wallet.dat` (SQLite descriptor wallet) with every
  derived output descriptor already imported — receive and change for each
  script type, active and ready for address generation. The default download
  is watch-only; while private recovery material is shown on screen, the
  export becomes the spending variant (account xprvs as descriptor keys) and
  the button says so. The descriptor birthday defaults to genesis so
  recovered keys are discovered by Bitcoin Core's initial scan; choose the
  "New keys" birthday only for entropy created at that moment. If a loaded
  wallet looks empty, repair it with `rescanblockchain 0` in Bitcoin Core.
  Generated database files match Bitcoin Core's own record layout
  byte-for-byte (verified against Bitcoin Core v28.3.0).

## Usage

Download the self-contained `entropylab.html` from the
[official website](https://entropylab.online) or the
[releases page](https://github.com/w-s-bitcoin/entropylab/releases), transfer it to a trusted
computer, disconnect that computer from all networks, and open the file in a
modern browser. For sensitive wallet material, use a dedicated air-gapped
machine and verify important addresses and descriptors with an independent
wallet or signing device before receiving funds.

To build the HTML file yourself, see [Building from source](#building-from-source).

### Verifying the download

Every merge to `rock` publishes a `SHA256SUMS.txt` checksum manifest for
`entropylab.html` (committed next to it in this repository) and a
[GitHub artifact attestation](https://github.com/w-s-bitcoin/entropylab/attestations)
for the exact bytes built by CI. After downloading, verify both:

```sh
sha256sum -c SHA256SUMS.txt
gh attestation verify entropylab.html -R w-s-bitcoin/entropylab
```

The attestation is keyless (Sigstore) and bound to this repository's release
workflow, so it authenticates the artifact independently of the hosting
account. The checksum manifest alone only detects accidental corruption —
always pair it with the attestation or with your own rebuild from source,
which is byte-for-byte reproducible.

An online version is available at [entropylab.online](https://entropylab.online)
for convenient access. Do not enter seed phrases, private keys, or other secret
wallet material into an internet-connected device; use the downloaded HTML on
a trusted air-gapped computer for sensitive operations.

EntropyLab does not generate wallet entropy. The optional BitBox Heads/Tails
controls use browser randomness only to choose an equivalent displayed die
face: 1–3 all mean Heads and 4–6 all mean Tails, so that numeric choice does not
change the resulting BitBox entropy. Wallet security still depends on the
quality and secrecy of the entropy, seed phrase, passphrase, or private key
supplied by the user.

## Building from source

The build imports the cryptographic libraries declared in `package.json`,
bundles them with the application using esbuild, and inlines the result into a
single self-contained HTML file. `package-lock.json` pins the complete
dependency tree and the integrity hash of every downloaded package.

EntropyLab's own secp256k1 calls — public-key derivation, ECDSA signing and
verification in PSBT inspection, and curve point math — run on
libsecp256k1 0.8.0 compiled to WebAssembly from the pinned Rust crate in
`secp256k1-wasm/` (exact crate versions in `secp256k1-wasm/Cargo.lock`,
toolchain pinned by `rust-toolchain.toml`) via the facade in
`src/js/secp256k1.js`. BIP32 extended-key derivation and address/script
construction still run on `@noble/curves`, brought in by the bundled
`@scure` libraries. The compiled artifact is committed as
`src/js/secp256k1-wasm-b64.js`, so building the site needs only Node.js. CI
rebuilds it from the Rust sources, runs its test suite against the fresh
build, and commits the runner's copy back to `rock` after each merge (the
same flow as the site artifact; byte identity across machines is not
asserted, since the C side compiles with the builder's clang, and build-host
paths are remapped out of the binary).

Requirements: Node.js 20.19 or newer.

```sh
npm ci
npm run build
```

To modify the curve bindings (`secp256k1-wasm/`), Rust (with the
`wasm32-unknown-unknown` target, installed automatically by rustup) is also
required; regenerate the committed artifact with `npm run build:wasm`.

Build output (generated; CI rebuilds it for every run and commits it back to
`rock` after each merge so the file stays downloadable from the repository):

- `entropylab.html` — the self-contained application (open this file)

The version is declared once in `package.json` and substituted into the
output at build time. The generated file is gitignored locally; CI builds
it before every test run and commits it back to `rock` after each merge.
To remove generated files, run `npm run clean`.

## Project structure

```
├── assets/                 Static assets (logo, favicon, social card)
├── scripts/
│   ├── build.mjs           Locked-dependency esbuild and HTML assembly
│   ├── build-wasm.mjs      libsecp256k1 WASM rebuild (npm run build:wasm)
│   └── verify-site.mjs     Site artifact verification (npm run verify)
├── secp256k1-wasm/         Pinned Rust crate: libsecp256k1 -> WebAssembly bindings
├── test/
│   ├── browser-instrumentation.html  In-page browser test hooks
│   ├── browser-suite.html            In-page browser test suite
│   ├── browser.test.mjs              Headless-Firefox integration harness
│   ├── browser-check.test.mjs        Tests for the startup browser sanity checks
│   ├── network-check.test.mjs        Tests for the network-check module
│   ├── sqlite-writer.test.mjs        Tests for the SQLite writer (verified with real SQLite)
│   ├── ui-defaults.test.mjs          UI defaults and markup invariants
│   ├── validate.test.mjs             Source and security invariants
│   ├── wallet-export-reference.mjs   Bitcoin Core wallet.dat ground-truth fixture
│   └── wallet-export.test.mjs        Tests for the wallet.dat export module
├── src/
│   ├── index.html          HTML template (markup and document head)
│   ├── assets/             Header logos, inlined as data URIs at build time
│   ├── css/styles.css      Application styles
│   └── js/
│       ├── app.js          Application logic and explicit package imports
│       ├── secp256k1.js    Curve facade over the WASM module (noble-shaped API)
│       ├── secp256k1-wasm-b64.js Generated WASM artifact (committed; build:wasm)
│       ├── sqlite-writer.js Minimal SQLite database file writer
│       ├── wallet-export.js Bitcoin Core wallet.dat descriptor export
│       ├── online.js       Hosted-site behavior and header version label
│       ├── network-check.js Network adapter detection and warning
│       ├── browser-check.js Startup browser sanity checks and kill-screen
│       ├── enhanced-inputs.js
│       └── repeat-inputs.js
├── entropylab.html         Compiled application (generated, CI-committed)
└── versions/archived/      Historical releases excluded from the picker
```

## Development and deployment

The toolchain is npm and Node.js (>=20.19). Install the exact dependency tree
with `npm ci`; every local and CI operation is exposed as an npm script:

```bash
npm test                    # run all tests, including the headless-Firefox suite
npm run test:ci             # the CI subset: network-check, ui-defaults, source invariants
npm run test:validate       # validate source and security invariants
npm run test:browser        # test crypto, sanitization, networking, exports in headless Firefox
npm run build               # compile src/ into the generated root files
npm run build:wasm          # rebuild the committed secp256k1 WASM artifact (needs Rust)
npm run verify              # verify the site artifact (entropylab.html, assets)
npm run ci                  # run the CI test subset, build, and verify in order
```

GitHub Actions builds the site first, then runs the same test steps for pull
requests and pushes to `rock`, stages the verified site (`entropylab.html`,
`assets/`) and deploys it to GitHub Pages. After a merge to
`rock`, a final job commits the rebuilt `entropylab.html`
back to the repository so the file stays downloadable; pull requests never
carry the generated output, so they stop conflicting on it. The staging step
copies the verified `entropylab.html` to a deployment-only `index.html`,
allowing both the site root and `/entropylab.html` to serve the same
application without committing a second application artifact. CI runs the
test suites that need no browser; the headless-Firefox suite runs locally
where a Firefox binary is available. Local checks and CI/CD use the same
commands; the workflow contains no separate build implementation.

The browser suite runs the assembled application in headless Firefox against a
local Node.js HTTP server. It feeds hostile markup and event-handler strings
through user-facing fields, verifies the application makes no network
requests at runtime, exercises the hosted warning and
assets, derives a known wallet through the UI, and inspects both watch-only
and private recovery-sheet exports. It also runs the BIP39 and BIP32 published
vectors directly against the application code. It is the only part of the
toolchain that needs a browser; the server, build, and test harness are
dependency-free Node.js.

## Security notice

Bitcoin private keys and seed phrases control funds. Review the code, test the
tool with known vectors, keep secret material offline, and maintain verified
backups. This software is provided without warranty; use it at your own risk.

## License

EntropyLab is released into the public domain under
[The Ooga Booga License](LICENSE) — a caveman-speak dedication of the software
to the public domain, with the same meaning as The Unlicense: free to copy,
modify, publish, use, compile, sell, or distribute, in source or binary form,
for any purpose and by any means, with no warranty of any kind. Any and all
copyright interest in the software is dedicated to the public at large.
