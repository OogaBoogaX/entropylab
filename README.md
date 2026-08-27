# EntropyLab

EntropyLab is a self-contained Bitcoin key and wallet calculator designed for
offline, air-gapped use. It converts user-supplied entropy, seed phrases, and
private keys into wallet recovery information without intentionally sending
sensitive data to a server.

Current version: **v0.1.3**

The project is created, owned, and maintained by **Mr.Hodl and Wicked**.

Official website: [entropylab.online](https://entropylab.online)

## Features

- Accepts dice rolls, coin flips, hexadecimal entropy, BIP39 seed phrases,
  extended keys, WIF keys, raw private keys, and Casascius mini private keys.
- Offers an optional on-screen virtual keyboard for every entropy input field
  (dice, D++, hex, binary, seed phrase, and private key), toggled by a small
  keyboard glyph, with a Shuffle control that reorders the keys on each press.
- Derives BIP39 seeds, BIP32 extended keys, wallet fingerprints, addresses,
  and Bitcoin Core-compatible descriptors.
- Supports legacy, nested SegWit, native SegWit, and Taproot single-signature
  address types.
- Supports Mainnet and Testnet wallet derivation, multisignature construction,
  and PSBT address rendering. Mainnet is selected by default.
- Derives watch-only multisignature wallets from extended public keys without
  requiring private keys.
- Inspects PSBT v0 transactions, reports PSBT-provided amounts and fees, checks
  for repeated ECDSA nonces from the same public key, and can compare supported
  SegWit v0 SIGHASH_ALL signatures with plain RFC 6979 in a temporary session.
- Produces recovery information that can be saved or printed for offline use.

## Usage

Download the self-contained [`index.html`](../../raw/main/index.html) from the
root of this repository (or from the
[releases page](https://github.com/w-s-bitcoin/entropylab/releases) /
[official website](https://entropylab.online)), transfer it to a trusted
computer, disconnect that computer from all networks, and open the file in a
modern browser. For sensitive wallet material, use a dedicated air-gapped
machine and verify important addresses and descriptors with an independent
wallet or signing device before receiving funds.

To build the HTML file yourself, see [Building from source](#building-from-source).

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

The project uses a zero-dependency Node.js build that inlines the sources in
`src/` into a single self-contained HTML file at the repository root.

Requirements: Node.js 18 or newer (no npm packages to install).

```sh
npm run build
```

Build output (committed to the repository so the file can be downloaded
directly):

- `index.html` — the self-contained application (open this file)
- `entropylab-<version>.html` — versioned copy used by the download links
- `versions.json` — version manifest used by the hosted version picker

The version is declared once in `package.json` and substituted into the
output at build time. After changing anything in `src/`, run `npm run build`
and commit the regenerated files; CI runs the test suite (`npm test`) and
verifies that the committed output is reproducible. To remove generated
files, run `npm run clean`.

## Project structure

```
├── assets/                 Static assets (logo, favicon)
├── scripts/
│   ├── build.mjs           Zero-dependency build script
│   └── verify-site.mjs     Site artifact verification (npm run verify)
├── test/
│   ├── browser-instrumentation.html  In-page browser test hooks
│   ├── browser-suite.html            In-page browser test suite
│   ├── browser.test.mjs              Headless-Firefox integration harness
│   ├── network-check.test.mjs        Tests for the network-check module
│   ├── ui-defaults.test.mjs          UI defaults and markup invariants
│   ├── virtual-keyboard.test.mjs     On-screen keyboard invariants
│   └── validate.test.mjs             Source and security invariants
├── src/
│   ├── index.html          HTML template (markup and document head)
│   ├── css/styles.css      Application styles
│   └── js/
│       ├── vendor.js       Bundled third-party crypto (noble, scure, bip39)
│       ├── app.js          Application logic
│       ├── online.js       Hosted-site behavior and version picker
│       ├── network-check.js Network adapter detection and warning
│       ├── enhanced-inputs.js
│       ├── repeat-inputs.js
│       └── virtual-keyboard.js On-screen keyboards for entropy fields
├── index.html              Compiled application (generated, committed)
├── entropylab-*.html       Versioned copy of the compiled application
├── versions.json           Version manifest for the hosted version picker
└── versions/archived/      Historical releases excluded from the picker
```

## Development and deployment

The toolchain is npm and Node.js (>=18) with no third-party dependencies. Every
local and CI operation is exposed as an npm script:

```bash
npm test                    # run all tests, including the headless-Firefox suite
npm run test:ci             # the CI subset: network-check, ui-defaults, source invariants
npm run test:validate       # validate source and security invariants
npm run test:browser        # test crypto, sanitization, networking, exports in headless Firefox
npm run build               # compile src/ into the committed root files
npm run verify              # verify the site artifact (snapshot, manifest, assets)
npm run ci                  # run the CI test subset, build, and verify in order
```

GitHub Actions runs the same steps for pull requests and pushes to `main`,
then stages the verified site (`index.html`, `entropylab-*.html`,
`versions.json`, `assets/`) and deploys it to GitHub Pages. CI runs the
test suites that need no browser; the headless-Firefox suite runs locally
where a Firefox binary is available. Local checks and CI/CD use the same
commands; the workflow contains no separate build implementation.

The browser suite runs the assembled application in headless Firefox against a
local Node.js HTTP server. It feeds hostile markup and event-handler strings
through user-facing fields and the version manifest, verifies all observed
application requests remain same-origin, exercises the hosted warning and
assets, derives a known wallet through the UI, and inspects both watch-only
and private recovery-sheet exports. It also runs the BIP39 and BIP32 published
vectors directly against the application code. It is the only part of the
toolchain that needs a browser; the server, build, and test harness are
dependency-free Node.js.

## Security notice

Bitcoin private keys and seed phrases control funds. Review the code, test the
tool with known vectors, keep secret material offline, and maintain verified
backups. This software is provided without warranty; use it at your own risk.

## Authors and ownership

EntropyLab belongs to **Mr.Hodl and Wicked**, who are its creators and
maintainers.

## License

EntropyLab is released under the [MIT License](LICENSE). Copyright (c) 2026
Mr.Hodl and Wicked.
