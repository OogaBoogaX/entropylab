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
- Derives BIP39 seeds, BIP32 extended keys, wallet fingerprints, addresses,
  and Bitcoin Core-compatible descriptors.
- Supports legacy, nested SegWit, native SegWit, and Taproot single-signature
  address types.
- Currently restricts wallet derivation, multisignature construction, and PSBT
  address rendering to Testnet. Mainnet remains visible but disabled while the
  application is in beta.
- Builds watch-only multisignature wallets from extended public keys without
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
├── scripts/build.mjs       Zero-dependency build script
├── test/network-check.test.mjs  Tests for the network-check module (npm test)
├── src/
│   ├── index.html          HTML template (markup and document head)
│   ├── css/styles.css      Application styles
│   └── js/
│       ├── vendor.js       Bundled third-party crypto (noble, scure, bip39)
│       ├── app.js          Application logic
│       ├── online.js       Hosted-site behavior and version picker
│       ├── network-check.js Network adapter detection and warning
│       ├── enhanced-inputs.js
│       └── repeat-inputs.js
├── index.html              Compiled application (generated, committed)
├── entropylab-*.html       Versioned copy of the compiled application
├── versions.json           Version manifest for the hosted version picker
└── versions/archived/      Historical releases excluded from the picker
```

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
