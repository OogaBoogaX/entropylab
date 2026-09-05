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
  for every entropy entry method. A separate **Brain wallet — lab** mode hashes
  exact UTF-8 text with SHA-256 and uses the 32-byte digest as 256-bit BIP39
  entropy (24 words). That is not a BIP39 passphrase, not a Bitcoin Core hdseed
  or address-key backup, and not the private-key brain-wallet path (which treats
  the same hash as a secp256k1 scalar). Strength is the entropy of the text, not
  the word count. Derive Wallet is required; the lab does not preview the
  mnemonic while typing.
- Derives BIP39 seeds, BIP32 extended keys, wallet fingerprints, addresses,
  and Bitcoin Core-compatible descriptors. Each master fingerprint is shown
  next to its deterministic [LifeHash](https://lifehash.info) icon so two
  keys can be told apart at a glance. The icon hashes the raw fingerprint
  bytes, so it matches the image Sparrow Wallet shows for the same key.
  Every row of the address tables has a QR button that opens that address as
  a scannable QR code, so any derived address — not just the first — can be
  verified on a signing device without retyping it.
- Supports legacy, nested SegWit, native SegWit, and Taproot single-signature
  address types. Derivation-scheme presets cover the BIP44, BIP49, BIP84,
  BIP86, and six-level BIP48 layouts and label each path level accordingly.
  A custom mode accepts an arbitrary-depth BIP32 account path, keeps Bitcoin
  network selection explicit, and appends the selected branch and address
  ranges. Typing `h` or `'` after a preset index enables its Harden control.
 - Supports numeric coin-type and account indexes for single-signature and
   multisignature derivation. Purpose, coin type, and account indexes are
   hardened by default; the starting address index is unhardened by default.
   Each can be changed independently. Coin type 0 uses Bitcoin Mainnet, coin
   type 1 uses Bitcoin Testnet, and custom indexes retain Mainnet address
   serialization. Hardened address children require private key material and
   therefore cannot be derived from multisig co-signer xpubs.
   A network picker in the header (the Bitcoin-orange coin next to the network
   name) shows the network every tool is set to and switches it — address
   formats, extended key versions, WIF prefixes, and coin-type defaults all
   follow, and each menu entry spells out the checks its choice implies. The
   PSBT tools read the picker's choice directly and have no network control of
   their own. Nothing connects anywhere: the choice only picks formats, and a
   tool's own advanced fields can still override it. Every load starts on
   Mainnet again.
- Derives watch-only multisignature wallets from extended public keys without
  requiring private keys. Multisig script type and purpose are separate as
  well; conventional script choices restore their standard purpose, while
  pasted co-signer origins auto-detect and must agree with the selected path
  indexes and hardening choices. Addresses are derived from the exported
  output descriptor itself by rust-miniscript (in the WASM crate), so the two
  cannot drift.
- Inspects PSBT v0 transactions, reports PSBT-provided amounts and fees, checks
  for repeated ECDSA nonces from the same public key — including signatures
  carried by finalized scriptSig/witness fields, which are decoded and analyzed
  rather than skipped — verifies optional Jade
  anti-exfil (sign-to-contract) transcripts without a key, and can compare supported
  SegWit v0 SIGHASH_ALL signatures with RFC 6979, including Bitcoin Core-style low-r grinding, in a temporary session.
  Every input's declared sighash policy and each signature's appended sighash
  byte are decoded without a key; anything other than exact SIGHASH_ALL is a
  blocking warning. Finalized signatures that cannot be decoded or associated
  with a key block any clean nonce verdict. The report gives each check a
  completed, problem, or incomplete state and gives an overall incomplete
  result whenever required data or support is missing. “Completed” describes
  only that check against the data in the file; it is not a claim that the
  transaction is safe or that PSBT-provided data is true.
- Accepts a fully signed raw Bitcoin transaction (hex or base64) in the same
  inspector: outputs, extracted ECDSA nonces, and inscription-envelope hints.
  Fee and RFC 6979 cannot be checked without previous outputs.
- With a session seed, root xprv, WIF, or hex key, labels each output as
  change, receive, or not in this wallet (accounts 0–2, 50 receive + 50
  change, all four script types). A two-or-more-output transaction with no
  matching change is a blocking warning. OP_RETURN outputs are decoded for size and a text/hex
  preview; the tool does not create data-carrier outputs.
- Scans PSBT tap-leaf scripts and finalized witnesses for inscription envelopes
  (`OP_FALSE OP_IF "ord"`). Reports content-type, size, and text previews; does
  not number sats, fetch chain data, create inscriptions, or render images.
- Edits PSBT v0 files field by field (a bip174.org-style editor backed by
  rust-bitcoin compiled to WebAssembly): a mempool.space-style
  transaction-flow diagram draws one box per input and output (claimed
  amount, address or script template, signing status) with per-column totals
  and bezier connectors into the unsigned transaction; selecting a box opens
  that key-value map for editing in a panel under the diagram, the
  transaction box opens the version/locktime fields, and output amounts edit
  directly in their boxes. Every key-value pair of the global,
  per-input, and per-output maps is decoded (BIP-174 and BIP-371 taproot
  fields), editable as raw hex, and removable, new pairs can be added, and the
  unsigned transaction's version, locktime, input prevouts/sequences, and
  output amounts/scripts get structured fields. Fields longer than 64
  characters (a whole previous transaction, a large script) collapse to a
  truncated preview with a length label; clicking the cell opens the full
  text in an editor window, where values stay editable. Re-serialization is
  validated by rust-bitcoin before the edited PSBT is shown. A second PSBT can
  be pasted for a semantic comparison against the editor's: the underlying
  transaction, the signing state, and the PSBT metadata are diffed separately
  on the decoded contents, so reordered map serialization is not reported as
  a change. The comparison reports differences only; it does not judge
  whether a change is safe. The editor never signs anything.
- Derives BIP-85 child entropy from the active key's BIP32 root (or a pasted
  root xprv): English BIP-39 mnemonics (12–24 words), HD-seed WIF, XPRV, HEX,
  and Base64/Base85 passwords. Same parent, application, and index always
  reproduce the same child — this is a calculator, not a generator. Children
  follow the published BIP-85 vectors and match COLDCARD, including derivation
  from a passphrase-extended root when a BIP-39 passphrase is in effect.
- Derives BIP-352 Silent Payment addresses (`sp1q…` / `tsp1q…`) from a seed or
  root xprv, including labeled codes, BIP-392 `spscan` / `spspend` descriptors,
  sender taproot outputs from pasted vin JSON, and receiver verification of
  pasted x-only outputs. Prints a BIP-321 `bitcoin:?sp=` URI and the BIP-353
  DNS TXT to paste on a domain you control; paste that URI back on Send.
  This is a calculator: it does not scan the chain or resolve names.
- Grinds vanity addresses for a Key Station key (Vanity tab), picked through
  the same chip picker as BIP-85 and Silent Payments. Two methods: the
  **passphrase grind** extends the key's BIP39 passphrase with base-62
  odometer counter characters, the **derivation grind** keeps the passphrase
  and steps through BIP32 account indexes. Every candidate is derived the
  standard way (PBKDF2 seed, BIP32 path — the key's own purpose, account,
  branch, and address index) in a dedicated WebAssembly module, one Web Worker
  per CPU core, and its mainnet address of the selected type (legacy, nested
  SegWit, native SegWit, Taproot, or a BIP-352 Silent Payment code) is checked
  against the chosen prefix. A short timing sample on tab entry (fixed
  published constants, never the session's keys) turns the odds into an
  expected time to a match, and **Stop on first find** halts the grind at the
  first hit. Same key and counter always reproduce the same
  address, so nothing is invented; **Update key** writes a found passphrase or
  account index back to the key and re-derives it, so the Keys tab, its
  exports, and the Journal show the vanity wallet. Found passphrases stay in
  page memory, are masked until revealed, and are wiped with the session.
- A session **Journal** (last workspace tab) holds an encrypted **Entropy
  Journal** notebook, a notepad stamped with this computer's date and time,
  an encrypted Key Manager, a live summary of everything derived in this sitting, and a debug log
  of tool switches and derives (fingerprints, not seeds). Its introduction
  remains above the Journal controls. Notepad, Key manager, Session state, and Session log
  stay visible but disabled until the user creates a journal with a valid
  password or successfully opens an existing journal; the create/open gate
  then disappears and the Journal starts on Notepad. The create form reports
  password length and confirmation matches live without exposing what was
  typed. Journal-wide **Download journal** and **Clear journal** actions stay
  below the introduction once a journal is unlocked; clearing wipes the
  encrypted entries, notepad, session snapshot, and log from page memory and
  returns to the create/open gate. The notebook keeps
  entropy the user already produced — dice, coins, hex, brain-wallet text, or
  a seed — under AES-256-GCM; the key is PBKDF2-SHA-256 (600,000 rounds) of a
  password the user chooses, with the salt derived from the password itself
  and the IV HMAC-SHA-256 of the plaintext, so the file is a pure function of
  password and entries and no CSPRNG is ever called. One JSON file the user
  downloads and loads back. Nothing is stored in the browser; download a file
  to keep it. Closing the page discards the sitting. The notebook is a
  calculator companion, not a password manager: it only stores material the
  user generated themselves.
  The **Key manager** tab packages selected derived Key Station keys and
  ignored-key metadata into an encrypted `.elkeys` file. It reuses the
  unlocked Journal password keys, so it adds no password prompt, random salt,
  or random nonce. Imported keys remain in Key Manager until the user chooses
  **Use in Key Station**; deleting a Key Station tab while a Journal is open
  likewise removes it from the station without discarding it from Key Manager.
  The Journal also includes a paged notepad. Pages use
  the Key Station's numbered naming convention, can be added or removed with
  the +/− controls, and can be renamed by activating the selected page again
  or pressing F2. Default names such as `Page 1` shorten to `P1` in narrow
  windows. A responsive control row below the editor sets each page's
  typeface, text size, and line spacing. Its key picker lists the currently
  derived Key Station keys with their LifeHashes; choosing one inserts a
  public inline reference with a line-height LifeHash and master fingerprint.
  Notepad, Session state, and Session log downloads use the unlocked journal password by
  default. Their matching checkboxes stay synchronized, so one change applies
  to Notepad, Session state, and Session log; unchecking exports the original
  plain JSON or text. Notepad can upload either its plain notebook JSON or its
  password-encrypted export while that journal is unlocked.
  Each page opens
  with a live local timestamp and freezes it when note text is entered. Delete
  the note back to its timestamp to return to the live new-note prompt. Press
  Enter after a note to open the next live timestamp and prompt. Press Enter on
  that empty prompt to leave an unstamped blank line and move a fresh live
  prompt to the line below. Delete at the empty prompt moves it back through
  those blank lines; once it reaches a completed note, the empty timestamp and
  prompt disappear and the caret returns to that note's end. Clicking any blank
  line moves an untouched live note there, or inserts a new live note there if
  the last note is already written; dragging across blank lines only selects
  them. Deleting a selected bottom section opens a live prompt on the blank line
  left at the caret. Clicking a written note cancels an untouched pending note
  and keeps the caret where clicked. Moving the pointer over the editor briefly
  reveals its clipboard button at the right edge; the same control is reachable
  from the keyboard and copies the active page as readable text. **Download notebook** writes versioned
  UTF-8 JSON containing page names, styles, and structured text/key runs; it
  stores only the key's display name and public fingerprint, then regenerates
  the LifeHash locally when that file is uploaded in a later session. Older
  `.txt` notes can also be uploaded as a single page. The Journal also holds
  a read-only summary that updates as the sitting changes and a debug log of
  meaningful dashboard actions: tool and station changes, calculations and
  failures, safe setting changes, copies, imports, downloads, clears, and PSBT
  structural edits. The log records public fingerprints where useful, but never
  secret-field values, filenames, note bodies, PSBT bytes, or individual entry
  keystrokes. It can be copied from its output field or downloaded. Nothing is stored in the
  browser; download a file to keep it. Closing the page discards the sitting.
- Runs a quick barrage of startup sanity checks on the host browser (secure
  context, CSPRNG, BigInt, UTF-8 encoding, NFKD, and WebAssembly). If any
  check fails, the page is replaced with a failure report listing the failed
  checks, because wallet output from a broken host cannot be trusted.
  iPhone/iPad/Mac Lockdown Mode blocks WebAssembly (the secp256k1 engine):
  exclude the site in Safari's page menu, or open the saved HTML in Firefox
  on an air-gapped computer. There is no JavaScript secp256k1 fallback.
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
- An optional **Sync entropy across methods** checkbox (off by default) keeps
  direct dice, card, number-base, seed-word, and private-key representations in
  sync while input is entered. Each destination waits for enough bits to emit
  its next complete character. Hashed inputs update the non-hashed methods in
  one direction; edits to non-hashed methods never overwrite hashed inputs.
- SLIP-132 extended-key display is a prefix swap only (same payload, new
  version bytes and checksum). Import/derive shows the key as pasted, the
  Bitcoin Core xprv/xpub or tprv/tpub, and the descriptor (script in the
  descriptor, not the prefix). A generic xprv is re-prefixed only when the
  path/script match: x = legacy, y = nested BIP49, z = native BIP84,
  Y = nested BIP48 multisig, Z = native BIP48 native-msig. Testnet uses
  t / u / v / U / V. There is no Taproot SLIP prefix.

## Usage

Download the self-contained `entropylab.html` from the
[official website](https://entropylab.online) or the
[releases page](https://github.com/OogaBoogaX/entropylab/releases), transfer it to a trusted
computer, disconnect that computer from all networks, and open the file in a
modern browser. For sensitive wallet material, use a dedicated air-gapped
machine and verify important addresses and descriptors with an independent
wallet or signing device before receiving funds.

To build the HTML file yourself, see [Building from source](#building-from-source).

### iPhone home-screen app

On iPhone, open [entropylab.online](https://entropylab.online) in Safari, then
choose **Share → Add to Home Screen → Open as Web App → Add**. Keep the page
open until its first load completes. The hosted app stores the self-contained
calculator in a versioned browser cache so the Home Screen app can reopen when
the phone has no network connection.

Before entering any seed phrase, private key, or other secret wallet material,
disconnect every network available to the phone, reopen EntropyLab from the
Home Screen, and confirm that the header reports **Offline**. A cached page is
not proof of an air gap: the status is based on browser network signals, and the
hosted worker checks for application updates whenever the app is opened while
connected. Clearing Safari website data or removing the Home Screen app may
remove the cached copy.

For sensitive or long-term use, the recommended path remains the downloaded,
verified `entropylab.html` on a dedicated air-gapped computer. The downloaded
file is still self-contained and never registers the hosted service worker.

### Verifying the download

Every merge to `rock` publishes a `SHA256SUMS.txt` checksum manifest for
`entropylab.html` (committed next to it in this repository), a matching
`CID.txt` (CIDv1 raw sha2-256 of those same bytes), and a
[GitHub artifact attestation](https://github.com/OogaBoogaX/entropylab/attestations)
for the exact bytes built by CI. After downloading, verify both:

```sh
sha256sum -c SHA256SUMS.txt
gh attestation verify entropylab.html -R OogaBoogaX/entropylab
```

The CID is a self-describing name for the SHA-256, not a second hash. The
calculator never talks to IPFS. To store or fetch the file on a **local**
node without GitHub or `entropylab.online` DNS:

```sh
ipfs block put --cid-codec=raw --allow-big-block entropylab.html   # pin the bytes you already verified
ipfs get -o entropylab.html "$(cut -d' ' -f1 CID.txt)"             # retrieve by CID
sha256sum -c SHA256SUMS.txt
```

`ipfs add` (UnixFS chunking) produces a different CID; that is expected.
Public gateways may refuse a multi-megabyte raw block — a local node is the
intended path. Never open a gateway URL as the wallet origin. Do not put
seeds or other private material on IPFS.

The attestation is keyless (Sigstore) and bound to this repository's release
workflow, so it authenticates the artifact independently of the hosting
account. The checksum manifest alone only detects accidental corruption —
always pair it with the attestation or reproduce the build from reviewed
source. For a given Git revision, `npm run build` deterministically assembles
`entropylab.html` from committed inputs, including the committed WASM modules;
the revision to check out is stamped in the generated file. Rebuilding those
modules from their Rust/C sources (`npm run build:wasm`) is separate, and its
output is not currently asserted to be byte-identical across machines. CI
still rebuilds the modules from source and runs the WASM binding tests against
the fresh build (see [Building from source](#building-from-source)).

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

## FAQ

### Does EntropyLab generate a seed or private key for me?

No. EntropyLab deterministically transforms entropy or key material that you
supply. It does not create secret wallet entropy. BIP-85 children are derived
from the parent root you provide and are reproducible from that same root,
application, and index.

### Can I enter a real seed phrase on the website?

Do not enter wallet secrets on an internet-connected device. Download the
self-contained HTML, verify it, transfer it to a trusted air-gapped computer,
and open it there. Keep backups and verify important results independently
before receiving funds.

### Does EntropyLab replace a hardware wallet or signing device?

No. EntropyLab is a calculator and verification tool. It can derive recovery
information, construct watch-only wallet data, and inspect supported PSBT
details, but it is not intended to be a transaction signer or broadcaster.
Use a separately verified wallet or signing device when spending bitcoin.

### How should I check an address or descriptor before using it?

Derive the same wallet with an independent implementation or signing device
and compare the address, derivation path, fingerprint, and descriptor. Do not
rely on matching only a shortened value or a visual icon.

### How do I know the downloaded HTML is authentic?

Follow [Verifying the download](#verifying-the-download). Check the SHA-256
manifest together with the GitHub artifact attestation, or build the file from
the reviewed source. A checksum by itself detects changed bytes but does not
authenticate who produced them.

### Why does EntropyLab accept short dice or card transcripts?

Short inputs are useful for deterministic tests, demonstrations, and recovery
experiments, so they are accepted with a warning. Hashing a short transcript
does not add entropy. Never secure funds with an input below the displayed
recommendation.

### How should I report a possible security problem?

Do not open a public issue for a suspected vulnerability involving incorrect
derivations, secret exposure, injected code, unexpected network access, or
possible loss of funds. Follow the private reporting instructions in
[SECURITY.md](SECURITY.md).

## Building from source

The build bundles the application with esbuild and inlines the result into a
single self-contained HTML file. All Bitcoin cryptography is compiled to
WebAssembly from the pinned Rust crate (below); the only JavaScript package
bundled into the artifact is `uqr` (QR rendering). `package-lock.json` pins
the complete dependency tree and the integrity hash of every downloaded
package; the `@noble`/`@scure` packages remain as dev-only differential test
oracles, pinned and never bundled.

EntropyLab's cryptography — secp256k1 curve operations (public-key
derivation, ECDSA signing and verification in PSBT inspection, curve point
math), hashes (SHA-256, SHA-512, RIPEMD-160, HMAC-SHA-512,
PBKDF2-HMAC-SHA-512), BIP32 extended-key derivation, BIP39 mnemonics,
Base58Check and bech32m encoding, output descriptor evaluation
(BIP380-386; taproot `sortedmulti_a` is layered on top), and
address/script construction
(p2pkh/p2sh/p2wpkh/p2tr, bare and taproot multisig) — runs on rust-bitcoin's
`secp256k1` crate (libsecp256k1 v0.4.1 vendored by secp256k1-sys 0.10.1),
`bitcoin`, `bitcoin_hashes`, `base58ck`, `bech32`, `bip39`, and
`miniscript`, compiled to
WebAssembly from the pinned Rust crate in `entropylab-wasm/` (exact crate
versions in `entropylab-wasm/Cargo.lock`, toolchain pinned by
`rust-toolchain.toml`) via the facades in `src/js/secp256k1.js`,
`src/js/hashes.js`, `src/js/hdkey.js`, `src/js/bip39.js`, `src/js/base58.js`,
`src/js/addresses.js`, and `src/js/bech32.js`. The only remaining JavaScript
bundled from npm is `uqr` (QR rendering; no cryptography). The compiled
artifact is committed as `src/js/entropylab-wasm-b64.js`, so building the
site needs only Node.js. CI
rebuilds it from the Rust sources, runs its test suite against the fresh
build, and commits the runner's copy back to `rock` after each merge (the
same flow as the site artifact; byte identity across machines is not
asserted, since the C side compiles with the builder's clang, and build-host
paths are remapped out of the binary).

PSBT parsing, typed field decoding, and re-serialization in the PSBT editor
run on rust-bitcoin 0.32.102 compiled to WebAssembly from the pinned crate in
`psbt-wasm/` (same pinning rules), exposed through `src/js/psbt-wasm.js` and
committed as `src/js/psbt-wasm-b64.js`. The WASM sees only PSBT bytes and
UTF-8 JSON; it holds no keys and generates no randomness.

Requirements: Node.js 20.19 or newer.

```sh
npm ci
npm run build
```

To modify the Rust bindings (`entropylab-wasm/`, `psbt-wasm/`), Rust (with the
`wasm32-unknown-unknown` target, installed automatically by rustup) is also
required; regenerate the committed artifacts with `npm run build:wasm`.

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
│   ├── build-wasm.mjs      crypto WASM rebuild (npm run build:wasm)
│   ├── cid.mjs             CIDv1 raw sha2-256 name for the release HTML
│   └── verify-site.mjs     Site artifact verification (npm run verify)
├── entropylab-wasm/        Pinned Rust crate: rust-bitcoin + rust-miniscript -> WebAssembly bindings
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
│       ├── journal.js      Encrypted entropy notebook, session notepad, snapshot, and debug log
│       ├── secp256k1.js    Curve facade over the WASM module (noble-shaped API)
│       ├── entropylab-wasm.js Shared WASM module loader
│       ├── entropylab-wasm-b64.js Generated WASM artifact (committed; build:wasm)
│       ├── hashes.js         Hash facade over the WASM module (noble-shaped API)
│       ├── hdkey.js          BIP32 HDKey facade over the WASM module (scure-shaped API)
│       ├── bip39.js          BIP39 mnemonic facade over the WASM module (scure-shaped API)
│       ├── bip39-english.js  Canonical 2048-word English list (UI data)
│       ├── base58.js         Base58Check facade over the WASM module
│       ├── addresses.js      Script/address/descriptor facade over the WASM module
│       ├── bech32.js         bech32m facade over the WASM module (BIP352)
│       ├── coders.js         hex/base64 byte coders (no cryptography)
│       ├── sqlite-writer.js Minimal SQLite database file writer
│       ├── wallet-export.js Bitcoin Core wallet.dat descriptor export
│       ├── online.js       Hosted-site online warning
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
npm run build:wasm          # rebuild the committed crypto WASM artifact (needs Rust)
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
