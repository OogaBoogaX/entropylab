# Security Policy

## Supported Versions

Only the most recent release receives security fixes. Users are encouraged to
always use the latest version, available from the
[releases page](https://github.com/OogaBoogaX/entropylab/releases) and the
[official website](https://entropylab.online).

| Version | Supported          |
| ------- | ------------------ |
| 1.0.0   | :white_check_mark: |
| < 1.0.0 | :x:                |

## Security Considerations

EntropyLab handles Bitcoin private keys, seed phrases, and other secret wallet
material. Original dice/input records plus their recipe can rebuild a wallet
and must be protected like seed phrases. Its security posture rests on the
following model:

- The tool is self-contained and designed for offline, air-gapped use. It does
  not intentionally transmit sensitive data to any server.
- The optional feature guide renders only bundled, translated plain text. It
  accepts known lesson IDs and keeps only lesson progress in page memory;
  it reads no wallet inputs, saves nothing in browser storage, and makes no
  network calls. Pagehide (including End Session) clears progress and closes
  it; a back/forward-cache restore starts fresh. Only an explicit Open this
  tool action invokes normal released-tool navigation. A completed lesson
  is not a security verdict or an endorsement of the user's environment.
- The Security log below Important records initial browser-reported
  connectivity, connectivity changes, and detected browser translation.
  Its API accepts only fixed event codes, never arbitrary messages, errors,
  user input or wallet material. The last 100 events and local timestamps
  stay in page memory; pagehide (including End session) clears them. A
  back/forward-cache restore starts fresh and retains any latched translation
  warning. No status probe or log export is sent over the network or saved
  in browser storage. Browser connectivity does not establish internet
  reachability or a physical air gap, and the translation marker does not
  identify the translation service or prove what text it received.
- The hosted site registers a service worker only on the exact HTTPS
  `entropylab.online` or `www.entropylab.online` origin. It stores only the
  self-contained application entry points in a content-versioned cache so an
  iPhone Home Screen web app can reopen without a network. Navigation is served
  only from that current named cache; the worker has no network fallback,
  background sync, push, or notification handling. When the app is opened
  while connected, the browser checks the hosted worker for an update and may
  replace the cached application. Cached availability and the browser's
  Offline label are not proof of a physical air gap.
- The downloaded `entropylab.html` remains the recommended path for sensitive
  use. It is one self-contained file, does not register the hosted service
  worker from `file://` or another host, and should be verified before transfer
  to a dedicated computer that is disconnected from every network. Download
  checksums establish byte integrity; GitHub/Sigstore attestations establish
  build provenance, not device safety.
- EntropyLab's own secp256k1 curve operations (public-key derivation, ECDSA
  signing and verification in PSBT inspection, curve point math) and its
  cryptographic hashes (SHA-256/SHA-512/RIPEMD-160/HMAC/PBKDF2) run on
  bitcoin-core/libsecp256k1 (the library securing Bitcoin Core) and
  rust-bitcoin's bitcoin_hashes, compiled to WebAssembly from the pinned,
  lockfiled Rust crate in `entropylab-wasm/` and executed entirely in-process
  — no network access, and the module never generates randomness (signing is
  RFC 6979 with caller-fixed extra entropy). BIP32 extended-key derivation,
  BIP39 mnemonics, Base58Check, bech32m, and address/script construction run
  on rust-bitcoin's crates in the same module, except that the PSBT editor
  uses `src/js/script-builder.js` and the pinned `@scure/btc-signer` package
  for address-to-output-script conversion. That JavaScript package and its
  bundled dependencies are part of the production audit surface. Script-to-
  address rendering in the editor and flow visualizer uses the WASM facade.
  CI rebuilds the WASM from the committed Rust sources and tests the fresh
  modules before building the
  site. Those same modules are bundled with the HTML candidate for downstream
  source and browser tests, deployment, and the post-merge artifact commit;
  publication does not compile a second WASM copy.
   CI compiles these modules inside the pinned dev image (one linux/amd64
   rootfs, one Ubuntu snapshot, clang 18.1.3) and requires a second build in
   that image to match the bytes it publishes; the artifact commit and the
   Pages deploy wait for that check. Their digests are published in
   `WASM-SHA256SUMS.txt`. A host clang is a different compiler. The 1.0.0
   hashes, and the page built from them, have been reproduced in that image
   on three machines outside GitHub, by three people: Windows with WSL2 and
   bare-metal Linux on x86_64, and macOS on ARM64 (the image under
   Rosetta). The page alone also rebuilds to the same bytes on each of those
   hosts without the image. [docs/Reproductions.md](docs/Reproductions.md)
   records each rebuild by commit. Build-host paths are remapped out of the
   binary.
  iOS/macOS Lockdown Mode disables WebAssembly. Exclude the site in Safari
  or use a host that can compile WASM. There is no JavaScript secp256k1
  fallback; a host that cannot run the module is treated as broken.
- Vanity wipes its retained final child and fixed parent nodes in place;
  matching a copy of a node and wiping that copy is not sufficient. Regression
  tests scan WASM memory for independently derived nodes, private keys, and
  chain codes after a grind. Passing these vectors does not guarantee erasure
  of every compiler or crypto-library temporary; terminate the worker to
  release its entire WASM instance.
- Clearing a Key or Multisig station invalidates pending derivation work.
  Pagehide and persisted-page restoration also invalidate derivations and
  clear rendered seed-word grids, checksum choices, and brain-lab hex — and
  the secondary renderings of a typed transcript: the dealt-cards strip, the
  "show calculations" work-outs, the die-fairness panel, and the progress
  lines (which quote a rejected word or token in an error cue). The same
  boundary ends the whole PSBT/Nonce session (key bytes, paste fields, the
  parsed report and its rendered views), resets every Multisig tab, and the
  two body-level overlays — the expand editor (whose value can be an entire
  previous transaction) and the QR dialog — release their contents on close
  and on page hide because station wipes cannot reach them. Locking the
  Journal empties the session's unsecured text: the snapshot (which can
  hold the whole session's recovery texts), the notepad, and the session
  log; the notebook's own entries come back from the journal file on
  unlock. The
  Vanity source block drops the passphrase it displayed the moment the key
  pick is dropped. Journal teardown (including Lock) invalidates pending
  notebook and Key Manager imports at both file-read and decryption
  boundaries. Obsolete completions cannot restore cleared state; this is
  not guaranteed erasure of immutable strings or browser-managed memory.
- Secret byte buffers are overwritten after use, on a best-effort basis. The
  WASM bindings zero every linear-memory buffer before freeing it
  (`el_free`/`psbt_free` use volatile writes) and erase their own secret
  temporaries — private keys, seeds, chain codes, mnemonics, passphrases,
  signing nonces, and HMAC/PBKDF2 blocks. The JavaScript layer zeroes the
  `Uint8Array`s it is done with (`.fill(0)`, `HDKey.wipePrivateData()`),
  including temporary BIP32 serialized key/chain-code views after master
  derivation, child derivation, and extended-key import (also on failure).
  Returned HDKey nodes keep independent copies; this cleanup does not wipe
  caller-owned seed buffers. A derived wallet, a BIP-85 child, and each
  station's copy of a key hold their secrets only as byte arrays and HDKey
  nodes; words, WIF, xprv and hex text are built only where a secret is
  shown, copied or exported, or where a tool takes it as text. The layer also
  clears intermediate BIP32 path nodes, per-address child keys, and the
  PSBT/BIP-85/Silent-Payments session roots when a session ends or the page
  unloads (when `pagehide` fires, which browsers do not guarantee). The
  limits are structural: JavaScript strings, BigInts and DOM values
  (revealed secrets, typed input) cannot be overwritten, only dereferenced
  — the "(best effort)" the UI already states — and heap copies
  made inside dependency types that expose no erase (HMAC engines,
  `bip39::Mnemonic`) remain until their memory is reused; the PSBT module
  adds pair-level residues of that class, inside rust-bitcoin's parsed
  structures and serde_json's value trees (its exports do wipe the
  whole-document copies — the assembled inspection JSON and the rebuilt PSBT
  bytes — before returning, and the suite scans for that; the small per-pair
  copies inside the dependencies remain until heap reuse).
  [What the page can and cannot erase](#what-the-page-can-and-cannot-erase)
  lists each case in plain language. Stack copies are
  handled separately: Rust frames spill arguments and temporaries into the
  WASM shadow stack, which lives in linear memory and is not erased when a
  frame returns, so the loaders of both the crypto module and the PSBT module
  wrap every export to zero the whole stack region once per task after any
  export ran (the Node suite asserts BIP39 entropy, the PBKDF2 passphrase
  salt, HMAC and hash inputs, and WIF keys are absent from linear memory once
  the task settles, and for the PSBT module that its stack region is zeroed
  and that the two whole-document copies its exports assemble — the
  inspection JSON and the rebuilt PSBT bytes — are gone once the task
  settles). None of this protects against a compromised machine.
- The on-screen result of any derivation can only be as trustworthy as the
  code that produced it. Review the source, build from `src/`, and test the
  tool with published vectors before relying on it.
- Wallet security depends on the quality and secrecy of the entropy, seed
  phrase, passphrase, or private key supplied by the user, and on the
  integrity of the machine it runs on.
- Silent Payment sender inputs use BIP-341 tweaked output-key scalars for
  P2TR key-path spends. Session-derived sender keys are handed over as byte
  buffers and wiped on success, construction failure, and partial resolution
  failure. The UI suppresses the vector API's private-key-sum diagnostic.
  Immutable BigInts and internal curve-library representations still depend
  on garbage collection; this is best-effort cleanup, not guaranteed erasure.
- Silent Payments (BIP-352) support is a calculator: it derives reusable
  addresses, sender outputs, and spend tweaks from user-supplied keys and
  pasted transaction data. It does not connect to a node, Electrum server, or
  indexer, and cannot detect payments on its own. BIP-321 URIs and BIP-353 DNS
  TXT records are printed from the derived code so you can publish them on a
  domain you control; the page never resolves names, never fetches
  silentpayments.net, and ignores Lightning parameters in a URI. When a URI
  includes an ordinary Bitcoin fallback address alongside `sp=`, sender
  outputs use the selected Silent Payment instruction and the results show
  the unused fallback as escaped text. That fallback is not validated or
  used to construct an output.
- Inscription envelope detection is a parser of witness/tap-leaf scripts. It
  does not render inscription media, assign sat numbers, or contact an indexer.
- PSBT analysis is explicitly bounded. EntropyLab does not independently fetch
  or verify previous outputs, its output-ownership search covers only the
  displayed account/address range and supported script types, RFC 6979 replay
  needs a matching session key plus a supported SegWit v0 digest, and
  Taproot/Schnorr nonces are not analyzed. The report marks these cases
  incomplete; a completed individual check is not a security conclusion for
  the transaction.
- The optional ECDSA nonce-history file is an explicit user download and never
  uses browser storage or the network. It contains check timestamps, master
  fingerprints when available, raw `r` values, domain-separated SHA-256
  identity tags for exact signing keys and verified message digests or source
  contexts, plus verification flags; it does not contain raw PSBTs,
  transactions, signatures, public keys, or digests. This is
  correlation-sensitive metadata and should stay offline. The master
  fingerprint is descriptive; comparisons use the exact signing-key tag, since
  one wallet can have many child keys. A confirmed alert requires the same
  key/`r` pair with different verified message tags; otherwise the result is
  only a warning. The current implementation covers ECDSA, not Schnorr.
- OP_RETURN detection is a parser of output scripts. It does not create
  data-carrier outputs, assign protocol meaning, or contact an indexer.
- The published `CID.txt` is CIDv1 (raw, sha2-256) of the release
  `entropylab.html` — the same digest as `SHA256SUMS.txt`, written as an IPFS
  name. The calculator never speaks IPFS: no node, no gateway, no IPNS, no
  `fetch`. Retrieving the file by CID is an online-machine step; verify
  `SHA256SUMS.txt` before moving the HTML onto an air-gapped computer. Do not
  publish seeds, xprvs, or other private material to IPFS.
- After each merge to `rock`, CI submits the tested `entropylab.html` digest
  to OpenTimestamps calendars and commits `entropylab.html.ots`. A pending
  proof is a calendar receipt, not a Bitcoin timestamp; a scheduled job
  upgrades it once a calendar has a block attestation. Verify upgraded
  proofs with `ots verify` against a local Bitcoin Core node. The calculator
  never stamps, upgrades, or fetches calendars.
- The session Journal (notepad, session snapshot, session log) lives only in
  this page's memory. It is never written to `localStorage`, IndexedDB, or the
  network. Closing or hiding the page discards it with the other secret
  fields. Downloads from all three tabs reuse the unlocked Entropy Journal
  keys and use Journal file encryption by default; the synchronized checkbox
  can explicitly switch them back to plain JSON or text. If the Journal was
  created without a password, its encoded downloads have no access protection.
  The log records tool
  names, timestamps, and fingerprints — not seed phrases, xprvs, or typed
  secrets.
- Key Manager lives behind the same unlocked Journal gate. Its `.elkeys`
  exports reuse the Journal's deterministic export encryption and optional password;
  the Key Manager does not generate a salt, nonce, password, or key material.
  Version 2 vaults store source inputs/settings, not cached wallet results.
  Both version 1 and 2 imports discard cached results, claimed identities,
  and any claimed verification state. Imports (including ignored entries)
  are labeled unverified and must be loaded into the lab and freshly derived
  before becoming station wallets or supplying outputs to other tools.
  Re-derivation proves consistency with the supplied inputs, not that the
  sender lacks a copy of the key or that the inputs have adequate entropy.
  Imported private material remains in page memory and is not loaded into Key
  Station until the user explicitly chooses it. Locking or clearing the
  Journal drops pending and ignored Key Manager entries on a best-effort basis.
- The Entropy Journal notebook holds entropy the user
  already produced, not a password manager and not a key generator. The
  AES-256-GCM key is PBKDF2-SHA-256 (600,000 rounds) of the optional password
  the user types, with the salt derived from the password itself; the IV is
  HMAC-SHA-256 of the plaintext under a second derived key. The file is
  therefore a deterministic function of the password and the entries — the
  journal never calls a CSPRNG. The trade-off is brute-force cost: anyone
  holding a password-protected file can test passwords at 600,000 SHA-256
  rounds per guess, so a password should have real length. An empty password
  is allowed to preserve a frictionless local workflow and the same file
  format, but it provides no access protection: anyone with the file can open
  every entry by leaving the password blank. The plaintext never goes to
  localStorage, IndexedDB, or the network.
- Low-entropy dice and card transcripts are accepted intentionally so the
  calculator can be used for deterministic tests, demonstrations, and
  recovery experiments. EntropyLab does not claim that hashing a short input
  makes it secure. When the entered transcript is below the recommended
  entropy target, the result displays a prominent warning with the estimated
  supplied entropy and says to use it only for testing. Both hashed-dice
  methods recommend 100 rolls for a 24-word seed; 99 rolls still trigger the
  below-recommendation warning. Users who intend to
  secure funds must meet the displayed roll/card recommendation and verify
  their procedure independently.
- Brain wallet — lab hashes the exact UTF-8 text with unsalted SHA-256 and
  treats the digest as BIP39 entropy. Guessable text is stolen coins. A valid
  24-word mnemonic from that hash is not the same wallet as hashing the text
  as a Bitcoin Core private key, and it is not a backup of a Core hdseed or
  address key. The private-key brain-wallet mode remains a separate scalar
  path.
- The vanity grinder (Vanity tab) is deterministic and works only on a Key
  Station key: a counter either extends that key's BIP39 passphrase (base-62
  odometer characters) or selects its BIP32 account index, and every
  candidate is derived the standard way (PBKDF2 seed, BIP32 path), so it
  invents no entropy and every result is a setting of a wallet the user
  already holds. A found passphrase is still a BIP39 passphrase: the words
  alone no longer recover the wallet, and the tab says so before Update key
  writes it back to the key. The key's seed words (passphrase grind) or the
  parent node above the account (derivation grind) are handed to the page's
  own Web Workers and wiped with the run. Found passphrases live only in page
  memory, are masked until revealed, and are dropped by the same
  pagehide/bfcache clearing as every other secret.
- BIP-85 children are a deterministic transformation of the parent BIP32 root,
  not newly generated entropy. A BIP-39 passphrase, when present, is part of
  that root (the same rule COLDCARD uses). Anyone who has the parent seed,
  the exact passphrase, the application, and the index can reproduce every
  child; protect the parent for the combined value of all derived wallets.
- The Lightning tab deciphers LND aezeed cipher seeds and derives node
  identity keys in WebAssembly; it never creates seeds. The scrypt KDF runs
  at LND's parameters (N=2^15, r=8, p=1) and both scrypt exports bound the
  parameters — a 32 MiB working-buffer cap and p ≤ 16 on `el_scrypt`, only
  LND's two legitimate parameter sets on `el_aezeed_decipher` — because WASM
  linear memory never shrinks, so an unbounded call would grow the heap
  permanently (32 MiB after the first production decode) or trap on
  allocation failure and take every export down with it. The scrypt crate
  does not zeroize its working buffers, so the exports overwrite them after
  every call by re-allocating and wiping the same sizes; without that scrub,
  the buffer's first block retains one PBKDF2 iteration of the passphrase,
  which would let a later reader of page memory test passphrase guesses
  without paying the scrypt cost. The vendored AEZ v5 module
  (MIT-licensed, not public domain; see `entropylab-wasm/src/aez/mod.rs`)
  erases its expanded key schedule on drop and its key-expansion hasher
  after use, and a wide zeroing stack frame runs before the exports return
  to overwrite spilled frame temporaries. The Node suite asserts the derived
  key and the scrypt buffers are absent from linear memory after a decode;
  closing the tab remains the only guaranteed erasure.
- The single-file design inlines all scripts (`script-src 'unsafe-inline'`),
  and the secp256k1 WebAssembly module adds `wasm-unsafe-eval` to the
  content security policy: Chromium and WebKit engines refuse to compile a
  WebAssembly module from JS without it. Application scripts are still all
  bundled at build time, so any inline script injected after packaging is
  outside the threat model this policy addresses.
- Material involving loss of funds (incorrect derivations, exfiltration of
  secret data, injected script execution in the generated HTML, unexpected
  network egress) is treated as a security issue.

## What the page can and cannot erase

EntropyLab overwrites the secrets it holds once you are done with them, on a
best-effort basis, but a web page cannot erase everything it touches. This
is where the line is.

**What the page erases.** While a key is loaded, the page holds its secrets as
bytes it can overwrite: the seed's entropy and seed, private keys, HD key
nodes, and a BIP39 passphrase or mini key you typed. Each station that uses
the key holds a copy of its own, kept the same way. Clearing a key, clearing
a station or ending its session overwrites those bytes with zeros; a key two
tabs share is overwritten once neither uses it. Leaving or closing the page
does the same when the browser runs the page's cleanup, which it does not
always do: a mobile browser that ends a tab in the background, or a browser
that crashes, skips it. That same cleanup ends the PSBT/Nonce session
completely (its reports included), resets every Multisig form, and empties
the panels that echo what you typed (dealt cards, the worked calculations,
the fairness tally, the progress lines) and the two dialogs (the value
editor and the QR view) — the dialogs also drop their contents the moment
you close them. Locking the Journal empties the session snapshot, the
notepad, and the session log; what an unlock restores is the notebook the
journal file holds, nothing looser. The WebAssembly modules overwrite every
buffer passed in or out and their working stacks after they run, and the
PSBT module also wipes the whole-file copies its exports assemble. Vanity
shuts its workers and their module down when a run ends. The
browser can still make copies of its own while it manages memory, which the
page cannot reach.

Private readouts disable browser text selection with `user-select: none`,
including displayed seed words and per-address WIFs. Copying uses a deliberate
clipboard icon beside the label or value's table row; clicking the value itself
does not copy. The controls read the current shown value at activation and do
not keep secrets in their attributes. Concealed values have no displayed copy
control. Editable input fields still support normal selection and editing.
Public derivation values remain selectable and copy when clicked; their labels
offer a clipboard icon when no QR button is available. Public copy controls
read the current value, and shortened public previews copy the complete value.
This reduces accidental selection and copying; it does not hide revealed text
from the browser, extensions, screenshots, or developer tools, and does not
protect clipboard history or sync.

Copying can also leave copies in the browser's own processes after End session
and tab closure. In the Windows 11 measurements described in
[#816](https://github.com/OogaBoogaX/entropylab/issues/816), Edge 154.0.4258.53
retained copied seed words until Edge itself quit. Quit the browser completely
after use; ending its processes releases their memory but does not prove that
every copy was erased.

**What the page cannot erase.** Some copies stay in the browser's memory
until the browser reuses that memory. The page can let go of them, but
cannot overwrite them:

- Text you type or paste. A field's value is text, and the browser's editor,
  undo history, spell checker and on-screen keyboard may keep copies of their
  own. The Key Station's BIP39 passphrase field is the exception: it shows
  one bullet per character and never holds the passphrase, which is kept in
  a form the page can wipe and reaches the seed as bytes. Each key still
  arrives as a one-character string, a paste or an input-method word arrives
  as its text once, and showing the passphrase builds it. In
  BIP39-word mode the field holds the text, as other fields do.
- Text the page builds from a secret: revealed seed words, WIFs, xprvs and
  hex, SeedQR, the recovery sheet, downloads, and what a copy button puts on
  the clipboard. The few tools that take the words as text build them too:
  the Silent Payments key field, the Vanity passphrase grind, and the
  Journal.
- The Journal and the Key Manager. The notepad and every entry are text, and
  so is a file once it is decrypted.
- JavaScript numbers. The Silent Payments calculations turn a key into a
  `BigInt`, and briefly into hex text.
- Copies made inside the libraries the WebAssembly modules use, where the
  library offers no way to erase them (HMAC engines, `bip39::Mnemonic`, and
  the per-pair copies rust-bitcoin and serde_json make while the PSBT module
  parses or rebuilds a file). End session overwrites both modules' whole
  memory with the patterns 0x55, 0xAA and 0xFF and then zeroes it, which
  removes these too.
- A Vanity grind stopped mid-run. Its workers are terminated, not wiped:
  termination is a hard kill, so the worker never runs its own wipe and its
  memory — the seed words and passphrase it grinds on — is freed unzeroed.
  Only closing the tab reclaims it. (A grind that finishes or is stopped
  gracefully wipes itself first.)

Other copies are outside the browser, where the page cannot reach them at
all. They can outlast the page and the browser, and some outlast a restart:

- The clipboard. It belongs to the operating system. Clipboard history
  (Win+V), cloud clipboard sync, Apple's Universal Clipboard and clipboard
  managers keep their own copies, possibly on other devices, and EntropyLab
  cannot remove them.
- Anything the operating system writes to disk. Swap, hibernation and crash
  dumps can hold a copy of the browser's memory, and no web page can prevent
  or erase that. Deleting the hibernation file afterwards does not reliably
  erase it on an SSD.

**What the page keeps from other software.** Some browser features and
extensions copy what the page shows or a field holds, and send it off the
computer or keep it where the page cannot erase it. The
Content-Security-Policy cannot stop them, because the browser or the
extension sends the text, not the page. Each offers an opt-out, and
EntropyLab uses it:

- Browser translation. Chrome's and Edge's built-in translators send the
  page's text to Google or Microsoft. Everything that shows a seed word, a
  key or a typed secret is marked `translate="no"`, the preventive opt-out
  for browsers that honor it. EntropyLab warns when it detects Chrome/Google
  translation through `translated-ltr` / `translated-rtl` classes on the
  document root or Edge/Microsoft translation through `_msthash`,
  `_msttexthash`, or `_mstmutation` attributes anywhere in the document.
  It checks at initialization and observes relevant attribute changes and
  inserted subtrees. Detection opens Important, keeps the warning visible
  even if markers disappear, and records one security-log event through the
  detection callback. This is best-effort, browser-marker-based detection
  after the fact, not prevention or proof of which text was sent. The markers
  are not a security boundary or a guaranteed future browser API. Firefox
  translates on the device.
- Writing aids. Edge's text prediction, which sends what you type to
  Microsoft, is off for the whole page. Every field opts out of Grammarly,
  which sends field text to its servers whatever the spell-check setting.
- Password managers. Every field except the Journal's file password opts out
  of 1Password, LastPass, Bitwarden and Dashlane, so a BIP39 passphrase is
  never offered to a cloud-synced vault.
- Session restore. Chrome saves field contents in its session-restore files
  on disk unless a field is marked `autocomplete="off"`. Every field is.
- The screen. Revealed private values are masked again when the window loses
  focus or is hidden, and after five minutes without input, so that Windows
  Recall, a screen share or a phone's app-switcher picture is less likely to
  catch them.

These opt-outs only work when the software honors them. They do not stop an
extension that ignores them, or one written to steal.

**What to do about it.**

- For real funds, use a dedicated computer that stays offline, with full-disk
  encryption on and hibernation off before you load a key. The
  [computer hardening checklist](docs/Computer_Hardening_Checklist.md) gives
  the steps for Windows, macOS and Linux, and the browser settings that copy
  what is on the page.
- Developers can inspect browser-memory residue with the
  [residue audit harness](docs/Residue_Audit.md) (`npm run test:residue`),
  which drives Chrome/Edge with a public fixture, requires a clean baseline
  and positive controls, and scans process captures for actual derived secrets.
  The positive capture precedes output and clipboard verification; those
  checks return digests, never private-key text, through the debugging pipe.
  Missing captures invalidate the run; uncalibrated needles prove nothing.
  Its zero is not proof, and automation can add copies — see the doc.
- Avoid the clipboard for secrets where you can. If you use it, turn off
  clipboard history and sync first.
- When you are done, press End session in the header. It wipes the page,
  zeroes the WebAssembly modules' memory, empties the clipboard if
  EntropyLab copied something there (as far as the page can tell — it
  cannot read the clipboard to check), and asks the browser to close the
  tab.
  Closing the tab releases its resources, but the browser's main process can
  retain copied secrets as described above. A tab you opened straight to the
  file closes; if it stays open,
  close it yourself. Chrome and Edge keep running after the last window
  closes unless "Continue running background apps" is off in their System
  settings.
- Then close the browser and restart the computer. That is a precaution, not
  a guarantee: a restart does not erase memory, and its contents can survive
  a short power-off.
- None of this protects a computer that is already compromised: malware or a
  malicious browser extension can read a secret as you type it.

## Reporting a Vulnerability

Please report suspected security issues privately through
[GitHub Security Advisories](https://github.com/OogaBoogaX/entropylab/security/advisories/new)
rather than opening a public issue. If private reporting is unavailable, reach
the maintainers through the [official website](https://entropylab.online).

Include the version, the affected input type and derivation path if relevant,
and a description of the impact. A maintainer will acknowledge the report and
coordinate a fix; scope it as narrowly as needed to reproduce responsibly.

## Disclaimer

This software is provided without warranty of any kind — no express, no
implied, no promise it work or fit any purpose — under
[The Ooga Booga License](LICENSE), which dedicates it to the public domain. The
caveman words mean what The Unlicense means. Keep verified backups, and use it
at your own risk.
