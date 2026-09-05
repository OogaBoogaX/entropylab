# Security Policy

## Supported Versions

Only the most recent release receives security fixes. Users are encouraged to
always use the latest version, available from the
[releases page](https://github.com/OogaBoogaX/entropylab/releases) and the
[official website](https://entropylab.online).

| Version | Supported          |
| ------- | ------------------ |
| 0.1.3   | :white_check_mark: |
| < 0.1.3 | :x:                |

## Security Considerations

EntropyLab handles Bitcoin private keys, seed phrases, and other secret wallet
material. Its security posture rests on the following model:

- The tool is self-contained and designed for offline, air-gapped use. It does
  not intentionally transmit sensitive data to any server.
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
  to a dedicated computer that is disconnected from every network.
- EntropyLab's own secp256k1 curve operations (public-key derivation, ECDSA
  signing and verification in PSBT inspection, curve point math) and its
  cryptographic hashes (SHA-256/SHA-512/RIPEMD-160/HMAC/PBKDF2) run on
  bitcoin-core/libsecp256k1 (the library securing Bitcoin Core) and
  rust-bitcoin's bitcoin_hashes, compiled to WebAssembly from the pinned,
  lockfiled Rust crate in `entropylab-wasm/` and executed entirely in-process
  — no network access, and the module never generates randomness (signing is
  RFC 6979 with caller-fixed extra entropy). BIP32 extended-key derivation,
  BIP39 mnemonics, Base58Check, bech32m, and address/script construction run
  on rust-bitcoin's crates in the same module. CI rebuilds the WASM from the
  committed Rust sources and runs its test suite against
  the fresh build before any deployment; the artifact job then commits the
  runner's copy back to the repository, the same flow as the site artifact.
   Cross-machine byte identity is not claimed — the C side compiles with the
   builder's clang, and build-host paths are remapped out of the binary.
  iOS/macOS Lockdown Mode disables WebAssembly. Exclude the site in Safari
  or use a host that can compile WASM. There is no JavaScript secp256k1
  fallback; a host that cannot run the module is treated as broken.
- Secret byte buffers are overwritten after use, on a best-effort basis. The
  WASM bindings zero every linear-memory buffer before freeing it
  (`el_free`/`psbt_free` use volatile writes) and erase their own secret
  temporaries — private keys, seeds, chain codes, mnemonics, passphrases,
  signing nonces, and HMAC/PBKDF2 blocks. The JavaScript layer zeroes the
  `Uint8Array`s it is done with (`.fill(0)`, `HDKey.wipePrivateData()`),
  including intermediate BIP32 path nodes, per-address child keys, and the
  PSBT/BIP-85/Silent-Payments session roots when a session ends or the page
  unloads. The limits are structural: JavaScript strings and DOM values
  (displayed seed phrases, WIF keys, typed input) cannot be overwritten, only
  dereferenced — the "(best effort)" the UI already states — and copies made
  inside dependency types that expose no erase (HMAC engines,
  `bip39::Mnemonic`) remain until their memory is reused. None of this
  protects against a compromised machine.
- The on-screen result of any derivation can only be as trustworthy as the
  code that produced it. Review the source, build from `src/`, and test the
  tool with published vectors before relying on it.
- Wallet security depends on the quality and secrecy of the entropy, seed
  phrase, passphrase, or private key supplied by the user, and on the
  integrity of the machine it runs on.
- Silent Payments (BIP-352) support is a calculator: it derives reusable
  addresses, sender outputs, and spend tweaks from user-supplied keys and
  pasted transaction data. It does not connect to a node, Electrum server, or
  indexer, and cannot detect payments on its own. BIP-321 URIs and BIP-353 DNS
  TXT records are printed from the derived code so you can publish them on a
  domain you control; the page never resolves names, never fetches
  silentpayments.net, and ignores Lightning parameters in a URI.
- Inscription envelope detection is a parser of witness/tap-leaf scripts. It
  does not render inscription media, assign sat numbers, or contact an indexer.
- PSBT analysis is explicitly bounded. EntropyLab does not independently fetch
  or verify previous outputs, its output-ownership search covers only the
  displayed account/address range and supported script types, RFC 6979 replay
  needs a matching session key plus a supported SegWit v0 digest, and
  Taproot/Schnorr nonces are not analyzed. The report marks these cases
  incomplete; a completed individual check is not a security conclusion for
  the transaction.
- OP_RETURN detection is a parser of output scripts. It does not create
  data-carrier outputs, assign protocol meaning, or contact an indexer.
- The published `CID.txt` is CIDv1 (raw, sha2-256) of the release
  `entropylab.html` — the same digest as `SHA256SUMS.txt`, written as an IPFS
  name. The calculator never speaks IPFS: no node, no gateway, no IPNS, no
  `fetch`. Retrieving the file by CID is an online-machine step; verify
  `SHA256SUMS.txt` before moving the HTML onto an air-gapped computer. Do not
  publish seeds, xprvs, or other private material to IPFS.
- The session Journal (notepad, session snapshot, session log) lives only in
  this page's memory. It is never written to `localStorage`, IndexedDB, or the
  network. Closing or hiding the page discards it with the other secret
  fields. Downloads from all three tabs reuse the unlocked Entropy Journal
  keys and are password-encrypted by default; the synchronized checkbox can
  explicitly switch them back to plain JSON or text. The log records tool
  names, timestamps, and fingerprints — not seed phrases, xprvs, or typed
  secrets.
- Key Manager lives behind the same unlocked Journal gate. Its `.elkeys`
  exports reuse the Journal's deterministic export encryption and password;
  the Key Manager does not generate a salt, nonce, password, or key material.
  Imported private material remains in page memory and is not loaded into Key
  Station until the user explicitly chooses it. Locking or clearing the
  Journal drops pending and ignored Key Manager entries on a best-effort basis.
- The Entropy Journal notebook is an encrypted notebook of entropy the user
  already produced, not a password manager and not a key generator. The
  AES-256-GCM key is PBKDF2-SHA-256 (600,000 rounds) of a password the user
  types, with the salt derived from the password itself; the IV is
  HMAC-SHA-256 of the plaintext under a second derived key. The file is
  therefore a deterministic function of the password and the entries — the
  journal never calls a CSPRNG. The trade-off is brute-force cost: anyone
  holding the file can test passwords at 600,000 SHA-256 rounds per guess, so
  the password needs real length. The plaintext never goes to localStorage,
  IndexedDB, or the network. Anyone with the file and the journal password
  can read every entry.
- Low-entropy dice and card transcripts are accepted intentionally so the
  calculator can be used for deterministic tests, demonstrations, and
  recovery experiments. EntropyLab does not claim that hashing a short input
  makes it secure. When the entered transcript is below the recommended
  entropy target, the result displays a prominent warning with the estimated
  supplied entropy and says to use it only for testing. Users who intend to
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
- The single-file design inlines all scripts (`script-src 'unsafe-inline'`),
  and the secp256k1 WebAssembly module adds `wasm-unsafe-eval` to the
  content security policy: Chromium and WebKit engines refuse to compile a
  WebAssembly module from JS without it. Application scripts are still all
  bundled at build time, so any inline script injected after packaging is
  outside the threat model this policy addresses.
- Material involving loss of funds (incorrect derivations, exfiltration of
  secret data, injected script execution in the generated HTML, unexpected
  network egress) is treated as a security issue.

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
