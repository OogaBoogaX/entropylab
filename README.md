# EntropyLab

EntropyLab is a self-contained Bitcoin key and wallet calculator designed for
offline, air-gapped use. It converts user-supplied entropy, seed phrases, and
private keys into wallet recovery information without intentionally sending
sensitive data to a server. The whole application is one HTML file, and its
markup passes the W3C HTML validator with zero errors.

Current version: **v1.0.0**

Official website: [entropylab.online](https://entropylab.online)

## Features

When a multi-worker Vanity search stops, its next counter is the first
unfinished counter, not the sum of candidates processed across workers.
Resuming can repeat work from later buckets, but will not skip an unfinished
gap in the requested range.

CI builds and tests the Rust/WASM modules before compiling the site, then
shares those exact modules with downstream tests and artifact publication.
For local testing after Rust changes, run `npm run build:wasm` before
`npm run build && npm test`; the checked-in modules may predate the changes.

How the code is tested (the CI suite, Bitcoin Core interop checks,
differential fuzzing, mutation testing, and the October 2026 review record)
is summarised in [docs/TESTING.md](docs/TESTING.md).

Clearing a Key or Multisig station cancels its pending derivation. Leaving
the page clears rendered seed-word copies and prevents a late derivation or
import from restoring cleared secrets. Clearing the journal also invalidates
pending notebook and Key Manager imports. See [SECURITY.md](SECURITY.md) for
the limits of browser-memory cleanup.

The crypto WASM module overwrites Rust heap allocations before releasing them,
including dependency-owned descriptor keys and text. Resizing preserves the
live bytes and erases the old allocation. This does not erase live objects,
JavaScript strings, browser copies, or operating-system memory.

The code fixes merged in [PR #843](https://github.com/OogaBoogaX/entropylab/pull/843)
provide the following behavior. Rejected HD derivation paths wipe any intermediate
private child already created, while preserving the caller's root. The sequential
PSBT UR decoder API deduplicates identical fragments and allocates only for supplied fragments;
invalid sequence numbers are refused. Large transaction scripts serialize
without depending on the browser's function-argument limit.
Nonce reports never pair a repeated-nonce warning with a no-repeat claim.
Inputs requiring more than 32,768 same-r pair comparisons are refused with
an explicit error before those pairs are allocated.

- A live **Security log** below Important shows the browser's initial
  connection status, online/offline changes, and detected browser translation
  with local timestamps. It keeps the last 100 fixed messages in page memory,
  records no wallet data, and clears when the session ends or the page is left.
  It sends no network probes; an Offline report is not proof of an air gap.
  Translation detection uses Chrome/Google's `translated-ltr` /
  `translated-rtl` document-root classes or Edge/Microsoft's `_msthash`,
  `_msttexthash`, or `_mstmutation` DOM attributes. This is best-effort
  detection after the fact using browser markers, not prevention or a
  guaranteed future browser API. Secret-bearing surfaces retain the
  preventive `translate="no"` opt-out; see [SECURITY.md](SECURITY.md).

- Accepts dice rolls, coin flips, playing-card transcripts, number-base
  transcripts (binary through base64), hexadecimal entropy, BIP39 seed
  phrases, extended keys, WIF keys, raw private keys, and Casascius mini
  private keys. Optional live chi-squared fairness analysis flags biased dice
  as rolls are entered for hashed-dice and BitBox input. D++ omits the panel
  because a complete transcript cannot reach the panel's Pearson threshold.
  Both hashed-dice methods recommend 100 rolls for a 24-word seed phrase.
  All five BIP39 phrase lengths (12, 15, 18, 21, and 24 words) are supported
  for every entropy entry method. A separate **Brain wallet — lab** mode hashes
  exact UTF-8 text with SHA-256 and uses the 32-byte digest as 256-bit BIP39
  entropy (24 words). That is not a BIP39 passphrase, not a Bitcoin Core hdseed
  or address-key backup, and not the private-key brain-wallet path (which treats
  the same hash as a secp256k1 scalar). Strength is the entropy of the text, not
  the word count. Derive Key is required; the lab does not preview the
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
  ranges. The default derives receive and change branches `{0-1}` and address
  indexes `{0-9}`, displayed as a full BIP-88 path template. Typing `h` or `'`
  after a preset index enables its Harden control.
  Derived HD keys with a root private key offer an optional **Match derivation
  purpose to script type** checkbox. It starts checked when the entered purpose
  matches the selected script type's standard hardened purpose; a different
  purpose or hardening starts unchecked. When checked, it derives each
  script type at its standard hardened purpose (44h, 49h, 84h, or 86h), keeping
  the rest of the path and ranges unchanged. Unchecking restores the original
  purpose and its hardening. Paths, keys, addresses, and exports update together;
  account-level imports and public-only roots cannot use this option.
  With matching checked, viewing a script tab also updates the input purpose
  and derivation path; **Edit Input** starts from that displayed path. For
  example, viewing Taproot changes the input purpose to `86h`; entering an
  `84h` path while Taproot remains selected starts the next key unchecked.
 - Supports numeric coin-type and account indexes for single-signature and
   multisignature derivation. Purpose, coin type, and account indexes are
   hardened by default; the starting address index is unhardened by default.
   Each can be changed independently. Coin type 0 uses Bitcoin Mainnet, coin
   type 1 uses Bitcoin Testnet, and custom indexes retain Mainnet address
   serialization. Hardened address children require private key material and
   therefore cannot be derived from multisig co-signer xpubs.
    A network picker in the header (the Bitcoin-orange coin next to the network
    name) offers Bitcoin, Testnet, Signet, and Regtest; it shows the network
    every tool is set to and switches it — address
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
  indexes and hardening choices. An exported wallet descriptor can also be
  pasted to repopulate the station — quorum, script type, key order, and
  co-signers; descriptors carrying private keys are refused. Addresses are
  derived from the exported
  output descriptor itself by rust-miniscript (in the WASM crate), so the two
  cannot drift.
- Inspects PSBT v0 transactions (paste, or upload a binary .psbt / hex or
  base64 text export; the loaded bytes download as .psbt or .txn), reports
  PSBT-provided amounts and fees, checks
  for repeated ECDSA nonces from the same public key — including signatures
  carried by finalized scriptSig/witness fields, which are decoded and analyzed
  rather than skipped — verifies optional Jade
  anti-exfil (sign-to-contract) transcripts without a key, and can compare supported
  SegWit v0 SIGHASH_ALL signatures with RFC 6979, including Bitcoin Core-style low-r grinding, in a temporary session.
  A signature on a script containing OP_CODESEPARATOR is reported as
  unverifiable rather than compared, because its digest commits to the script
  from just past the last executed separator.
  Every input's declared sighash policy and each signature's appended sighash
  byte are decoded without a key; anything other than exact SIGHASH_ALL (or
  Taproot's equivalent SIGHASH_DEFAULT) is a
  blocking warning. Finalized signatures that cannot be decoded or associated
  with a key block any clean nonce verdict. The report gives each check a
  completed, problem, or incomplete state and gives an overall incomplete
  result whenever required data or support is missing. “Completed” describes
  only that check against the data in the file; it is not a claim that the
  transaction is safe or that PSBT-provided data is true.
- Accepts a fully signed raw Bitcoin transaction (hex or base64) in the same
  inspector: outputs, extracted ECDSA nonces, and inscription-envelope hints.
  Fee and RFC 6979 cannot be checked without previous outputs.
- Keeps an optional cross-session ECDSA nonce history in page memory and lets
  the user download or upload it as versioned JSON. The file contains only
  the check time, master fingerprint when available, raw `r`, a
  domain-separated SHA-256 tag for the exact signing key, a tagged message or
  source identity, and a verification flag — never the PSBT, transaction,
  signature, public key, or message digest. The exact-key tag prevents child
  keys sharing a master fingerprint from being conflated. It can confirm reuse
  only when the same key/`r` pair has different verified message digests;
  incomplete records produce a warning instead. The file is
  correlation-sensitive metadata and should remain offline. Nothing persists
  unless it is downloaded.
- With a session seed, root xprv, WIF, or hex key, labels each output as
  change, receive, or not in this wallet (accounts 0–2, 50 receive + 50
  change, all four script types). A two-or-more-output transaction with no
  matching change is a blocking warning. OP_RETURN outputs are decoded for size and a text/hex
  preview; the tool does not create data-carrier outputs.
- Scans PSBT tap-leaf scripts and finalized witnesses for inscription envelopes
  (`OP_FALSE OP_IF "ord"`). Reports content-type, size, and text previews; does
  not number sats, fetch chain data, create inscriptions, or render images.
- Edits PSBT v0 and v2 (BIP-370) files field by field (a bip174.org-style
  editor backed by
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
  whether a change is safe. An edited PSBT too large for a static QR code is
  shown as an animated `ur:crypto-psbt` fragment sequence for air-gapped
  scanning, and an **Insane editing** switch lifts the consensus-layer checks
  for deliberately broken files while still listing their problems. The
  editor never signs anything.
- Verifies and extends Bitcoin Core descriptor wallets (Core Wallet tab):
  upload a SQLite `wallet.dat` (Bitcoin Core 23+; legacy Berkeley DB wallets
  are refused) and every record is decoded — client versions, wallet flags,
  sync locators, descriptors with their cached branch parents and private-key
  records, and the active scriptPubKey pointers — then re-checked claim by
  claim: descriptor checksums and recomputed DescriptorIDs, cache parents
  re-derived from the account keys (an honest warning where a descriptor
  shape sits outside that re-derivation, never a silent pass), private-key
  records against their pubkeys
  and record hashes, the network magic against the chain's genesis hash, and
  every descriptor key's xpub/tpub version against that network.
  Private key material is listed but redacted unless a reveal toggle is on.
  Additional ranged descriptors (watch-only or, into a wallet that already
  signs, private) can be appended; the rebuilt database is re-parsed and
  re-verified before it downloads (an edited file that fails any check is not
  offered), and records the tool does not decode are preserved byte-for-byte.
  As with Core, a private descriptor is refused by a disable-private-keys
  wallet, and a descriptor whose keys belong to another network is refused. A signing wallet's proven key material can also
  move into a Key Station slot for review: the private key records are
  reassembled into the exact root or account xprv they belong to (given the
  descriptor's own public bookkeeping) — only when the secret provably matches
  the record's pubkey and the embedded extended key — and the Key Station
  opens with the key filled in for the user to derive and compare by hand,
  on the wallet's own chain (a regtest wallet derives `bcrt1…`).
  Only the standard path the Key Station derives is accepted (a master key
  with its purpose/coin/account-0 tail, or an account key on `/0/*` or
  `/1/*`); a non-standard path is skipped, because the fingerprint would
  still match while every address would not. Watch-only and Core-encrypted
  wallets are refused outright.
- Derives BIP-85 child entropy from the active key's BIP32 root (or a pasted
  root xprv): English BIP-39 mnemonics (12–24 words), HD-seed WIF, XPRV, HEX,
  and Base64/Base85 passwords. Same parent, application, and index always
  reproduce the same child — this is a calculator, not a generator. Children
  follow the published BIP-85 vectors and match COLDCARD, including derivation
  from a passphrase-extended root when a BIP-39 passphrase is in effect.
  Unremoved BIP-39 and XPRV children can be selected as HD roots in BIP-85,
  Silent Payments, Vanity, PSBT/Nonce inspection, and multisig; WIF children
  can be selected for PSBT/Nonce inspection. Their pickers show the parent
  LifeHash, an arrow, then the child LifeHash and fingerprint. Deleting a child
  removes its picker options and wipes any private sessions loaded from it.
  Vanity matches from an immutable child can be searched and copied, but not
  written back to that child.
- Derives BIP-352 Silent Payment addresses (`sp1q…` / `tsp1q…`) from a seed or
  root xprv, including labeled codes, BIP-392 `spscan` / `spspend` descriptors,
  sender taproot outputs from pasted vin JSON, and receiver verification of
  pasted x-only outputs. Prints a BIP-321 `bitcoin:?sp=` URI and the BIP-353
  DNS TXT to paste on a domain you control; paste that URI back on Send.
  Hybrid URIs with an ordinary Bitcoin fallback address still use Silent
  Payments; the results identify the fallback address as not used.
  This is a calculator: it does not scan the chain or resolve names.
- Grinds vanity addresses for a Key Station key or a compatible BIP-85 child
  (Vanity tab), picked through the same chip picker as BIP-85 and Silent
  Payments. Two methods: the **passphrase grind** extends the key's BIP39
  passphrase with base-62 odometer counter characters, the **derivation grind**
  keeps the passphrase and steps through BIP32 account indexes. Every
  candidate is derived the standard way (PBKDF2 seed, BIP32 path — the key's
  own purpose, account, branch, and address index) in a dedicated WebAssembly module, one Web Worker
  per CPU core, and its mainnet address of the selected type (legacy, nested
  SegWit, native SegWit, Taproot, or a BIP-352 Silent Payment code) is checked
  against the chosen prefix. For Silent Payment codes, the first custom
  character is limited to `g f 2 t v d w 0`; later characters can use the
  full Bech32 alphabet. A short timing sample on tab entry (fixed
  published constants, never the session's keys) turns the odds into an
  expected time to a match, and **Stop on first find** halts the grind at the
  first hit. Same key and counter always reproduce the same
  address, so nothing is invented. For a Key Station source, **Update key**
  writes a found passphrase or account index back to the key and re-derives it,
  so the Keys tab, its exports, and the Journal show the vanity wallet. BIP-85
  children stay unchanged. Found passphrases stay in
  page memory, are masked until revealed, and are wiped with the session.
- Derives Lightning node identity public keys (a Lightning tab held back from
  release navigation while its UI is polished) from a seed
  phrase: an LND 24-word **aezeed** cipher seed is deciphered in WebAssembly
  (scrypt key derivation, AEZ v5, CRC-32C checksum; a wrong passphrase is
  detected, unlike BIP39) and its entropy derives the node key at LND's
  `m/1017'/coinType'/6'/0/0` keychain path, while a BIP-39 phrase follows the
  ldk-node convention (BIP39 seed, master key, re-seeded second BIP32 tree,
  node secret at `m/0'`). The decoded cipher seed's internal version and
  wallet birthday are shown alongside the node key; the decoded entropy and
  salt and the BIP32 root xprv (what `chantools showrootkey` prints) sit
  behind a reveal toggle. Decoding only: the tab never creates seeds.
- A session **Journal** has three working areas: **Notes**, **Keys**, and
  **Session**. Notes opens first; Keys holds recoverable key inputs, and
  Session shows the current report first, saved historical snapshots in their
  own disclosure, and the **Debug log** separately. Current and saved reports
  have independent reveal, copy, and export controls; revealed labels use the
  same red cue as private data elsewhere. In live and saved snapshots, private field
  labels are red and their values blue, using the same styles as derived keys;
  public fields keep their ordinary styling. Saved snapshots, including older
  backups and files opened through **Open report**, highlight recognized report
  fields without changing their text. Unrecognized text stays plain; coloring
  does not verify saved contents. Copy and export preserve the original text.
  Multisig reports include public
  descriptors, paths, and displayed addresses.
  **Create journal** and **Open backup** are the starting choices. Section
  tabs and global controls stay hidden until the user creates a journal, with
  or without a password, or opens an existing backup. The create form reports
  whether password protection is enabled and checks confirmation matches live
  without exposing what was typed. A blank password is accepted and provides
  no access protection: anyone holding the resulting file can open it by
  leaving the password blank. Journal-wide backup and **Clear journal**
  actions remain available alongside protection and save status in every area.
  The complete backup contains every notes page and its formatting, all
  managed and archived key inputs, unfinished Key Station inputs, saved
  historical records, the session snapshot, and the debug log. The complete backup includes the current
  private recovery snapshot even when the on-screen snapshot is concealed.
  Unfinished Key Station inputs restore as a separate, unverified input set in
  Keys; they never replace the current working form or derive automatically.
  An empty working form consumes no backup slot. The 100-active-input limit
  includes an unfinished form; backup refuses overflow rather than omitting it.
  These limits apply to Journal storage, not standalone Key Station derivation.
  Changes to notes and key inputs mark the
  Journal as unsaved; edits made while a backup is encrypting remain unsaved.
  **Clear journal** opens a confirmation with choices to download a backup,
  discard the Journal, or cancel. Downloading keeps the Journal open: the page
  cannot verify that the file was saved, so discarding still requires an
  explicit choice. Cancel keeps the Journal intact. Discard wipes the
  password and Journal contents from page memory on a best-effort basis and
  returns to the create/open gate. Keys still open in Key Station remain
  there; End Session clears the whole page. Leaving the page still clears
  the Journal without this confirmation.
  The backup uses AES-256-GCM; the key is PBKDF2-SHA-256 (600,000 rounds) of the
  optional password the user chooses, with the salt derived from that password
  and the IV HMAC-SHA-256 of the plaintext. The file is a pure function of
  password and backup content; no CSPRNG is called. Nothing is stored in the
  browser; download a file to keep it. Closing the page discards the sitting.
  Opening a complete backup restores its Journal sections together. Saved
  snapshots are historical text, concealed until explicitly revealed; they do
  not recreate live wallets, multisig sessions, or PSBTs. Backup snapshots keep
  recovery material and descriptors but omit recomputable address and WIF rows;
  the live Session report and its separate export still include those rows.
  Reopening and saving without newly derived results does not append another
  snapshot. Changed derived results append a report while preserving earlier
  recovery material. The snapshot size limit remains explicit; export saved
  history before removing it if that limit is reached.
  **Open report** reads exported snapshot and Debug log files using the open
  Journal's password setting. Its read-only viewer starts concealed and never
  installs data into tools or the Journal. Closing the viewer, automatic
  concealment, or clearing the Journal releases its report text. Session offers
  **Remove saved snapshot** when history is present. Confirmation removes
  that history from this Journal and future backups while preserving current
  session data, notes, key inputs, and existing downloaded files; Cancel keeps
  it. Old entry-only files remain readable, and their records appear in Keys
  only when present.
  Existing saved records can be edited. Save or cancel an open record edit
  before downloading a complete backup. Changing its recovery inputs removes
  the old wallet association; changing its label or notes preserves it.
  Journal no longer creates manual entries or duplicate records on each
  derivation. Complete backups retain historical records and require the
  updated reader (payload version 3).
  Section-only exports remain secondary controls. **Clear debug log** asks for
  confirmation; Cancel keeps the log. Confirming removes its events and leaves
  one event marking the clear. Pending log exports cannot download the old log
  after it is cleared. The log follows new events only while the reader is
  already at the bottom.
  Recovery exports use the Journal's password setting; a password protects
  them, while files created without one have no access protection. The
  debug log export follows the same password setting.
  The **Keys** area exports all available source inputs and archived inputs
  into an `.elkeys` file. Its summaries use the app's shared text styles;
  public fingerprints, paths, and keys copy on click with inline feedback.
  Archived metadata wraps to keep the complete path readable.
  The file uses the open Journal's password setting without
  another password prompt, random salt, or random nonce. **Import key inputs**
  is available beside the Key Station action and previews the input names and
  archived count before changing the Journal. Encrypted key-input imports
  must use the current Journal's password; importing with a separate source
  password is not yet supported.
  **Import and derive** adds the new inputs and derives them in order, using
  each input's saved network; archived inputs stay archived. Canceling the
  preview leaves the Journal unchanged. An archive-only file imports its
  archived inputs without starting derivation. **Derive all pending** retries
  outstanding inputs, and **Review inputs** loads one into Key Station for
  editing, asking before replacing an unfinished draft. The saved network
  appears beside Derive Key and follows an explicit Network-menu change.
  Archiving the source or clearing Journal does not change that reviewed
  draft's network or bypass its duplicate checks.
  If Journal has been cleared and derivation reuses an existing key, the
  reviewed inputs remain in the Key Station draft.
  Imports remain **unverified inputs** until fresh derivation succeeds.
  Cached addresses, private outputs, fingerprints, and claimed identities
  from legacy files are discarded. New key files use input-only format
  version 2; version 1 files remain importable. Cached outputs cannot replace
  missing source inputs. A present passphrase must be text; malformed values
  reject the whole file before preview or installation.
  A freshly derived full-root identity (or compressed public key for an
  imported single key) and matching setup reuse the existing
  station key unchanged and archive the imported source inputs. The setup
  comparison includes network, scripts, paths, ranges, and available recovery
  material. If reviewed inputs were corrected before reusing an existing key,
  the original inputs and a separately labeled reviewed copy are retained in
  the archive. If the same wallet has a different setup, choose **Keep existing**
  to leave the imported inputs pending, **Add separate setup**, or **Stop
  deriving** to stop the batch. Account-level imports without a comparable
  root identity get separate station tabs.
  Failed and unprocessed inputs remain pending; stopping a batch keeps keys
  already added. Low-entropy and fingerprint-collision warnings still require
  their usual decisions. The batch preserves and restores the unfinished Key
  Station draft and previous station selection. Newly derived imported keys
  keep their names, with a numbered suffix if another key uses the same name;
  reusing an existing setup keeps that station key's name.
  Archiving is available for detached inputs and does not unload a live Key
  Station key. **Restore and derive** returns archived inputs to the active
  list and runs the same derivation and duplicate checks as import. Failed
  or stopped inputs stay available for review and retry. Archive rows show
  the saved method, network, and path to distinguish input sets before use.
  Deleting a Key Station tab while a Journal is open removes it from the
  station while retaining its inputs in the Journal.
  **Open all saved keys** returns multiple verified, detached keys to Key
  Station together, without deriving them again or changing pending inputs.
  Notes is a plain text editor with up to 100 named pages. Pages use
  the Key Station's numbered naming convention, can be added or removed with
  the +/− controls, and can be renamed by activating the selected page again
  or pressing F2. Default names such as `Page 1` shorten to `P1` in narrow
  windows. Notes defaults to the same monospace input text as the rest of
  the app. Appearance controls can customize each page's
  typeface, text size, and line spacing. The editor can be resized vertically.
  Its key picker lists derived Key Station keys, multisig wallets, and BIP-85
  children with their LifeHashes. Choosing one inserts a public inline
  reference; multisig references retain the wallet name, threshold, and ordered
  co-signer fingerprints, with unknown origins explicitly marked.
  Notes can import plain notebook JSON or a Journal-format export while the
  matching Journal is open.
  Switching pages retains each page's caret, selection, and scroll position
  for this sitting. Invalid or duplicate page names show a correction message.
  Names and note text remain exactly as entered when the interface language
  changes. Section imports accept encrypted exports up to 4 MiB; canceling
  an import or rejecting a file does not mark saved content as changed.
  New pages start with this computer's current local date and time.
  A placeholder beside each live timestamp disappears when editing begins;
  it is never included in copied notes or backups.
  **Ctrl/⌘+Enter** appends another timestamped block at the end of the
  page, preserving existing text and separating notes with a blank line.
  The new timestamp ticks each second until the first edit on that page,
  including typing, paste, deletion, undo, or starting input composition.
  Clicking, selecting, and scrolling leave it ticking without moving the
  caret or changing backup status. Deleting a note's entire body while leaving
  its final timestamp restarts that clock; Undo can recover the deleted text.
  Imported timestamp-only notes stay fixed until explicitly edited. Importing
  onto an untouched starter page replaces that starter instead of adding a
  redundant page.
  Enter continues the current note. Typing, clicking, and deleting never
  insert timestamps. Each line-start timestamp and its two following spaces
  are protected from partial edits, including timestamps in older backups.
  Select its complete note, through the text before the next timestamp, to
  delete it; selecting all clears the page. Body text and timestamp selections
  remain freely copyable. A refused drag into a protected timestamp restores
  the source text. Imported CRLF/CR newlines normalize to the editor's LF
  newlines, and lookalike references retain their literal spelling. Backspace
  immediately after an empty timestamp
  removes the complete timestamp and its two spaces together; a fully cleared
  page stays empty. Key
  references still select and delete as complete units. Moving the pointer over the editor briefly
  reveals its clipboard button at the right edge; the same control is reachable
  from the keyboard and copies the active page as readable text.
  Notes and Debug log copy controls read their current text only when clicked;
  they do not retain another copy of it on the button. The separate
  notes export encrypts versioned UTF-8 JSON containing page names, styles,
  and structured text/key runs. References contain public descriptive metadata,
  never key material or instructions to restore a wallet. Multisig references
  use text runs so older notebook readers preserve their contents.
  LifeHashes are regenerated locally when that file is uploaded in a later session. Older
  `.txt` notes can also be uploaded as a single page. The Journal also holds
  a read-only summary that updates as the sitting changes and a detailed debug
  log: navigation, appearance, tool and station changes, calculations and
  failures, safe setting changes, privacy toggles, copies, imports, downloads,
  clears, and PSBT structural edits. It retains up to **512 KiB of UTF-8 JSON
  event data or 10,000 events**, whichever comes first. At the limit it removes
  the oldest events and shows how many were removed. The reader shows 400
  events at a time, with Earlier, Newer, and Latest events controls; reading
  earlier history does not change what gets copied or exported. Opening a
  complete backup places its saved history before events already recorded in
  this browser session and combines their discarded-event counts. The same
  retention limits apply to the combined log; opening a legacy entry-only file
  also preserves this session's existing events.
  Backups from the original 400-event Journal remain readable within the
  512 KiB log limit; an unusually large older log is rejected explicitly,
  without trimming it. Backups with more events require this updated reader.
  The existing overall backup and
  file-size limits still apply. New events record public
  fingerprints where useful, but omit secret-field values, raw derivation-path
  input, filenames, note bodies, PSBT bytes, and individual entry keystrokes.
  Imported event text is unverified and may contain sensitive information.
  Display, Copy, and Export escape control characters and invisible separators
  so an imported field cannot impersonate another event; backups retain the
  original field data.
  **Copy debug log** copies all retained events as plain text. **Export debug
  log** downloads an encrypted report using the Journal's password setting.
  Both capture the log when clicked, before adding their own outcome events,
  and include a notice if older events have been removed.
  Requests and completed operations are distinguished; a download starting does
  not confirm that the file was saved. The exported report keeps the existing
  format and remains readable through **Open report**. **Clear debug log**
  offers **Export first**, **Clear**, and **Cancel**. Export first keeps the
  log and dialog open so you can check the downloaded file before explicitly
  clearing. Clear removes only the log and its discarded count, then records
  one clear event. Cancelling an export still being prepared prevents its
  download handoff. Nothing is stored in the
  browser; download a file to keep it. Closing the page discards the sitting.
- Runs a quick barrage of startup sanity checks on the host browser (secure
  context, CSPRNG, BigInt, UTF-8 encoding, NFKD, and WebAssembly). If any
  check fails, the page is replaced with a failure report listing the failed
  checks, because wallet output from a broken host cannot be trusted.
  iPhone/iPad/Mac Lockdown Mode blocks WebAssembly (the secp256k1 engine):
  exclude the site in Safari's page menu, or open the saved HTML in Firefox
  on an air-gapped computer. There is no JavaScript secp256k1 fallback.
- Before any input is wired, runs published test vectors (BIP39 encoding and
  seed, BIP32 private and public derivation, the BIP44/49/84/86 first receive
  addresses, and an RFC 6979 ECDSA signature and its verification) through the
  same WebAssembly engine the calculator uses, and kills the page the same way
  if this browser computes any of them wrong. The separate PSBT module gets the
  same treatment once it loads: BIP-174 and BIP-370 decodes, a byte-exact
  rebuild through the editor's own path, rejection of an invalid file, and the
  BIP-341 Taproot sighash-byte rule. It catches a miscompiling engine
  or a corrupted copy; it cannot catch an exploit aimed at the vectors
  themselves, so for anything that matters, compare the master fingerprint and
  first address against a second browser or signing device too.
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
- A derived multisig can export a watch-only Bitcoin Core `wallet.dat` (same
  SQLite descriptor wallet as Key Station, never with private keys) and the
  `importdescriptors` JSON for a blank `disable_private_keys` wallet. Drop the
  `.dat` in `wallets/<name>/` and `loadwallet`, or feed the JSON to
  `bitcoin-cli importdescriptors`. A derived multisig also prints and saves a
  one-page watch-only policy sheet (network, `m-of-n`, co-signer fingerprints,
  descriptor checksum, receive address 0) so every signer can verify the
  policy before funding, and a BIP 388 wallet policy (template + xpubs) for
  wallets that register policies. Calculator export, not a generator.
- On a derived key, **Edit Input** loads its inputs into Key Station.
  **Derive New Key** creates a separate tab, including for identical inputs.
  The secondary action, **Update Existing Key**, replaces only that source
  tab after successful derivation. Custom tab names survive updates; a tab
  still named for its fingerprint follows the key if that fingerprint changes.
- MS Station keeps a session key selected when its co-signer derivation path
  changes. Clicking that selected key removes it; using it on another
  co-signer still requires opting into key reuse and distinct derivation paths.
  On a derived multisig, **Edit Input** loads its inputs into MS Station.
  **Derive New Multisig** creates a separate tab and preserves existing
  multisigs, even when the inputs are identical. The secondary action,
  **Update Existing Multisig**, replaces that source tab after successful
  derivation.
  Multisig tabs display their saved names, including renames; updating an
  existing multisig preserves its name, and the edit note identifies it by
  its current tab name.
- An optional **Sync entropy across methods** checkbox (off by default) keeps
  direct dice, card, number-base, seed-word, and private-key representations in
  sync while input is entered. Each destination waits for enough bits to emit
  its next complete character. Hashed inputs update the non-hashed methods in
  one direction; edits to non-hashed methods never overwrite hashed inputs.
  With sync off, every dice-roll method retains its own independent transcript.
- SLIP-132 extended-key display is a prefix swap only (same payload, new
  version bytes and checksum). Import/derive shows the key as pasted, the
  account xpub/tpub, any account private-key export, and the descriptor
  (script in the descriptor, not the prefix). The master xpub/tpub is at `m`;
  the account xpub/tpub is at the selected account path. A generic xprv is
  re-prefixed only when the path/script match: x = legacy, y = nested BIP49,
  z = native BIP84, Y = nested BIP48 multisig, Z = native BIP48 native-msig.
  Testnet uses t / u / v / U / V. There is no Taproot SLIP prefix.
- Displayed private recovery material cannot be highlighted. Use the clipboard
  icon beside its label (or in its table row) to copy it. This covers seed-word
  previews, WIFs, extended private keys, private descriptors, entropy and seed
  hex, BIP-85 children, Silent Payments and Lightning secrets, and Journal
  readouts. Clipboard icons appear only when their private values are revealed;
  successful copying briefly shows a green checkmark. Editable input fields
  retain normal text editing.
- Public derivation values remain highlightable and copy when clicked.
  Their labels provide a compact clipboard icon where there is no QR button;
  QR-backed values keep their QR action without a duplicate clipboard icon.
  This includes fingerprints, public keys, extended public keys, descriptors,
  and addresses across the derivation tools.
- Gates each release behind a two-step disclaimer: the first step warns that
  the software is experimental, and the second names what the browser cannot
  protect (keys paged to disk, clipboard history, memory surviving close) and
  unlocks only after the reader types a proof digit — derived from how long
  the warning was read, never from a CSPRNG. Acceptance is remembered per
  version, so each new release asks again.
- Guards the session with just-in-time warnings: deriving from less entropy
  than recommended requires an explicit confirmation, and a newly derived key
  whose master fingerprint matches another open key asks before it is kept.
  While the page is offline, external reference links open as QR codes to
  scan with an online device instead of navigating.
- Offers optional on-screen keyboards for mouse-only entry of seed words,
  passphrases, private keys, and Base64/Base32 text, and a footer toggle
  between dark and light themes.
- Speaks five languages: a header selector switches the interface between
  English, German, Spanish, French, and Portuguese, with untranslated strings
  falling back to English.

## Usage

Download the self-contained `entropylab.html` from the
[official website](https://entropylab.online) or the
[releases page](https://github.com/OogaBoogaX/entropylab/releases), transfer it to a trusted
computer, disconnect that computer from all networks, and open the file in a
modern browser. For sensitive wallet material, use a dedicated air-gapped
machine and verify important addresses and descriptors with an independent
wallet or signing device before receiving funds. Before loading a real key, work
through the [computer hardening checklist](docs/Computer_Hardening_Checklist.md).

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
`CID.txt` (CIDv1 raw sha2-256 of those same bytes), a
[GitHub artifact attestation](https://github.com/OogaBoogaX/entropylab/attestations)
for the exact bytes built by CI, and an OpenTimestamps proof
(`entropylab.html.ots`) of that same digest. After downloading, verify:

```sh
sha256sum -c SHA256SUMS.txt
gh attestation verify entropylab.html -R OogaBoogaX/entropylab
```

The three WASM modules embedded in the HTML are committed as
`src/js/*-wasm-b64.js`; their digests are in `WASM-SHA256SUMS.txt`, committed
next to `SHA256SUMS.txt`. From a checkout of the release commit:

```sh
sha256sum -c WASM-SHA256SUMS.txt
```

The build is also **reproducible**: `entropylab.html` rebuilds byte-for-byte
from the source commit stamped in its footer, so "CI built these bytes from
that source" can be checked instead of trusted. Docker is the only
prerequisite — the pinned development image is the canonical build
environment (fixed Node, Rust, and clang):

```sh
git checkout <stamped-commit>   # the commit shown in the file's footer
docker compose run --rm dev bash -c "npm ci --ignore-scripts && npm run build"
sha256sum entropylab.html       # compare with SHA256SUMS.txt
```

One caveat after a Rust change: the stamped commit still carries the previous
committed WASM modules, so check out the artifact commit that published the
page (or any later commit whose `WASM-SHA256SUMS.txt` matches the published
one) instead — it stamps the same commit.

This rebuilds the HTML from source using the committed WASM modules as fixed
inputs. Rebuilding those modules (`npm run build:wasm` inside the same image)
uses the image's pinned clang. CI requires two such builds to match the
modules it publishes: the artifact commit and the Pages deploy wait for that
check. A host clang build is not those bytes. Rebuilds on other machines that
matched the published hashes, the page and the modules alike, are recorded in
[docs/Reproductions.md](docs/Reproductions.md), with how to add one.

The boundary is the image. The page and the WASM modules are reproducible
inside it: same commit, same digest. The Dockerfile pins the Ubuntu base by
digest, the package archive to one snapshot, and the Node, Rust and clang
versions; the image built from it is not itself bit-for-bit reproducible (the
three builders in docs/Reproductions.md got three image digests and the same
outputs). Its compilers are prebuilt binaries, trusted as a seed. This is not
a full-source bootstrap. Full-source chains exist, from a few hundred bytes of
hex assembler (hex0, GNU Mes) up to GCC and, in Guix, on to Rust through
mrustc, but EntropyLab's toolchain has not been built that way, and no one
has checked that such a build gives the same compiler or the same modules.
EntropyLab claims byte-identical builds inside the pinned image, not that the
compiler was built from an inspectable seed.

The checksum detects accidental corruption. The attestation (Sigstore) says
this repository's CI built those bytes. OpenTimestamps says the digest
existed as of a Bitcoin block, independently of GitHub. A newly committed
`.ots` is a *pending* calendar receipt, not a timestamp — do not call it
stamped until `ots info entropylab.html.ots` shows a Bitcoin attestation.
Then, on a machine with Bitcoin Core (a pruned node is fine):

```sh
ots verify entropylab.html
```

On **Windows**, `opentimestamps-client`'s `python-bitcoinlib` dependency
looks for OpenSSL as `libeay32.dll`, which stock Windows does not provide
(`LoadLibrary() argument 1 must be str, not None`). No full OpenSSL install
is needed: Git for Windows already ships it. Copy
`libcrypto-3-x64.dll` (and `libssl-3-x64.dll`) from
`C:\Program Files\Git\mingw64\bin\` into any PATH directory as
`libeay32.dll` and verification runs natively.

EntropyLab itself never stamps, upgrades, or verifies `.ots` files and never
talks to a calendar. The HTML stays air-gappable.

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
modules from their Rust/C sources (`npm run build:wasm`) is separate: CI
asserts it inside the pinned image, and
[docs/Reproductions.md](docs/Reproductions.md) records the rebuilds on other
machines. CI also runs the WASM binding tests against the fresh build (see
[Building from source](#building-from-source)).

An online version is available at [entropylab.online](https://entropylab.online)
for convenient access. Do not enter seed phrases, private keys, or other secret
wallet material into an internet-connected device; use the downloaded HTML on
a trusted air-gapped computer for sensitive operations.

EntropyLab does not generate wallet entropy, and it does not use browser
randomness anywhere. The BitBox and D++ coin-flip steps record a fixed
equivalent die face: any face in the Heads range derives the same word as any
other, so that choice never changes the resulting entropy. Wallet security
still depends on the quality and secrecy of the entropy, seed phrase,
passphrase, or private key supplied by the user.

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

### Do enough input bits or a good dice score prove my wallet is secure?

No. Displayed bit counts describe the input's capacity under assumptions:
dice rolls must be independent and fair, and card deals must come from
uniformly shuffled decks with independent reshuffles. The app cannot infer
those properties from the transcript. Hashing or converting the input to
24 words does not increase its unpredictability.

The dice panel checks face frequencies only. Repeating `123456` has balanced
counts but is predictable. Its χ² percentile is not the probability that
the die is fair, and passing the check does not certify randomness. This
limitation is consistent with [NIST's guidance on statistical randomness
tests](https://csrc.nist.gov/pubs/sp/800/22/r1/upd1/final).

A valid BIP39 checksum checks internal consistency; it does not prove that
the phrase is secret, random, or the intended backup. Every BIP39 passphrase
produces a seed, so a mistyped passphrase can lead to a different wallet
without an error. Verify the intended wallet independently before funding it.
See the [BIP39 specification](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki).

### How should I report a possible security problem?

Do not open a public issue for a suspected vulnerability involving incorrect
derivations, secret exposure, injected code, unexpected network access, or
possible loss of funds. Follow the private reporting instructions in
[SECURITY.md](SECURITY.md).

## Building from source

The build bundles the application with esbuild and inlines the result into a
single self-contained HTML file. The wallet cryptographic primitives run in
WebAssembly from the pinned Rust crates (below). The JavaScript bundle also
includes `uqr` (QR rendering) and `@scure/btc-signer` through
`src/js/script-builder.js`, which the PSBT editor uses to convert supplied
addresses to output scripts. Its bundled dependencies are part of the
production audit surface, even though the package is listed under
`devDependencies`. The `@noble`/`@scure` packages also serve as differential
test oracles; they are not exclusively test-only. `package-lock.json` pins
the complete dependency tree and the integrity hash of every downloaded
package.

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
`src/js/addresses.js`, and `src/js/bech32.js`. The PSBT editor and flow
visualizer render script addresses through the WASM `addressFromScript`
facade; the script builder's address-to-script conversion is the JavaScript
exception described above. The compiled artifact is committed as `src/js/entropylab-wasm-b64.js`, so building the
site needs only Node.js. CI
rebuilds it inside the pinned dev image, runs its test suite against the
fresh build, and commits that copy back to `rock` after each merge (the
same flow as the site artifact). The image pins clang; a host clang build
is not that copy. Build-host paths are remapped out of the binary.
[docs/Reproductions.md](docs/Reproductions.md) records the rebuilds of the
published hashes in that image on other machines.

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

To modify the Rust bindings (`entropylab-wasm/`, `psbt-wasm/`, `vanity-wasm/`),
Rust (with the `wasm32-unknown-unknown` target, installed automatically by
rustup) is also required; regenerate the committed artifacts with
`npm run build:wasm`.

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
│   ├── self-test-wasm.test.mjs       Tests for the boot self-test (oracle-checked vectors)
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
│       ├── self-test.js    Known-answer vectors run through the WASM before boot
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
npm run test:ci             # every test file except the two browser suites (what CI's "complete dependency-free suite" runs)
npm run test:validate       # validate source and security invariants
npm run test:browser        # test crypto, sanitization, networking, exports in a headless browser (Firefox in CI; Chrome/Chromium too when installed)
npm run build               # compile src/ into the generated root files
npm run build:wasm          # rebuild the committed crypto WASM artifact (needs Rust)
npm run verify              # verify the site artifact (entropylab.html, assets)
npm run ci                  # run test:ci, build, and verify in order
```

GitHub Actions builds the site first, then runs the same test steps for pull
requests and pushes to `rock`, stages the verified site (`entropylab.html`,
`assets/`) and deploys it to GitHub Pages. After a merge to
`rock`, a final job commits the rebuilt `entropylab.html`
back to the repository so the file stays downloadable; pull requests never
carry the generated output, so they stop conflicting on it. The staging step
copies the verified `entropylab.html` to a deployment-only `index.html`,
allowing both the site root and `/entropylab.html` to serve the same
application without committing a second application artifact. CI runs every
test file on every pull request: `npm run test:ci` and the two headless-Firefox
browser suites (`npm run test:browser`); locally the browser suites also run in
Chrome/Chromium when one is installed. Local checks and CI/CD use the same
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
