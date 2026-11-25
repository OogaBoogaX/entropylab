# Changelog

Release notes for EntropyLab. Each release is a single self-contained
`entropylab.html`; verify it against the signed `SHA256SUMS.txt` before use.

## v1.1.0 — 2026-11-24

### Security fixes

- **Fixes from the v1.0.0 → rock red-team audit (#1456)**: the signer audit
  now verifies finalized signatures (legacy, native and wrapped SegWit v0,
  Taproot key path) without blessing consensus-invalid fields, including
  NULLDUMMY for every multisig; the build stamp covers every file the build
  reads; ordinary phone photos fit the QR decoder's padded limits; and the
  v1.0.0 record separates the valid release assets from stale copies in its
  git tag.
- **Fixes from the red team of the release candidate (#1486 to #1491)**:
  - **Private key form**: a key entered as hex, a mini key or brain-wallet
    text keeps its format after it is derived. Before, the form went back to
    WIF, and a key file or Journal backup then re-derived the WIF slot
    (#1490). A file saved by an earlier build may still store the format as
    WIF: on import, pick the right format in the Private key form. The key
    itself is in the file.
  - **Key Station**: changing the Method or the seed length, a Secure entry
    word, or a Bitcoin Core tab import stops a running derivation, so a key
    can't store inputs its wallet was not derived from (#1489).
  - **PSBT Inspector**: the fee-bump (RBF) verdict is kept with the run,
    survives a language switch and "Show more", counts in the Overall line
    and names the address (#1487). An edit that changes nothing removes
    nothing; an edit that changes a field clears the whole result, so no
    verdict stays next to fields it was not computed from (#1491).
  - **Bitcoin Core tab**: wallets created by Bitcoin Core itself verify; the
    DescriptorID is computed from Core's own form of the descriptor (#1488).
  - **Signer audit**: finalized fields are verified with coherent, bounded
    context (#1486).
- **Fixes from the v1.0.0 audit**: #849, #852, #853, #854, #856, #863,
  #982, #984, #985, #986, #987, #988-#994, #996 and #1000.
- **PSBT Inspector checks hold on more input types**: the wrapped P2WPKH
  final-witness check compared the wrong 20 bytes (#849). A P2SH-wrapped segwit
  input whose scriptSig doesn't match its prevout is refused (#1018).
  Finalized wrapped-segwit inputs without their redeemScript are still
  checked (#890). Explicit `SIGHASH_DEFAULT` and native SegWit finalization
  rules are enforced (#953). Codeseparator scripts are marked unverifiable
  instead of passing (#857).
- **Nonce checks cover more signatures**: finalized wrapped and P2WSH inputs
  (#895), and Taproot (BIP340) nonces compared for reuse like ECDSA ones
  (#1051). The nonce report says whether RFC 6979 was recomputed, and for how
  many signatures (#1074).
- **PSBT Compare is exact**: maps are compared as multisets, and an invalid
  document never gets an "equal" verdict (#850). The reference cross-check
  fails on truncated errors (#852).
- **Bounded work on hostile PSBTs**: derivation and signature analysis are
  bounded (#983), input-side key work is bounded per render (#1059), and every
  PSBT view renders at most 500 inputs and outputs (#1052).
- **Refused inputs**:
  - a WIF from the wrong network family (#991);
  - a multisig extended key as a BIP-85 parent (#992);
  - a repeated key across BIP 388 policy slots (#1065);
  - malformed passphrases before BIP39 seed derivation (#1015), including
    malformed UTF-8 in the passphrase vault (#990) and U+0085 in the
    canonical-phrase guard (#1058);
  - a null passphrase, which no longer means "no passphrase" (#1030);
  - descriptor shapes the exporter or Bitcoin Core would not accept
    (#1039, #1057);
  - an uncompressed key in `rawtr()`, which is no longer treated as public
    (#1385).
- **Fewer copies of secrets in memory**:
  - the seed is derived from bytes, never a whole-phrase string (#1212, #1228);
  - intermediate copies are wiped across PSBT/SP scanning (#853), nonce and
    RFC 6979 inspection (#858), JS boundaries (#959, #1000, #1001), wallet.dat
    key records (#1023, #1064) and the master-fingerprint preview (#1237);
  - no unused text copies of seed entropy (#1205);
  - each wallet-result wipe in the page-hide sweep is isolated, so one failure
    can't skip the rest (#1017).
- **Concealing on leave and print**: the Journal's session snapshot is
  concealed on leave (#863), and revealed secrets are concealed when a print
  job begins (#985).
- **Journal files**: bounded at every parse layer and refused by size before
  reading (#989, #1005). Duplicate entry ids are refused (#1002). A
  passwordless open is acknowledged before entries load, and the pending
  acknowledgement is forgotten on wipe (#984, #996).
- **Vanity** fails closed on inconsistent match records and mid-grind key
  edits (#859). The PSBT session reloads when Update Key rewrites its key
  (#981).
- **Smaller fixes**:
  - hashed card deals get only their true one-deck entropy credit (#980);
  - the OTS upgrade is bound to the published page's digest (#982);
  - two service-worker revisions never share a cache name (#987);
  - legacy multi-part UR reassembly now says it isn't whole-message verified
    (#986);
  - Silent Payments paste parsing is bounded (#1004);
  - wallet.dat and BIP 388 controls are gated on descriptor tail support
    (#1003);
  - a malformed address-shaped output is an error in the script builder (#955),
    and a mistyped Base58 address of address shape never becomes OP_RETURN
    text (#1354).
- **Private values use an in-app clipboard**: copy icons on private values
  copy only within EntropyLab, never to the system clipboard, so copied seeds
  and private keys can't be pasted into other apps; the in-app clipboard is
  zeroed at End Session (#1347).
- **End Session** clears EntropyLab's saved preferences, except the language
  (#1230), and wipes even when a camera capture fails to clear (#1311).
  Clearing a PSBT upload retires pending file reads, and a file's size is
  checked before it is read (#1356).
- **From the v1.1.0 red team** (a full audit of the release candidate):
  - **Bitcoin Core tab**: a wallet that holds only a master key record counts as
    encrypted, so a private descriptor can't be written into it in plaintext
    (#1455);
  - **PSBT Inspector**: one oversized derivation record can no longer switch
    off the "PSBT lies" warning on every later output (#1457);
  - **Global sync**: a private key always syncs into 24 words, never a cut-off
    12, and the page says the words aren't a backup of the key (#1459). A hex
    key with a non-hex character (#1440), a zero key or one at or above the
    group order (#1480) publishes nothing;
  - **MultiSig**: the co-signer field refuses BIP45 key shapes it would have
    read as a different wallet (#1460);
  - **PSBT Inspector and Editor**: a huge derivation path can't freeze the
    tab, a refused session key no longer stays behind, Taproot signatures
    are policy-checked, and editing a signed-over field drops the signatures
    (#1479);
  - **Script builder**: a bare `0x`, a bare small integer, an over-520-byte
    data push and a silent payment address no longer make an output anyone
    can spend or no one can (#1478);
  - **Fewer copies of secrets**: a words QR is matched as bytes, never split
    into strings (#1478), and parsed keys and seed bytes are wiped on every
    exit in Key Station, BIP-85 and the key scan (#1479, #1480);
  - **Bounded inputs**: an hsm_secret file over 1 KiB is refused before it is
    read (#1478), and pasted vanity counters are bounded (#1477).

### New

- **Secure entry, Scan SeedQR and Scan QR (private key) in Key Station**:
  - **Secure entry** is an optional switch, off on every load. It limits
    copies of secrets during entry: seed words go through a one-at-a-time
    word picker, a private key into a masked field, and hashed dice rolls
    onto a pad, never as page text.
  - **The scans** read a SeedQR, CompactSeedQR, BIP39 words or a WIF from the
    camera or a photo straight into Secure entry, after a confirmation that
    names the format.
  - Built in #1313, #1364, #1372, #1395, #1405, #1412 and #1447; fixed before
    shipping in #1439, #1441 and #1442.
- **Lightning tab** (after Transactions):
  - derive an LND (aezeed), ldk-node (BIP-39) or Core Lightning (hsm_secret)
    node key, in a terminable worker (#1045, #1126, #1167, #1203, #1211, #1222);
  - a BOLT11 invoice and BOLT12 offer decoder card (#1115, #1116, #1166, #1246);
  - the node key follows the page's network menu, and the tab's own Network
    dropdown is gone (#1428).
- **Bitcoin Core tab**: verify and extend a Bitcoin Core `wallet.dat` (#516,
  #1119, #1147). The tab was called "Core Wallet" while it was being built
  (#1494).
- **Journal tab** (#1086).
- **Verify workspace**: check OpenTimestamps proofs offline (#460, #1314).
- **Privacy tab** (formerly Silent Payments), with a station switcher and a
  BIP-47 payment codes station (#1243, #1256, #1280, #1286, #1329).
- **PSBT Inspector**:
  - the answer comes first, with detail one click away (#1145);
  - a Signer Audit for the PSBT you sent (#1080, #1102, #1118);
  - an RBF fee-bump check: does the bump only raise the fee? (#1164, #1176,
    #1206);
  - Privacy signals at the end of the result (#1302, #1363, #1399);
  - a warning on outputs to undefined witness versions (#821).
- **Nonce Inspector**: an anti-exfil transcript box for Jade, BitBox02 and
  AEXB, and a live anti-exfil QR observer (#1128, #1135, #1213, #1229, #1236,
  #1258, #1261, #1262, #1267, #1315).
- **Bitcoin Core checks**:
  - "Check a descriptor for key reuse", including duplicate keys across
    multipath branches (#1144, #1153);
  - "Copy Core deriveaddresses" (#1142, #1154);
  - "Download verification package", public data only (#1143, #1159);
  - all made visible by #1206;
  - Key Station exports watch-only Core descriptor JSON (#971).
- **MultiSig**: BIP-138 encrypted backup and open (#1374, #1396, #1398).
  Animated UR for watch-only descriptors and BIP-388 policies that don't fit
  one QR (#760).
- **QR**:
  - **Scan PSBT QR** on the PSBT Inspector, Nonce Inspector and PSBT Editor
    fields, the fee-bump original, the PSBT sent to the signer and the
    Editor's comparison PSBT. It reads one static QR or an animated
    `ur:crypto-psbt` sequence. Only a payload that starts with the PSBT magic
    is written, after the whole code has arrived. Clearing a tool, leaving
    Transactions, a language switch and End Session close the scanner and stop
    its camera (#1322, #1357, #1358, #1370).
  - **PSBT QR transports**: PSBT-only BBQr (`H`, `2`, `Z`) joins the reader.
    Complete pasted UR/BBQr transfers are accepted in the Editor and the
    Inspector, with bounded data, mixed transfers rejected, and SeedSigner and
    Coinkite interoperability vectors (#1375).
  - **Camera lifecycle**: one camera stream and one deadline across animated
    parts. A permission grant is rejected while the page is hidden or
    unfocused. Capture stops on cancel or when another panel takes over, and
    late grants and frames are ignored. Scans are continuous and focus-gated
    (#1404).
  - QR camera scanning for the public-text fields (#1373), and a labelled Copy
    button in the QR popup (#860).

### Changed

- **Copying private values no longer pastes into other apps**: see "Private
  values use an in-app clipboard" under Security fixes (#1347).
- **Passphrases starting with U+FEFF derive a different wallet than in
  v1.0.0** (#856): the BIP39 salt now hashes the leading U+FEFF
  the way the BIP39 reference does, and key-file export/import round-trips it
  byte-faithfully. A passphrase that begins with U+FEFF (pasted, never typed)
  opened the BOM-less wallet in v1.0.0; to reach that old wallet, enter the
  passphrase without the leading U+FEFF.
- **Notes where they help**:
  - a passphrase longer than 50 characters warns that some hardware wallets
    can't restore it (#1414);
  - a gap-limit note under both "Starting address index" fields (#1130).
- **Tabs**: the PSBT workspace is now "Transactions" (short "Txns") (#1079),
  and tool tabs show how many items they hold (#969).
- **Dice**: the frequency-test wording is clearer (#844). The PSBT Editor's
  input label is version-neutral (#1376).
- **Dialogs**: the background is inert, with focus fallbacks and dialog
  semantics (#1259).

### Fixed

- **Journal**: Unlock waits for the chosen file to finish reading (#889).
- **Passphrase field**:
  - pasted line breaks are stored the way a single-line field stores them
    (#1049);
  - the field empties when a refused entry empties the vault (#1062);
  - BIP39-word mode is refused for a stored passphrase with a line break
    (#1087);
  - a cancelled composition or a prevented edit can't corrupt the vault
    (#1027).
- **Silent Payments**: sending works from unsigned inputs with keys from the
  session, reads hex-string witness arrays, and skips hybrid keys (#1020,
  #1028).
- **PSBT diagram**: same-amount, different-script UTXO claims are marked as
  conflicts (#976). Multisig change-derivation records are no longer flagged
  as lies (#851). BIP-327 MuSig2 input types are named, and the diff treats
  them as signing (#854).
- **MultiSig Station**: wires the documented exports and covers the displayed
  address window in importdescriptors (#861).
- **Key Station**: changing the final word drops the old wallet in German,
  Spanish, French and Portuguese, as it already did in English (#1458). The
  D++ coin note names the right side (#1480).
- **Lightning**: a BOLT12 offer priced in a currency shows that currency, not
  msat (#1461).

### Translations

- More of the app is translated: the Key Station's runtime text and station
  tabs (#931), the Vanity station (#916), Multisig, Silent Payments and BIP-85
  (#970), and the inspectors' reports, which now repaint on a language switch
  (#945). The Verify workspace is translated too (#1314).
- Translation quality: a committed context file corrects and guides
  translations (#897). Mistranslations found in two audits are fixed (31 in
  #906, 39 in #1066), and terms are pinned to the catalog's own words (#918,
  #927, #940, #958, #1060). A missing or malformed audit verdict never
  publishes (#1355).

### Docs and verification

- A plain "Verify your download" guide (#1317).
- The guide's build-attestation check accepts only the CI workflow on `rock`
  (`--signer-workflow` and `--source-ref`; GitHub CLI 2.68.0 or later, #1493).
- A threat model, with SECURITY.md corrected on Taproot nonces (#1073).
- How EntropyLab is tested (#1036).
- The boundary of the reproducible-build claim (#847).
- Hardening: a private window in a profile with no extensions (#1384).
- v1.0.0 reproduction records (#718, #826).
- The security posture, with the evidence for each claim and its limits
  (`docs/SECURITY_POSTURE.md`, #1481).
- iPhone: keep iOS updated, and never keep a seed or SeedQR picture on the
  phone (#1462).

### Build and release

- **Development builds say so**: `rock` (and so the live site) carries version
  `1.1.0-dev`, so its footer reads `v1.1.0-dev · commit …` instead of the
  signed release's `v1.0.0` (#1406, #1409). A published release whose page
  still says `-dev` fails the release-assets check.
- **CI hardening**:
  - checkout credentials aren't persisted in scheduled or release workflows
    (#994, #1016);
  - attestation is scoped to a push-only job, and image downloads are pinned
    (#956);
  - the OpenTimestamps proof is stamped without the push token (#1047, #1127);
  - the release Environment's fencing of secret-bearing jobs is guarded (#886);
  - Node.js security releases are applied (#1040, #1189).
- **entropylab.online shows only signed releases**: it deploys a published,
  signed release's own `entropylab.html`, and a merge to `rock` never changes
  it (#1434). Development builds go to preview.entropylab.online, carry a
  banner saying they are unsigned, and stay out of search (#1448, #1453).
- **Builds**: the build stamps the actual source commit (#957), and a
  `--preview` flag lets unreleased features merge hidden (#1152). The build
  refuses inputs that would run or break out where it inlines them: links,
  `*/` or `</script` in the license banner and classic scripts, and markup
  outside a small allowlist in the logos (#1477).
- **Tests**:
  - the Bitcoin Core interop tests run against a pinned, verified bitcoind,
    now 32.1 (#1038, #1041, #1279);
  - a PSBT finalization differential suite against @scure/btc-signer (#1048);
  - a shared fuzz kit (#1046);
  - mutation-testing gaps closed (#864, #868, #1019, #1032, #1033).

Work in progress, hidden in release builds: the payjoin sender checklist,
wallet-backup recovery equivalence, MuSig2 verification (#1429) and the
per-input signer report.

## v1.0.0 — 2026-10-11

First stable release. Source commit
`c1037ba3a20d0c6db1b3265a7385b2944ce827e6`, the same commit as v1.0.0rc3:
the `entropylab.html` release asset is byte-identical to rc3 (SHA-256
`bdf048ebbf9286a3b18998f28e1cccef1f9f9a0284a880c1864875f903adeb8d`), so
the release `SHA256SUMS.txt` and four rc3 signatures in `SHA256SUMS.asc`
carry over unchanged.

The copies committed inside the v1.0.0 tag are from an earlier build, not
those release assets. Their page has SHA-256
`3804d57898224b8cfccfcacc8aa7c32cd93d514896de7e045e14ed35c22cf2f7`, and
their stale signature file does not verify against their stale manifest.
Use the release downloads; see
[Verify your download → known issue](docs/Verify_Your_Download.md#known-issue-v100).

No source changes since rc3. The release-candidate notes below describe what
1.0.0 ships.

## v1.0.0rc3 — 2026-10-10

Third release candidate for 1.0.0. Source commit
`c1037ba3a20d0c6db1b3265a7385b2944ce827e6`.

### Behaviour changes from rc2

- **Derived-key default addresses change from rc2** (#828): with the default
  BIP84 / Native SegWit input, **Match derivation purpose to script type** starts
  checked. Legacy, Nested SegWit, and Taproot now use `44h`, `49h`, and `86h`
  instead of `84h`; Native SegWit stays at `84h`. Their watch-only descriptors,
  `wallet.dat` exports, and recovery sheets follow those paths. Uncheck to
  restore the originally entered purpose and hardening for every script type,
  including the rc2 default of `84h` across all four tabs. The rest of the path
  and ranges stay unchanged.
- **LifeHash icons match the Blockchain Commons C++ reference** pixel for pixel
  (#831). About 1% of fingerprints, those on a float32 rounding boundary, show
  a slightly different icon than in rc2. Fingerprints, keys, and addresses are
  unchanged.

### Secrets and session hygiene

- Private readouts (recovery phrases, WIFs, private keys and descriptors,
  entropy, BIP-85 outputs, and other secrets) can no longer be selected; they
  copy only through explicit clipboard controls, and concealed, stale, or
  wiped values never reach the clipboard. Public outputs copy on click, and
  copy controls are consistent across tools (#827).
- End session tells Microsoft Edge users to quit Edge completely, since Edge
  kept copies of a copied seed phrase after the tab closed (#820, #816).

### Correctness

- Switching or removing saved key and multisig tabs during a derivation no
  longer lets one key's wallet land in another tab's state; in-flight
  derivations are cancelled (#830).
- Vanity: a partial worker-spawn failure ends the run instead of grinding
  zeroed key material and reporting matches for no real key (#830).
- Tapscript: the BIP-341 annex is recognised only when the witness has at
  least two elements (#830).

### Build, CI, and tooling

- New `fuzz-lifehash-cpp` CI job fuzzes LifeHash against the compiled C++
  reference at a pinned commit and gates the artifact and deploy (#831).

### Documentation

- `SECURITY.md` describes the clipboard copies Edge keeps and recommends fully
  quitting the browser (#827).
- The messaging stories clarify where computers must stay offline (#823).

### Translations

- Automated catalog updates for DE, ES, FR, and PT cover the strings added
  since rc2, including the Edge warning and the new copy labels (#836–#840).

## v1.0.0rc2 — 2026-10-07

Second release candidate for 1.0.0. Source commit
`7f48ec43dd8bb93734842918b07fbf896fdc8a7b`.

### Secrets and session hygiene

- **End session**: a header button that wipes the page, overwrites module
  memory with patterns before zeroing, retires the WASM modules, and closes
  the tab (#713, #732, #733, #735).
- **Passphrase vaults**: the BIP39 passphrase (#716) and the Silent Payments,
  PSBT, and Nonce passphrases (#734) no longer sit in their input fields.
- Secrets are kept away from browser translation, text services, and the
  screen (#711); Edge's translation markers are detected too (#787).
- Key payloads decoded by the extended-key and WIF helpers are zeroed (#712),
  and the private-key getters no longer leave unzeroed copies (#790).
- A live **security log** below Important records what the page did (#751,
  #781).
- New computer hardening checklist for the copies no page can reach
  (`docs/Computer_Hardening_Checklist.md`), including quitting the browser
  after End session and Edge Startup boost (#714, #807).

### Correctness

- PSBT: refuse key data on BIP-370 singleton fields (#696). This changes
  `src/js/psbt-wasm-b64.js`.
- Dice: recommend 100 rolls for 24-word hashed seeds (#775); the hashed
  methods are relabelled **Base 10 [1-6]** (COLDCARD / SeedSigner) and
  **Base 6 [0-5]** (Keystone), with no change to derivation (#809).
- Removed the unreachable D++ fairness analysis (#699).

### Interface

- Design tokens for text sizes, radii, spacing, and colours (#731), documented
  with the shared UI patterns in `docs/UI_Patterns.md` (#774).
- Restyled dropdowns and network menu, network detail lines, option checks,
  clear-button names, and vanity formula notes (#717, #752, #763).
- The page passes the W3C HTML checker with zero errors (#800, #801, #802).

### Translations

- Warning and QR strings are now extracted for translation (#701); the vanity
  estimate, copy labels, and QR popup are translated (#691); the attribute
  guard understands regex literals (#715).
- Automated catalog updates for DE, ES, FR, and PT.

### Build, CI, and tooling

- The footer stamps the last commit that changed a build input instead of
  HEAD, so docs, changelog, and signature commits no longer change
  `entropylab.html` or invalidate signed release sums; builds refuse a
  shallow clone (#819).
- Release secrets are read only from the rock-locked release environment
  (#702), and the OpenTimestamps client is hash-locked and kept away from the
  push token (#703).
- Published release assets are checked against the released HTML (#700).
- Dev-only browser memory-residue harness (`docs/Residue_Audit.md`) (#750,
  #792, #805).
- Windows and headless-Firefox fixes for the test suites (#710, #803, #806);
  the adversarial harness explains its dice-bits estimate and fails the run
  on real failures (#695).

### Documentation

- Vanity WASM crate in the build instructions (#804), a first draft of public
  copy in `docs/Messaging.md` (#698), and a clearer offline story (#789).

## v1.0.0rc1 — 2026-10-01

First release candidate for 1.0.0. Tag `v1.0.0rc1` at
`cb220887c052b18c767a32823214010b65ffdd3a`; `entropylab.html` SHA-256
`7f8685814e2bab0c80f75dd6d2cff1b3354bee51faecd65942a73e12968808a0`.

Everything since the 0.x line: Keys, MultiSig, PSBT (Inspector / Editor /
Nonce), BIP-85, Silent Payments, and Vanity stations; watch-only `wallet.dat`
/ `importdescriptors` exports; PSBT v0+v2 editing with animated
`ur:crypto-psbt` QR export; ECDSA nonce-reuse and RFC 6979 analysis; BIP-352
send/verify; the two-step release disclaimer; five-language interface
(EN/DE/ES/FR/PT); network picker (Bitcoin, Testnet, Signet, Regtest).
