# Changelog

Release notes for EntropyLab. Each release is a single self-contained
`entropylab.html`; verify it against the signed `SHA256SUMS.txt` before use.

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
