# EntropyLab — Adversarial Security Audit

**Date:** 2026-10-18
**Auditor:** Kimi (independent adversarial review; not a third-party sign-off)
**Target:** `C:\Users\steve\entropylab` — branch `rock`, commit
`684727bce1d46cbe58c39b07113ba76887eb7fdf` (2026-10-18 16:58:13 +0000),
which is `upstream/rock` and `upstream/HEAD` of `https://github.com/OogaBoogaX/entropylab`.
**Working tree:** clean at audit start and at every re-check during the audit
(untracked `Claude outputs/` only — prior agent outputs, not source). This
checkout tracks three remotes (`upstream` = OogaBoogaX, `origin` = MrHodlX
fork, `herogamer`); all claims below are about the local checkout of
`upstream/rock` at the SHA above, not about the live Pages deployment.

**Method:** Eight focused deep-dive passes (six parallel + two follow-up),
each instructed to verify claims by running the repository's own test files
(`node --test`) and by adversarial probes against the shipped modules; the
two headline findings were additionally re-verified by the lead auditor
reading the cited code directly. Full suite `npm test` run at the end.
Findings from the prior audit (docs/Adversarial_Audit.md, GPT-6, PR841
A1–A5) were excluded from re-reporting.

---

## 1. Architecture and attack-surface map (Phase 0)

- **Artifact model:** one self-contained `entropylab.html` built by
  `scripts/build.mjs` from `src/` (shell body injected into `index.html`).
  Crypto primitives live in three Rust→WASM crates
  (`entropylab-wasm` — BIP39/PBKDF2/CKD/secp256k1/tx-parse/sighash/aezeed,
  `psbt-wasm` — BIP174 parse/verify/scriptcode, `vanity-wasm` — key search),
  embedded as base64 modules at build time. One runtime npm dependency
  (`uqr` for QR encoding). No frameworks.
- **Trust boundaries identified:**
  1. User-typed entropy (dice/cards/hex/keys/mnemonics/BitBox transcripts) → conversion pipeline.
  2. Pasted/imported files and text (PSBTs, UR fragments, BIP321 URIs, descriptors, journal backups, key files) → parsers → DOM.
  3. QR payloads (camera scan / pasted) → same parser path.
  4. Translation catalogs (produced by external automation, loaded at runtime) → i18n sanitizer → DOM.
  5. Hardware-wallet transcripts (BitBox S2C / anti-exfil) → verifier.
  6. Service worker / Cache Storage (two whole-document caches, same-origin GET navigations only).
  7. Build/CI pipeline (npm deps, pinned Docker image, GitHub Actions, artifact publication).
- **Execution context:** browser tab, meta-CSP
  (`default-src 'none'; connect-src 'none'; form-action 'none'; base-uri
  'none'; object-src 'none'; img-src 'self' data:; script-src 'unsafe-inline'
  'wasm-unsafe-eval'; worker-src 'self' blob:`), framing killed in JS,
  `file://`-compatible (meta CSP applies there). Secrets live only in the
  open tab's DOM/memory; nothing secret is persisted (verified sweep).
- **Core product claim:** the app *never* generates entropy; it is a
  deterministic calculator from user-supplied material to wallet recovery
  data. This claim is swept and confirmed in §4.

## 2. Security invariants (Phase 1) and where they live

| # | Invariant | Enforcing code (verified this audit) |
|---|---|---|
| I1 | No code path manufactures randomness for secret material | Sweep: `crypto.getRandomValues` only as capability probe (`browser-check.js:50-56`), `Math.random` only in browser-check digit animation, `Date.now`/`performance.now` only for wallet.dat birthday/benchmarks; Rust crates compiled with no `rand` features; signing is RFC 6979 |
| I2 | User entropy converts bit-exactly; validation fails closed | `bip39.js` / `entropylab-wasm` — see §3.1 |
| I3 | Displayed transaction/PSBT = what would be signed | `psbt-wasm` verify + `psbt-viz`/`psbt-editor` — one divergence found (M1) |
| I4 | Secrets never persist (storage/cookies/cache) and never egress | No `fetch`/XHR/WS/`sendBeacon` anywhere in `src/js/` (grep-verified); storage sweep — only UI-preference localStorage keys; CSP `connect-src 'none'` |
| I5 | Secrets concealed on loss of attention | `conceal-on-leave.js` (blur/visibility/idle), pagehide wipes — print gap found (L5) |
| I6 | Untrusted markup never reaches HTML sinks unsanitized | All 134 `innerHTML`-class sinks in app.js route through escape/sanitizer chain; i18n catalog values pass allowlist sanitizer emitting from a fixed table |
| I7 | Imported cryptographic data cannot alter derivation or transaction semantics | PSBT parse fail-closed + byte-faithful round-trip; editor drops all signing-committing pairs on any edit |
| I8 | Hardware-device data treated as untrusted | BitBox transcript parse/compare only; anti-exfil commitment verified before acceptance (signing-path report, §3.7) |
| I9 | Same inputs → same outputs; no ambiguous derivation | Path parsers, version-byte checks, network-family asserts on every import path |
| I10 | Offline is real: no runtime fetch, no version skew hazards | Zero network APIs; SW caches only its two install documents, GET-only, same-origin |
| I11 | Supply chain: pinned, hash-verified, reproducible | Exact pins + integrity on every lockfile entry, `npm ci --ignore-scripts` universal, digest-pinned image, actions pinned to 40-hex SHAs, byte-reproducible build |
| I12 | Errors fail closed | browser-check and boot self-test kill the page; journal unlock throws on any GCM failure; PSBT problems block rebuild/export |

## 3. Findings

Severity reflects realistic impact in the stated threat model (air-gapped
single-user tab; attacker controls pasted data, QR content, imported files,
translation catalogs, or the CI pipeline; attacker does not control the
user's OS/browser).

### M1 — Medium · PSBT flow diagram can render a conflicting UTXO claim as clean, hiding what would actually be signed
**Where:** `src/js/psbt-viz.js:121-130` (`claimedPrevout`) vs
`psbt-wasm/src/verify.rs:1045-1057` (`input_claims`).
**Failure path:** when an input carries both `PSBT_IN_WITNESS_UTXO` and
`PSBT_IN_NON_WITNESS_UTXO`, the diagram's "they must agree" check compares
**only the amounts** (`witnessClaim.value === nonWitnessClaim.value`) and
then renders the non-witness claim's address with no conflict mark. The
consensus verifier compares amount **and** scriptPubKey and raises
`utxo_claim_conflict` as an error. A PSBT whose two claims have the same
1000 sats but different scripts (witness claim → P2WPKH, non-witness claim
→ P2PKH) therefore renders a clean input box naming the P2PKH address and a
clean fee line, while a BIP-143 segwit signer would sign over the *witness*
claim's scriptCode/amount — exactly the display-vs-signed divergence this
audit probes for. The error does appear in the problems list further down
the page and does gate rebuild/export, which is why this is not High.
**Verification:** probed by the deep-dive agent (crafted PSBT, real parser
and renderer: `problems` contains `utxo_claim_conflict/error`; `psbtVizHtml`
output contains the P2PKH address and no conflict marker; fee renders
clean); re-confirmed by lead auditor reading both code sites directly.

### L1 — Low · Hashed-cards entropy estimate overstates a single-deck deal by up to ~49 bits
**Where:** `src/js/app.js:3988` (duplicate-pool boundary in
`hodlParseCards`), `app.js:3967-3971` (`hodlCardWithoutReplacementBits`),
displayed at `app.js:4047`, consumed by the low-entropy warning at
`app.js:7116-7118`.
**Failure path:** every card past position `needed.first` is treated as a
draw from a *fresh full 52-card deck* (both the duplicate check and the bit
credit), but the "shuffle the deck again" instruction is only issued when
`needed.extra` is truthy — i.e. only for 24-word seeds. For 12/15/18/21-word
targets a user who continues one physical shuffle (the natural reading; the
dealt-cards display shows one continuous deal) produces a transcript that is
a prefix of one permutation, ceiling log2(52!) ≈ 225.6 bits, while the UI
reports e.g. `52 cards ≈ 274.3 bits`. The flattering-direction error is in
exactly the number a user relies on to judge margin. Derivation itself is
unaffected (hash includes all dealt cards; deterministic; low-entropy gate
fires on card count, so no gate bypass). Companion quirk, fail-safe
direction: a third shuffle's cards get falsely flagged as duplicates,
blocking derive.
**Verification:** probe run by the deep-dive agent extracting the real
functions (52-card single-deck deal for a 12-word seed: accepted, 0
duplicates, note reports 274.3 bits); re-confirmed by lead auditor reading
`hodlCardNeeded`/`hodlParseCards`/`hodlCardsEntropy`.

### L2 — Low · Legacy (pre-MUR) UR fragments from two different payloads reassemble without a whole-message check
**Where:** `src/js/psbt-ur.js:282-284` (legacy branch; the comment itself
notes fragments are "tied only by per-chunk checksums"). An attacker who can
substitute one displayed fragment (swapped printout, tampered animation)
with a same-index fragment of a different legacy-encoded PSBT of matching
declared length gets a spliced payload accepted: each fragment passes its
CRC-32, the CBOR length check passes, reassembly "succeeds". The MUR branch
got the whole-message CRC fix in the prior audit (C3-5); the legacy branch
was left as-is. Mitigation: the result feeds the display-only PSBT
inspector, which re-parses with full BIP-174 validation, so spliced blobs
are almost always rejected loudly there; legacy fragments only exist from
pre-MUR EntropyLab output. **Verification:** agent probe built two legacy
payloads, spliced fragment 2 of B into A, decoder accepted the mixed bytes.

### L3 — Low · A UTXO claim pair carrying keydata is decoded and displayed but not counted by fee/verify layers — with no problem raised
**Where:** `psbt-wasm/src/lib.rs:911-926` (witness-UTXO `decode_pair`
ignores keydata) vs `lib.rs:1113-1146` / `verify.rs:1020-1042` (require key
exactly `[0x01]`) and `src/js/psbt-viz.js:122-124` (accepts any decoded
pair). A PSBT with witness-UTXO key `01 00` shows its amount in the box and
diagram, but fee renders "unknown" and `problems` is empty — the two display
layers contradict with no explanatory entry. Fail-safe direction (nothing
vouched), so Low. **Verification:** agent probe (box shows 1,000 sats, fee
unknown, `problems: []`, rust-bitcoin error string displayed).

### L4 — Low · Whole-script fallback verifies partial signatures on legacy scripts that can never execute
**Where:** `psbt-wasm/src/scriptcode.rs:326-333` +
`psbt-wasm/src/verify.rs:369-373`. A legacy (SigVersion::BASE) script
containing `OP_CHECKSIGADD` (0xba, tapscript-only per BIP-342) fails
EvalScript on every path, so no signature in it can ever be consumed; but
`code_starts` returns the same "empty candidate set" shape as an honest
signature-free script, so `check_ecsa` falls back to the whole-script
scriptCode and can return `Ok` with no problem raised — inverting the
module's own contract ("a candidate verifies" ⇒ some execution accepts it).
Affects partial-sig diagnostics only (warning-level). **Verification:** code
trace + agent probe (invalid partial sig on `OP_1 OP_CHECKSIGADD` legacy
claim reported as "signature does not verify…", never "cannot be valid").

### L5 — Low · The conceal sweep never runs on print
**Where:** `src/js/conceal-on-leave.js:15-18` (only `blur`,
`visibilitychange`, idle timer); no `beforeprint`/`matchMedia("print")`
anywhere in `src/` (grep-verified). Revealing a seed/WIF table and pressing
Ctrl+P renders the live DOM in print preview without any conceal; the app's
own `window.print()` path (`app.js:2094-2112`) is synchronous and cannot
conceal mid-dialog. Mitigation: printing a deliberately revealed sheet is
equivalent to the existing "save unencrypted private sheet" feature; the
msig policy sheet is watch-only by construction. **Verification:** code
trace (absence certain; live print-preview blur behavior not exercised in a
browser during this audit — noted in §6).

### L6 — Low · Passwordless journal backups have a fully public key; forged files are accepted
**Where:** `src/js/journal.js:473,814-817` — AES/HMAC keys are PBKDF2 over
the empty password with a public fixed salt, so anyone can forge a journal
file a passwordless user's `openDocument` accepts. Injected Key Manager
entries are inert (strict allowlist, `result`/`needsDerivation` forced —
verified by probe and `test/keymanager-import-render.test.mjs`), so the
residual risk is content injection into a trusted private-notes surface
(fake "recovered phrase" entries a user might act on). The UI discloses the
mode twice (`app.js:16188`, `:16096`). Password-protected journals fail
closed on forged files, wrong passwords, and `iterations` tampering — all
probe-verified. Related Info: envelope metadata (`iterations`, `iv`) is
outside the AEAD, so a crafted file can set `iterations: 10_000_000` and
make each unlock attempt pay a multi-second PBKDF2 (bounded by
`JOURNAL_MAX_ITERATIONS`, user-initiated).

### L7 — Low · Service-worker install can cache two different revisions under one cache name
**Where:** `src/service-worker.js:9-16` — `cache.addAll` performs two
independent `cache: "reload"` fetches; during a rolling deploy the two
responses can be different revisions cached together. Bounded: both entries
are complete self-contained documents, so no intra-document version mixing
is possible (the worker serves only whole cached documents for navigations);
self-heals next cycle; no runtime/POST/secret response is ever cached
(verified). **Verification:** code trace + `test/pwa.test.mjs`.

### L8 — Low · `ots-upgrade.yml` upgrades and republishes any committed `.ots` proof without binding it to the current `entropylab.html` digest
**Where:** `.github/workflows/ots-upgrade.yml:39-68` — no
`sha256sum entropylab.html` anywhere in the file (grep-verified), unlike the
stamp job (`ci-cd.yml:654-660`), which does compare. A stray `.ots` for
foreign bytes on `rock` (admin direct push — `enforce_admins` is off — or a
revert of a stamp commit) would be upgraded to a full Bitcoin attestation
and pushed with `RELEASE_PUSH_TOKEN`; only `release-assets.yml:51-57`
detects it, at release time. Fix is two lines: refuse/skip when the proof's
digest differs from the checkout's HTML. Related Info: the stamp job's race
window between artifact push and checkout (`ci-cd.yml:631-677`) can leave
the committed `.ots` covering a digest the tree no longer carries until the
next run — self-healing.

### L9 — Low · Ledger of remaining Low/Info observations (each verified by the listed pass)

- **BitBox analyzer/parser disagree on a 5/6 in the first five rolls** —
  analyzer flags invalid + disables derive; parser silently skips as reroll,
  so the word preview can look complete on an input the card flags invalid.
  Fail-closed direction (button stays disabled). `app.js:3379-3383` vs
  `:5484-5491` vs `:6768`. (Entropy pass)
- **`bip39.js:102` decodes a non-ASCII byte-form passphrase leniently**
  (U+FFFD replacement instead of refusal). Not reachable from the UI
  (vault round-trips only typed text); recorded because the
  "displayed passphrase = hashed passphrase" invariant is enforced by
  construction, not validation. (Entropy pass)
- **`PassphraseVault.setBytes` decodes UTF-8 leniently; crafted bytes make
  `text()` throw** (`passphrase-vault.js:66-81,108-110` — no overlong/
  surrogate/0x10FFFF clamp; RangeError reproduced). No live path found that
  feeds malformed bytes; hardening item. (Input-parsing pass)
- **i18n sanitizer silently drops an unmatched closing allowlisted tag**
  (`i18n-sanitize.js:177-178`) — cosmetic. The sanitizer itself defeated a
  23-case bypass battery (duplicate attrs, `javascript:`, mixed case,
  SVG/script, unterminated quotes); output alphabet is closed. (Input pass)
- **`bip321.js:13` rewrites `+` to `%20`** (form-urlencoded convention)
  where BIP-21/RFC 3986 treats `+` literally — checked against every
  consumed param; no exploitable confusion in this app. (Input pass)
- **Dead "silent network switch" branch in `hodlSingleKeyWallet`**
  (`app.js:688`) with a note printed even for testnet WIFs — unreachable
  today (`hodlAssertPrivateKeyNetwork` guards the only call site), but a
  trap for future callers. (HD pass)
- **BIP-85 root loader skips the multisig-scope check** that Key Station
  import enforces (`app.js:11107-11117` vs `:1388`) — inconsistency only,
  derivation byte-correct. (HD pass)
- **Taproot ownership row for uncompressed keys fails closed** instead of
  using bytes 1..33 (`ownership.js:31-41`) — a correct Taproot row is
  missed; recorded so nobody "fixes" it into a wide slice. (HD pass)
- **Watch-only depth-0 ownership scan reports "no-session"** instead of
  "watch-only" (`ownership.js:147-158`) — fail-closed, messaging only. (HD pass)
- **BIP-85 "Use key" injects the parent root xprv into a plain input
  field** (`app.js:11144`) — the one place extended private material is
  written into a browser-managed field; pinned attributes + pagehide wipe
  mitigate. (Session pass)
- **Boot self-test coverage floor** — aezeed/scrypt/AEZ, BIP-85, silent
  payments, WIF/base58 checksums, Taproot signing are not in the boot gate
  (`self-test.js` header states this honestly). (Session pass)
- **Journal dead `verify` digest** (`journal.js:472`) — computed+wiped,
  used by nothing. **Unbounded entry size on authenticated files**
  (`journal.js:704-717`). **Deterministic salt** means same-password
  journals share one AES key (files linkable) — documented trade.
  **Synthetic-IV** leaks plaintext equality only (~2⁻⁴⁸ IV collision);
  encKey/ivKey independent halves — verified. (Journal pass)
- **`RELEASE_PUSH_TOKEN` expanded into the artifact push command line**
  (`ci-cd.yml:612`) — readable in `/proc` on the runner; single-tenant,
  masked; the project's own env-var guard covers other jobs. (Supply pass)
- **`persist-credentials` omitted in two workflows** (`jev-adversarial.yml:28-32`,
  `translate.yml:47,94`) — mitigated by `permissions: {}` / `contents: read`.
  **Node version drift** (`translate.yml:31` pins `"22"` vs `"22.23.2"`
  elsewhere). **`reproduce.mjs` varies only staging-path shape**, not
  TZ/HOME/umask (no build input reads them today; CI's runner-vs-image
  comparison does vary HOME/PATH). **Committed-WASM drift is warning-only
  by design** (`ci-cd.yml:808-810`). (Supply pass)
- **Coldcard/SeedSigner/Keystone/BitBox compatibility claims are
  self-referential** — pinned only against this repo's own hashing; no
  external vector in-repo establishes tool equivalence. Worst case: a
  wallet that differs from the named tool's, recoverable, transcript shown.
  (Entropy pass)

### L10 — Low · PSBT session identity is name-based and goes stale after vanity "Update key" (trace-verified, not demonstrated end-to-end)
**Where:** `src/js/app.js:17213-17215` (vanity apply refreshes `hodlSpSource`/`hodlBip85Source` but never `hodlPsbtSource`), contrast the deliberate BIP-85 handling at `app.js:11382-11386`; session text builder `app.js:9850`/`:10716`; run-stamp by name `app.js:10753-10755`.
**Failure path:** run a passphrase-grind, click "Update Key" (Key Station key re-keyed, new master fingerprint), return to the PSBT Inspector: the session still holds the *old* seed while its line names the same key; ownership ("change is ours") and RFC 6979 verdicts are then computed against the pre-update key under the post-update label. Same-named keys can also leave the run button blocked with a stale report on screen. Kept Low because the tool verifies, never signs, and every verdict is computed from the material actually loaded — mismatch shows as non-verification, never as false-clean. **Verification:** code trace only (UI session state; per project rules not unit-asserted) — flagged as the one finding not demonstrated with a running assertion.

## 3.1 Entropy conversion & seed creation (pass 1)
No randomness injection anywhere (I1 holds). Entropy conversion verified faithful: all five BIP39 lengths round-trip byte-exact incl. all-zero/all-0xff, differential vs `@scure/bip39` across BOM/NBSP/CJK/combining/whitespace passphrases with 0 mismatches; unknown word/wrong count/bad checksum refuse before any derivation (double validation JS+crate); last-word candidate sets exactly the checksum-valid words (brute-forced); hashed dice/cards use raw SHA-256 over disjoint alphabets with honest beyond-recommendation handling; aezeed passes LND published vectors with distinct error taxonomy and CRC-before-AEZ ordering. WASM boundary (`withInput`/`withOutput`/`el_free`) copies exactly and zeroes every buffer. Findings: L1, plus the two Info items in §L9.

## 3.2 HD derivation, keys, addresses (pass 2)
No exploitable finding. Malformed paths (`m/0//1`, `m/-1`, Unicode prime, ≥2^31) all throw; hardened-from-xpub fails closed; testnet/version-byte mismatches error on every import path (extended key re-versioning records the entry network and asserts family; WIF import asserts; silent-payment HRP checked post-decode); scalar range/on-curve validated by libsecp256k1 at every entry; BIP-85 matches official vectors with exact spec paths; bech32m mixed-case rejected before lowercasing; y/z-prefix imports force their script policy with a visible warning; depth/parent-fingerprint/chain-code structure enforced; residue wiped on success and error paths throughout (A1 regime intact). Ran 233 tests across 17 suites — all pass.

## 3.3 PSBT & transaction pipeline (pass 3)
The display-vs-signed question resolved into M1/L3; everything else held: unmodified inspect→build round-trip byte-identical (BIP-174 valid vector 2, probed); sighash names honest incl. nonstandard types and SIGHASH_SINGLE-without-output; non-witness-UTXO txid mismatch is an error; parser rejects non-canonical varints, trailing data, duplicate keys, v2-in-v0, with overflow-checked spans and allocation caps; editor drops every tx-committing pair type (0x02/07/08/13/14/1b/1c) on any edit and rolls back doc+anchor+stale state on rejection; scriptcode enumeration differential-tested against Bitcoin Core's `sighash.json` (500 vectors, 210 with separators) and BIP-143 examples; taproot sighash commits to the annex, 65-byte SIGHASH_DEFAULT refused on both sides; fee arithmetic BigInt with MAX_MONEY gates; verification-budget exhaustion is an error. 255 tests across 17 suites pass.

## 3.4 Untrusted input parsing & output encoding (pass 4)
All 134 HTML sinks in app.js enumerated and traced to escape/sanitizer chains — no gap found; hostile batteries against the i18n sanitizer (23 cases) and BIP321 parsing (17 cases) fully neutralized; MUR QR reassembly metadata+whole-message-CRC bound (BIP-352... BCR-2024-001 vectors pinned); no CSV exists (formula injection: none); wallet.dat private inclusion wired to reveal+content with filename/label consistency; JSON import paths prototype-pollution-safe (spread/allowlist semantics); size caps on every import path. Findings: L2, plus §L9 items. 298 pass / 6 bitcoind skips.

## 3.5 Session, storage, residue, offline integrity (pass 5)
No secret ever reaches any storage (grep-verified; only UI-preference localStorage keys); clipboard single-writer with masked fields copying nothing; End Session order wipe→WASM-retire→clipboard→DOM→close is fail-safe; security-log fixed event codes, bounded, cleared at pagehide; service worker navigation-only/GET-only/same-origin with content-derived version hash; zero network-capable APIs in the app; CSP as in §1 with framing kill; no postMessage/opener/BroadcastChannel foreign-message surface; lifehash fed only public fingerprints. Findings: L5, L7, plus §L9 items. 471 tests pass across the two batches run.

## 3.6 Supply chain, build, CI (pass 6)
Lockfile: exact pins, integrity on every entry, registry-only URLs, `npm ci --ignore-scripts` at all 16 call sites; no network input to the artifact (digest-pinned image, hash-pinned toolchain tarballs, actions pinned to 40-hex SHAs, OTS wheel-hash-locked); artifact digest chain build→test→attest→artifact→timestamp→Pages all re-verify the same sha256; no `pull_request_target`; test hooks provably absent from the release artifact (string-absence on the committed 6.8 MB HTML); CID.txt recompute matches and binds `entropylab.html` bytes; committed WASM b64 artifacts self-consistent and byte-identical to what the committed HTML embeds. Findings: L8, plus §L9 items. 60 tests pass.

## 3.7 Private-key use & signing paths (pass 7)
EntropyLab *never signs transactions* — no sign/finalize/extract path exists (verified); "private key use" means RFC 6979/low-R recomputation, Jade anti-exfil commitment verification, BIP-352 send-mode scalar derivation, and the vanity grinder. Key resolution (`hodlPrivForPub` exact pubkey match; `hodlPrivForPath` fingerprint **and** re-derive-and-recheck) failed every crafted-input probe (wrong path, wrong fingerprint, x-only, hybrid keydata → null, uniform messages). RFC 6979: `extraEntropy` CSPRNG explicitly rejected at the facade; grind bounded at 64 (Bitcoin Core unbounded — divergence theoretical, P ≈ 2⁻⁶⁴, hedged warning); no nonce or partial-sig storage anywhere. Anti-exfil commitment math verified against upstream secp256k1-zkp `s2c/main_impl.h` / `eccommit_impl.h` — the commitment IS verified, direction correct, malicious transcripts can only produce warnings and can never suppress the independent reuse verdicts. Key races generation-guarded; vanity candidates purely counter-derived with no RNG, private keys never cross worker→main (only counters/passphrase/public payload), buffers wiped per job with zero-on-free. Findings: L10, plus §L9 Info items. 111 tests pass (4 POSIX-only skips).

## 3.8 Journal crypto, keymanager, lightning, bip352, small crypto, tx-parse (pass 8)
Journal unlock fail-closed on wrong password/tamper/forgery (probe-verified with an independently reimplemented KDF); generation guard #389 has no TOCTOU window; keys non-extractable and never serialized; AEZ vendored diff documented (wiping only), exercised through LND's published cipherseed vectors in the shipped-artifact suite; keymanager strict allowlist renders crafted imports inert; lightning module derives only (no invoice parsing — nothing to signature-check), LND keyring paths match reference, differential vs `@scure/bip32`; bip352 passes all 28 official send+receive vector groups both directions with taproot output-key/NUMS handling matching the BIP text and all scalar/tweak range violations throwing; secp256k1 facade RFC 6979-identical to `@noble/curves`, DER strict, infinity/high-S handled; hashes/coders match NIST/RFC 4231/node:crypto vectors; `el_tx_parse` flat layout writer/reader agree field-for-field; **sighash differential fuzz is genuinely independent** (64 seeded cases vs `@scure/btc-signer`, byte-digest equality for BIP143, relabelled signatures must fail) — run, pass. browser-check cannot fail open in the shipped artifact. Findings: L6, plus §L9 items.

## 4. Bottom line

**No Critical or High finding.** One Medium (M1 — PSBT flow diagram can hide a UTXO-claim conflict behind a clean box), ten Low, and a set of Info/hardening notes. The core claims hold under adversarial probing: no entropy invention anywhere (I1), no secret persistence or egress (I4), no HTML-sink gap (I6), PSBT parsing/verification fail closed and byte-faithful (I7), supply chain pinned and reproducible (I11). The recurring weakness is not crypto but *display honesty* — M1, L1, L3 and the BitBox 5/6 quirk are all cases where one layer's verdict contradicts another's presentation.

**Highest-value fixes, in order:**
1. M1 — compare `scriptPubKey` (and value) in `claimedPrevout`, or render the conflict mark whenever the consensus layer raised `utxo_claim_conflict`.
2. L1 — either always instruct the reshuffle at `needed.first` (making the fresh-deck credit true), or credit continued same-deck draws their true residual entropy.
3. L8 — bind `ots-upgrade.yml` to the checkout's `entropylab.html` digest before upgrading/republishing a proof.
4. L6 — refuse passwordless journal files on import (or label the accepted file's provenance in-editor), and clamp `setBytes` code points ≤ 0x10FFFF.
5. L10 — refresh `hodlPsbtSource` (or re-stamp by fingerprint) on vanity "Update key" and station-key deletion.

## 5. Not inspected / limitations

- `test/browser.test.mjs` harness internals and `test/adversarial/harness.mjs`; the live-browser residue harness was not exercised in this audit (no browser run beyond the host suite).
- `cargo test` for all three Rust crates (no Rust toolchain on this host) — WASM correctness rests on the JS artifact suites and prior CI.
- `entropylab-wasm/src/aez/` internals beyond the documented `mod.rs` diff; `accessor.rs`/`aesround.rs`/`block.rs` assumed verbatim per provenance header.
- `scripts/residue-audit.mjs` internals (874 lines — import/exec surface only); full bodies of `i18n-translate.mjs`/`i18n-sync.mjs`/`i18n-sources.mjs`.
- Large app.js regions only grep-sampled: ~5.4k–11.8k (keyboard/seed-form builders) and ~13.6k–15.8k (Key Station render paths); the 38 `hodlPublic*Html` call sites were spot-checked, not exhaustively enumerated.
- Live GitHub repo settings (branch protection `enforce_admins` state, App permissions) inferred from workflows and their tests only; no Docker execution; no live Pages deployment comparison.
- Windows-host caveats: 4 POSIX-only test skips; the one `npm test` failure is the browser suite's temp-dir cleanup (`rmSync` EPERM on `%TEMP%`), an environment issue, not an application defect.
- Finding L10 is trace-verified only; M1/L1/L2/L3/L4/L6 were demonstrated with running probes; the rest are code-trace findings.

## 6. Validation commands run during this audit (all from repo root)

```sh
npm test                       # 2368 tests: 2355 pass, 12 skipped, 1 env-only failure (browser temp cleanup)
node --test test/psbt-wasm.test.mjs test/psbt-viz.test.mjs test/psbt-cost.test.mjs \
     test/psbt-nonwitness-utxo.test.mjs test/psbt-sighash.test.mjs test/psbt-codeseparator.test.mjs \
     test/psbt-consensus-scriptcode.test.mjs test/psbt-differential-fuzz.test.mjs \
     test/hdkey-differential-fuzz.test.mjs test/psbt-editor-tx.test.mjs test/script-builder.test.mjs \
     test/opreturn.test.mjs test/tx-ownership.test.mjs          # 255 pass (Area 3)
node --test test/bip85.test.mjs test/hdkey-bip39-wasm.test.mjs test/derivation-path.test.mjs \
     test/extended-private-keys.test.mjs test/secret-key-range.test.mjs test/slip132-import.test.mjs \
     test/slip132-display.test.mjs test/addresses-wasm.test.mjs test/address-match.test.mjs \
     test/descriptor.test.mjs test/single-private-key.test.mjs test/keymanager.test.mjs \
     test/keymanager-import-render.test.mjs test/ownership-hdkey-wipe.test.mjs \
     test/ownership-keys.test.mjs test/bip352.test.mjs test/hdkey-differential-fuzz.test.mjs
                                                                 # 233 pass (Area 2)
node --test test/journal.test.mjs test/journal-backup.test.mjs test/journal-wipe-race.test.mjs \
     test/private-data.test.mjs test/public-data.test.mjs test/clipboard.test.mjs \
     test/security-log.test.mjs test/conceal-on-leave.test.mjs   # 158 pass (Area 5a)
node --test test/end-session.test.mjs test/network-check.test.mjs test/browser-check.test.mjs \
     test/self-test-wasm.test.mjs test/pwa.test.mjs test/station-secrets.test.mjs \
     test/secret-clear.test.mjs test/residue-audit.test.mjs test/residue-browser.test.mjs \
     test/hidden-seed-mask.test.mjs test/extended-key-payload-wipe.test.mjs \
     test/secret-field-attributes.test.mjs test/secret-field-registry.test.mjs
                                                                 # 313 pass (Area 5b)
node --test test/cid.test.mjs test/toolchain-pin.test.mjs test/workflow-secrets-environment.test.mjs \
     test/workflow-ots-supply-chain.test.mjs test/workflow-translate.test.mjs \
     test/ci-completeness.test.mjs test/wasm-boundary.test.mjs test/i18n-gate.test.mjs
                                                                 # 60 pass (Area 6)
node --test test/psbt-anti-exfil.test.mjs test/rfc6979-antiexfil.test.mjs test/psbt-low-r.test.mjs \
     test/vanity-wasm.test.mjs test/private-key-getter-copies.test.mjs   # 64 pass (pass 7)
node --test test/key-switch-derivation-race.test.mjs test/psbt-output-derivation.test.mjs \
     test/sp-send-session.test.mjs                              # 31 pass (pass 7)
node --test test/psbt-schnorr-nonce.test.mjs test/jev-transport.test.mjs \
     test/adversarial-outcome.test.mjs                          # 16 pass, 4 skipped (pass 7)
node --test test/sighash-differential-fuzz.test.mjs             # 64 cases pass (pass 8)
```
Plus per-pass adversarial `node -e`/in-memory probes cited inline above, and the
lead auditor's independent source verification of M1 (`psbt-viz.js:121-130` vs
`verify.rs:1045-1057`) and L1 (`app.js:3957-3997,4041-4053`).

*Agreement on this finite corpus does not prove every input, device,
dependency, or security claim correct; the not-inspected list above bounds
this report's claims.*
