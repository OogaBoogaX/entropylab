# EntropyLab red-team handoff — for the next auditor

**Date written:** 2026-10-19. **Repo:** `C:\Users\steve\entropylab`, branch `rock`, HEAD `1449839d`
(audit ran at that commit; re-check `git log` before trusting anything here — fixes land fast).

## What this is

A state-of-the-audit brief so you can go deeper instead of re-covering ground. It lists:
(1) the rules of engagement, (2) every finding from this pass with its verification status,
(3) what was proven clean so you don't re-verify it, (4) the seams we know are still open
or under-tested — your real starting points.

## Rules of engagement (unchanged from the task owner)

- **Read-only.** Never modify the repo. Scratch/probe files only under `C:\Users\steve\tmp\<your-dir>\`.
  Never run `npm run build` (it rewrites artifacts). Running `node --test test/<file>.test.mjs`
  and `node -e` probes against the real shipped modules is the established, encouraged method.
- **Deliberate behaviors — NOT bugs:** low-entropy inputs are accepted (educational lab);
  short passphrases allowed; the Journal permits passwordless open after an explicit ack;
  the PSBT editor permits raw-transaction paste without UTXO verification (no chain access
  by design); the vanity grinder is deliberately slow WASM. Report these areas only when
  the implementation fails its own claims.
- **Severity realism, not count.** Ten verified findings beat fifty nits. Every finding needs:
  ID, severity, confidence (`Probe-verified` / `Trace-verified` / `Speculative`), file:line at
  current HEAD, minimal reproduction, minimal fix.
- No `cargo` and no browser on this host: review Rust in source, probe behavior through the
  prebuilt JS WASM wrappers; browser-behavior claims stay Trace-verified at best and must name
  the browser/version being reasoned about.

## How to probe (established patterns)

- **App functions:** `test/app-slice-harness.mjs` loads slices of the real `app.js` — used for
  journal, final-sigs, deletion-lifecycle and dice/card probes.
- **WASM wrappers:** instantiate exactly like `test/psbt-*.test.mjs`, `test/hdkey-bip39-wasm.test.mjs`,
  `test/vanity-wasm.test.mjs` do via `src/js/*-wasm-b64.js`.
- **Independent oracles (allowed, in node_modules):** `@scure/bip32`, `@scure/bip39`,
  `@noble/curves`, `@noble/hashes`, `node:crypto`.
- **SQLite:** `node:sqlite` (Node 24) and system `python3` sqlite3 verify generated wallet.dat
  bytes against the real C library.
- Prior probes are preserved in `C:\Users\steve\tmp\rt-*\` (rt-delta, rt-journal, rt-keystation,
  rt-psbtjs, rt-psbtrust, rt-vanity, rt-wasmcore, rt-wallet, rt-entropy, rt-misc, rt-supply,
  rt-session, rt-seedforms) — read them for reproduction, re-run freely.

## Findings of this pass (all verified; fix first if you're auditing, don't re-derive)

### Medium
- **RT-SEEDFORMS-1** — "Show passphrase" checkbox lacks `data-private-reveal`; conceal-on-leave
  (blur/hide/idle/print) never re-masks it. `app.js:4704` vs sweep `app.js:17877-17886`.
  Fix: mark the checkbox; add a conceal test.

### Low
- **RT-JOURNAL-1** — concurrent `hodlJournalUnlock()` bypasses the passwordless ack
  (double-click races arm→install). `app.js:16442-16487`. Fix: busy-guard.
- **RT-KEYSTATION-1** — delete/clear/ignore of a station key leaves live cloned sessions in
  PSBT/SP/BIP-85 tools (and xprv text in `#bip85-key`/`#sp-key`). `app.js:14221-14248`,
  `13698-13717`, `13304-13322`; cascade pattern exists at `hodlDeleteActiveBip85` (`11437-11465`).
- **RT-VANITY-1** — same gap: a grind sourced from a deleted key keeps running in up to 64
  workers holding its secret material.
- **RT-WALLET-1** — signet/regtest ownership scans use coin type 0 (`ownership.js:15-17`) while
  the app derives those wallets at coin type 1 (`app.js:219-222`); own outputs report `external`.
- **RT-DELTA-2** — final-sig candidate cap (`84f3aa1a`) bypassed: scriptCode pushes skip
  `addCandidate` (`app.js:10330`); ~58 s tab freeze worst case. Fix: route through `addCandidate`.
- **RT-PSBTJS-1** — `psbt-viz.js:123-133` `claimedPrevout` uses first-match in map order, not the
  set resolution its comment claims; bogus+proper claim pair → attacker-chosen box amount next to
  a clean fee. Widens known-open L3.
- **RT-PSBTRUST-2** — final-script policy enforced as consensus with false error texts
  (PUSHDATA1 pushes; uncompressed pubkeys), gating export. `verify.rs:699-714,893`.
- **RT-PSBTRUST-1** — taproot `SIGHASH_SINGLE`-without-output is silently unverifiable where the
  ECDSA analog is named. `verify.rs:619-620,665,960-964`.
- **RT-ENTROPY-1** — mnemonic tokenizer split: `app.js:185` normalizes `[^a-z\s]`→space while the
  analyzer (`app.js:4445`) tokenizes `/\S+/`; glued-with-`！` phrases enable Derive under a red flag.
- **RT-WASMCORE-1** — hybrid SEC pubkeys (0x06/0x07) accepted by `secp_verify`/`Point.fromBytes`
  vs the previous noble facade. `entropylab-wasm/src/lib.rs:181,283`.
- **RT-DELTA-1** — vault UTF-8 decoder accepts stray lead bytes (`9f bf`, `f9 bf bf bf`);
  fix `dacc362b` hole; `passphrase-vault.js:87,96-106`.
- **RT-SEEDFORMS-2** — dice `beforeinput` transcript expando survives End-Session wipe
  (`app.js:3595-3596` vs `17930-17935`).
- **RT-KEYSTATION-2** — `state.fields.pass` Uint8Arrays not zeroed on per-key drop paths.
- **RT-WALLET-2** — mixed branch window {1,2}: branch-2 addresses displayed, never exported.
- **RT-SESSION-1** — print conceal relies solely on `beforeprint`; no WebKit≤Safari-17 fallback
  (no print-CSS mask, no matchMedia listener). Confirm the Safari version boundary on real hardware.

### Info (verified, low/no exploitability)
Journal: duplicate-id shadow entries (`journal.js:503`), armed-open plaintext not discarded,
unbounded `file.text()` before the 4 MiB cap. Vanity: deferred-chunk throw bypasses wipeSecrets.
Misc: uncapped SP paste fields, bip352 redeem push-check skip, label-tweak-zero edge.
WasmCore: lone-surrogate passphrase leniency (`bip39.js:104`), pbkdf2 iterations>2^32 wrap,
bech32m bad-word error path drops word Vec unwiped (`lib.rs:1157-1164`).
Wallet: HD path lacks the msig private-material refusal; msig export buttons render for shapes
that throw on click. Supply: `release-assets.yml` checkout leaves persist-credentials default.
Delta: legacy-UR decoder (`psbt-ur.js`) is dead code at HEAD — L2's attack path is unreachable.
Env flake (not a defect): `test/psbt-scriptcode-dos.test.mjs:278` timing assertion.

## Known-open from prior audits (don't re-report)

L3 (UTXO claim keydata decode/display mismatch), L4 (legacy OP_CHECKSIGADD whole-script
fallback), BitBox 5/6 analyzer/parser quirk, `bip39.js:102` lenient byte decode, i18n sanitizer
unmatched-close-tag drop, `bip321.js` `+`→`%20`, invisible-Unicode gaps in the catalog
neutralizer, live bidi in PSBT text surfaces (incl. `inscription.js:373` preview), journal
deterministic salt/synthetic-IV (documented), boot self-test coverage floor, hardware-compat
self-referential claims, RELEASE_PUSH_TOKEN on cmdline, reproduce.mjs env variance,
committed-WASM drift warning-only. Ledger docs: `docs/Adversarial_Audit.md`,
`2026-10-18-adversarial-audit.md` (M1/L1/L2/L5/L7/L8/L10 are now FIXED and
probe-verified fixed this pass).

## Proven clean this pass — don't re-verify unless code changed

- 97,632-case PSBT mutation fuzz → zero traps. HD 1,008-case differential vs @scure/bip32.
  RFC6979 300/300 vs @noble/curves. BIP39/aezeed parity. Descriptor polymod vs Core v28 vector.
- wallet.dat integrity via real SQLite (multi-page B-trees, 5000-record synthetic); Core v28
  constants cross-verified against upstream sources; watch-only files contain zero prv bytes.
- WASM boundary wipes (incl. mid-call exceptions); vanity worker boundary clean (heap-snapshot
  instrumented); End-Session ordering fail-safe; bfcache re-clear; text-services observer covers
  dynamic fields; security-log fixed codes only.
- Supply chain: digest chain build→test→attest→timestamp→Pages verifies one sha256; actions
  40-hex pinned; test hooks absent from the artifact; CID.txt recompute matches; i18n gate sound.

## Where to go deeper (the seams that remain)

1. **psbt-wasm, un-driven paths:** legacy multisig companion-subset explosion via the real
   `MAX_MULTISIG_COMPANIONS` path (never driven to the cap); sanitize.rs CKD/scan budget
   exhaustion (bounds reviewed statically only); worst-case legacy sighash cost with a maximum
   ~100k-input tx under the 256-sighash budget (bounded, unmeasured); tapscript 2.5M-op leaf
   analysis measured only by a host test. Run MiRi/valgrind-class UB checks if you have a
   toolchain — no `unsafe`-block dynamic check has ever run here.
2. **Real-browser verification debt:** print-conceal on Safari ≤17 (RT-SESSION-1) and Firefox
   sanitizer/parser differential were never run; the live residue harness
   (`docs/Residue_Audit.md`) has never produced a successful full capture run on this host.
3. **Session-lifecycle class (ripe — one pattern, N sites):** RT-KEYSTATION-1/-2, RT-VANITY-1
   all come from delete/clear/update paths skipping consumer teardown. `hodlDeleteActiveBip85`
   (~`app.js:11437`) is the reference pattern; audit every mutating lifecycle function
   (msig delete, journal lock, station rename/detach, workspace switch) against every consumer
   holding cloned key material. Also check whether `fields.pass` residue exists on OTHER clone
   paths (update-in-place, import flows).
4. **WASM↔JS parity:** hybrid-pubkey acceptance (RT-WASMCORE-1) suggests systematically
   diffing every facade judgment against the noble/scure references — encoding strictness is
   the class that keeps paying out.
5. **Display-vs-signed (recurring weakness across three audits):** RT-PSBTJS-1 and M1's ancestor
   were both first-match/comment-vs-code divergences. Enumerate every renderer that consumes
   *sets* of PSBT pairs and check the selection logic against the consensus layer's.
6. **Journal crypto at the edges:** caps and ack landed recently; the ack state machine
   (arm/wipe/re-arm/generation) still yielded a race this week — model-check the remaining
   interleavings (create during armed open, export during unlock, wipe during decrypt).
7. **Unicode/tokenization (recurring):** RT-ENTROPY-1, RT-WASMCORE-3, the i18n neutralizer gaps
   are the same class — a second code path that sees different bytes/tokens than the one the
   user sees. Diff every analyzer-vs-parser pair and every display-vs-hash string.
8. **App.js cross-coverage:** fully covered this pass, but it is an 18k-line file edited daily;
   re-diff new sinks (`innerHTML|insertAdjacentHTML`) and new secret fields against
   `test/secret-field-registry*` after any merge.
