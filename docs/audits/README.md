# Audit archive and remediation ledger

Every red-team report is filed here, one file per pass, named
`YYYY-MM-DD-<auditor-or-scope>.md`. Reports are immutable once merged: a
correction, a refutation or a new reproduction is a new row in this ledger
with its own evidence, not an edit to the report.

The ledger is the record of what was fixed and what was not. A finding gets
one of:

- **Fixed** — with the commit and the test or probe that pins it.
- **Accepted open** — deliberately not fixed here, with the reason.
- **Not a vulnerability** — the report's claim was refuted, with the reason.
- **Incomplete** — partially fixed; the remaining part is named.

Verdicts come from an independent reviewer (Astra) and are quoted from the
review thread on PR #1000 / PR #1001. Where the reviewer and the report
disagree, both rows stay and the disagreement is named.

## Reports

| Date | File | Auditor | Reviewed at | Verdict source |
|---|---|---|---|---|
| 2026-10-18 | [`2026-10-18-adversarial-audit.md`](2026-10-18-adversarial-audit.md) | adversarial pass (Codex) | `684727bc` | report's own follow-up commits |
| 2026-10-19 | [`2026-10-19-kimi-k3-handoff.md`](2026-10-19-kimi-k3-handoff.md) | Kimi K3 | `1449839d` | PR #1001 review |
| 2026-10-20 | [`2026-10-20-deepseek-second-pass.md`](2026-10-20-deepseek-second-pass.md) | DeepSeek | `3e663cd4` | PR #1001 review |

Earlier ledger: [`../Adversarial_Audit.md`](../Adversarial_Audit.md) (2026-10-11).

## 2026-10-18 adversarial pass

| ID | Status | Evidence |
|---|---|---|
| M1 PSBT diagram hides a conflicting UTXO claim | Fixed | `2fae67ee`; `psbt-viz.js` conflict rows, singleton keydata refused (`psbt-wasm/src/lib.rs:886`) |
| L1 Hashed-cards entropy overstates a single deck | Fixed | `65a8c3c5` |
| L2 Legacy UR fragments reassemble without a whole-message check | Fixed (disclosure) | `1c2b7fd9` |
| L3 Keydata-bearing UTXO claim not counted by fee/verify | Fixed | `psbt-wasm/src/lib.rs:886` |
| L4 Whole-script fallback verifies impossible legacy partials | Accepted open | — |
| L5 Conceal sweep never runs on print | Fixed | print fallback in `conceal-on-leave.js:20-30` |
| L6 Passwordless journal backups have a public key | Accepted (disclosed) | acknowledgement flow `26790fde`, `18cdf371` |
| L7 Service worker can cache two revisions under one name | Fixed | `641578f2` |
| L8 OTS upgrade republishes without digest binding | Fixed | `28d530a8` |
| L9 Ledger of remaining Low/Info observations | Accepted (mixed) | per-item notes in the report; fixed items landed elsewhere |
| L10 PSBT session identity goes stale after vanity "Update key" | Fixed | `13f4ba22` |

## 2026-10-19 Kimi K3 handoff

All sixteen were verified closed by the reviewer on `a81a4395`, except
RT-WASMCORE-1, which was refuted.

| ID | Status |
|---|---|
| RT-SEEDFORMS-1, RT-JOURNAL-1, RT-KEYSTATION-1, RT-KEYSTATION-2, RT-VANITY-1, RT-WALLET-1, RT-WALLET-2, RT-DELTA-1, RT-DELTA-2, RT-PSBTRUST-1, RT-PSBTRUST-2, RT-PSBTJS-1, RT-ENTROPY-1, RT-SEEDFORMS-2, RT-SESSION-1 | Fixed |
| RT-WASMCORE-1 (hybrid pubkeys) | Not a vulnerability — libsecp accepts hybrid `0x06/0x07` with a parity check and the bytes denote the same point; script/address builders reject them |

Reviewer's caveat, quoted: the remaining JS copies were "distinct from the
validation-time `Array.from` copy removed for AR-07".

## 2026-10-20 DeepSeek second pass

| ID | Status | Evidence |
|---|---|---|
| RT-BUILD-1 Committed WASM predates the merged fixes | Incomplete — accepted | Publication job owns replacement; ruling on PR #1001 comment 6290296352. CI builds from source; no artifact is committed on the branch |
| RT-CONCEAL-2 Three secret surfaces outside conceal | Fixed | `2fae67ee`, `app.js:18061-18081`, `expandable.js:103-119`, `psbt-editor.js:1354` |
| RT-JSBOUNDARY-1 Abandoned JS copies of secrets | Fixed | `679eaa15`; six paths wiped in `finally`; `test/js-boundary-copies.test.mjs` retains the temporaries, including the two exception paths the reviewer probed (red pre-fix: 52-byte WIF kept) |
| RT-WASMRESIDUE-1 Only one crate wipes its heap | Fixed | `2fae67ee`; `psbt-wasm/src/lib.rs:71-77,127-155`, `vanity-wasm/src/lib.rs:172-199` |
| RT-VANITYPASS-1 Dead `#vanity-pass` feature and a test that fabricated it | Fixed | `2fae67ee`, `app.js:16966-16995` |
| Speculative: `clearSecretFields` not exception-isolated | Incomplete — accepted Info | Named wipes are guarded (`app.js:18088-18098`); the wallet-result loop at `18096` is not. No product trigger established |
| Speculative: deferred vanity chunk throw bypasses the wipe | Fixed | `vanity-worker.js:168-177` |

Also from the reviewer on the same review (not in either report):

| ID | Status | Evidence |
|---|---|---|
| AR-01…AR-11 (review of the fixes) | Fixed | `93e6746d`, `32f9f620`, `f1712b46` |
| Regtest editor renders `tb1` and refuses valid `bcrt1` | Fixed | `679eaa15`; `app.js:17741`, `script-builder.js:88`, `test/psbt-editor-network.test.mjs` |

## Known-open, accepted for this merge gate

Re-checked by the second pass; not re-reported. Only the armed-open item was
fixed on this branch.

| Item | Status | Evidence |
|---|---|---|
| Journal duplicate ids / stale `nextId` | Accepted open | `journal.js:739-741` |
| `file.text()` before the 4 MiB cap | Fixed | `File.size` is refused over `3 × limit + 3` bytes before the read; `test/journal-open-acknowledge.test.mjs` |
| Uncapped Silent Payments paste fields | Fixed | vin and output text plus item counts are bounded before parse/split; `test/sp-send-session.test.mjs` |
| bip352 redeem script not hash-checked | Accepted open | `bip352.js:207-212` |
| bip352 zero label tweak | Accepted open | `bip352.js:83-88,286-298` |
| Lone-surrogate passphrase | Accepted open | `bip39.js:102-112` |
| PBKDF2 iteration wrap | Not a product vulnerability | sole caller uses 2048 |
| BIP45 export buttons on unsupported shapes | Accepted open | `app.js:2191-2222` |
| HD wallet.dat path lacking msig xprv refusal | Not a product vulnerability | descriptors kept separate |
| `release-assets.yml` persists checkout credentials | Accepted open | `release-assets.yml:21-30` |
| Armed-open plaintext kept after acknowledgement | Fixed | `app.js:16634-16646` |

Plus the prior known-open set carried in the handoff (ledger above, BitBox
5/6, i18n sanitizer, bip321 `+`, invisible Unicode, bidi in PSBT text,
journal salt/IV, boot self-test floor, compatibility claims,
`RELEASE_PUSH_TOKEN`, reproduce variance, drift policy).

## Adding to the ledger

New report: add the file, a row in **Reports**, and one row per finding.
Never delete a row; supersede it. A "Fixed" row needs a commit and a test or
a probe that fails without the fix.
