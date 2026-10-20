# EntropyLab red-team audit — second pass

**Repo:** `C:\Users\steve\entropylab`, branch `rock`, HEAD `3e663cd4` (merge of PR #1000)  
**Prior report audited:** `2026-10-19-kimi-k3-handoff.md` (written at `1449839d`)  
**Method:** read-only. No tracked file was modified. Probes ran under `C:\Users\steve\tmp\rt-*\`; targeted test runs used `node --test`. No `cargo`, no browser on this host, so browser claims are Trace-verified against the DOM code, not runtime-tested; where a browser boundary matters I name Chromium 130 / Firefox 131 / Safari 18 as the reasoning target. Line numbers are at `3e663cd4` and differ from the handoff.

This pass re-verified every prior finding against the code, extended the incomplete ones, and hunted the seams the prior pass called clean. The short version: **the prior report is substantially accurate.** Two of its findings are wrong as stated (RT-WALLET-1's live consequence, RT-SESSION-1's Safari boundary), one has a wrong mechanism (RT-PSBTJS-1), one has a wrong half (RT-PSBTRUST-2's uncompressed-pubkey claim), and one is not a vulnerability at all (RT-WASMCORE-1). Everything else confirmed, several with a sharper reproduction. The most important new operational fact is that **the branch at this HEAD does not contain the WASM fixes it merged**: 10 tests fail and the committed artifact predates #1000.

---

## 1. High

### RT-BUILD-1 — The merged WASM fixes are not in the committed artifact; `npm test` is red at HEAD
**Confidence:** Probe-verified. **Status:** known-open ledger item ("committed-WASM drift warning-only"), now escalated — this is not theoretical drift.

`src/js/entropylab-wasm-b64.js` was last committed by `ef96e30f` (2026-10-18 16:57 UTC). All three #1000 Rust commits landed later (`be909248`, `bd3ce87e`, `e7fc426c`, 2026-10-19 20:33 -0400 = Oct 20 00:33 UTC). `entropylab.html` was last rebuilt by `ac22b218` at 14:31 UTC on Oct 19, also before the fixes.

Measured at HEAD:

```
node --test test/wipe-wasm.test.mjs test/addresses-wasm.test.mjs
ℹ tests 61
ℹ pass 51
ℹ fail 10
```

Failures include `bech32m encoding wipes temporary words on invalid word after a valid prefix` ("the copied words survived in WASM linear memory") and nine descriptor residue scans ("the parsed xprv private key survived in WASM linear memory"). These are exactly the behaviours #1000's source changes fix: `entropylab-wasm/src/lib.rs:1199-1220`, `descriptor.rs:186-203`, and the wiping allocator at `lib.rs:64-93`.

Why CI is green anyway: the `build-wasm` job (`.github/workflows/ci-cd.yml:175-225`) runs `npm run build:wasm` from source and tests *that* artifact, so it validates the source, not the checked-in bytes. The drift comparison at `ci-cd.yml:810` is a `::warning`, and the post-merge artifact commit has not landed at this HEAD. The released page may be assembled from freshly built bytes, but the repository state — the thing an auditor, a reproducer, or a user downloading the single-file build gets — ships the pre-fix binary.

**Repro:** the command above. **Minimal fix:** run `npm run build:wasm && npm run build` and commit the outputs before any release from this commit; make the `rock`/release drift check fail rather than warn, or add an assertion that the committed `*-b64.js` is reproducible from the checked-in Rust sources in the required `test` job. Do not "fix" the tests.

---

## 2. Medium

### RT-SEEDFORMS-1 — The revealed passphrase survives conceal, including print
**Confidence:** Trace-verified. **Prior:** confirmed.

The "Show passphrase" switch is built by the shared helper at `src/js/app.js:4704`:

```js
let reveal = hodlSwitchRowMarkup("passphrase-reveal", hodlT("Show passphrase"), ...)
```

`hodlSwitchRowMarkup` (`app.js:5624-5626`) emits only `id`, `aria-describedby` and `checked` — no `data-private-reveal`, unlike the privacy bar at `app.js:1878`. `hodlConcealPrivateValues` (`app.js:17876-17886`) therefore never flips it, and `hodlPassphraseShown` (`app.js:4480`) is reset only by the word-mode toggle or a clear (`app.js:5400`, `4511`, `4524`). In free-text mode `#pass` shows bullets, and the plaintext lives in the mirror `#passphrase-highlight`, filled at `app.js:4620-4622`. Blur, tab hidden, idle and `beforeprint` all leave the plaintext mirror on screen; printing renders it.

**Repro:** free-text passphrase → tick Show passphrase → click another window (or Ctrl+P). The highlight still holds the passphrase. **Fix:** give `hodlSwitchRowMarkup` an option that emits `data-private-reveal` and use it at `app.js:4704`; the existing `onchange` at `app.js:5389-5395` re-renders masked. Add a conceal regression test through the real conceal handler.

### RT-KEYSTATION-1 — Removing a key leaves every cloned secret session alive
**Confidence:** Probe-verified (app-slice harness) + Trace-verified. **Prior:** confirmed and extended.

`hodlDeleteActiveKey` (`app.js:14221-14248`) does one cascade: `hodlSpDropAddressesFrom("key:"+id)`. It never wipes the PSBT session root (`hodlPsbtHd`/`hodlPsbtPriv`/source), the BIP-85 parent (`hodlBip85Root`), the silent-payments station root (`hodlSpHd`/`hodlSpSource`), or the vanity run, and it never clears `#bip85-key` (`app.js:11215-11216`) or `#sp-key` (`app.js:11764-11766`), both of which hold a root xprv/mnemonic in plaintext. `hodlKeyManagerIgnore` (`app.js:13304-13323`) and `hodlKeyManagerDetachFromStation` (`app.js:13337-13350`) cascade *nothing* — not even the SP address tabs. The reference implementation is `hodlDeleteActiveBip85` (`app.js:11437-11465`), which tears down PSBT, SP, addresses and vanity when its source matches. Also confirmed: journal lock (`app.js:16533` → `hodlKeyManagerReset`, `13350-13367`) wipes only journal/key-manager state, leaving tool clones; workspace switch is explicitly non-wiping (`app.js:14754-14756`).

**Repro:** derive a key, load it into BIP-85 and Silent Payments, start a PSBT session and a vanity grind, then delete the key. `#bip85-key`/`#sp-key` remain populated, the working state still references the key, and the grind keeps running. **Fix:** one shared `hodlReleaseKeyConsumers(keyId)` (the `hodlDeleteActiveBip85` cascade generalised) called from clear, delete, ignore, detach and lock, plus `hodlVanityCancel()`.

### RT-JOURNAL-1 — A double-click installs a passwordless journal without the acknowledgement
**Confidence:** Probe-verified (real functions). **Prior:** confirmed and upgraded from Low.

`hodlJournalUnlock` (`app.js:16442-16490`) has no in-flight guard. Both concurrent calls `await hodlJournalOpenDocument` (`16456`); the first takes `opened`, fails the armed-token test and sets `hodlJournalOpenReadyFor` (`16458-16465`); the second then sees equality and installs (`16467-16473`), hiding the ready row. The probe reports:

```
single press  -> installed: false  ack visible: true   decryptions: 1
double press  -> installed: true   ack hidden: false   decryptions: 2
```

`src/shell.html:829` promises a second, knowing press. It also runs 600k-round PBKDF2 twice on the main thread. **Fix:** a boolean/disabled-button guard around the whole unlock, and call `hodlJournalDiscardOpened(opened)` before the armed `return` (the decrypted document is otherwise dropped to GC unwiped — known-open item, re-confirmed).

### RT-DELTA-2 — The final-signature candidate cap is bypassed
**Confidence:** Probe-verified. **Prior:** confirmed.

`addCandidate` (`app.js:10304-10318`) dedupes and caps at 32, but the scriptCode loop pushes directly (`app.js:10330`):

```js
for (let push of hodlScriptPushes(scriptCode)) if (hodlLooksPubkey(push)) candidates.push(push);
```

`scriptCode` comes from an attacker-declared witness UTXO plus a self-consistent `witnessScript`, and `hodlScriptPushes` allows 511 pushes (`app.js:10237-10259`). With the shared 256-digest budget (`app.js:12572`), the worst case is ~256 × 543 ≈ 1.4×10⁵ libsecp verifications — seconds of frozen tab on desktop, more on mobile. The comment at `app.js:10360` claiming the set is capped is false for this path. **Fix:** route the push through `addCandidate`.

### RT-WALLET-2 — A custom branch window silently drops a branch and labels the wrong one as change
**Confidence:** Probe-verified (real export functions). **Prior:** confirmed, with a correction.

The window allows `branchStart=1, range=2` (`app.js:2615-2625`). Derivation builds both branches (`app.js:1140-1144`), but the account only exposes `receiveDescriptor` for branch 0 and `changeDescriptor` for branch 1 (`app.js:1143-1144`, `1175-1176`). `wallet-export.js:248-262` then loops `[0,1]`: branch 0 is absent, branch 1 is emitted as `internal: true`. Branch 2, though displayed in the address tables and descriptor list, is never exported. The prior report said branch 2 was lost; the correction is that **branch 1 is also misfiled as the change chain**. The msig Core JSON has the same shape (`app.js:2165-2173`). A user importing the file gets a wallet with no external descriptor and a "change" chain that is actually their first receiving branch.

**Repro:** create an HD account with branch start 1, range 2, export wallet.dat; inspect `activeexternalspk` (absent) and `activeinternalspk` (branch 1). **Fix:** iterate `account.addressBranches`, emitting each with `internal: branchStart === 0 && branch === 1`; omit internal when the window does not contain branch 1.

### RT-PSBTRUST-2 — A standardness policy is enforced as a consensus rule and gates export
**Confidence:** Probe-verified (committed WASM). **Prior:** confirmed for the PUSHDATA half; one sub-claim refuted.

`script_pushes` iterates `script.instructions_minimal()` (`psbt-wasm/src/verify.rs:699-717`), so a consensus-valid PUSHDATA1 push of a 72-byte signature returns `None`; the P2PKH check then reports ERROR "final scriptSig of a P2PKH input is not push-only" (`verify.rs:806-815`), and the same happens to the P2SH last-push check (`verify.rs:810`). MINIMALDATA is a standardness flag, not consensus, and the file's own comment says "Consensus, not policy" (`verify.rs:322`). The consequence is a valid PSBT refused at the export gate unless the user enables Insane editing (`psbt-editor.js:585-624`, `851-873`). A helper that accepts any encoding already exists — `script_pushes_any_encoding` (`verify.rs:716-740`) — but is used only by `classify`'s fallback.

**Refuted sub-claim:** the handoff also lists "uncompressed pubkeys" as a false consensus error. For witness v0, BIP-141 *requires* compressed pubkeys, so rejecting a 65-byte key in a P2WPKH witness is consensus-correct. The real defect there is the error text: when the HASH160 of an uncompressed key equals the program, the message says "final witness public key does not hash to the claimed output's witness program" (`verify.rs` near 830), which is false — the fix is wording plus a distinct reason, not acceptance.

**Fix:** use `script_pushes_any_encoding` for the legacy structural checks, keep the exact-push witness checks, and correct the uncompressed-key message.

### RT-PSBTJS-1 / L3 extension — Name-only pair matching lets a PSBT display a false amount and a false "finalized" state
**Confidence:** Probe-verified (crafted raw PSBT) + Trace-verified. **Prior:** confirmed, but the stated mechanism is wrong; the real mechanism is broader and reaches signing status.

`psbt-viz.js:123-133` resolves `claimedPrevout` by `pair.name` alone, first match in file order. The pair view is named from the type byte only (`psbt-wasm/src/lib.rs:743-756`, assigned at `808-811`), and the typed decoder for `input,0x01` never rejects keydata (`lib.rs:891-936`). So a key `01 aa` is presented as `PSBT_IN_WITNESS_UTXO` with a decoded value, while the fee and verifier require the exact one-byte key (`lib.rs:1125` `pair_utxo_claim` requires `key.len() == 1`; `verify.rs:167-171`). The witness-vs-non-witness pair *is* set-resolved as the comment says — the hole is same-type lookalikes.

Probe: `01aa = TxOut(1 sat, scriptA)` first, `01 = TxOut(10,000 sats, scriptA)` second → the diagram shows **1 sat**, the fee shows **9,000 sats**, `duplicateKeys: complete`. New surface: `signingStatus` (`psbt-viz.js:142-151`) counts finals and signatures by name, so a `08 aa` final-witness pair renders "finalized" with "no problems", while the verifier reads only exact `0x08` and never verifies it. Extend `psbt-cost.js:64-70` for the same keydata guard.

**Fix:** in `decode_pair`, treat a keydata-bearing pair as an unknown/invalid pair for singleton input/output types (the BIP-370 singleton list at `lib.rs:337-351` is the model); or expose `key` in the pair view and require `key.length === 2` in `psbt-viz.js` and `psbt-cost.js`. One change fixes display, cost and signing status.

---

## 3. Low

- **RT-KEYSTATION-2 — `fields.pass` arrays are not zeroed on per-key drop.** Allocated at `app.js:4507-4508`, wiped only by the page-wide sweep at `app.js:17905-17908`; delete (`14236`) and ignore (`13310-13316`) leave the `Uint8Array` to GC. Confirmed. Fix: zero before splice/push, and include it in the cascade helper.
- **RT-VANITY-1 — the grinder survives its source key.** Per-worker copies at `vanity.js:340-352` live until terminate; only `hodlVanityCancel()`/`#terminate()` (`vanity.js:376-387`) kills them, and the key-removal paths never call it. Extended: `hodlVanityMatches` and `hodlVanityRun` also survive (`app.js:16772-16806` only blanks the chip). Up to 64 workers (`vanity.js:170`). Confirmed.
- **RT-SEEDFORMS-2 — dice `beforeinput` expando.** `input.hodlDiceBeforeInput` is set at `app.js:3595-3596` and not deleted by the wipe at `app.js:17930-17935`, but the paired `input` event deletes it (`3612`, `3653`), so only an aborted/composition `beforeinput` leaves it. Qualified to Low.
- **RT-PSBTRUST-1 — taproot SIGHASH_SINGLE without an output is silently unchecked.** The ECDSA path names `sighash_single_no_output` (`verify.rs:338-349`); taproot key-path hits `taproot_sighash_key_spend` → `None` → `None => {}` (`verify.rs:619-620`), and final key-path fails closed with the misleading "sighash cannot be computed" (`954-964`). BIP-341 makes this an invalid signature. Confirmed.
- **RT-ENTROPY-1 — the analyzer and parser tokenize differently; the handoff's repro is wrong but the class is real.** `hodlNormalizeMnemonicText` (`app.js:185-186`) turns non-letters into separators; the analyzer uses `/\S+/` (`app.js:4440`); the Key Station filter deletes punctuation but keeps digits (`app.js:7535-7537`), and the derive gate uses the normalizer (`app.js:7111`, derive at `7471-7473`). The `！` repro is refuted — the filter removes `！` before analysis. The ASCII-digit repro works:

  ```
  abandon1abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
  ```

  Analyzer: 11 tokens, `abandon1abandon` flagged red. Normalizer: 12 words, 11×`abandon` + `about` — the canonical zero-entropy phrase, which derives a valid seed with the button enabled. Confirmed by probe.

  **New extensions:** (a) canonically equivalent input derives different wallets — the filter deletes precomposed `ý` from `armý` (leaving `arm`) but only the combining mark from `army\u0301` (leaving `army`), and both 12-word results are valid and shown green; (b) the same paste behaves differently per station — Key Station merges at punctuation (`abandon，ability` → `abandonability`, rejected) while SP/PSBT/Lightning split and accept it. Fix: one tokenizer for analysis and parsing; strip digits in the filter (or flag them in the analyzer); reject non-ASCII characters instead of silently deleting them.
- **RT-DELTA-1 — the vault UTF-8 decoder validates the continuation class but not the lead class.** `passphrase-vault.js:87` treats every `0x80-0xBF` as a 2-byte lead and every `>=0xF0` as a 4-byte lead. Probes: `9f bf`, `bf bf`, `f9 bf bf bf` and `fc 80 80 80` decode; `80`, `c0 80`, `ed a0 80`, `f4 90 80 80` are refused. The comment says stray continuations are refused. Live exposure is hardening-only because every producer emits valid UTF-8. Fix: validate the lead against `0xC2-0xDF`, `0xE0-0xEF`, `0xF0-0xF4`.
- **RT-WALLET-1 — refuted as live; the live bug is regtest address display.** `ownership.js:15-17` does disagree with `app.js:219-222` for signet/regtest, but the ownership index is only ever called with `mainnet|testnet` (`app.js:12326-12328`, `12003`), and the non-mainnet default is `testnet`, which matches the derivation (coin 1). What is live: `hodlNetworkDefault` (`app.js:17755`) maps a regtest picker to `"testnet"`, so the inspector renders `tb1…` for regtest outputs that need `bcrt1…` (`addresses.js:26-32`). Script matching still works. Fix both together — teaching `hodlNetworkDefault` to return `"regtest"` without fixing `ownership.js` would turn the latent coin-type mismatch into the original finding.
- **RT-CONCEAL-2 — three secret surfaces are outside conceal.** The expandable modal `#exp-readout`/`#exp-text` (`expandable.js:72-73`) releases only on close/pagehide/pageshow (`90-108`) and its own comment says a value may carry an xprv; blur/hidden/print leave it. PSBT result panes `#psbt-out` (`shell.html:649`), `#psbted-out` (`673`) and `#psbted-compare-out` (`683`) render the same xprv-bearing pairs that make `#psbt-text` a registered secret field, with no reveal gate. `#brain-lab-hex` (`app.js:4980`, filled at `5007`) is the SHA-256 of the brain-wallet text — key material — displayed in clear and cleared only by the page-wide wipe (`18009-18010`). Fix: close/release the modal from conceal, route the panes through the existing private-value gating, and treat the brain hash as a private value.
- **RT-JSBOUNDARY-1 — avoidable JS copies of secret bytes are never zeroed.** `bech32.js:55` `wordBytes = Uint8Array.from(words)` holds the 5-bit encoding of `spscan`/`spspend` private keys and is never wiped; `base58.js:26` encodes a WIF/xprv into a `Uint8Array` that is dropped unzeroed; `psbt-wasm.js:131` encodes the entire editor JSON, including any proprietary-field xprv, into a `Uint8Array` and never wipes it; `bip352.js:252/347` build `words` number arrays and `wordBytes` copies from private scalars (BigInts themselves are unwipeable and already documented). The prior "WASM boundary clean" claim covers the module and the buffers it frees, not these JS-side copies. Residue only — no remote path; fix by `fill(0)` in `finally`, matching the discipline already used in `hdkey.js`/`addresses.js`.
- **RT-WASMRESIDUE-1 — only one of the three crates wipes its heap.** `entropylab-wasm/src/lib.rs:64-93` installs `WipingAllocator` (dealloc wipes `layout.size()`, realloc allocates/copies/wipes the old block); `psbt-wasm` and `vanity-wasm` have no `#[global_allocator]`. Their `RawPair` vectors, per-pair hex `String`s and serde_json trees (`psbt-wasm/src/lib.rs:1375`, `1506`) are freed unzeroed, and `LAST_ERROR` is `clear()`ed, not wiped (`70-72`). All three crates set `panic = "abort"`, so a trap runs no `Drop` and no dealloc wipe; End Session's whole-memory overwrite is the only backstop. This extends #1000's allocator work to the other two crates. Low residue.
- **RT-VANITYPASS-1 — dead feature and a test that fabricates its element.** `app.js:16786,16794,16806` code against `#vanity-pass`, but `src/shell.html` has only `#vanity-pass-note` (line 240). `test/secret-clear.test.mjs:422` creates the missing element, so the test passes against markup that does not exist. Info; fix the dead code or the markup, and make the test read the shell.
- **RT-SESSION-1 — the version claim is refuted; the fallback gap is real.** `conceal-on-leave.js:18-20` has only `beforeprint` (plus blur, visibilitychange and idle). There is no `matchMedia("print")` fallback and no `@media print` masking rule. But MDN BCD gives `beforeprint` Safari 13+, so "WebKit ≤ Safari 17 lacks it" is false. The residual is a missing belt-and-braces path, not a live browser gap. Info.

---

## 4. Speculative (not counted as findings)

- **`clearSecretFields` is not exception-isolated** (`app.js:17888-18040`): it is a flat sequence, and `hodlJournalWipeMem()` sits after several calls. A throw before it would skip the journal wipe while End Session proceeds. I could not identify a concrete call that throws on a realistic path, so this stays Speculative; the fix is a `try/finally` around each stage.
- **Vanity deferred-chunk throw** (`vanity-worker.js:137-170`): the synchronous `try/catch` does not cover a later `setTimeout(step, 0)` task, so a WASM trap there would skip `wipeSecrets()`. This is a known-open item and I found no reachable trap; Speculative.

---

## 5. Prior findings — verdict table

| Prior ID | Verdict at `3e663cd4` |
|---|---|
| RT-SEEDFORMS-1 | Confirmed. Medium (print exposure). |
| RT-JOURNAL-1 | Confirmed, **upgraded**: concurrent unlock actually installs plaintext without the ack. Medium. |
| RT-KEYSTATION-1 | Confirmed and **extended** to ignore/detach/journal-lock/workspace-switch; `#bip85-key`/`#sp-key` plaintext survives. Medium. |
| RT-VANITY-1 | Confirmed and extended (matches/run also survive). Medium as part of the key-lifecycle gap. |
| RT-KEYSTATION-2 | Confirmed. Low. |
| RT-SEEDFORMS-2 | Qualified: transient unless `beforeinput` has no paired `input`. Low. |
| RT-WALLET-1 | **Refuted as live.** Only `mainnet/testnet` reach `ownership.js`; the module mismatch is latent. New live regtest-prefix bug instead. Low. |
| RT-WALLET-2 | Confirmed, with a correction: branch 1 is exported as `internal`, branch 2 is dropped. Medium. |
| RT-DELTA-1 | Confirmed; lead class unvalidated. Low/hardening. |
| RT-DELTA-2 | Confirmed. Medium. |
| RT-PSBTRUST-1 | Confirmed. Low. |
| RT-PSBTRUST-2 | Confirmed for PUSHDATA1/minimal-encoding; **uncompressed-witness sub-claim refuted** (rejection is consensus-correct; only the message is wrong). Medium. |
| RT-PSBTJS-1 | Confirmed in effect, **mechanism corrected**: the witness-vs-non-witness pair is set-resolved; the hole is same-type keydata-bearing lookalikes, and it extends into signing status. Medium. |
| RT-ENTROPY-1 | Confirmed, **repro corrected** (`！` filtered before analysis; ASCII digits reproduce it), plus NFC/NFD and cross-station extensions. Low. |
| RT-WASMCORE-1 | **Not a vulnerability.** `PublicKey::from_slice` accepts hybrid `0x06/0x07` with a parity check (`entropylab-wasm/src/lib.rs:218,320`), so the bytes denote the same curve point; script/address builders reject them. Info. |
| RT-SESSION-1 | **Version claim refuted** (Safari 13+, not ≤17). Missing print fallback is Info. |

**Known-open items re-checked, not re-reported as new:** duplicate journal ids and unreconciled `nextId`; armed-open decrypted document not discarded; unbounded `file.text()`/`arrayBuffer()` before the caps; uncapped SP paste fields; `bip352` P2SH redeem not hash-checked; label-tweak-zero; lone-surrogate passphrase collision; PBKDF2 iteration wrap (unreachable); msig export buttons on shapes that throw; HD wallet.dat path lacking the msig xprv refusal; the committed-WASM drift policy itself. #1000's three Rust fixes are real in source — the bech32m paths wipe `fes`, `descriptor.rs` wipes `out`/KeyMap/records on every error exit, and the allocator's realloc semantics are unit-tested in-crate — but see RT-BUILD-1 for the shipped state.

---

## 6. Checked clean in this pass (no finding)

- **Persistence:** no sessionStorage, IndexedDB, cookies, `window.name`, `sendBeacon` or BroadcastChannel; localStorage holds only theme/locale/ack flags; the service worker caches only `./` and `./entropylab.html`; downloads are the only secret sink, by design.
- **Lifecycle wipe ordering:** `pagehide` is not `persisted`-guarded, so entering bfcache wipes; `pageshow {persisted}` wipes again; End Session dispatches `pagehide` synchronously before its first `await` (`end-session.js:103`), so a reload cannot interleave.
- **WASM wrappers:** `withInput`/`withOutput` free in `finally`; `hdkey.js`, `addresses.js`, `aezeed.js` wipe their buffers; the stack scrub is scheduled in `finally`. The gaps are the JS copies in RT-JSBOUNDARY-1.
- **PSBT diff:** `psbt-diff.js:47-93` groups by raw key as a multiset and withholds equality on `rustBitcoinError`/duplicate keys; `signingAnchor` is order-sensitive (false positive, safe direction).
- **No `console.*` anywhere in `src/js`;** psbt-wasm error strings carry field names, not values.
- **Not re-run:** the prior pass's fuzz/differential/SQLite campaigns (no cargo/browser here). I did not find code that contradicts them.

---

## 7. Fix order

1. **RT-BUILD-1** — rebuild and commit artifacts; make drift a hard failure. Nothing else in #1000 reaches users until this is done.
2. **RT-SEEDFORMS-1, RT-CONCEAL-2** — one conceal registry change covers the passphrase switch, the expandable modal and the brain hash.
3. **RT-KEYSTATION-1 + RT-VANITY-1 + RT-KEYSTATION-2** — one `hodlReleaseKeyConsumers` cascade, called from every removal path, with `fields.pass` zeroized.
4. **RT-JOURNAL-1** — in-flight guard plus `hodlJournalDiscardOpened` on the armed return.
5. **RT-PSBTVIZ-1/L3** — reject keydata on singleton pairs in `decode_pair`, then align `psbt-viz`/`psbt-cost`.
6. **RT-PSBTRUST-2, RT-DELTA-2, RT-WALLET-2** — small, contained.
7. **RT-ENTROPY-1** — one tokenizer, and reject non-ASCII rather than delete it.
8. The residue items (RT-DELTA-1, RT-JSBOUNDARY-1, RT-WASMRESIDUE-1) as a follow-up hardening pass.