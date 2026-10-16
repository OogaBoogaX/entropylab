# Local adversarial review, 2026-10-11

## Status of the split

This report records historical evidence from PR841, not fresh validation of
this documentation branch. Its code fixes and dice UI wording are submitted
separately following the maintainer’s split request. Until those changes merge,
this branch alone does not provide the fixes or changed UI labels described
below. The original candidate hashes and counts remain historical evidence,
not hashes or test totals for the three split heads.

The recovery harness is copied unchanged from `0058824`. Source inspection
confirmed its inputs are fixed public fixtures, with no unknown-secret search,
user-wallet loading, external address lookup, or fund interaction. It was not
executed during this split and its earlier results are not claimed as rerun.
Use only disposable public test material, never real wallet secrets or funds.


Branch: `review/adversarial-audit`. Starting commit: `741d7f2` (also the
local `rock` tip). The branch had no prior review commits or saved findings.
This review uses the local checkout; it does not establish that the remote
branch will remain unchanged after the fetched revision.

Review performed with GPT-6 (OpenAI Codex).

Pre-PR re-review fetched the parent repository's `rock` branch and confirmed
it still pointed to `741d7f2`. All three fixes passed source review. The final
focused tests were replayed against an isolated archive of that original
commit: seven tests failed for the claimed defects. The same 47 focused tests
all passed against the fixed sources.

A final review of the nonce comparison and report/error paths found two
additional medium-severity issues, A4 and A5 below. No critical or high issue
was confirmed in the reviewed scope; that assessment is bounded by the scope
and validation described here.

## Objectives and scope

EntropyLab converts user-supplied material deterministically into Bitcoin
recovery information. It must not manufacture secret entropy, transmit wallet
data, require runtime downloads, or present incomplete verification as proof
of transaction safety. The release remains a self-contained HTML file.

This pass inspected the HD-key facade, transaction parsing/serialization,
PSBT cost calculation and flow rendering, Rust UTXO-claim resolution and
monetary sanity checks, sequential UR assembly, nonce-history validation,
entropy conversion paths, translation sanitizer, WASM boundary cleanup,
passphrase storage, and session teardown. Existing vector, differential,
network, state, and browser tests supplement that source inspection.

The follow-up education pass makes the project's user-protection goals
explicit in the scan:

| Contract | Existing evidence reviewed | Limit that the explanation must preserve |
| --- | --- | --- |
| Preserve supplied bits and method-specific transcripts | Number-base, hashed-dice, cards, BitBox, D++, and global-sync suites | Length/capacity is not measured unpredictability; synchronization and hashing add none |
| Reproduce Bitcoin recovery data | Published BIP39/BIP32 vectors and independent HD-key comparisons | A valid checksum is not proof of secrecy or the intended wallet; a wrong BIP39 passphrase still derives a seed |
| Explain source statistics honestly | Pearson CDF/threshold tests and a balanced deterministic sequence | Frequency tests do not establish independent, unpredictable rolls |
| Keep transaction claims separate from verification | PSBT amount, sighash, nonce, consensus, and analysis-status suites | Offline inspection cannot establish chain state or overall safety to sign |
| Keep secrets local and control exposure | Network, entropy-source, session-wipe, and browser suites | Browser-memory cleanup is best effort; a test pass is not guaranteed erasure |

This is a bounded code review, not a formal proof or an independent audit of
every dependency or Rust cryptographic primitive. No review can certify
"100% accurate" UI data: PSBT amounts are supplied claims, chain state is
unavailable offline, ownership searches have explicit bounds, and browser
memory erasure is best effort. These limits remain part of the security model.

## Findings and executed plans

### A1 — Intermediate private child survives a rejected HD path

Contract: valid BIP32 paths preserve published-vector results; refused paths
must wipe private intermediate nodes without wiping the caller's root.

`HDKey.derive` wiped intermediates on successful iteration only. A later
malformed or out-of-range segment threw while the last child still held its
private scalar. This is a memory-residue issue, not an incorrect derived key.

Plan executed: retain references to the actual child buffers in a regression,
confirm that refusal leaves a live private key, then wipe the last owned child
in the error path. Successful children and the caller's root remain usable.

Regression: `failed HD paths wipe intermediate private buffers and preserve
the caller root` in `test/hdkey-bip39-wasm.test.mjs`. The pre-fix failure was
`true !== false` for a retained intermediate's `hasPrivateKey`. The accepted
case uses published BIP32 vector 1.

The re-review also covers an injected child-derivation exception (checking
that the exact error propagates), multi-level successful derivation, zeroing
of discarded buffers, and retention of the returned private child. Its
successful output is compared to the existing pinned `@scure/bip32` reference.

### A2 — Large scripts fail transaction serialization

Contract: structurally decodable large scripts serialize byte-for-byte,
while truncated transactions and out-of-range amounts remain refused.

`serializeTx` spread script bytes into `Array.push` arguments. At 150,000
bytes this raised `RangeError: Maximum call stack size exceeded`, below the
parser's five-megabyte cap. The serializer is used when stripping witness
data for non-witness UTXO txid verification and for synthesized transactions.

Plan executed: pin expected bytes independently using fixed transaction wire
fields and CompactSize prefixes, reproduce the argument-limit failure, then
append variable-length scripts iteratively. Test both input and output scripts
and truncated wire data. This adds no new consensus acceptance rule.

Regression: `large input and output scripts serialize without an
argument-limit failure` in `test/tx-sighash-wasm.test.mjs`.

### A3 — Sequential UR duplicates and attacker-controlled allocation

Contract: complete sequential multipart fragments reconstruct the exact payload;
identical repeats are idempotent; conflicts, incomplete sets, and zero or
unsafe sequence integers are refused without allocation driven by the
declared count.

The decoder deduplicated slots but concatenated the original fragment list.
Repeating an early fragment therefore caused a whole-message checksum error.
Existing duplicate coverage repeated the final padded fragment, whose excess
bytes were sliced away and concealed the defect. The declared count also
controlled an array allocation before completeness was checked. Zero sequence
numbers could pass the single-fragment branch.

Impact is confined to the decoder module API: the current application UI
imports the UR encoder for QR output, not this decoder. These are real decoder
correctness and resource-handling bugs, but this review does not claim a
currently reachable UI import exploit.

Plan executed: add early-repeat, invalid-sequence, and enormous-count
regressions; reproduce checksum failure, missing rejection, and invalid array
length; replace slots with a map of supplied fragments, assemble its unique
ordered values, and validate positive safe integers before decoding payloads.

Regressions in `test/psbt-ur.test.mjs`:

- `repeating an early UR fragment preserves the assembled bytes`
- `UR sequencing rejects zero and unsafe integers before assembly`
- `a huge declared UR count is refused without allocating count-sized slots`

The legacy-fragment test also checks out-of-order fragments with an exact
repeat against the original fixed PSBT bytes; this fails on the old decoder
and passes on the map-based assembly.

Existing published Bytewords/MUR vectors, conflict checks, whole-message
checksums, and legacy fragment support remain in coverage.

### A4 — Collision-heavy nonce groups exhaust memory (medium)

Contract: preserve exact nonce comparison results within 32,768 candidate
pairs across the whole inspection, and explicitly refuse larger collision
sets without allocating their pairs or recording a completed verdict.

Grouping by r avoided all-pairs work for ordinary distinct nonces, but a
single collision-heavy group still produced quadratic work and result arrays.
A 135,072-byte PSBT with 3,000 partial signatures sharing r required 4,498,500
pairs. Running the real parser and comparator in an isolated Node worker
with a 128 MB old-space limit exhausted the worker heap; a distinct-r control
completed in 5 ms. Both UI inspectors reach this comparator. Opening crafted
input could freeze or terminate the tab; no key disclosure was demonstrated.

Plan executed: first add a rejected-collision regression and observe the
missing exception, then preflight the sum of each group's n*(n-1)/2 before
constructing any pairs. The same fixture now throws the deliberate limit
error. This is an availability bound, not a consensus rule; unusually large
benign repeated-signature sets are also refused.

`nonce comparison refuses collision floods before constructing unbounded
pair lists` covers 256 accepted and 257 refused identical-r records, the
exact whole-file boundary, multiple groups that collectively exceed it, and
10,000 distinct nonces that remain accepted. The existing grouped-comparison
reference test retains its verdict checks. A handler-level regression runs
the actual renderers and comparator through both inspectors for PSBT and raw
transaction input: prior output clears, the error surfaces, and no new nonce
verdict is recorded. Input acquisition and unrelated UI services are stubbed.

### A5 — Repeated-nonce reports also claim no repetition (medium)

Contract: a same-key repeated-r warning must never coexist with a no-repeat
assurance; distinct readable r values may still report no repetition.

The PSBT and raw-transaction renderers appended the reuse warning, then ran
a separate cross-key/incomplete/clean conditional chain. With same-key reuse
and no cross-key or unreadable records, that second chain also appended the
false no-repeat line. The warning and stored verdict were present, which
limits the impact, but the contradictory safety message could mislead users.

Plan executed: run both real renderers on fixed same-key signatures with
r=1/r=1 and r=1/r=2 controls; observe the false assurance in each repeated
case; require empty reused and possible-reuse buckets before emitting it.
Tests assert only the safety-critical no-repeat substring and the stored
verdict, not CSS or full presentation copy. They use readable DER without
prevouts and intentionally establish possible reuse, not signature validity.

### Education follow-up — Frequency balance is not certified entropy

The dice panel labeled a balanced transcript "Looks pretty fair" and described
larger samples as enough to assess fairness. Its test already used the fully
predictable sequence `123456` repeated five times: Pearson's face-count
statistic correctly returns zero, but that does not establish randomness.

The labels now describe frequency warnings. The note states the independent,
fair-roll assumption, identifies the CDF as a reference percentile, and says
that the check cannot establish independence, unpredictability, or entropy.
Source comments distinguish dice/card capacity formulas from measurements.
README and SECURITY explain source assumptions, hash-output length, checksum
limits, and BIP39 passphrase recovery, with primary references to
[NIST SP 800-22](https://csrc.nist.gov/pubs/sp/800/22/r1/upd1/final) and
[BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki).

This is an educational correction, not a derivation or statistical-algorithm
change. The existing balanced-sequence test now also checks that sorted runs
with identical counts produce the same report; it passed before and after the
wording change. Browser assertions check the existing `data-tone` state
instead of pinning the old labels. Before/after captures were inspected at
1280px and 390px widths in dark and light themes. No styles or locale catalogs
changed. The nonce-comparison comment was also qualified to state that pair
and verdict preservation applies within its newly enforced budget.

The maintainer's [release-hold comment](https://github.com/OogaBoogaX/entropylab/pull/841#issuecomment-6113811756)
discusses the original three fixes. A4/A5 and this educational correction were
added afterward and are explicitly described in the PR; they have not been
represented as approved by that comment. The requested hold until after the
`v1.0.0` tag remains part of the PR description.

## Validation

Initial red and subsequent green for A1/A2:

```sh
node --test test/hdkey-bip39-wasm.test.mjs test/tx-sighash-wasm.test.mjs
```

Initial red and subsequent green for A3:

```sh
node --test test/psbt-ur.test.mjs
```

Initial red and subsequent green for A4 and A5, respectively:

```sh
node --test test/psbt-nonce-reuse.test.mjs
node --test test/psbt-nonce-render.test.mjs
```

The A4 initial failure was a missing expected exception. Both A5 renderer
tests failed because the repeated-r report contained the no-repeat claim.
The additional handler test covers the unchanged error-handling contract
and passed without changing those handlers. The combined nonce comparison,
rendering, analysis-status, and finalized-signature suites pass all 28 tests.

Education follow-up coverage, green before and after the wording change:

```sh
node --test test/dice-fairness.test.mjs
```

Final validation passed:

- `npm run build && npm test`: 2,253 tests, 2,243 passed, zero failures,
  10 skipped. Chrome ran the hosted/offline browser suite and the native-input
  residue-driver checks. Firefox and Edge are absent; eight optional live
  Bitcoin Core checks were skipped because bitcoind is absent.
- `npm run verify`: self-contained site artifact checks passed.
- `npm run reproduce`: HTML and service worker were byte-identical across
  two staging paths. This host check does not repeat the canonical Docker
  image's cross-environment WASM reproducibility check.
- `git diff --check`: passed.
- `npm audit --json`: zero known advisories in the pinned npm dependency tree
  at review time. This does not certify unreported or non-npm vulnerabilities.
- `HDKEY_FUZZ_ITERATIONS=1000 PSBT_FUZZ_ITERATIONS=1000 node --test
  test/hdkey-differential-fuzz.test.mjs test/psbt-differential-fuzz.test.mjs`:
  all four differential tests passed using the existing independent references.
- `node --test test/ci-completeness.test.mjs`: all three checks passed with
  the new renderer suite staged and registered in `test:ci`.

The first sandboxed full-suite attempt could not bind loopback servers.
The successful suite ran with approved access for the local browser and
mock-API tests. No external review API was invoked.

No locale catalogs, dependencies, generated WASM modules, or unrelated
Android work are part of these fixes. The generated HTML is excluded from
the review commits even though this checkout tracks it.

## Exact-candidate recovery verification

The follow-up checked the unmodified `entropylab-candidate` HTML downloaded
from [CI run 38176311703](https://github.com/OogaBoogaX/entropylab/actions/runs/38176311703),
for PR head `3f3c53c16a42eb2d43b2eda52f9d47e74298b16e`. Its SHA-256 matched
the run's checksum manifest:

```text
8dd69de8c17642a3d1d447eb20dbc50aa78a8a9e4506b182e1078fd140afff7a
```

The locally rebuilt HTML has the same digest, and all three downloaded WASM
modules match the checked-in modules byte-for-byte. That CI run completed
successfully, including Firefox integration and the canonical image's
cross-environment reproducibility checks. This is the PR candidate, not a
newly published or signed release; the maintainer's release hold still applies.

The opt-in `test/candidate-recovery.mjs` takes an existing HTML file and never
builds, instruments, or replaces its code. It drives the real UI with native
text input in Chrome, disables browser networking after each page load, and
reads the rendered recovery values. The oracle runs separately in Node:
Node PBKDF2 plus the already-pinned `@scure/bip39`, `@scure/bip32`,
`@scure/btc-signer`, and `@scure/base`. Published
[BIP84](https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki) and
[BIP86](https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki)
addresses anchor the reference and UI comparisons. Only public deterministic
test material is used; it must never receive funds.

Contract unchanged: supported recovery inputs must reproduce independently
determined seed/key/address results; malformed recovery inputs must not enable
derivation. This adds coverage only, so no production change or artificial
initial failure is required.

```sh
node test/candidate-recovery.mjs /absolute/path/to/entropylab.html
```

The complete run passed:

- 80 mnemonic recoveries: all five BIP39 entropy lengths, all four supported
  networks, and BIP44/49/84/86. Passphrases cover empty, ASCII, composed and
  decomposed Unicode, and leading/trailing whitespace.
- 20 hex recoveries: all five lengths with zero, all-ones, alternating-byte,
  and incrementing-byte inputs, including leading-zero preservation.
- 32 extended-key imports: root private and account public imports for each
  network/script combination. A bare account xpub has no authenticated full
  origin; the check requires the correct relative suffix and no invented
  master path.
- 792 receive/change address comparisons at indices 0, 1, and 2; private
  imports also match the independent WIF encoding. Mnemonic/hex cases match
  the mnemonic, entropy bytes, PBKDF2 seed, master private key, and account
  public key. Watch-only imports expose no private recovery values.
- Every accepted case conceals private output until reveal and clears the
  rendered recovery/address output on Wipe. This checks DOM state, not memory
  erasure.
- Five refusals: bad mnemonic checksum, extra word, unknown word, corrupted
  xprv checksum, and corrupted xpub checksum. Derivation stays disabled and
  no address result appears.
- Zero observed external HTTP(S) requests and zero uncaught browser exceptions
  during these flows. Existing network-silence suites cover the broader API
  contract.

`npm run build && npm test` passed again: 2,253 tests, 2,243 passed, zero
failures, and the same 10 local optional skips described above.
`npm run verify` and `git diff --check` passed. This follow-up adds only the
audit harness and documentation; the tested application bytes are unchanged.

No additional application defect or critical/high finding was confirmed.
This was a further GPT-6 review using independent reference implementations,
not a separate third-party auditor's sign-off. Agreement on this finite corpus
does not prove every input, device, dependency, or security claim correct.
