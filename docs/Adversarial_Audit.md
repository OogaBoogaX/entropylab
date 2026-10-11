# Local adversarial review, 2026-10-11

Branch: `review/adversarial-audit`. Starting commit: `741d7f2` (also the
local `rock` tip). The branch had no prior review commits or saved findings.
This review uses the local checkout; it does not establish that the remote
branch has no newer commits.

Review performed with GPT-6 (OpenAI Codex).

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

Contract: complete sequential fragments reconstruct the exact payload;
identical repeats are idempotent; conflicts, incomplete sets, and zero or
unsafe sequence integers are refused without allocation driven by the
declared count.

The decoder deduplicated slots but concatenated the original fragment list.
Repeating an early fragment therefore caused a whole-message checksum error.
Existing duplicate coverage repeated the final padded fragment, whose excess
bytes were sliced away and concealed the defect. The declared count also
controlled an array allocation before completeness was checked. Zero sequence
numbers could pass the single-fragment branch.

Plan executed: add early-repeat, invalid-sequence, and enormous-count
regressions; reproduce checksum failure, missing rejection, and invalid array
length; replace slots with a map of supplied fragments, assemble its unique
ordered values, and validate positive safe integers before decoding payloads.

Regressions in `test/psbt-ur.test.mjs`:

- `repeating an early UR fragment preserves the assembled bytes`
- `UR sequencing rejects zero and unsafe integers before assembly`
- `a huge declared UR count is refused without allocating count-sized slots`

Existing published Bytewords/MUR vectors, conflict checks, whole-message
checksums, and legacy fragment support remain in coverage.

## Validation

Initial red and subsequent green for A1/A2:

```sh
node --test test/hdkey-bip39-wasm.test.mjs test/tx-sighash-wasm.test.mjs
```

Initial red and subsequent green for A3:

```sh
node --test test/psbt-ur.test.mjs
```

Final validation passed:

- `npm run build && npm test`: 2,248 tests, 2,238 passed, zero failures,
  10 skipped. Chrome ran the hosted/offline browser suite and the native-input
  residue-driver checks. Firefox and Edge are absent; eight optional live
  Bitcoin Core checks were skipped because bitcoind is absent.
- `npm run verify`: self-contained site artifact checks passed.
- `npm run reproduce`: HTML and service worker were byte-identical across
  two staging paths. This host check does not repeat the canonical Docker
  image's cross-environment WASM reproducibility check.
- `git diff --check`: passed.

The first sandboxed full-suite attempt could not bind loopback servers.
The successful suite ran with approved access for the local browser and
mock-API tests. No external review API was invoked.

No locale catalogs, dependencies, generated WASM modules, or unrelated
Android work are part of these fixes. The generated HTML is excluded from
the review commits even though this checkout tracks it.
