# Mutation-testing pilot: four security modules

A one-off experiment from 2026-10-10. A mutation tester makes small edits to the code ("mutants"), such as deleting a line, flipping a comparison or changing a constant. It then runs the tests against each edit. A mutant the tests still pass on ("survived") marks a behaviour nothing checks. EntropyLab doesn't require mutation testing (see AGENTS.md: per-change fault injection is the norm), so this measured where the suite is weaker than its size suggests.

- **Code:** rock `372a507` (the 1.0.0rc3 cut `c1037ba` plus its artifact and timestamp commits). Line numbers below refer to that commit.
- **Tool:** StrykerJS 10.0.0 with its command runner, so each mutant runs `node --test` over a chosen list of test files. It was installed with `npm install --no-save --ignore-scripts` in a scratch worktree, and `package.json` and the lockfile were not touched.
- **Modules:** `clipboard.js`, `end-session.js`, `addresses.js`, `hdkey.js`.

## Scores

**Pass 1** ran every mutant against the module's own focused tests. **Pass 2** re-ran the suspicious lines against every test file that can reach the module through the import graph. app.js was left out of that graph, because tests take its functions from source text and never run its imports.

| Module | Lines | Mutants | Killed | Survived | Pass 1 score | Pass 2: still surviving on the re-run lines |
|---|---|---|---|---|---|---|
| clipboard.js | 106 | 87 | 68 | 19 | 78% | 6 of 20 |
| end-session.js | 148 | 131 | 35 | 96 | 27% | n/a: only its own test reaches it in Node |
| addresses.js | 189 | 187 | 133 | 54 | 71% | 9 of 17 |
| hdkey.js | 286 | 313 | 207 (+2 timeouts) | 104 | 67% | 12 of 14 |

The scores matter less than the survivors. Most survivors are error-message strings, markup, or double guards where the WASM rejects the same input anyway. Four were real gaps.

## Gaps found, and the tests that now cover them

None of these is reachable as a bug today. Each is a check that a refactor could remove without any test failing. All four tests pass on rock. For each, the listed weakening was made by hand, the test failed, and the change was reverted.

1. **Two private-key buffer wipes (hdkey.js:173, :193).** `privateExtendedKey` builds a 33-byte key field, and `serialize` builds the 78-byte body holding the key and chain code. Deleting either `fill(0)` passed every test that reaches hdkey.js. The existing observer only sees `slice`/`subarray` copies, not `new Uint8Array(n)`.
   - Test: `privateExtendedKey clears the key field and the serialization it builds` (`test/hdkey-bip39-wasm.test.mjs`). It observes the buffers hdkey.js allocates while building the BIP32 vector 1 `m` and `m/0H` serializations, and requires each to be zero afterwards.
   - Fails when: either `fill(0)` is removed.
2. **The descriptor index check (addresses.js:160).** All 8 of its mutants survived. The WASM reads the index as a `u32`, so with the check removed, `descriptorDerive(…, 2**32 + 5)` returned index 5's address and `1.5` returned index 1's. The multisig form validates its start index first, so nothing reaches this today.
   - Test: `descriptorDerive refuses indexes outside 0 to 2^31 - 1 instead of wrapping them` (`test/addresses-wasm.test.mjs`). It checks the published BIP84 address at index 0 and `@scure/bip32` + `@scure/btc-signer` at 2^31 − 1. It requires a refusal for 2^32 + 5, 2^31, 1.5, −1, NaN, Infinity, 2^53, a string, null and undefined.
   - Fails when: the check is removed, the upper bound is dropped, `>` becomes `>=`, or `isSafeInteger` becomes `isFinite`.
3. **The BIP32 retry path (hdkey.js:263–267).** When a child key is invalid (I_L ≥ n, about 2^-128 per step), BIP32 says to proceed with the next index. That step was pinned only by a source-text regex (#359), and these mutants all survived: `index + 1` → `index - 1`, both maximum-index bounds, `>=` → `>`, and `code === 1` → `false`.
   - Test: `a BIP32 retry verdict derives the next index, and the last index refuses (issue #359)` (`test/hdkey-bip39-wasm.test.mjs`). WebAssembly exports are frozen, so the test loads a copy of hdkey.js whose only change routes the CKD call through a stub. The stub reports the retry verdict at chosen indexes and calls the real export otherwise. `@scure/bip32` at index + 1 is the oracle (private, hardened and public parents, and two retries in a row). The last index must refuse, for both a private and a public parent. If hdkey.js changes that call, the test fails loudly and asks for the seam to be updated.
   - Fails when: any of the mutants above is applied.
4. **End session's clipboard claim (end-session.js:109–110).** Turning `.catch(() => false)` into `true`, or dropping `{ clipboardCleared }`, survived. The existing "refuses to clear" test checked that the session still ended, not what the screen then said.
   - Test: `End session claims an emptied clipboard only when the clear succeeded` (`test/end-session.test.mjs`). It covers clears that succeed, report false, and are refused.
   - Fails when: either of those mutants is applied, or the claim is always shown.

## Left as they are

- **Clipboard-clear bookkeeping (clipboard.js:54, 71, 74, 75).** After a failed clear, the "page wrote the clipboard" flag can be reset, so a retry would skip. After the Clipboard API succeeds, the `execCommand` fallback can still run. Both are low risk, because End session runs once and replaces the page.
- **`DESCRIPTOR_PUBLIC_KEY` (addresses.js:151).** Three regex mutants survive because the bare `[hex]{64}(?![hex])` alternative finds the same tail as the `(?:02|03)[hex]{64}` and `04[hex]{128}` alternatives for every well-formed key. They are not strictly equivalent, though. For a malformed hex run followed by a hardened step (for example `02<64 hex>ab/0'`), deleting them turns "Invalid output descriptor" into the "hardened" refusal. Both still refuse, so this is cleanup, not a fix.
- **`addressFor("p2tr", …)` with a 32-byte x-only key (addresses.js:183).** No test or caller in the reach set passes one. Either test it or drop the branch.
- **end-session.js's ~90 markup survivors.** They are the ended screen and the confirm dialog, which the browser suite's End session test covers. Stryker can't see browser runs.

## How the tooling behaved

- **It works with this repo.** The command runner runs `node --test`, and the instrumented ESM loads in jsdom-free tests and in `new Function`/`vm` evaluation. It has no per-test coverage here, so every mutant runs the whole command.
- **Source-text tests break on instrumented code.** The four "(source guard)" tests and the #359 I_L test had to be skipped with `--test-skip-pattern`. Text guards also can't kill a runtime mutant; they only stop the literal edits they name.
- **Cost:** about 75 minutes of laptop CPU in total. Pass 1 took 17 s (clipboard), 18 s (End session), 2 min (addresses) and 31 min (hdkey). Pass 2 took 6, 10 and 8 minutes. The full unit suite took 6.6 minutes locally (2,238 tests) against about 70 seconds in CI, which is why pass 2 used reachability rather than the full suite.
- **Not covered:**
  - **app.js** (17,600 lines). Not tried. Tests extract its functions as text, so expect the same breakage as the source guards.
  - **The browser suite.** Mutants switch through `process.env`, which the browser never sees, so each one would need its own rebuild.
  - **The Rust crates.** `cargo-mutants` wasn't tried.

## Re-running it

From a scratch worktree (never the main checkout), with free RAM checked first (concurrency 3 needed about 5 GB):

```sh
npm ci
npm install --no-save --ignore-scripts @stryker-mutator/core@10.0.0
npx stryker run stryker.hdkey.json
```

An example config (hdkey.js against every test file that reaches it):

```json
{
  "testRunner": "command",
  "commandRunner": {
    "command": "node --test --test-reporter=dot --test-skip-pattern=\"source guard\" --test-skip-pattern=\"I_L == 0 returns the BIP32 retry verdict\" test/addresses-wasm.test.mjs test/extended-private-keys.test.mjs test/hdkey-bip39-wasm.test.mjs test/hdkey-differential-fuzz.test.mjs test/key-purpose-match.test.mjs test/msig-cosigner-rederive.test.mjs test/private-key-getter-copies.test.mjs test/psbt-output-derivation.test.mjs test/secret-clear.test.mjs test/secret-key-range.test.mjs test/self-test-wasm.test.mjs test/station-secrets.test.mjs test/wasm-boundary.test.mjs test/wipe-wasm.test.mjs"
  },
  "mutate": ["src/js/hdkey.js"],
  "coverageAnalysis": "off",
  "concurrency": 3,
  "timeoutMS": 60000,
  "reporters": ["html", "json", "clear-text"],
  "tempDirName": ".stryker-tmp-hdkey",
  "cleanTempDir": true
}
```

The new retry test loads a patched copy of hdkey.js, so it may also need skipping on instrumented code, like the source guards. Any CI use (for example a manual or weekly job that files survivors as an issue, never gating merges) is the maintainers' call.
