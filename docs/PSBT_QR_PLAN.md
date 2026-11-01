# PSBT QR receive: branch plan and multi-agent handoff

## 1. Start here

This is an implementation plan, not a claim that the feature is finished. No application code or appliance image was changed to prepare it.

- Worktree: `/home/agent/doggyballs/entropylab-psbt-qr`.
- Integration branch: `psbt-qr-receive`.
- Publication remote: `fork` = `git@github-doggyballs:doggyballs/entropylab.git`.
- Upstream remote: `origin` = `OogaBoogaX/entropylab`; intended eventual PR base: `rock`.
- Recorded branch base: `f389371c5bbbf4582a2de24a42b28f0ac2788c6e`.
- Existing keyboard worktrees and `/home/agent/doggyballs/rockos-odroid` are separate workstreams. Do not edit, reset, deploy from, or merge them into this branch.
- Read `AGENTS.md`, `CONTRIBUTING.md`, and `docs/UI_Patterns.md` before implementation. Use the doggyballs identity and required truthful model attribution. Push explicitly to `fork`, never `origin`. Opening/submitting an upstream PR requires the operator's approval; preparing this branch does not authorize submission.

**Goal:** receive a complete PSBT from a static or animated QR, show progress and cancellation, and offer its bytes to the existing PSBT workflow without loading incomplete, wrong-type, conflicting or over-budget data. SeedSigner is the reference for protocol interoperability and constrained-device usability, not a replacement transaction parser.

## 2. Important upstream change: do not implement the old proposal verbatim

The initial investigation inspected upstream `f65306d38de9869b2c5dc8ae18771b77a3d4752e`. The fresh fetch for this worktree contains additional work:

- `3e12704a`: bounded fountain decoder/strict UR collector, no UI.
- `4017841c`, `e8176979`: collector limits and per-part work hardening.
- `6b07a1d4`: PSBT payload reader and scan panel, explicitly **not wired**.

Consequently, adding a new fountain decoder, new PSBT reader, or another scanner panel is NOT the default task. Audit, exercise, extend and integrate the existing implementations. Upstream is active: the integration owner must check newer commits and competing PRs before implementation, then freeze the working base and record any scope change here. Do not silently change this plan's base underneath active workers.

### Existing components at the recorded base

| Surface | Existing implementation | Remaining responsibility |
|---|---|---|
| QR output | `src/js/psbt-editor.js`, `address-qr.js`, `psbt-ur.js`; `uqr` 0.1.3 | Preserve static/animated output; interoperability regression only |
| Image decoder | `qr-wasm/` (`quircs`), `src/js/qr-worker.js`, `qr-scan.js` | Reuse worker/WASM; no second image-decoding dependency |
| Camera controller | `src/js/qr-scanner.js` | Currently stops after a positive decode; qualify efficient continuous multipart acquisition without breaking one-shot consumers |
| UR assembly | `src/js/ur-fountain.js` | Prove independent SeedSigner compatibility and bounds; fix only demonstrated gaps |
| PSBT payload reader | `src/js/psbt-qr-payload.js` | Static base64/hex, UR types `crypto-psbt`/`psbt`, PSBT magic and size checks; magic is NOT full PSBT validation |
| Scan widget | `src/js/qr-psbt-scan.js` | `mountPsbtScan`; field replacement confirmation, lifecycle handling; partial results currently call `scanner.start()` again |
| Application entry points | `app.js`, `psbt-editor.js`, `src/shell.html` | No `mountPsbtScan` integration found in these JS entry points at this base |
| Feature/build gate | `scripts/build.mjs`, `preview-blocks.mjs` | QR scanning is preview-only infrastructure; preserve the release/preview boundary |
| Global cleanup | `end-session.js`, `qr-scan.js`, `ur-fountain.js` | Trace and connect retirement to all relevant app lifecycle events; prove behavior |

Existing tests include `test/ur-fountain.test.mjs`, `psbt-qr-payload.test.mjs`, `qr-psbt-scan.test.mjs`, `qr-scanner.test.mjs`, `qr-worker.test.mjs`, `qr-wasm.test.mjs`, `qr-frame-decoder.test.mjs`, `psbt-ur.test.mjs`, `psbt-live-qr.test.mjs` and `address-qr.test.mjs`. Reuse them; their existence does not prove they cover the proposed feature.

### Evidence already exercised

- The appliance's unchanged v1.0.0 HTML SHA-256 is `bdf048ebbf9286a3b18998f28e1cccef1f9f9a0284a880c1864875f903adeb8d`.
- Workstation Chromium against that exact HTML displayed a static QR for the public 486-byte `p2wpkh-1in-2out.b64` fixture and an animated six-part UR for the 1,117-byte `mixed-many-inputs.b64` fixture. Exact UR text was rejected by Editor Load and left Inspector Inspect disabled. This is not camera or SeedSigner interoperability evidence.
- A disposable Bun invocation against this worktree imported `createPsbtQrReader` and the existing UR encoder, supplied the 1,117-byte fixture's six sequential fragments in reverse order, and recovered byte-identical bytes. This proves the newly landed reader runs; the encoder and reader are from the same project, so it is NOT an independent fountain oracle or a camera test.
- No feature build, full suite, physical QR scan, or independent SeedSigner interchange was run when writing this plan.

### PQR-01 upstream reconciliation (2026-10-31, integrator)

Executed against the live remotes, not the plan's original fetch:

- `origin/rock` tip = `f389371c` (the recorded base). **No upstream commits since
  the base.** Frozen integration commit: `29ef723c` (plan-only). Wave A
  worktrees branch from it.
- `origin/scan-qr/pr2-fountain` is a **merged lineage, not a competitor**: it
  landed in `rock` (PR #1273, merge `7e165809`) and is an ancestor of the base;
  every commit the plan lists as "new work" (`3e12704a`, `4017841c`, `e8176979`,
  `6b07a1d4`) is in the base files.
- **No open upstream PR touches this scope.** The only related open PR is
  #1336 (`hotpixelgroup:fix/qr-scanner-timeout-flake`), which edits
  `test/qr-scanner.test.mjs` (PQR-04). Decision: do not block on it. PQR-04
  re-checks its status immediately before touching scanner tests; if it lands on
  `rock` first, rebase; otherwise keep the local changes and note it in the PR.
- Base component verification (files on disk at the base):
  - `createUrCollector` (`src/js/ur-fountain.js`) landed via `20044477` + the
    fountain commits; `createPsbtQrReader` (`src/js/psbt-qr-payload.js`),
    `mountPsbtScan` (`src/js/qr-psbt-scan.js`), `createQrScanner`
    (`src/js/qr-scanner.js`) via `6b07a1d4` and earlier. All four exist at the
    base.
  - `mountPsbtScan` is **not wired into any entry point** (`app.js`,
    `psbt-editor.js`, `src/shell.html`): PQR-05's job stands.
  - `retireUrCollectors()` is exported but **not wired** into End Session /
    pagehide (`endSession`'s `retireModules` is `[hodlRetireWasm,
    hodlRetirePsbtWasm]`). PQR-05 wires it (§4E).
  - Released consumers that must not break: `qr-key-scan.js` (preview-gated key
    scan), `qr-scan.js` (generic scan + `retireQrDecoders` scrub reporting),
    `aexb-capture.js` (released anti-exfil capture; imports `createUrCollector`
    — the fountain collector is already release code).
- Scope: **no change** from §3.

## 3. Scope and non-goals

Required supported paths:

1. Explicit PSBT scan controls for Inspector input and Editor primary input. Include Editor comparison input if consistent with the existing three-panel design; PQR-01 must freeze the exact target list before workers start, and any exclusion must be explicit.
2. Static base64 PSBT QR; preserve existing hex handling. Single-part UR and multipart `ur:crypto-psbt`, including systematic and fountain frames. Preserve the reader's `ur:psbt` alias without advertising SeedSigner support for that alias unless independently demonstrated.
3. Text-pasted supported UR input must use the same bounded reader, rather than a divergent legacy decoder path. Preserve existing base64/hex and Inspector raw-transaction behavior. Do not route ordinary raw transactions through a PSBT-only gate.
4. Explicit scan progress, cancel, restart, permission-denied/no-camera/timeout behavior, and field-replacement confirmation. Scanning transports data; it does not approve, sign or broadcast a transaction.
5. A self-contained offline preview HTML, no runtime downloads, no remote decoder, no storage-backed camera frames or scan history.

Out of scope: new signing capability or consensus rules; seed/key/WIF import through the PSBT scanner; SeedQR/CompactSeedQR; BBQR, Specter multipart and legacy UR compatibility unless separately agreed; generic image-upload UI; keyboard work; USB storage; entropy generation; unrelated UI redesign; enabling unreleased features in the default release; automatic appliance deployment.

## 4. Shared contracts to freeze before parallel edits

PQR-01 owns this contract. The names below describe existing APIs, not stubs to create. Prefer extending them compatibly for existing callers; do not create parallel implementations or compatibility wrappers to avoid migrating affected callers.

### A. Transport and ownership

- `createUrCollector(options)` in `ur-fountain.js` exposes `receive`, `state`, `reset`; it produces a complete CBOR message only after reassembly/integrity checks.
- `createPsbtQrReader({maxBytes})` exposes `receive(text)`, `progress()`, `reset()`. Its current result vocabulary includes `complete` with `bytes`, `partial`, `done`, `not-psbt`, `wrong-type`, `mismatch`, `too-large`, `bad-cbor`, `bad-part`.
- The protocol owner documents each status as recoverable/terminal, its state-mutation policy, and byte-buffer ownership. The scanner and text importer consume this same contract. Progress is not successful completion, and a checksum is not sender authentication or transaction validity.
- A completed PSBT must enter the existing parser/validation path before it is presented as a valid transaction. Prefix/magic validation alone does not establish this. Do not weaken parser errors to make scanning appear successful.
- Never import private-seed payloads through this context or silently switch to another tool when a different QR type appears.
- Reader reset/disposal wipes owned mutable buffers best-effort and invalidates pending generations. Do not claim secure RAM erasure: JS strings, browser copies and worker termination limit that claim.

### B. Field integration

- Retain `mountPsbtScan(host, {field, translate, onLoad, ...})` as the widget integration surface unless a concrete problem requires a coordinated change.
- One owner controls any shared acquisition so two panels cannot silently hold competing camera streams. Starting another panel must stop the old acquisition and invalidate its late replies.
- Empty-field completion can offer/populate the PSBT. Existing user input must not be overwritten without explicit Replace confirmation; recheck field state at confirmation time, not only scan start.
- Define `onLoad` precisely: update the existing field/input state and existing parse workflow; no duplicate parse engine or automatic transaction approval.
- Text UR parsing must be bounded and avoid expensive full reassembly on every keystroke. Define incomplete-input behavior and when Load/Inspect becomes available without changing ordinary file/text import semantics.

### C. Acquisition and cleanup

- Reuse `createQrDecoder` and the worker; one decode in flight. No second camera or decoder library.
- Existing `createQrScanner` is one-shot; existing PSBT widget restarts it after a partial result. Measure and address repeated permission/capture setup rather than assuming that is efficient continuous scanning.
- A continuous mode, if needed, is explicit and preserves one-shot behavior for existing key/other consumers. Freeze callback/continuation semantics and buffer ownership before changing either file.
- Stop/cancel, completion, panel switch, workspace/tab change, document hidden, conceal, pagehide, destroy and End Session must release capture appropriately and prevent late callbacks from updating a field. Define what is retained on pause; default to clearing incomplete PSBT state on user cancellation.
- Preserve worker watchdog/scrub reporting. Close must not report a successful scrub when the worker was forcibly terminated without acknowledgement.

### D. Resource policy

Existing defaults are evidence, not validated appliance budgets:

| Boundary | Recorded default | Required proof |
|---|---|---|
| UR message / reader | 1,048,576 bytes | Input text/CBOR/decoded size checks before large allocations; specify CBOR overhead treatment |
| UR fragment count | 1,000 | Reject hostile count claims; cannot allocate in proportion to an unchecked number |
| Collector work | 10,000,000 steps per received part | Bound mixed-frame reduction, retained bytes and cumulative session work as well |
| Worker image | 4,194,304 pixels; dimensions capped at 4096 | Preserve checks before allocation and transfer |
| Camera controller | 60-second default timeout; frame scale cap 1280x720 | An overall scan deadline must not reset forever on every partial frame |

Freeze numeric acceptance limits after measuring existing fixtures. A valid transaction can exceed the supported optical budget: reject it explicitly, never truncate. Track duplicate-only and malicious non-progress streams; no unbounded queue of frames, fragments or promises. Do not increase limits or remove caps to pass a benchmark. Keep default output QR framing unchanged unless interoperability demonstrates a real defect.

### E. Frozen values (measured from the base, 2026-10-31)

**Status contract** — collector status → reader status, as actually coded in
`ur-fountain.js` / `psbt-qr-payload.js` (section 4A names the APIs; this fixes
their semantics):

| Reader status | Source | Recoverable? | Ownership / state policy |
|---|---|---|---|
| `complete` + `bytes` | collector full reassembly, CRC + padding OK; or static base64/hex with PSBT magic | Terminal (success) | `done = true`; collector killed, removed from the global `collectors` registry, buffers wiped; `bytes` is the returned copy |
| `done` | collector `complete` | Terminal | every subsequent `receive` → `done`; only `reset()` recovers |
| `partial` | collector `progress` or `duplicate` | Yes (stream continues) | session accumulates; `progress()` → `{received, total}` (null while unbound or done) |
| `wrong-type` | collector: UR type not in `types` | Yes (stream continues) | bound session untouched; single part arriving mid-session → `mismatch` |
| `mismatch` | collector: part `seqLen` ≠ bound `seqLen`, or collector-level `conflict` (same seqNum, different data) | Alive → continues; killed → **persists until `reset()`** | on kill: all buffers zeroed, removed from registry |
| `too-large` | collector: messageLen > `maxMessageLen` / seqLen > `maxSeqLen`; or static decode over limit | Alive → continues; killed → persists until `reset()` | zeroed on kill |
| `bad-part` | malformed part (seq / frag count / length), `legacy`, collector `invalid` (reassembled message fails CRC/padding → kill), or reader default catch-all | `invalid` → persists until `reset()`; otherwise stream continues | per-part data zeroed after integrate |
| `bad-cbor` | reader: collector `complete` but `hodlCborUnwrapPsbt` failed | Reset required | reader auto-`collector.reset()`; message copy zeroed on unwrap |
| `not-psbt` | static path: no PSBT magic | Per part; no collector state | static `bytes` zeroed on failure |

- Only `complete` returns owned bytes. The caller owns them: zero them on write,
  discard, or late arrival (`mountPsbtScan` does this; preserve it).
- JS strings are not zeroable (decoded text, browser copies, worker retention) —
  wipe claims are best-effort only; do not document otherwise.
- The reader is stateful per instance (`done` flag): one reader per scan session;
  `mountPsbtScan` resets on open and close — preserve that.

**Target field list** (frozen; consistent with the existing three-panel PSBT
design — no exclusions):

| Entry point | Element | Notes |
|---|---|---|
| Inspector primary | `#psbt-text` (textarea, "PSBT v0 or raw transaction (base64 or hex)") | base64/hex/raw-tx paste unchanged; `ur:` paste → reader only (gate: `crypto-psbt`/`psbt`); never routes raw transactions through the PSBT-only gate |
| Editor primary | `#psbted-text` (textarea, "PSBT v0 (base64 or hex)") | base64/hex unchanged; `ur:` → reader |
| Editor comparison | `#psbted-compare-text` (textarea, "Other PSBT (base64 or hex)") | PSBT-only; comparison remains the existing read-only diff (`psbt-diff.js`) |

- **Text-paste UR contract:** `ur:`-prefixed input goes through
  `reader.reset(); reader.receive(text)` — the same bounded reader the camera path
  uses; no divergent legacy decoder. Non-`ur:` text keeps the existing parse
  paths (`psbtBytesFromText` in the Inspector; editor load/compare).
- **`onLoad` contract:** write the field as base64, dispatch a bubbling
  `InputEvent({ inputType: "insertFromPaste" })` so the existing parse flow sees
  it, then invoke the passed `onLoad`. No duplicate parser, no automatic
  approval.
- **Replace confirmation:** emptiness is checked at completion (existing);
  PQR-04 also re-checks at Replace click (gap §4F.1).
- **Fixture location (PQR-02/03 agreement):** `test/fixtures/psbt-qr/` (new dir)
  — `manifest.json` (per the §6 spec) plus generated `.ur`/`.b64` fixtures.
  Independent oracles: `test/fixtures/bc-ur/reference-vectors.json` (BCR-2024-001,
  license `test/fixtures/bc-ur/LICENSE`) for fountain fragment selection and
  `test/fixtures/psbt/*.b64` public PSBTs. No network downloads in tests.

**Preview policy** (measured mechanism; key-scan precedent in `app.js`):

- `scripts/build.mjs` defines `__ENTROPYLAB_PREVIEW__` via esbuild `define` as
  the bare boolean token `true`/`false`; esbuild dead-eliminates the falsy branch
  (including dynamic imports) and inlines reachable dynamic modules into the
  single iife. At the base, `npm run build` reproduces the committed release
  artifact byte-for-byte: sha256 `778ab1c33002fd500807e0c3f7606f5970bc8ad3329e8d2239f3674288ba2ad1`
  (8,265,590 bytes, v1.0.0).
- Pattern to copy (key scan: `hodlKeyScanHostMarkup` / `hodlBindKeyScan` in
  `app.js`):
  1. Host div: `<!-- preview --> <div id="psbt-qr-host"></div> <!-- /preview -->`
     inside `#psbt-card`, and `<div id="psbted-qr-host"></div>` likewise inside
     `#psbted-card` (`src/shell.html`). Release builds strip the block; the
     widget mounts into the host (replacing its children).
  2. `app.js`: module vars + dynamic `import("./qr-psbt-scan.js")` under
     `typeof __ENTROPYLAB_PREVIEW__ !== "undefined" && __ENTROPYLAB_PREVIEW__`;
     mount when the host exists and is empty; keep the reference;
     `catch(() => {})`.
  3. Teardown: in the End Session / pagehide wipe block (beside
     `hodlKeyScan?.destroy()` / `hodlKeyScanModule?.retireQrDecoders()`):
     destroy each PSBT scan widget, call `retireQrDecoders()` (module export)
     and `retireUrCollectors()` (import from `ur-fountain.js`).
- **Release gate (operator-approved revision):** require byte-identical rebuilds
  of the current source tree, absence of all three PSBT scan hosts in the release
  artifact, and unchanged release base64/hex/raw-transaction behavior. The
  historical base hash above is provenance evidence, not the candidate's required
  hash: source stamps and esbuild identifier allocation change with source inputs.
  Preserve truthful stamping; do not normalize an artifact and call it byte-identical.
  Preview acceptance must exercise all three mounted entry points.

**Resource policy** (measured defaults; unchanged unless PQR-04 measurement
justifies it):

| Boundary | Measured default |
|---|---|
| Message / reader size | 1,048,576 bytes (`maxBytes` / collector `maxMessageLen`) |
| Fragment count | `maxSeqLen` = 1,000; `seenCap` = 4·seqLen+64; `mixedCap` = 2·seqLen+16 |
| Collector work | 10,000,000 steps per received part (index + byte, cascades included); over-budget pending data zeroed and dropped |
| Worker image | 4,194,304 pixels; side capped at 4096; file upload capped 10 MiB |
| Camera session | one 60,000 ms timer per `start()` (never resets per partial frame); frame scale capped 1280×720 |
| Static QR output | `PSBT_QR_STATIC_MAX_BYTES` = 800 (output side; unrelated to the input limit) |
| Text paste (existing) | `psbtBytesFromText`: 7,000,000 compact chars / 5,000,000 decoded bytes (Inspector) |

- Do not raise any bound to pass a fixture; over-budget data is explicitly
  refused (`too-large`), never truncated.

### F. Gaps to close (PQR-04/PQR-05; each with a test)

1. **Replace click does not re-check the field.** Emptiness is checked when the
   dialog opens; the Replace button writes `pending` unconditionally. A field edit
   while the dialog is open would be overwritten by the stale scan. Re-check at
   click: non-empty field → keep the dialog (re-prompt against current content);
   never write a scan that no longer matches the field's state.
2. **Partial results restart the one-shot scanner.** `restartCamera()` calls
   `scanner.start()` → a full `getUserMedia` re-negotiation per partial result.
   PQR-04 measures this on the real fixtures
   (`test/fixtures/psbt/p2wpkh-1in-2out.b64`,
   `test/fixtures/psbt/mixed-many-inputs.b64`) and decides: document the
   restart, or add an explicit continuous-acquisition mode to `createQrScanner`
   that preserves one-shot behaviour for the existing consumers
   (`qr-key-scan.js`, `qr-scan.js` consumers, `aexb-capture.js`).
   `retireQrDecoders` scrub reporting must stay correct either way.
3. **`retireUrCollectors()` is not wired** into the End Session / pagehide
   teardown (only `hodlRetireWasm` / `hodlRetirePsbtWasm` /
   `retireQrDecoders` are called).
4. `mountPsbtScan` is mounted by no code — PQR-06's browser scenarios are
   blocked on PQR-05. The widget's own unit suite exists and must keep passing.

## 5. Multi-agent work packages

One integration owner maintains this plan, shared contracts and final history. Agents claim an ID and owner in the ledger before editing. A file has one writer at a time. Use separate task worktrees/branches for independent agents; do not have multiple sessions commit the same worktree/index.

| ID | Suggested owner | Scope / exclusive write area | Dependencies | Completion evidence |
|---|---|---|---|---|
| PQR-00 | Integrator | Worktree, branch, this plan, branch instructions | None | Planning branch established; no app changes |
| PQR-01 | Integrator + read-only reviewer | Reconcile new upstream/PRs; freeze contracts, target fields, preview policy, error/budget policy | PQR-00 | Base SHA and no-duplicate-work decision; interfaces agreed before edits |
| PQR-02 | Protocol/interop agent | `ur-fountain.js`, `psbt-qr-payload.js`, relevant portions of `psbt-ur.js`; their behavior tests | PQR-01, fixture contract with PQR-03 | Independent SeedSigner systematic/fountain compatibility, bounds and rejection cases; no replacement decoder unless existing one is demonstrably unsuitable |
| PQR-03 | Fixture/reference agent | Public QR fixtures and provenance manifest in agreed `test/fixtures/` location; reference-generation instructions | PQR-01 | Immutable reference revisions, licenses, exact payload hashes and expected outcomes; no application source edits |
| PQR-04 | Camera/lifecycle agent | `qr-scanner.js`, `qr-psbt-scan.js`; their lifecycle tests | PQR-01; coordinate payload status contract with PQR-02 | Bounded continuous multipart capture, cancel/restart/late-result handling, field confirmation; no duplicate UI component |
| PQR-05 | Integration/UI owner | `app.js`, `psbt-editor.js`, `src/shell.html`, minimal shared CSS, global cleanup and build gates | PQR-02/PQR-04 APIs frozen; integrate after both are usable | All agreed entry points work in built preview; text/file regressions pass; release remains gated |
| PQR-06 | Browser/acceptance agent | Feature behavioral browser scenarios, isolated fixtures/runner changes by agreement; no competing product edits | PQR-03/PQR-05 | Real decoder + built HTML smoke, optical frame simulation, screenshots, cleanup and network observations |
| PQR-07 | Security reviewer (read-only) | Diff, resource accounting, wrong-type/mixed-message handling, lifecycle, privacy and network review | Integrated candidate | Findings with reproducible evidence; no speculative issues presented as exploits |
| PQR-08 | Integrator | `package.json` test registration, README/SECURITY user documentation, reproducibility evidence, PR description | PQR-02..07 | Focused history, consolidated checks, honest remaining hardware limits; request approval before PR submission |
| PQR-HW | Separate RockOS/hardware owner | Camera qualification, enclosure and narrowly scoped OS permissions in RockOS repo, NOT this app branch | Can research in parallel; optical test needs integrated artifact and camera | Physical scan measurements and explicit appliance qualification; never silently change the stock image |

Parallel schedule:

- Wave A: PQR-01 first; then PQR-02, PQR-03 and PQR-04 can proceed concurrently on owned files. PQR-HW research is independent.
- Wave B: PQR-05 integrates real protocol and camera paths. PQR-06 can prepare public scenarios earlier but must exercise the integrated build, not only mocked echoes.
- Wave C: PQR-06 and PQR-07 independently assess the integrated candidate; PQR-08 owns fixes/integration and final checks.
- Do not run builds, broad suites or formatters concurrently in the shared integration worktree. Schedule required security red-before-green checks in isolated task worktrees; integrate and run the consolidated verification once after the edit wave. Never suppress a known failure or repeatedly rerun it unchanged.

### Ledger

| ID | Owner | Status | Evidence / blocker |
|---|---|---|---|
| PQR-00 | Planning integrator | Complete | Base/worktree above; source-reader smoke above; documentation-only setup |
| PQR-01 | Integrator (2026-10-31) | Complete | Upstream reconciled; base freeze `29ef723c`; contracts frozen §4E/§4F; release gate revised with operator agreement |
| PQR-02 | AutonomousTern + Integrator | Implemented; final consolidated verification pending | Published vectors, 1000-fragment boundary, duplicate/non-progress bounds, terminal reader fix; independent exact-byte diff tool passes |
| PQR-03 | CompactVulture + Integrator | Complete | 53 pinned reference cases plus manifest; offline integrity/acceptance tests pass; reproducibility checked |
| PQR-04 | FinancialWildebeest | Integrated | `1ced6f6f`; continuous capture; 87 integration/consumer tests passed before final timeout cleanup regression |
| PQR-05 | Integrator | Implemented and smoke-tested | Three preview hosts; Inspector UR full parser; bounded text/camera reader; navigation/global retirement |
| PQR-06 | QrBrowserAcceptance | Optical smoke passed | 25 checks; real embedded worker/WASM; 41 optical frames; all 11 simulated streams ended; broad browser checks pass after accessible staging/clean-source stamp |
| PQR-07 | QrSecurityReview | Reviewed; four root causes addressed | Static follow-up found no remaining findings in reviewed scope; exercised regression evidence below |
| PQR-08 | Integrator | In progress | Documentation and CI registration complete; final consolidated verification pending; no upstream PR authorization |
| PQR-HW | Unassigned | Research available; physical proof pending | See section 9; no purchase or deployment performed |

### Integration evidence and approved release gate

- PQR-04 camera acquisition measurement: six parts required six starts before
  continuous mode; after it, one start and no between-part reopens (agent report).
- Integrator exercised preview multipart text through the real Inspector parser:
  public 486-byte fixture displayed one signed input, two outputs, and a
  23,456-sat fee. No key was loaded. Three PSBT scan hosts mounted in Chromium.
- `test/psbt-qr-text.test.mjs` initially rejected the complete UR as invalid
  base64/hex; the bounded-reader integration accepts the original public bytes.
  Incomplete and wrong-type UR remain rejected; raw-transaction hex is unchanged.
- Review identified hidden-context capture, recoverable refusals hiding Stop,
  cancelled multipart state retention, and full reassembly on every Inspector
  input. Fixed by closing on navigation, separating acquisition/status state,
  resetting on cancellation, and cheap readiness checks. Focused lifecycle
  tests failed before those fixes and passed after. Navigation and readiness
  regressions were also exercised with their guards temporarily removed,
  then restored (late write and ten repeated assemblies respectively).
- **Operator-approved gate revision:** the operator selected “Reproducible,
  preview-gated release” after the historical hash conflict was explained.
  `build-commit.mjs` deliberately stamps changed sources with a new commit
  (dirty builds use `unknown`); esbuild also renames identifiers when the
  import graph changes. Require current-source reproducibility, artifact-level
  preview exclusion/inclusion, and release behavior regressions instead of
  manufacturing the old full-file hash. The historical hash remains recorded.
- Reference corpus: `test/fixtures/psbt-qr/manifest.json`, 53 cases generated
  from stable SeedSigner `e0a80d4b`. Complete cases require exact SHA-256 and
  length of the reference's serialized PSBT plus independently recorded
  transaction fields. This supersedes the exploratory tx-core-only comparison:
  byte ordering can differ from the original file, but not from emitted bytes.
- `/tmp/pyvenv/bin/python scripts/seed-signer-diff.py` passed 53
  reference-to-app acceptance/rejection cases and six app-to-reference
  exact-byte output checks. Public fixtures: native SegWit, mixed inputs and
  Taproot; LOW/MEDIUM/HIGH densities; no runtime/reference dependency in npm tests.
- Known external limitation: the pinned SeedSigner CRC encoder uses variable
  width. Taproot LOW systematic part 2 has a short CRC and is strictly refused.
  It remains a negative fixture, not a fabricated successful interchange.
  Fountain-only valid-frame recovery is separately proven; raw camera animation
  containing that malformed frame is not qualified.
- New terminal-state regressions reproduced a real reader defect: conflict or
  invalid reassembly could be bypassed by switching to static input. The reader
  now latches `mismatch`/`bad-part` until explicit reset. Focused red-before-green
  command: `node --test --test-name-pattern='terminal multipart|invalid reassembly|bad CBOR resets' test/psbt-qr-payload.test.mjs`.
- Browser staging requires `TMPDIR=/home/agent/doggyballs/psbt-browser-tmp`
  with this workstation's Snap Chromium: its private `/tmp` cannot read the
  ordinary harness staging paths. Use `CHROME_BINARY=/usr/bin/chromium-browser`.
  The committed build's provenance check must run against clean build inputs;
  a deliberately dirty build correctly stamps `unknown`.


### Copy/paste agent assignment

> Work only on PQR-XX in `docs/PSBT_QR_PLAN.md`, on a dedicated task branch/worktree derived from the agreed integration commit. Read AGENTS.md and CONTRIBUTING.md first. Claim your owner/status; confirm your exclusive files and interface dependencies with the integrator. Reuse existing implementations. Public vectors only; no network at app runtime, no new dependency without review, no edits to generated HTML/WASM or locale catalogs. Record the security contract and required independent red/green evidence before/after behavior changes. Do not run shared builds or broad suites mid-wave. Return changed paths, interface changes, actual commands/results, limitations and ready-to-integrate commits. Do not deploy, open a PR, push upstream or modify another agent's files.

## 6. Independent interoperability and negative-case matrix

Reference SeedSigner revisions:

- Development: `ada81cde050e46c19cb6e3fa73872b73955a138c`.
- Stable 0.8.7: `e0a80d4b33b8eb7fb1e9fd14a27b7cd11c7d2cd6`.
- QR transport sources: `src/seedsigner/models/encode_qr.py`, `decode_qr.py`, `helpers/ur2/`, `gui/screens/scan_screens.py`.
- QR transport inspection found the relevant mechanics identical across those snapshots; transaction validation changed separately. Do not copy older signer policy into EntropyLab. SeedQR is private seed transport, not PSBT transport.

Fixture manifest must record: reference project/revision/license, generator command/environment, public PSBT provenance, raw-byte SHA-256/length, emitted frame sequence, expected accepted bytes or rejection, and which direction is tested. Generate expected outputs with the pinned independent implementation or published vectors, not by copying the implementation-under-test's answers. Keep reference tooling separate from runtime dependencies. Do not silently download moving references in tests.

Required cases:

- Small static base64; existing hex regression; single-part UR; ordinary multipart systematic frames.
- SeedSigner-emitted fountain sequence received after the initial systematic frames have been skipped; reversed order, deterministic loss and duplicates at multiple reference densities.
- EntropyLab-emitted static/animated output decoded by the independent reference, byte-exactly. This is a regression, not a request to redesign output.
- Full PSBT parsing after transport; magic-only garbage rejected by the existing parser, not labelled valid.
- Wrong UR type, SeedQR/CompactSeedQR, WIF, arbitrary URLs/text and invalid UTF-8 cannot trigger a key import or navigation.
- Same-format different-message splice, conflicting duplicate, changed sequence count/message length/checksum/fragment size; no completed hybrid message.
- Corrupt QR/Bytewords/CBOR, invalid sequence numbers, legacy fragments without accepted whole-message semantics, truncated and trailing bytes.
- Size/count/work-limit boundaries, large advertised lengths, very long text, duplicate flood and non-progress fountain stream. Check rejection occurs before expensive allocation.
- Complete then duplicate, reset then new message, cancel while decoding, late permission resolution, late frame reply, repeated open/close, two panels, document hide/conceal/pagehide, End Session, camera unplug and permission denial.
- Existing text/file import, editor comparison, static/animated export and one-shot key scanner consumers remain unchanged except explicitly agreed behavior.
- Existing field modified while scanning or while Replace confirmation is open: never overwrite newer edits silently.

Do not infer parser authenticity from CRC success or call an unsigned public fixture a real spend. Some existing synthetic fixtures deliberately include invalid signatures; document their intended role rather than treating a warning as a regression.

## 7. Verification and evidence gates

### Development commands (implementation stage, not run by this plan)

Use the pinned container where required by CONTRIBUTING. Inspect package scripts after any rebase.

```sh
npm ci
node --test test/ur-fountain.test.mjs test/psbt-qr-payload.test.mjs
node --test test/qr-scanner.test.mjs test/qr-psbt-scan.test.mjs
node scripts/build.mjs --preview --out out/psbt-qr-preview
npm run build
npm test
npm run test:browser
npm run verify
npm run reproduce
```

These are baseline commands, not a claim of coverage or success. Add genuinely new behavioral cases to the appropriate existing runners and register them with CI. Keep preview output separate; do not deploy a test-hook build. Stage dependencies once per worktree; do not repeatedly rebuild while siblings edit shared files.

Required evidence levels:

1. Independent byte-level protocol fixtures and bounded negative cases.
2. Real image decoder exercised on QR images/frames, not a fake decoder returning the expected payload.
3. Built preview in an actual browser: visible scanning/progress/error/Replace behavior, existing parser result, screenshots, cancellation and cleanup. Simulated camera frames are useful but labelled as simulated; exercise real worker/WASM, not mocked output.
4. Default release build still excludes unreleased scan controls/worker paths as intended. No egress, frame logging, frame persistence or newly generated entropy. Verify offline self-contained operation.
5. Native camera trial on target hardware, public data only: startup/scan time, frame size/rate, RSS/cgroup peak, CPU, cancel responsiveness, unplug/replug, orientation, lighting and focus distances. No silent promotion of desktop results to board acceptance.

Security-sensitive changes follow upstream's test-first contract. A failing test must fail for the claimed behavior, not accidental setup; expected answers must be independent. Do not pin incidental copy, class names or source layout. Permanent tests must catch consumer-visible behavior; use disposable smoke tooling for one-off measurements. Tests alone do not prove the camera UI works.

## 8. Definition of done and PR packaging

The branch is implementation-complete only when the agreed field entry points, text UR path, independent fountain interoperability, resource limits and lifecycle behavior work end-to-end in a built preview. Existing source modules or a passing same-project round-trip are not completion.

- Reuse landed upstream code and explain only the remaining delta.
- No new runtime dependency unless explicitly reviewed; retain licenses/attribution for any reused reference code or vectors. SeedSigner's Python camera code is not transplanted into the browser.
- No generated artifacts, private material, screenshots of secrets or device identifiers committed.
- README and SECURITY explain supported formats, limits, preview status, permissions, cancellation, checksum-vs-authentication and no secure-erasure claim.
- Record verification commands with observed outcomes, independent reference revisions and known failures. If hardware is unavailable, label it untested; do not claim appliance readiness. An upstream draft may disclose a hardware gate only with operator approval.
- Keep substantive commits small by concern: evidenced protocol fixes, lifecycle/widget changes, app integration, acceptance/docs. Do not squash away necessary provenance before review.
- Push only the doggyballs branch. Upstream submission is a separate approval; merging or deploying is not authorized by this plan.
- This coordination plan and its AGENTS pointer are fork-local planning material. Before upstream submission, the integrator decides whether to omit them from the focused upstream diff or retain only documentation useful to upstream contributors.

## 9. Separate camera / RockOS / rear-case workstream

This is not an app-PR dependency for software development and must not cause broad OS permissions in this branch.

Research points to USB UVC, not a Raspberry Pi CSI camera: M1S documentation exposes MIPI-DSI for a display, not a camera CSI connector. Captured vendor-kernel research found `CONFIG_USB_VIDEO_CLASS=m` and `uvcvideo.ko`; module presence is not a successful capture test. Verify the exact Lite board revision, module dependencies and supported modes with actual hardware.

Candidate research sources (not purchase approvals or tested compatibility):

- [Waveshare OV5640 USB camera family](https://www.waveshare.com/ov5640-5mp-usb-camera-b.htm): compact module family with autofocus/fixed-focus variants; verify exact SKU, minimum useful focus distance, connector/cable and mounting drawing before choosing.
- [Waveshare OV5693 USB camera B](https://www.waveshare.com/product/ov5693-5mp-usb-camera-b.htm): autofocus candidate; compare screen-QR focus stability and low-resolution UVC modes, not megapixel count alone.
- [Hardkernel internal USB board for M1S](https://www.hardkernel.com/shop/internal-usb-board-for-m1s): possible internal port expansion; verify exact board/header compatibility and connector clearance. A compatible powered hub is another prototype option, subject to power/backfeed checks.
- [Waveshare 7inch HDMI LCD C drawings](https://www.waveshare.com/wiki/7inch_HDMI_LCD_(C)) and [M1S datasheet](https://cdn-reichelt.de/documents/datenblatt/A300/ODROID_M1S.pdf).

Mechanical concept: screen faces the operator; camera looks out the opposite/back face toward the online wallet's screen. Mount the camera on an independent bracket/standoffs near a rear edge, with an unobstructed lens opening, short restrained internal cable, service access and ventilation. Keep it clear of the ODROID heatsink and HDMI/USB bends. Do not invent hole coordinates or final depth: obtain the actual LCD rear-board revision/photo, manufacturer CAD and camera lens-height drawing before enclosure CAD. Test focus through any protective window; glare and case occlusion can defeat an otherwise compatible camera.

Do not infer power headroom from a 5V/3A supply label: measure the display, board and selected camera together. Touch and external keyboard already consume USB connections during testing. No purchase was made; exact close-focus performance, fit and native capture remain open.

RockOS currently denies camera access via its device policy and private browser `/dev`. Any later integration must be a separately labelled candidate with the specific required camera interface and minimum metadata access, not `/dev/video*` or all-host-device exposure. Preserve the sandbox and fail-closed checks. Keep the working SD, eMMC backup and recovery SD intact; no eMMC writes, fuse changes, SSH fallback or arbitrary network changes. Physical/operator coordination remains mandatory.

## 10. Immediate handoff

Assign one integrator to PQR-01. After it reconciles the fresh upstream work and freezes contracts, assign independent agents to PQR-02, PQR-03 and PQR-04. Keep PQR-05 shared integration under a single writer. Use PQR-06/PQR-07 for independent verification rather than having each implementer certify their own work alone.

The first deliverable is a no-duplicate-work contract and independent fixtures, not another implementation of the already-landed fountain collector or scan panel.
