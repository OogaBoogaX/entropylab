# Residue audit (developer harness)

`npm run test:residue -- --browser chrome` runs a public fixture through the
app, captures browser-process memory at defined checkpoints, and searches
those captures for the fixture's actual secrets. This is a manual developer
tool, outside `npm test` and CI. Its unit tests run in `npm run test:ci`; its
live Chromium driver checks need a browser, so they run with
`npm run test:browser` (CI's browser job). Neither performs memory captures.

**Never fund the fixture wallet.** Its mnemonic, passphrase, and valid derived
keys are public test data. The harness launches a new, temporary profile; it
does not attach to an existing browser or accept a user's wallet as input.

## Requirements

Capture tools are detected, never bundled:

| Platform | Capture tool | Setup |
|---|---|---|
| Windows | ProcDump | <https://learn.microsoft.com/sysinternals/downloads/procdump>, or `PROCDUMP_BINARY` |
| Linux | gcore from gdb | `sudo apt install gdb` / `sudo dnf install gdb`, or `GCORE_BINARY` |
| macOS | Unsupported | Fails before launching a browser |

Chrome/Chromium and Edge are supported. Set `CHROME_BINARY` / `CHROMIUM_BINARY`
or `EDGE_BINARY` when they are not on PATH or in the usual install locations.
The default is Chrome, falling back to Edge. An explicit `--browser` does not
fall back. Node 20.19+ is sufficient; no new npm dependency is needed.

**Firefox is currently unsupported.** The former in-page driver retained
fixture literals and could not reliably close the tab. It has been removed.
`--browser firefox` fails explicitly; a future implementation needs an external
driver with the same isolation and checkpoint contracts.

Linux ptrace permissions and browser sandboxing can prevent gcore from reading
some processes. Capture failures are reported and invalidate the run; they
are not interpreted as zero residue. Reports retain the capture tool's diagnostic
tail (up to 8,192 characters). The harness does not change OS permissions.

If `MEMPROCFS_MOUNT` is set, the optional live-file path scans per-process
files instead of creating dumps. It recognizes `<mount>/<pid>/` and
`<mount>/proc/<pid>/`; other layouts are recorded as unavailable. A recognized
directory does not guarantee that every memory region is exposed. Incomplete
captures invalidate the run. A primary capture tool must still be detected.

## Fixture and search targets

The fixture uses the published BIP39 128-bit `80…80` vector, starting
“letter advice cage”, with the public passphrase
`EntropyLab residue audit 750 - PUBLIC TEST ONLY`.

`makeSecrets()` contains the actual 64-byte BIP39 seed, master xprv, and first
compressed mainnet WIF/private scalar at `m/84'/0'/0'/0/0`. These constants
were established independently with Node's PBKDF2 and the repository's pinned
`@scure/bip32` / `@scure/base` dependencies. Tests re-derive and compare them.
No app-derived output is used as its own expected answer.

The scanner searches UTF-8 and UTF-16LE text, raw seed/private-scalar bytes,
and the mnemonic's base64 text. It does not cover every possible encoding.

## Driver and checkpoints

The harness stages a **release build**, without test hooks, in a temporary
directory and serves it on loopback. The only injected statement suppresses
`window.close()` until after the wipe capture. No fixture literal or session
driver is injected. The staged file itself must contain none of the needles.

Node drives the UI through Chromium's debugging pipe. Fixture text arrives
through native input events, never evaluated JavaScript source, page globals,
or checkpoint URLs. Values returned by the browser are compared on the host;
protocol object groups are released. Revealed output and clipboard verification
return only SHA-256 digests, rather than secret text, through the debugging pipe.
No debugging TCP listener is opened.

The session selects 12-word seed mode, enters the public mnemonic/passphrase,
checks the input, and switches to the word-number view, which exposes the
app's real **Copy seed phrase** control. The derived, revealed mnemonic,
master xprv and first WIF must match the host's expected fixture.

| Checkpoint | Required state |
|---|---|
| `before-input` | App booted; no fixture entered; complete captures and no needle hits |
| `after-derive` | Derive clicked and the completed wallet rendered |
| `after-reveal` | Private values are revealed; capture precedes output verification and all clipboard actions |
| `after-copy` | The app's seed-copy control ran and the clipboard equals the fixture mnemonic |
| `after-wipe` | End Session completed and the ended screen is present |
| `after-tab-close` | The fixture tab is confirmed closed; surviving processes are enumerated again |

The clipboard is cleared before the copy step to prevent a stale value passing
the check. The check reads the clipboard after the real app copy; it never
substitutes a successful mock write. Clipboard failure aborts the run.
A blank keeper tab lets the browser process survive closing the fixture tab.

After the `after-reveal` capture, digests of the rendered private fields are
checked against the expected mnemonic, master xprv and first WIF. A mismatch
stops the run before copying. Thus the derived xprv/WIF cannot pass the positive
control just because output verification returned them through CDP. The capture
alone does not establish that the wallet matches; the subsequent verification
must also succeed for a complete valid run.

`test/residue-browser.test.mjs` uses the same release build, debugging-pipe
adapter and `Input.insertText` as the manual harness. It checks trusted,
cancelable `beforeinput`, a masked passphrase field, and the independently
pinned wallet. Blocking the edit must reject the wrong xprv; blocking the real
Copy seed phrase action must reject the clipboard check. These tests require
Chrome/Chromium or Edge, skip explicitly when neither is installed, and run with
`npm run test:browser`. The unit mock still assigns `.value`; it proves
ordering, not native event delivery.

## Controls and reports

A contaminated or incomplete `before-input` capture stops the run before input.
At `after-reveal`, the scanner must find **each** of the mnemonic, xprv and WIF.
Missing checkpoints or any skipped/failed process capture invalidate the run.
Invalid runs exit nonzero (2 for harness/tool errors), retaining partial reports.

Calibration is also listed per needle. A seed may have been wiped during
derivation, before the first post-derive capture. If a needle was never seen
before End Session, a later zero is **NOT CALIBRATED**, not evidence of erasure.

Reports and captures are written to gitignored `out/residue/`:

- `residue-report.json`: metadata, overall validity/reasons, calibration,
  attempted processes, skipped captures, hits and file offsets.
- `residue-report.md`: human-readable equivalent, including invalid/uncalibrated
  results and skipped checkpoints.
- `browser.log`: browser diagnostics retained after temporary-profile cleanup.

`--browser-process` restricts captures to the parent process. It can fail the
positive controls if the fixture is found only in a renderer; that result is
invalid, not a clean browser. Dumps exceeding 4 GiB are deleted **after capture**;
this is not a streaming disk quota. Provision disk space for all checkpoints.

The [example report](examples/residue-report.example.md) is illustrative,
not a claim about a measured OS/browser combination.

## Limits

**Zero hits is not proof of erasure.** It only describes the scanned processes,
representations and times on this OS/browser. A hit proves those bytes were in
the captured data; it does not identify which app, browser, debugger or OS
subsystem retained a copy.

Automation, protocol input/return buffers, and clipboard verification can add
copies of their own. The positive capture precedes output reads and clipboard
actions, and private-key output is never returned as plaintext over CDP. Input
buffers can still supply mnemonic/passphrase hits. Later verification reads and
hashing create renderer-side temporaries; releasing protocol objects and wiping
the hash input byte arrays cannot erase immutable strings or browser copies.
Moving the driver outside the page removes persistent fixture literals, not
every observer effect. Compare identical harness settings;
do not treat counts as an exact inventory of application-owned allocations.

On 2026-10-05, a real gcore attempt with GNU gdb 15.1 and Chromium 153.0.8010.0
in the Ubuntu 24.04 development environment failed at `before-input`:
`ptrace: Inappropriate ioctl for device.` No dump was produced, the report was
invalid, and the driver refused to enter fixture data. This exercises actual
capture failure handling, not successful acquisition or erasure. A successful
gcore/ProcDump run on a host permitting capture remains required for measured
residue results; ProcDump has not been run for this change.

Process captures are sequential, not an atomic snapshot, and processes can
appear or exit between enumeration and capture. The test does not cover swap,
hibernation, old crash dumps, GPU buffers, clipboard history or every browser
encoding. Results do not generalize to another browser/OS build. See the
[Computer Hardening Checklist](Computer_Hardening_Checklist.md) for disk and OS
exposure outside this measurement.
