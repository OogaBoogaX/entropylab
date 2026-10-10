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

On Windows, run the harness from an elevated prompt; a non-elevated ProcDump
cannot attach to all of Chrome's processes. Elevated Chrome and Edge relaunch
themselves de-elevated and exit, which would close the debugging pipe, so on
Windows the harness launches them with `--do-not-de-elevate`. The browser
process therefore runs elevated; its renderers keep their usual sandbox.
ProcDump's piped output is UTF-16LE and is decoded before its result is
checked. Dump file names avoid ProcDump's name substitutions (`PID`,
`PROCESSNAME`, `YYMMDD`, `HHMMSS`, `EXCEPTIONCODE`).

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
protocol object groups are released. Revealed output verification
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
| `after-copy` | The app's seed-copy control ran and showed its copied state |
| `after-wipe` | End Session completed and the ended screen is present |
| `after-tab-close` | The fixture tab is confirmed closed; surviving processes are enumerated again |

The harness never touches the clipboard itself: only the app's Copy seed phrase
button does. The copy is confirmed by the button's copied state, which the app
sets only after its own clipboard write succeeded; a failed or blocked copy
aborts the run. Reading the clipboard back left a copy of the mnemonic in the
browser process after the tab closed (2026-10-06: Chrome's only one, and 2 of
Edge's 4), so the harness does not verify the clipboard's contents.
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
Copy seed phrase action must fail the copy confirmation. These tests require
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

Automation and protocol input/return buffers can add
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
residue results.

On 2026-10-05, a real ProcDump attempt (v12.01) against Chrome on Windows 11
failed at `before-input`: a subset of Chrome's processes are protected (their
command line is unreadable and a non-elevated ProcDump attach is refused,
exiting `No process matching the specified PID`), so those captures were
skipped and the fail-closed harness invalidated the run. A full-tree Chrome
capture on Windows requires running the harness elevated, or a Chromium build
without protected processes. The exit-code handling itself is unit-tested;
end-to-end measured residue on Windows still needs an elevated run.

On 2026-10-06, elevated attempts (ProcDump v12.01, Chrome 154.0.8037.98) found
three further Windows problems, now fixed and unit-tested. Elevated Chrome
de-elevated and closed the pipe before `before-input`. Every complete dump was
refused, because ProcDump's UTF-16LE output never matched `Dump 1 complete`,
and because `-pid<n>` in the requested name was expanded by ProcDump. Two
start-up renderers exited during the sweep.

Process captures are sequential, not an atomic snapshot, and processes can
appear or exit between enumeration and capture. Before each checkpoint's sweep
the harness waits until the browser's process tree, enumerated every 2 s, has
stayed unchanged for 20 s at `before-input` (Chrome retires start-up renderers
for about half a minute) and for 6 s at later checkpoints, giving up after 120 s
and 60 s. A set still changing then is captured as last seen, and the report
says so. A process that exits during the sweep is recorded as an exit, not a
failed capture, only when ProcDump reports `No process matching the specified
PID` and a successful fresh enumeration of the browser's tree no longer lists
it; the report lists every exit. A failed process query, malformed output or
missing browser root stops the run as invalid, rather than confirming an exit.
Any other capture failure still invalidates the run,
as does a checkpoint that scanned no process. An exited process was not scanned
at that checkpoint. The test does not cover swap,
hibernation, old crash dumps, GPU buffers, clipboard history or every browser
encoding. Results do not generalize to another browser/OS build. See the
[Computer Hardening Checklist](Computer_Hardening_Checklist.md) for disk and OS
exposure outside this measurement.
