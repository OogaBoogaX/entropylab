// Unit tests for the pure parts of the dev-only residue harness
// (scripts/residue-audit.mjs): tool detection, the deterministic fake-secret
// factory, the needle scanner, the report writer, and the checkpoint list.
// These run without any capture tool installed — the full harness needs
// ProcDump (Windows) or gcore (Linux) and is run by hand.
// Run with `npm test` (part of the CI list).
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import vm from "node:vm";
import { PassThrough } from "node:stream";
import { EventEmitter } from "node:events";
import { pbkdf2Sync, webcrypto } from "node:crypto";
import { HDKey as ReferenceHDKey } from "@scure/bip32";
import { base58check } from "@scure/base";
import { sha256 } from "@noble/hashes/sha2.js";
import * as audit from "../scripts/residue-audit.mjs";
import {
  CHECKPOINTS,
  CONTROL_CHECKPOINT,
  DISCLAIMER,
  ResidueToolError,
  detectTools,
  main,
  makeSecrets,
  makeNeedles,
  scanFile,
  writeReports,
  driverScript,
} from "../scripts/residue-audit.mjs";

const tmp = () => mkdtempSync(join(tmpdir(), "residue-test-"));

// Contract: accept only measurements of the actual public fixture after the
// requested UI operation; reject contaminated controls and failed secret copies.
test("regression: fixture needles describe the actual BIP39/BIP84 wallet", () => {
  const secrets = makeSecrets();
  const seed = pbkdf2Sync(secrets.mnemonic.normalize("NFKD"), "mnemonic" + secrets.passphrase.normalize("NFKD"), 2048, 64, "sha512");
  const root = ReferenceHDKey.fromMasterSeed(seed);
  const child = root.derive("m/84'/0'/0'/0/0");
  assert.equal(secrets.seedHex, seed.toString("hex"), "the seed needle must be the derived BIP39 seed");
  assert.equal(secrets.xprv, root.privateExtendedKey, "the root needle must be the derived master xprv");
  assert.equal(secrets.wif, base58check(sha256).encode(Uint8Array.from([128, ...child.privateKey, 1])), "the WIF needle must be the first BIP84 receive key");
});

test("regression: the fixture is absent from app self-tests and injected code", () => {
  const secrets = makeSecrets();
  const selfTests = readFileSync(new URL("../src/js/self-test.js", import.meta.url), "utf8");
  for (const value of Object.values(secrets)) {
    assert.ok(!selfTests.includes(value), "fixture data already exists before input");
    assert.ok(!driverScript(secrets).includes(value), "the injected script must not retain a fixture literal");
  }
});

// An independent UI state machine. It records effects, so emitting a checkpoint
// name or a click without completing its operation cannot satisfy these tests.
const exerciseDriver = async ({ copyWorks = true, wrongInput = false, wrongWallet = false } = {}) => {
  const secrets = makeSecrets(), checkpoints = [], expressions = [], returnedValues = [], state = { derived: false, clipboard: "", ended: false, outputRead: false, clipboardRead: false };
  const element = (extra = {}) => ({ value: "", disabled: false, checked: false, hidden: false, textContent: "", dispatchEvent() {}, click() {}, ...extra });
  const ids = {
    "key-manager": element(), "seed-length-select": element(), seed: element(), pass: element(),
    out: element(), reveal: element({ click() { this.checked = true; } }),
    go: element({ click() { setImmediate(() => { state.derived = true; ids.out.textContent = wrongWallet ? "unrelated wallet" : [secrets.mnemonic, secrets.xprv, secrets.wif].join(" "); }); } }),
    "end-session": element(), "end-session-confirm": element({ click() { state.ended = true; ids.out.textContent = ""; } }),
  };
  let outputText = "";
  Object.defineProperty(ids.out, "textContent", {
    get() { state.outputRead = true; return outputText; },
    set(value) { outputText = value; },
  });
  const outputElement = text => {
    const el = element();
    Object.defineProperty(el, "textContent", { get() { state.outputRead = true; return text; } });
    return el;
  };
  // Like the app, a copy button shows its "copied" state only after its own
  // clipboard write succeeded.
  const copyButton = text => {
    const button = element({ copied: false, click() { if (copyWorks) { state.clipboard = text; button.copied = true; } } });
    button.classList = { contains: name => name === "is-copied" && button.copied };
    return button;
  };
  const seedCopy = copyButton(secrets.mnemonic);
  const publicCopy = copyButton("xpub-public-key");
  const select = (selector) => {
    if (selector.includes("data-session-ended")) return state.ended ? element() : null;
    if (selector.includes("data-copy-seed-phrase")) return seedCopy;
    if (selector.includes("data-copy-field")) return state.derived ? publicCopy : null;
    if (selector.includes("data-key-group") || selector === "#acct-tabs") return state.derived ? element() : null;
    if (selector.startsWith("#workspace")) return element();
    if (selector === 'input[name="seed-method"][value="numbers"]') return element();
    return ids[selector.replace(/^#/, "")] || null;
  };
  const document = {
    getElementById: id => ids[id] || null,
    querySelector: select,
    querySelectorAll: selector => selector.startsWith("#out")
      ? (wrongWallet ? [outputElement("unrelated wallet")] : [secrets.mnemonic, secrets.xprv, secrets.wif].map(outputElement))
      : [element({ textContent: "Seed phrase" })],
    documentElement: { dataset: { selfTestsFailed: "0" } },
  };
  const record = async name => checkpoints.push({ name, ...state });
  const context = vm.createContext({ document, Event: class {}, URLSearchParams, Date, TextEncoder, crypto: webcrypto, setTimeout: fn => setImmediate(fn),
    navigator: { clipboard: { writeText: async text => { state.clipboard = text; }, readText: async () => { state.clipboardRead = true; return state.clipboard; } } },
    window: { addEventListener() {}, close() {} },
    Image: class { set src(url) { record(new URL(url, "http://localhost").searchParams.get("name")).then(() => this.onload()); } },
  });
  const page = {
    evaluate: async expression => {
      expressions.push(expression);
      const value = await vm.runInContext(expression, context);
      returnedValues.push(value);
      return value;
    },
    click: async selector => { const el = select(selector); assert.ok(el, selector); el.click(); },
    type: async (selector, text) => { select(selector).value = wrongInput && selector === "#seed" ? "different input" : text; },
    waitFor: async expression => {
      for (let i = 0; i < 10; i++) {
        if (await page.evaluate(expression)) return;
        await new Promise(resolve => setImmediate(resolve));
      }
      assert.fail(expression);
    },
    waitForClipboard: async expected => { state.clipboardRead = true; if (state.clipboard !== expected) throw new Error("secret copy did not succeed"); },
    waitForSeedCopy: async () => {
      if (!await page.evaluate(`document.querySelector("#form [data-copy-seed-phrase]").classList.contains("is-copied")`)) throw new Error("secret copy did not succeed");
    },
    close: async () => { state.closed = true; },
  };
  // Execute the old implementation as well: the regressions first fail on its
  // actual effects, not a missing new export.
  if (audit.driveSession) await audit.driveSession(page, secrets, record);
  else {
    vm.runInContext(driverScript(secrets).replace(/<\/?script>/g, ""), context);
    await context.window.__residueDrive();
  }
  return { checkpoints, state, expressions, returnedValues };
};

test("regression: after-derive is captured only after a wallet exists", async () => {
  const { checkpoints } = await exerciseDriver();
  assert.equal(checkpoints.find(p => p.name === "after-derive")?.derived, true, "capture occurred before Derive");
});

test("regression: after-copy follows a successful secret copy, not an xpub copy", async () => {
  const { checkpoints } = await exerciseDriver();
  assert.equal(checkpoints.find(p => p.name === "after-copy")?.clipboard, makeSecrets().mnemonic);
});

test("regression: a refused clipboard write prevents after-copy", async () => {
  await assert.rejects(exerciseDriver({ copyWorks: false }), /copy/);
});

test("observer regression: the driver never touches the clipboard; only the app's Copy button does", async () => {
  // Contract: the harness neither clears nor reads the clipboard. Reading it
  // back left a copy of the mnemonic in the browser process after the tab
  // closed: Chrome's only one, and 2 of Edge's 4 (2026-10-06, measured with
  // and without the read-back). The copy is confirmed by the app's own copied
  // state instead, which it sets only after its write succeeded.
  const { state, expressions } = await exerciseDriver();
  assert.equal(state.clipboardRead, false, "the driver read the clipboard back");
  assert.deepEqual(expressions.filter(expression => expression.includes("navigator.clipboard")), [], "the driver called the Clipboard API itself");
});

test("driver rejects a changed input or a wallet that differs from the fixture", async () => {
  await assert.rejects(exerciseDriver({ wrongInput: true }), /refusing to derive/);
  await assert.rejects(exerciseDriver({ wrongWallet: true }), /does not match/);
});

test("fixture values never become evaluated JavaScript source", async () => {
  const { expressions } = await exerciseDriver();
  for (const expression of expressions) for (const value of Object.values(makeSecrets())) assert.ok(!expression.includes(value));
});

test("observer regression: private-key controls precede output and clipboard reads", async () => {
  const { checkpoints } = await exerciseDriver();
  const control = checkpoints.find(row => row.name === CONTROL_CHECKPOINT);
  assert.equal(control.outputRead, false, "output verification copied the keys before the control capture");
  assert.equal(control.clipboardRead, false, "clipboard verification ran before the control capture");
});

test("observer regression: output verification returns digests, never private-key text", async () => {
  const { returnedValues } = await exerciseDriver();
  for (const label of ["xprv", "wif"]) {
    assert.ok(!JSON.stringify(returnedValues).includes(makeSecrets()[label]), `${label} entered the debugging return buffers`);
  }
});

test("capture regression: a denied capture records the tool's diagnostic", async () => {
  const dir = tmp();
  try {
    const execFile = () => {
      const child = new EventEmitter();
      child.stdout = new PassThrough(); child.stderr = new PassThrough();
      setImmediate(() => {
        child.stdout.end("capture started\n");
        child.stderr.end("ptrace: Operation not permitted.\n");
        child.emit("exit", 1); child.emit("close", 1);
      });
      return child;
    };
    await assert.rejects(audit.capture({ tool: { kind: "gcore", binary: "gcore" }, pid: 123, outDir: dir, checkpoint: "before-input", execFile }), /ptrace: Operation not permitted/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// A fake ProcDump that reproduces the given stdout, writes a file of the
// given size at the target path (or not), and exits with the given code.
// `encoding: "utf16le"` and `substitute: true` reproduce what ProcDump v12.01
// does on Windows 11 (seen 2026-10-06): its piped output is UTF-16LE with no
// BOM, and it expands the file-name substitutions `procdump -?` lists
// (PROCESSNAME, PID, EXCEPTIONCODE, YYMMDD, HHMMSS). The "pid" in
// "before-input-pid28876.dmp" was expanded, so matching ignores case. The
// folder part of the path is left alone. `written` is the file it wrote.
const PROCDUMP_SUBSTITUTIONS = { PROCESSNAME: "chrome", EXCEPTIONCODE: "0x00000000", YYMMDD: "261006", HHMMSS: "084522" };
const fakeProcdump = ({ output, fileBytes = null, code, encoding = "utf8", substitute = false }) => {
  const execFile = (binary, args) => {
    const child = new EventEmitter();
    child.stdout = new PassThrough(); child.stderr = new PassThrough();
    setImmediate(() => {
      if (fileBytes !== null) {
        const target = args[args.length - 1], pid = args[args.length - 2];
        const name = substitute
          ? basename(target).replace(/PROCESSNAME|PID|EXCEPTIONCODE|YYMMDD|HHMMSS/gi, token => PROCDUMP_SUBSTITUTIONS[token.toUpperCase()] ?? pid)
          : basename(target);
        execFile.written = join(dirname(target), name);
        writeFileSync(execFile.written, Buffer.alloc(fileBytes, 1));
      }
      child.stdout.end(Buffer.from(output, encoding));
      child.emit("exit", code); child.emit("close", code);
    });
    return child;
  };
  return execFile;
};

// ProcDump v12.01's stdout for one full dump on Windows 11 (2026-10-06,
// pid 28876), with the dump folder shortened.
const PROCDUMP_V12_SUCCESS = [
  "",
  "ProcDump v12.01 - Sysinternals process dump utility",
  "Copyright (C) 2009-2026 Mark Russinovich and Andrew Richards",
  "Sysinternals - www.sysinternals.com",
  "",
  "[08:45:20]Dump 1 info: Available space: 77670146048",
  "[08:45:20]Dump 1 initiated: C:\\residue\\before-input-2887628876.dmp",
  "[08:45:20]Dump 1 writing: Estimated dump file size is 573 MB.",
  "[08:45:22]Dump 1 complete: 573 MB written in 2.0 seconds",
  "[08:45:22]Dump count reached.",
  "",
].join("\r\n");

test("capture: a successful ProcDump one-shot dump exits 1 and is accepted", async () => {
  // Contract: ProcDump exits 1 after a successful one-shot dump, having
  // printed "Dump 1 complete" (verified against ProcDump v12.01 on Windows).
  // gcore keeps the Unix contract (0 success, nonzero failure) covered above.
  const dir = tmp();
  try {
    const execFile = fakeProcdump({ output: "[14:32:04]Dump 1 complete: 235 MB written in 3.9 seconds\n[14:32:05]Dump count reached.\n", fileBytes: 64, code: 1 });
    const result = await audit.capture({ tool: { kind: "procdump", binary: "procdump64" }, pid: 4242, outDir: dir, checkpoint: "before-input", execFile });
    assert.equal(result.out, execFile.written, "a ProcDump success resolves the dump file it wrote");
    assert.equal(result.skipped, null);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("capture: a failed ProcDump run that leaves a file is rejected, not counted as captured", async () => {
  // Contract: fail closed. ProcDump can exit nonzero after "Dump 1 error: ..."
  // and still leave a partial file at the target path. That file must not be
  // mistaken for a complete capture. Verified output shape from ProcDump
  // v12.01's error line.
  const dir = tmp();
  try {
    const execFile = fakeProcdump({ output: "[14:32:04]Dump 1 error: Error writing dump file: Access is denied.\n", fileBytes: 64, code: 2 });
    await assert.rejects(
      audit.capture({ tool: { kind: "procdump", binary: "procdump64" }, pid: 4242, outDir: dir, checkpoint: "before-input", execFile }),
      /without completing the dump|Dump 1 error/,
    );
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("capture: an empty ProcDump dump file is no capture, never a clean one", async () => {
  // Contract: a zero-byte dump holds no memory, so it must be treated as no
  // capture (skipped), not as a scanned-clean process.
  const dir = tmp();
  try {
    const execFile = fakeProcdump({ output: "[14:32:04]Dump 1 complete: 0 MB written in 0.1 seconds\n[14:32:05]Dump count reached.\n", fileBytes: 0, code: 1 });
    const result = await audit.capture({ tool: { kind: "procdump", binary: "procdump64" }, pid: 4242, outDir: dir, checkpoint: "before-input", execFile });
    assert.equal(result.out, null);
    assert.equal(result.skipped, "empty dump written");
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("capture: ProcDump's real UTF-16LE output is decoded, so a complete dump is accepted", async () => {
  // Contract: a ProcDump capture counts on "Dump 1 complete" without
  // "Dump 1 error", whatever encoding ProcDump writes. v12.01 writes UTF-16LE
  // to a pipe; read as UTF-8 it never matched, so all 9 complete dumps of the
  // elevated 2026-10-06 run were refused.
  const dir = tmp();
  try {
    const execFile = fakeProcdump({ output: PROCDUMP_V12_SUCCESS, encoding: "utf16le", fileBytes: 64, code: 1 });
    const result = await audit.capture({ tool: { kind: "procdump", binary: "procdump64" }, pid: 28876, outDir: dir, checkpoint: "before-input", execFile });
    assert.equal(result.skipped, null);
    assert.equal(result.out, execFile.written);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("capture: UTF-16LE ProcDump failures are still refused, with a readable diagnostic", async () => {
  // Contract: decoding must not turn a failure into a capture. "Dump 1 error"
  // with a leftover file, and v12.01's "No process matching" refusal (seen
  // 2026-10-06 for a renderer that had exited), stay failures, and the report
  // shows ProcDump's words rather than NUL-separated bytes.
  const dir = tmp();
  try {
    const failures = [
      { output: PROCDUMP_V12_SUCCESS.replace("Dump 1 complete: 573 MB written in 2.0 seconds", "Dump 1 error: Error writing dump file: Access is denied."), fileBytes: 64, code: 2, expected: /without completing the dump: [\s\S]*Dump 1 error: Error writing dump file: Access is denied\./ },
      { output: "\r\nProcDump v12.01 - Sysinternals process dump utility\r\n\r\nNo process matching the specified PID can be found.\r\n", code: -2, expected: /without completing the dump: [\s\S]*No process matching the specified PID can be found\./ },
    ];
    for (const { output, fileBytes = null, code, expected } of failures) {
      const execFile = fakeProcdump({ output, encoding: "utf16le", fileBytes, code });
      await assert.rejects(audit.capture({ tool: { kind: "procdump", binary: "procdump64" }, pid: 24488, outDir: dir, checkpoint: "before-input", execFile }), expected);
    }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("capture: the dump ProcDump wrote is found after its documented file-name substitutions, at every checkpoint", async () => {
  // Contract: a completed dump is scanned where ProcDump wrote it. ProcDump
  // expands PROCESSNAME, PID, EXCEPTIONCODE, YYMMDD and HHMMSS in the file
  // name (`procdump -?`, v12.01), so "before-input-pid28876.dmp" was written
  // as "before-input-2887628876.dmp" and reported as "no dump written".
  const dir = tmp();
  try {
    for (const checkpoint of CHECKPOINTS) {
      const execFile = fakeProcdump({ output: "[08:45:22]Dump 1 complete: 573 MB written in 2.0 seconds\r\n", fileBytes: 64, code: 1, substitute: true });
      const result = await audit.capture({ tool: { kind: "procdump", binary: "procdump64" }, pid: 28876, outDir: dir, checkpoint, execFile });
      assert.equal(result.skipped, null, checkpoint);
      assert.equal(result.out, execFile.written, checkpoint);
    }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("browser launch: Windows Chromium is told not to de-elevate, so an elevated harness keeps its pipe", () => {
  // Contract: an elevated harness (needed for ProcDump to reach Chrome's
  // processes) must keep the browser it launched. Elevated Chrome
  // 154.0.8037.98 and Edge 154.0.4258.53 relaunch themselves de-elevated and
  // exit 0 at once, closing the debugging pipe, unless given
  // --do-not-de-elevate (2026-10-06). Linux has no de-elevation.
  const dir = tmp();
  const launches = new Map();
  const spawnProcess = (binary, args) => {
    launches.set(binary, args);
    const child = new EventEmitter(); child.pid = 1;
    return child;
  };
  try {
    for (const os of ["win32", "linux"]) {
      audit.spawnBrowser({ binary: `residue-test-no-browser-${os}` }, { profile: dir, logPath: join(dir, `${os}.log`), platform: os, spawnProcess });
    }
    const windows = launches.get("residue-test-no-browser-win32"), linux = launches.get("residue-test-no-browser-linux");
    assert.ok(windows?.includes("--do-not-de-elevate"), "Windows launch keeps an elevated browser");
    assert.ok(windows.includes("--remote-debugging-pipe"));
    assert.ok(linux && !linux.includes("--do-not-de-elevate"), "Linux launch is unchanged");
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("process tree: a checkpoint captures a process set only once it stops changing", async () => {
  // Contract: the capture list is a set seen unchanged on two consecutive
  // enumerations, in any order; a set still changing at the deadline is
  // captured as last seen and marked unsettled, never trimmed or dropped.
  // On 2026-10-06 two Chrome start-up renderers exited mid-sweep, failing the
  // run closed.
  const run = async (sets, options = {}) => {
    let clock = 0, index = 0;
    const polls = [];
    const result = await audit.settleProcessTree({
      enumerate: () => { polls.push(clock); return sets[Math.min(index++, sets.length - 1)]; },
      sleep: async ms => { clock += ms; },
      now: () => clock,
      intervalMs: 1000,
      timeoutMs: 5000,
      ...options,
    });
    return { ...result, polls };
  };
  const startup = await run([[1, 2, 3, 4, 5], [1, 2, 3], [3, 1, 2]]);
  assert.equal(startup.settled, true);
  assert.deepEqual([...startup.pids].sort(), [1, 2, 3]);
  assert.deepEqual(startup.polls, [0, 1000, 2000]);
  assert.equal(startup.waitedMs, 2000);

  const quiet = await run([[7, 8], [8, 7]]);
  assert.equal(quiet.settled, true);
  assert.deepEqual(quiet.polls, [0, 1000]);

  const churning = await run([[1], [1, 2], [1, 3], [1, 4], [1, 5], [1, 6], [1, 7]]);
  assert.equal(churning.settled, false);
  assert.deepEqual(churning.pids, [1, 6], "the last set seen before the deadline is captured");
  assert.deepEqual(churning.polls, [0, 1000, 2000, 3000, 4000, 5000]);

  // Chrome retired start-up renderers 15-33 s after launch, up to 10 s apart
  // (2026-10-06), so a brief agreement is not a quiet spell. With stableMs the
  // set must stay unchanged that long; a change restarts the wait.
  const pause = await run([[1, 2, 3], [1, 2, 3], [1, 2], [1, 2], [1, 2], [1, 2]], { stableMs: 3000 });
  assert.equal(pause.settled, true);
  assert.deepEqual(pause.pids, [1, 2], "the set seen before the late exit is not captured");
  assert.equal(pause.waitedMs, 5000);
});

test("reports say when a checkpoint's process set never settled", () => {
  const dir = tmp();
  try {
    const entries = [{ pid: 1, scanned: 1, skipped: null }];
    const results = [
      { name: "before-input", settle: { settled: false, waitedMs: 30000 }, entries, hits: [] },
      { name: "after-derive", settle: { settled: true, waitedMs: 2000 }, entries, hits: [] },
    ];
    const { mdPath } = writeReports({ outDir: dir, meta: { platform: "win32", browser: "chrome", tool: "procdump" }, results });
    const md = readFileSync(mdPath, "utf8");
    const section = name => {
      const start = md.indexOf(`## ${name}`), end = md.indexOf("\n## ", start + 1);
      return md.slice(start, end === -1 ? undefined : end);
    };
    assert.match(section("before-input"), /still changing after 30 s/);
    assert.doesNotMatch(section("after-derive"), /still changing/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// A fake browser process: records signals and exits when told to.
const fakeBrowser = () => {
  const child = new EventEmitter();
  Object.assign(child, { pid: 4242, exitCode: null, signalCode: null, signals: [] });
  child.exit = (code, signal = null) => { child.exitCode = code; child.signalCode = signal; child.emit("exit", code, signal); };
  child.kill = signal => { child.signals.push(signal); setImmediate(() => child.exit(null, signal)); return true; };
  return child;
};

test("cleanup regression: the browser is closed through the protocol, not SIGKILLed out from under its helpers", async () => {
  const child = fakeBrowser(), sent = [];
  const client = { send: async method => { sent.push(method); setImmediate(() => child.exit(0)); throw new ResidueToolError("browser debugging pipe closed"); } };
  await audit.stopBrowser(child, client, { timeoutMs: 1000 });
  assert.deepEqual(sent, ["Browser.close"]);
  assert.deepEqual(child.signals, [], "a browser that closes cleanly must not be SIGKILLed");
  assert.equal(child.exitCode, 0);
});

test("cleanup regression: a browser that ignores Browser.close is still killed", async () => {
  const child = fakeBrowser();
  await audit.stopBrowser(child, { send: async () => new Promise(() => {}) }, { timeoutMs: 20 });
  assert.deepEqual(child.signals, ["SIGKILL"]);
  const gone = fakeBrowser();
  gone.exit(1);
  await audit.stopBrowser(gone, { send: async () => assert.fail("an exited browser needs no close") });
});

test("cleanup regression: work-dir removal retries the whole walk and never throws", async () => {
  let calls = 0;
  const raceThenClear = () => { if (++calls < 3) throw Object.assign(new Error("ENOTEMPTY: directory not empty"), { code: "ENOTEMPTY" }); };
  assert.equal(await audit.removeWorkDir("/work", { delayMs: 1, remove: raceThenClear }), null);
  assert.equal(calls, 3, "a late helper write must be retried with a fresh walk");
  const stuck = await audit.removeWorkDir("/work", { attempts: 2, delayMs: 1, remove: () => { throw new Error("EBUSY"); } });
  assert.match(stuck.message, /EBUSY/, "the last error is returned for the caller to report");
});

test("CDP pipe correlates fragmented replies, ignores events, and rejects protocol errors", async () => {
  const writer = new PassThrough(), reader = new PassThrough();
  const client = audit.createPipeClient(writer, reader);
  const sent = [];
  writer.on("data", chunk => sent.push(JSON.parse(chunk.toString().slice(0, -1))));
  try {
    const one = client.send("One", {}, "session"), two = client.send("Two");
    const failed = assert.rejects(client.send("Bad"), /browser command failed: Bad/);
    assert.equal(sent[0].sessionId, "session");
    const bytes = Buffer.from(JSON.stringify({ id: sent[1].id, result: { text: "réponse" } }) + "\0");
    const split = bytes.indexOf(Buffer.from("é")) + 1;
    reader.write(bytes.subarray(0, split)); reader.write(bytes.subarray(split));
    reader.write(JSON.stringify({ method: "Unsolicited.event" }) + "\0" + JSON.stringify({ id: sent[0].id, result: { ok: true } }) + "\0");
    reader.write(JSON.stringify({ id: sent[2].id, error: { message: "refused" } }) + "\0");
    assert.deepEqual(await one, { ok: true });
    assert.deepEqual(await two, { text: "réponse" });
    await failed;
  } finally { client.dispose(); }
});

test("CDP pipe rejects a lost browser and times out an unanswered command", async () => {
  const writer = new PassThrough(), reader = new PassThrough();
  const client = audit.createPipeClient(writer, reader, { timeoutMs: 10 });
  try {
    await assert.rejects(client.send("NoReply"), /timed out/);
    const failed = assert.rejects(client.send("BrowserGone"), /pipe closed/);
    reader.end();
    await failed;
    await assert.rejects(client.send("TooLate"), /pipe closed/);
  } finally { client.dispose(); }
});

test("Firefox is rejected before a contaminated legacy driver can run", () => {
  assert.throws(() => audit.resolveBrowser({ browser: "firefox", browserExplicit: true }), /external driver/);
});

const completeMeasurements = () => ["before-input", "after-derive", "after-reveal", "after-copy", "after-wipe", "after-tab-close"].map(name => ({
  name, entries: [{ pid: 123, scanned: 1 }],
  hits: name === "after-reveal" ? ["mnemonic", "wif", "xprv"].map(label => ({ pid: 123, label, encoding: "utf8", count: 1 })) : [],
}));

test("measurement validity requires a clean captured baseline and complete captures", () => {
  assert.equal(typeof audit.assessRun, "function");
  const good = completeMeasurements();
  assert.equal(audit.assessRun(good).valid, true);
  const contaminated = structuredClone(good);
  contaminated[0].hits.push({ pid: 123, label: "mnemonic", encoding: "utf8", count: 1 });
  assert.equal(audit.assessRun(contaminated).valid, false);
  const blind = structuredClone(good);
  blind[0].entries[0] = { pid: 123, skipped: "access denied" };
  assert.equal(audit.assessRun(blind).valid, false);
  const partial = structuredClone(good);
  partial[4].entries.push({ pid: 456, skipped: "access denied" });
  assert.equal(audit.assessRun(partial).valid, false);
  assert.equal(audit.assessRun(good.slice(0, -1)).valid, false);
});

test("a missing private-key control invalidates the run; unseen seed bytes are uncalibrated", () => {
  assert.equal(typeof audit.assessRun, "function");
  const results = completeMeasurements();
  const assessment = audit.assessRun(results);
  assert.equal(assessment.coverage.find(row => row.label === "seedHex").calibrated, false);
  assert.equal(assessment.coverage.find(row => row.label === "xprv").calibrated, true);
  results[2].hits = results[2].hits.filter(hit => hit.label !== "wif");
  assert.equal(audit.assessRun(results).valid, false);
});

// Exit rule (the user's decision, 2026-10-06): a process that verifiably
// exited between enumeration and its capture is recorded as an exit, not as
// an incomplete capture. On 2026-10-06 Chrome's PassageEmbeddingsService shut
// itself down mid-sweep at after-reveal and invalidated an otherwise complete
// run.
const EXITED = { pid: 20204, out: null, exited: "exited before capture" };

test("a process that verifiably exited before its capture does not make a checkpoint incomplete", () => {
  // Contract: an exit counts as accounted for. The run stays valid only if
  // every other process was captured and scanned, each checkpoint scanned at
  // least one process, and both controls hold.
  const withExits = completeMeasurements();
  withExits[0].entries.push(EXITED);
  withExits[2].entries.push(EXITED);
  assert.deepEqual(audit.assessRun(withExits).reasons, []);

  const onlyExits = completeMeasurements();
  onlyExits[4].entries = [EXITED];
  assert.equal(audit.assessRun(onlyExits).valid, false, "a checkpoint that scanned nothing is still incomplete");

  const exitAndFailure = completeMeasurements();
  exitAndFailure[2].entries.push(EXITED, { pid: 456, skipped: "capture failed: access denied" });
  assert.equal(audit.assessRun(exitAndFailure).valid, false, "an exit does not excuse another process's failed capture");

  const controlGone = completeMeasurements();
  controlGone[2] = { name: "after-reveal", entries: [{ pid: 123, scanned: 1 }, EXITED], hits: [] };
  assert.equal(audit.assessRun(controlGone).valid, false, "the positive control is unchanged");
});

test("capture: only ProcDump's no-such-process refusal, confirmed by a fresh enumeration, is recorded as an exit", async () => {
  // Contract: ProcDump v12.01 prints "No process matching the specified PID
  // can be found." for an exited pid (2026-10-06). That alone is not enough:
  // the pid must also be missing from a fresh enumeration. Any other failure,
  // or any other tool, stays a failed capture.
  const noProcess = "\r\nProcDump v12.01 - Sysinternals process dump utility\r\n\r\nNo process matching the specified PID can be found.\r\n";
  const dumpError = PROCDUMP_V12_SUCCESS.replace("Dump 1 complete: 573 MB written in 2.0 seconds", "Dump 1 error: Error writing dump file: Access is denied.");
  const gcoreGone = () => {
    const child = new EventEmitter();
    child.stdout = new PassThrough(); child.stderr = new PassThrough();
    setImmediate(() => { child.stdout.end(""); child.stderr.end("ptrace: No such process.\n"); child.emit("exit", 1); child.emit("close", 1); });
    return child;
  };
  const dir = tmp();
  try {
    const sweep = async ({ kind = "procdump", output, execFile = fakeProcdump({ output, encoding: "utf16le", code: -2 }), running }) =>
      (await audit.captureAll({ tool: { kind, binary: kind }, pids: [20204], outDir: dir, checkpoint: "after-reveal", needles: makeNeedles(), running, execFile })).entries[0];

    const gone = await sweep({ output: noProcess, running: () => false });
    assert.match(gone.exited, /exited before capture/);
    assert.equal(gone.skipped, undefined);

    const stillListed = await sweep({ output: noProcess, running: () => true });
    assert.equal(stillListed.exited, undefined);
    assert.match(stillListed.skipped, /capture failed: [\s\S]*No process matching/);

    const unchecked = await sweep({ output: noProcess, running: undefined });
    assert.equal(unchecked.exited, undefined, "without a fresh enumeration nothing is recorded as an exit");

    const otherFailure = await sweep({ output: dumpError, running: () => false });
    assert.equal(otherFailure.exited, undefined);
    assert.match(otherFailure.skipped, /Dump 1 error/);

    const gcore = await sweep({ kind: "gcore", execFile: gcoreGone, running: () => false });
    assert.equal(gcore.exited, undefined);
    assert.match(gcore.skipped, /No such process/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// A missing PID is evidence only after a successful, well-formed query.
// In particular, ProcDump's refusal can also occur for a protected process;
// a failed CIM query must not turn that refusal into a verified exit.
test("process tree accepts complete Windows and Unix process listings", () => {
  const rows = [
    { ProcessId: 300, ParentProcessId: 200 },
    { ProcessId: 100, ParentProcessId: 1 },
    { ProcessId: 400, ParentProcessId: 1 },
    { ProcessId: 200, ParentProcessId: 100 },
  ];
  for (const [platform, stdout] of [["win32", JSON.stringify(rows)], ["linux", "300 200\n100 1\n400 1\n200 100\n"]]) {
    const pids = audit.processTree({ pid: 100, platform, exec: () => ({ status: 0, stdout }) });
    assert.deepEqual(pids.sort((a, b) => a - b), [100, 200, 300]);
  }
  assert.deepEqual(audit.processTree({ pid: 100, platform: "win32", exec: () => ({
    status: 0, stdout: JSON.stringify({ ProcessId: 100, ParentProcessId: 1 }),
  }) }), [100], "PowerShell may serialize a single result as an object");
});

test("process tree rejects failed or malformed enumerations instead of assuming only the root remains", () => {
  for (const [platform, stdout, malformed] of [
    ["win32", '[{"ProcessId":100,"ParentProcessId":1}]', ["not JSON", "null", "[]", "{}", '[{"ProcessId":100}]', '[{"ProcessId":"100","ParentProcessId":1}]', '[{"ProcessId":200,"ParentProcessId":1}]']],
    ["linux", "100 1\n", ["not a process table", "100\n", "100 1 unexpected\n", "200 1\n"]],
  ]) {
    const failures = [
      { status: 1, stdout, stderr: "process query failed" },
      { status: null, signal: "SIGTERM", stdout },
      { status: 0, error: new Error("spawn failed"), stdout },
      { status: 0, stdout: "" },
      ...malformed.map(stdout => ({ status: 0, stdout })),
    ];
    for (const result of failures) {
      assert.throws(() => audit.processTree({ pid: 100, platform, exec: () => result }),
        ResidueToolError, `${platform}: ${JSON.stringify(result)}`);
    }
  }
});

test("capture regression: a failed fresh enumeration cannot certify a process exit", async () => {
  const dir = tmp();
  const noProcess = "No process matching the specified PID can be found.\r\n";
  const sweep = result => audit.captureAll({
    tool: { kind: "procdump", binary: "procdump64" }, pids: [200], outDir: dir,
    checkpoint: "after-wipe", needles: makeNeedles(),
    execFile: fakeProcdump({ output: noProcess, encoding: "utf16le", code: -2 }),
    running: pid => audit.processTree({ pid: 100, platform: "win32", exec: () => result }).includes(pid),
  });
  try {
    for (const result of [
      { status: 1, stdout: "", stderr: "Get-CimInstance failed" },
      { status: null, error: new Error("powershell unavailable"), stdout: "" },
      { status: 0, stdout: "invalid JSON" },
    ]) await assert.rejects(sweep(result), ResidueToolError);

    const gone = await sweep({ status: 0, stdout: '[{"ProcessId":100,"ParentProcessId":1}]' });
    assert.ok(gone.entries[0].exited, "a successful fresh enumeration can confirm absence");
    const present = await sweep({ status: 0, stdout: '[{"ProcessId":100,"ParentProcessId":1},{"ProcessId":200,"ParentProcessId":100}]' });
    assert.equal(present.entries[0].exited, undefined);
    assert.match(present.entries[0].skipped, /capture failed/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("reports list every process that exited before its capture", () => {
  const dir = tmp();
  try {
    const results = completeMeasurements();
    results[2].entries.push(EXITED);
    const { mdPath, jsonPath } = writeReports({ outDir: dir, meta: { platform: "win32", browser: "chrome", tool: "procdump" }, results });
    const md = readFileSync(mdPath, "utf8");
    assert.match(md.slice(0, md.indexOf("| Needle |")), /1 process exited before its capture/);
    const reveal = md.slice(md.indexOf("## after-reveal"), md.indexOf("\n## after-copy"));
    assert.match(reveal, /- pid 20204: exited before capture/);
    assert.equal(JSON.parse(readFileSync(jsonPath, "utf8")).checkpoints[2].entries[1].exited, "exited before capture");
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("the checkpoint list is the documented order, with the positive control before the wipe", () => {
  assert.deepEqual([...CHECKPOINTS], ["before-input", "after-derive", "after-reveal", "after-copy", "after-wipe", "after-tab-close"]);
  assert.equal(CONTROL_CHECKPOINT, "after-reveal");
  assert.ok(CHECKPOINTS.indexOf(CONTROL_CHECKPOINT) < CHECKPOINTS.indexOf("after-wipe"), "the control must run while secrets are still on screen");
});

test("tool detection: Windows needs ProcDump, with env override winning", () => {
  const fsNever = { existsSync: () => false };
  assert.throws(
    () => detectTools({ env: {}, probe: () => null, fs: fsNever, platform: "win32" }),
    (error) => error instanceof ResidueToolError && /ProcDump not found/.test(error.message) && /PROCDUMP_BINARY/.test(error.message),
  );
  const viaEnv = detectTools({ env: { PROCDUMP_BINARY: "C:\\tools\\procdump.exe" }, probe: () => null, fs: fsNever, platform: "win32" });
  assert.equal(viaEnv.kind, "procdump");
  assert.equal(viaEnv.binary, "C:\\tools\\procdump.exe");
  const viaPath = detectTools({ env: {}, probe: (bin) => (bin === "procdump64" ? "procdump64" : null), fs: fsNever, platform: "win32" });
  assert.equal(viaPath.binary, "procdump64");
  const viaInstallDir = detectTools({ env: {}, probe: () => null, fs: { existsSync: (p) => p === "C:\\Sysinternals\\procdump.exe" }, platform: "win32" });
  assert.equal(viaInstallDir.binary, "C:\\Sysinternals\\procdump.exe");
});

test("tool detection: Linux needs gcore, and MemProcFS is an optional extra, never required", () => {
  const fsNever = { existsSync: () => false };
  assert.throws(
    () => detectTools({ env: {}, probe: () => null, fs: fsNever, platform: "linux" }),
    (error) => error instanceof ResidueToolError && /gcore not found/.test(error.message),
  );
  const withGcore = detectTools({ env: {}, probe: (bin) => (bin === "gcore" ? "gcore" : null), fs: fsNever, platform: "linux" });
  assert.equal(withGcore.kind, "gcore");
  assert.equal(withGcore.memprocfs, null, "no MemProcFS mount, no deep mode");
  const deep = detectTools({ env: { MEMPROCFS_MOUNT: "/mem" }, probe: () => "gcore", fs: { existsSync: (p) => p === "/mem" }, platform: "linux" });
  assert.equal(deep.memprocfs, "/mem");
});

test("tool detection: other platforms fail clearly and run nothing", () => {
  assert.throws(
    () => detectTools({ env: {}, probe: () => null, fs: { existsSync: () => false }, platform: "darwin" }),
    (error) => error instanceof ResidueToolError && /darwin|No capture tool support/.test(error.message),
  );
});

test("the fake secrets are deterministic, well-shaped, and the mnemonic is the published test vector", () => {
  const first = makeSecrets(), second = makeSecrets();
  assert.deepEqual(first, second, "the factory must be deterministic");
  assert.equal(first.mnemonic.split(" ").length, 12);
  assert.equal(first.mnemonic, "letter advice cage absurd amount doctor acoustic avoid letter advice cage above", "the published BIP39 0x80 vector");
  assert.match(first.seedHex, /^[0-9a-f]{128}$/);
  assert.equal(base58check(sha256).decode(first.wif).length, 34, "a checksummed compressed mainnet WIF");
  assert.equal(ReferenceHDKey.fromExtendedKey(first.xprv).depth, 0, "a valid master key");
  assert.equal(first.passphrase, "EntropyLab residue audit 750 - PUBLIC TEST ONLY");
});

test("needles cover every secret in UTF-8 and UTF-16LE, plus a base64 form", () => {
  const needles = makeNeedles();
  const byLabel = new Map();
  for (const needle of needles) byLabel.set(needle.label, (byLabel.get(needle.label) || 0) + 1);
  for (const label of ["mnemonic", "passphrase", "seedHex", "wif", "xprv", "privateKeyHex"]) {
    assert.equal(byLabel.get(label), ["seedHex", "privateKeyHex"].includes(label) ? 3 : 2, `${label} needs its string/binary encodings`);
  }
  assert.equal(byLabel.get("mnemonic-base64"), 1, "the audit found encoded copies; scan for one");
  const utf16 = needles.find((n) => n.label === "passphrase" && n.encoding === "utf16le");
  assert.deepEqual([...utf16.bytes.subarray(0, 4)], [0x45, 0x00, 0x6e, 0x00], "UTF-16LE: E/NUL/n/NUL");
});

test("the scanner finds needles in both encodings with correct offsets, and reports zero for clean buffers", async () => {
  const dir = tmp();
  try {
    const secrets = makeSecrets(), needles = makeNeedles();
    const file = join(dir, "dump.bin");
    const pad = Buffer.alloc(1024, 0x41);
    const utf8Needle = Buffer.from(secrets.passphrase, "utf8");
    const utf16Needle = Buffer.from(secrets.mnemonic, "utf16le");
    writeFileSync(file, Buffer.concat([pad, utf8Needle, Buffer.alloc(512, 0x42), utf16Needle, Buffer.alloc(64, 0x43)]));
    const hits = await scanFile(file, needles);
    const passUtf8 = hits.get("passphrase|utf8");
    assert.equal(passUtf8.count, 1);
    assert.equal(passUtf8.offsets[0], 1024);
    const mnemUtf16 = hits.get("mnemonic|utf16le");
    assert.equal(mnemUtf16.count, 1);
    assert.equal(mnemUtf16.offsets[0], 1024 + utf8Needle.length + 512);
    assert.equal(hits.get("wif|utf8"), undefined, "a secret that was never planted must not appear");

    const clean = join(dir, "clean.bin");
    writeFileSync(clean, Buffer.alloc(4096, 0));
    const none = await scanFile(clean, needles);
    assert.equal(none.size, 0, "a clean buffer reports no hits");

    const empty = join(dir, "empty.bin");
    writeFileSync(empty, "");
    assert.equal((await scanFile(empty, needles)).size, 0, "an empty dump is handled");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the scanner catches a needle split across the chunk boundary", async () => {
  const dir = tmp();
  try {
    const secrets = makeSecrets(), needles = makeNeedles();
    const needle = Buffer.from(secrets.seedHex, "utf8");
    const file = join(dir, "boundary.bin");
    // Plant the needle straddling the 8 MiB chunk boundary.
    const before = Buffer.alloc(8 * 1024 * 1024 - 10, 0x44);
    writeFileSync(file, Buffer.concat([before, needle, Buffer.alloc(64, 0x45)]));
    const hits = await scanFile(file, needles);
    assert.equal(hits.get("seedHex|utf8").count, 1, "a needle split across chunks was missed");
    assert.equal(hits.get("seedHex|utf8").offsets[0], before.length);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the bootstrap parses as JavaScript and retains no fixture or session driver", () => {
  const secrets = makeSecrets();
  const script = driverScript(secrets);
  for (const value of Object.values(secrets)) assert.ok(!script.includes(value));
  const context = vm.createContext({ window: { close() {} } });
  vm.runInContext(script.replace(/<\/?script>/g, ""), context);
  assert.equal(typeof context.window.close, "function");
  assert.equal(context.window.__residueDrive, undefined);
});

test("the external driver completes every checkpoint in order, including the negative control", async () => {
  const { checkpoints } = await exerciseDriver();
  assert.deepEqual(checkpoints.map(row => row.name), [...CHECKPOINTS]);
  assert.equal(checkpoints[0].derived, false);
  assert.equal(checkpoints.at(-1).closed, true);
});

test("the reports carry the disclaimer and call out the positive control", () => {
  const dir = tmp();
  try {
    const { jsonPath, mdPath } = writeReports({
      outDir: dir,
      meta: { platform: "win32", browser: "firefox", tool: "procdump" },
      results: [
        { name: "after-reveal", hits: ["mnemonic", "xprv", "wif"].map(label => ({ pid: 1234, label, encoding: "utf16le", count: 3 })) },
        { name: "after-wipe", hits: [] },
      ],
    });
    const json = JSON.parse(readFileSync(jsonPath, "utf8"));
    assert.equal(json.disclaimer, DISCLAIMER);
    assert.equal(json.checkpoints.length, 2);
    const md = readFileSync(mdPath, "utf8");
    assert.match(md, /Zero hits is not proof of erasure/);
    assert.match(md, /after-reveal — POSITIVE CONTROL PASSED/);
    assert.match(md, /after-wipe[\s\S]*?No hits\./);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a run whose positive control finds nothing is marked invalid in the report", () => {
  const dir = tmp();
  try {
    const { mdPath } = writeReports({
      outDir: dir,
      meta: { platform: "linux", browser: "chrome", tool: "gcore" },
      results: [{ name: "after-reveal", hits: [] }],
    });
    assert.match(readFileSync(mdPath, "utf8"), /POSITIVE CONTROL FAILED \(run invalid\)/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the positive control passes only on a mnemonic hit, never on some other secret", () => {
  // The mnemonic is the value the control knows is on screen at after-reveal.
  // A hit on any other needle (here the passphrase) must not pass the control:
  // a run that found only "TREZOR" never proved it can find the phrase itself.
  const dir = tmp();
  try {
    const { mdPath } = writeReports({
      outDir: dir,
      meta: { platform: "win32", browser: "firefox", tool: "procdump" },
      results: [{ name: CONTROL_CHECKPOINT, hits: [{ pid: 4242, label: "passphrase", encoding: "utf16le", count: 4 }] }],
    });
    assert.match(
      readFileSync(mdPath, "utf8"),
      /POSITIVE CONTROL FAILED \(run invalid\)/,
      "a control hit on a non-mnemonic label must invalidate the run",
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a needle lying entirely inside the retained chunk overlap is counted exactly once", async () => {
  const dir = tmp();
  try {
    const secrets = makeSecrets(), needles = makeNeedles(secrets);
    const maxNeedle = Math.max(...needles.map((n) => n.bytes.length));
    assert.ok(maxNeedle >= 64, "the fixture needles are shorter than this test assumes");
    const needle = Buffer.from(secrets.seedHex, "utf8"); // 64 bytes
    const file = join(dir, "overlap.bin");
    // Plant the needle so it ends exactly at the 8 MiB chunk boundary: it is
    // fully found in chunk one AND lies entirely within the tail that chunk
    // two re-searches. It must still be counted once.
    const before = Buffer.alloc(8 * 1024 * 1024 - needle.length, 0x46);
    const after = Buffer.alloc(4096, 0x47);
    writeFileSync(file, Buffer.concat([before, needle, after]));
    const hits = await scanFile(file, needles);
    assert.equal(
      hits.get("seedHex|utf8").count,
      1,
      "a match fully inside the retained overlap was counted again in the next chunk",
    );
    assert.equal(hits.get("seedHex|utf8").offsets[0], before.length);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a checkpoint that captured nothing reports SKIPPED, never a clean 'No hits.'", () => {
  // A blind checkpoint (every capture skipped, e.g. no debugging port to close
  // the tab with) must not read like a clean zero: "No hits" on a checkpoint
  // where no dump was ever scanned would silently overstate the result.
  const dir = tmp();
  try {
    const { mdPath } = writeReports({
      outDir: dir,
      meta: { platform: "win32", browser: "firefox", tool: "procdump" },
      results: [
        { name: "after-tab-close", hits: [], entries: [{ pid: 99, out: null, skipped: "no debugging port on this engine" }] },
        { name: "after-wipe", hits: [] },
      ],
    });
    const md = readFileSync(mdPath, "utf8");
    assert.match(md, /after-tab-close — SKIPPED: no dump was captured/, "a blind checkpoint must be labelled skipped with its reason");
    assert.doesNotMatch(md.split("## after-wipe")[1], /SKIPPED/, "a checkpoint whose dumps were scanned still reports its (zero) hits");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("main wires the run: detection first, then staging — never a log-and-return stub", async () => {
  // The entry point npm run test:residue invokes must proceed from tool
  // detection into the browser drive. The staging seam throwing proves the
  // call reached that stage; a main() that only logs and returns fulfills
  // instead and fails this test. The browser override keeps this independent
  // of any browser installed on the machine running the suite.
  const order = [];
  class Marker extends Error {}
  const detect = () => {
    order.push("detect");
    return { kind: "procdump", binary: "fake-procdump", memprocfs: null };
  };
  const stage = async () => {
    order.push("stage");
    throw new Marker("staging reached");
  };
  let error = null;
  try {
    await main([], { log: () => {}, detect, stage, browser: { id: "fake", kind: "firefox", binary: "fake-browser" } });
  } catch (thrown) {
    error = thrown;
  }
  assert.ok(error instanceof Marker, "main must proceed from detection into staging (it fulfilled without running the drive)");
  assert.deepEqual(order, ["detect", "stage"], "detection must come before staging");
});
