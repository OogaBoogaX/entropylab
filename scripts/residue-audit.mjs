// Dev-only memory-residue harness: drives the app in a real browser, plants
// deterministic public test secrets, captures each browser process's memory at fixed
// checkpoints with an external tool, and scans the captures for the secrets.
//
// This is NOT part of `npm test` or CI. It needs a capture tool that is
// detected, never bundled:
//   - Windows: ProcDump (PROCDUMP_BINARY, or procdump/procdump64 on PATH)
//   - Linux:   gcore, from gdb (GCORE_BINARY, or gcore on PATH)
//   - Optional deeper path: MemProcFS (MEMPROCFS_MOUNT) — scan live VM pages
//     without dumping, where it is installed.
//   - macOS: no reliable capture tool; the harness stops with a clear message.
//
// Honest framing (also printed into every report): a zero hit count is NOT
// proof of erasure — only that these bytes were not in these processes at
// this moment on this OS. A positive hit IS proof of residue. The pre-wipe
// positive control must find the secrets, or the run is invalid.
//
// Run: npm run test:residue
import { execFileSync, spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { closeSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, openSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync, createReadStream } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export const root = dirname(dirname(fileURLToPath(import.meta.url)));
const platform = process.platform;

export const DISCLAIMER =
  "Zero hits is not proof of erasure: it means only that these bytes were not found in these processes at this moment, on this OS, with this allocator state. A positive hit is proof of residue.";

// The checkpoints, in order. after-tab-close scans the browser's surviving
// processes (the browser process, once the tab's renderer is gone).
export const CHECKPOINTS = Object.freeze([
  "before-input", // negative control: no fixture bytes may already be present
  "after-derive",
  "after-reveal", // the positive control: secrets MUST be found here
  "after-copy",
  "after-wipe", // End session
  "after-tab-close",
]);
export const CONTROL_CHECKPOINT = "after-reveal";

export class ResidueToolError extends Error {}

// --- Tool detection (detected, never bundled) ------------------------------

const runProbe = (bin) => {
  try {
    const result = spawnSync(bin, [platform === "win32" ? "-?" : "--version"], { stdio: "pipe", timeout: 15000 });
    return result.status !== null ? bin : null;
  } catch {
    return null;
  }
};

export const detectTools = ({ env = process.env, probe = runProbe, fs = { existsSync }, platform: os = platform } = {}) => {
  if (os === "win32") {
    const binary = env.PROCDUMP_BINARY
      || ["procdump", "procdump64"].map(probe).find(Boolean)
      || ["C:\\Tools\\procdump.exe", "C:\\Sysinternals\\procdump.exe"].find((p) => fs.existsSync(p));
    if (!binary) throw new ResidueToolError(
      "ProcDump not found. Install it (https://learn.microsoft.com/sysinternals/downloads/procdump) "
      + "or set PROCDUMP_BINARY to its path. The harness does not bundle it.");
    return { kind: "procdump", binary, memprocfs: env.MEMPROCFS_MOUNT && fs.existsSync(env.MEMPROCFS_MOUNT) ? env.MEMPROCFS_MOUNT : null };
  }
  if (os === "linux") {
    const binary = env.GCORE_BINARY || probe("gcore");
    if (!binary) throw new ResidueToolError(
      "gcore not found. Install gdb (Debian/Ubuntu: sudo apt install gdb; Fedora: sudo dnf install gdb) "
      + "or set GCORE_BINARY to its path. The harness does not bundle it.");
    return { kind: "gcore", binary, memprocfs: env.MEMPROCFS_MOUNT && fs.existsSync(env.MEMPROCFS_MOUNT) ? env.MEMPROCFS_MOUNT : null };
  }
  throw new ResidueToolError(`No capture tool support on ${os} (ProcDump is Windows, gcore is Linux). Nothing was run.`);
};

// --- Public, deterministic fixture -------------------------------------------
// The 128-bit 0x80 BIP39 vector, with a distinctive public passphrase. The
// expected wallet values below were established outside the app using Node's
// PBKDF2 and the already-pinned @scure/bip32/base implementations; the tests
// independently re-derive them. These are VALID keys. NEVER send funds to them.
export const FAKE_MNEMONIC = "letter advice cage absurd amount doctor acoustic avoid letter advice cage above";
export const FAKE_PASSPHRASE = "EntropyLab residue audit 750 - PUBLIC TEST ONLY";
export const makeSecrets = () => Object.freeze({
  mnemonic: FAKE_MNEMONIC,
  passphrase: FAKE_PASSPHRASE,
  seedHex: "c2603fba231a90214aeb45b5e2667fdc7e5dc692edeba678a75416239dfbb21aaf2b5d2d7d87cf69e26b45f051c21c4c79ef32f4a0ab561f5bdafe32259509fa",
  xprv: "xprv9s21ZrQH143K2qXGaTvSdde5a8BVcy8WFdroJT3ib1VxFxihVoZ7JxiYLY7xJXpqZMZcJniPyHuvqRPLzfsNW79wd9SvyomcervC1gTGdnV",
  // Compressed mainnet WIF at m/84'/0'/0'/0/0, the default UI path.
  wif: "L5hLeY8Kpd8GHzm18W7qRSswwPMVr6QT2Cn9xwmc6u6GJPUf4p43",
  privateKeyHex: "fce993d6bcaa1c08520418bd7bfd1d9adaa52d91dc360324c002ea6bc1cb1eb9",
});

// Common representations: UTF-8/UTF-16LE text, raw seed/private-key bytes, and
// the mnemonic's base64 form. This is not an exhaustive encoding inventory.
export const makeNeedles = (secrets = makeSecrets()) => {
  const needles = [];
  const add = (label, text) => {
    needles.push({ label, encoding: "utf8", bytes: Buffer.from(text, "utf8") });
    needles.push({ label, encoding: "utf16le", bytes: Buffer.from(text, "utf16le") });
  };
  add("mnemonic", secrets.mnemonic);
  add("passphrase", secrets.passphrase);
  add("seedHex", secrets.seedHex);
  add("wif", secrets.wif);
  add("xprv", secrets.xprv);
  add("privateKeyHex", secrets.privateKeyHex);
  // WASM/typed-array secret bytes are binary, not the characters of their hex.
  for (const label of ["seedHex", "privateKeyHex"]) {
    needles.push({ label, encoding: "raw", bytes: Buffer.from(secrets[label], "hex") });
  }
  needles.push({ label: "mnemonic-base64", encoding: "utf8", bytes: Buffer.from(Buffer.from(secrets.mnemonic, "utf8").toString("base64"), "utf8") });
  return needles;
};

// --- Scanner ----------------------------------------------------------------

// Streaming needle search: one pass over the file per needle would be O(n·m);
// instead read in overlapping chunks and search each needle in each chunk.
const CHUNK = 8 * 1024 * 1024;
export const scanFile = async (file, needles) => {
  const hits = new Map(); // key: `${label}|${encoding}` -> { count, offsets }
  const maxNeedle = Math.max(...needles.map((n) => n.bytes.length));
  const stream = createReadStream(file, { highWaterMark: CHUNK });
  let offset = 0, tail = Buffer.alloc(0);
  for await (const chunk of stream) {
    const window = Buffer.concat([tail, chunk]);
    for (const needle of needles) {
      // Resume past what this needle already searched in the retained tail:
      // a match lying entirely inside the overlap was counted in the previous
      // chunk and must not be counted again here. The floor of
      // `tail.length - needle length + 1` (never below 0) is the first start
      // position the previous window could not have examined.
      let at = Math.max(0, tail.length - needle.bytes.length + 1);
      while (true) {
        const found = window.indexOf(needle.bytes, at);
        if (found === -1) break;
        const absolute = offset - tail.length + found;
        const key = `${needle.label}|${needle.encoding}`;
        const entry = hits.get(key) || { count: 0, offsets: [] };
        entry.count++;
        if (entry.offsets.length < 8) entry.offsets.push(absolute);
        hits.set(key, entry);
        at = found + 1;
      }
    }
    tail = window.subarray(Math.max(0, window.length - maxNeedle));
    offset += chunk.length;
  }
  return hits;
};

// --- Process tree -----------------------------------------------------------

export const processTree = ({ pid, platform: os = platform, exec = spawnSync } = {}) => {
  const pids = new Set([pid]);
  if (os === "win32") {
    // wmic is deprecated; use PowerShell's CIM query for parent links.
    const out = exec("powershell", ["-NoProfile", "-Command",
      "Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId | ConvertTo-Json"], { encoding: "utf8" }).stdout;
    try {
      const rows = JSON.parse(out || "[]"), list = Array.isArray(rows) ? rows : [rows];
      let grew = true;
      while (grew) {
        grew = false;
        for (const row of list) if (pids.has(row.ParentProcessId) && !pids.has(row.ProcessId)) { pids.add(row.ProcessId); grew = true; }
      }
    } catch { /* keep the root pid only */ }
  } else {
    const out = exec("ps", ["-eo", "pid=,ppid="], { encoding: "utf8" }).stdout || "";
    const children = new Map();
    for (const line of out.split("\n")) {
      const [cpid, ppid] = line.trim().split(/\s+/).map(Number);
      if (cpid) (children.get(ppid) || children.set(ppid, []).get(ppid)).push(cpid);
    }
    const queue = [pid];
    while (queue.length) {
      for (const child of children.get(queue.shift()) || []) if (!pids.has(child)) { pids.add(child); queue.push(child); }
    }
  }
  return [...pids];
};

// --- Capture ----------------------------------------------------------------

const MAX_DUMP_BYTES = 4 * 1024 * 1024 * 1024; // post-capture retention limit, not a disk quota
export const capture = async ({ tool, pid, outDir, checkpoint, execFile = spawn } = {}) => {
  const out = join(outDir, `${checkpoint}-pid${pid}.dmp`);
  if (tool.memprocfs) return { pid, out: null, skipped: "memprocfs-live" };
  const args = tool.kind === "procdump"
    ? ["-ma", "-accepteula", String(pid), out]
    : ["-o", out, String(pid)]; // gcore writes <out>.<pid>
  await new Promise((resolve, reject) => {
    const child = execFile(tool.binary, args, { stdio: "pipe" });
    // Drain both pipes: a verbose dumper must not block on a full output pipe.
    // Keep only a bounded diagnostic tail for denied/failed captures.
    let diagnostic = "";
    const record = chunk => { diagnostic = (diagnostic + chunk.toString()).slice(-8192); };
    child.stdout?.on("data", record); child.stderr?.on("data", record);
    child.on("error", reject);
    child.on("close", code => code === 0 ? resolve()
      : reject(new Error(`${tool.kind} exited ${code} on pid ${pid}${diagnostic.trim() ? `: ${diagnostic.trim()}` : ""}`)));
  });
  const file = tool.kind === "gcore" ? `${out}.${pid}` : out;
  if (existsSync(file) && statSync(file).size > MAX_DUMP_BYTES) {
    rmSync(file, { force: true });
    throw new ResidueToolError(`capture of pid ${pid} exceeded ${MAX_DUMP_BYTES} bytes; deleted. Re-run with --browser-process to dump less.`);
  }
  return { pid, out: existsSync(file) ? file : null, skipped: existsSync(file) ? null : "no dump written" };
};

// --- Reports ----------------------------------------------------------------

const CONTROL_LABELS = ["mnemonic", "xprv", "wif"];
// Each of these values is verified in the revealed wallet by the host.
const controlPassed = (checkpoint) =>
  Boolean(checkpoint) && checkpoint.name === CONTROL_CHECKPOINT
  && CONTROL_LABELS.every(label => checkpoint.hits.some(hit => hit.label === label && hit.count > 0));

const capturedCompletely = checkpoint => Boolean(checkpoint?.entries?.length)
  && checkpoint.entries.every(entry => entry.scanned > 0 && !entry.skipped);
const cleanBaseline = checkpoint => capturedCompletely(checkpoint) && checkpoint.hits.length === 0;

export const assessRun = (results) => {
  const reasons = [];
  const baseline = results.find(result => result.name === "before-input");
  if (!cleanBaseline(baseline)) reasons.push("negative control missing, contaminated, or incompletely captured");
  for (const name of CHECKPOINTS) {
    if (!capturedCompletely(results.find(result => result.name === name))) reasons.push(`${name}: incomplete capture`);
  }
  const control = results.find(result => result.name === CONTROL_CHECKPOINT);
  for (const label of CONTROL_LABELS) {
    if (!control?.hits.some(hit => hit.label === label && hit.count > 0)) reasons.push(`${label}: positive control failed`);
  }
  const beforeWipe = results.filter(result => ["after-derive", "after-reveal", "after-copy"].includes(result.name));
  // A transient seed may already have been wiped during derivation. Never turn
  // its absence at every checkpoint into a claim that End Session erased it.
  const coverage = [...new Set(makeNeedles().map(needle => needle.label))].map(label => ({
    label,
    calibrated: cleanBaseline(baseline) && beforeWipe.some(result => result.hits.some(hit => hit.label === label && hit.count > 0)),
  }));
  return { valid: reasons.length === 0, reasons, coverage };
};

export const writeReports = ({ outDir, meta, results }) => {
  const blind = (checkpoint) =>
    !checkpoint.hits.length && Array.isArray(checkpoint.entries) && checkpoint.entries.length > 0
    && checkpoint.entries.every((entry) => entry.skipped);

  const json = {
    tool: "residue-audit",
    disclaimer: DISCLAIMER,
    meta,
    assessment: assessRun(results),
    checkpoints: results,
  };
  writeFileSync(join(outDir, "residue-report.json"), JSON.stringify(json, null, 2));

  const lines = ["# Residue audit report", "", `> ${DISCLAIMER}`, ""];
  lines.push(`Platform: ${meta.platform} · Browser: ${meta.browser} · Capture: ${meta.tool}`, "");
  lines.push(json.assessment.valid ? "Controls passed. Zero hits still do not prove erasure." : "**INVALID RUN**", "");
  for (const reason of json.assessment.reasons) lines.push(`- ${reason}`);
  if (meta.error) lines.push(`- Run stopped: ${meta.error}`);
  lines.push("", "| Needle | Pre-wipe calibration |", "|---|---|");
  for (const row of json.assessment.coverage) lines.push(`| ${row.label} | ${row.calibrated ? "Observed after a clean baseline" : "NOT CALIBRATED — a later zero is inconclusive"} |`);
  lines.push("");
  for (const checkpoint of results) {
    const suffix = checkpoint.name !== CONTROL_CHECKPOINT ? ""
      : controlPassed(checkpoint) ? " — POSITIVE CONTROL PASSED" : " — POSITIVE CONTROL FAILED (run invalid)";
    // A checkpoint where every capture was skipped captured nothing; say so
    // rather than reporting a clean zero nobody scanned for.
    const blindNote = blind(checkpoint) ? ` — SKIPPED: no dump was captured (${[...new Set(checkpoint.entries.map((entry) => entry.skipped))].join("; ")})` : "";
    lines.push(`## ${checkpoint.name}${suffix}${blindNote}`, "");
    if (!checkpoint.hits.length) lines.push(blind(checkpoint) ? "No dump was scanned." : "No hits.", "");
    else {
      lines.push("| pid | secret | encoding | hits |", "|---|---|---|---|");
      for (const hit of checkpoint.hits) lines.push(`| ${hit.pid} | ${hit.label} | ${hit.encoding} | ${hit.count} |`);
      lines.push("");
    }
    const skips = (checkpoint.entries || []).filter((entry) => entry.skipped);
    if (skips.length) {
      for (const entry of skips) lines.push(`- pid ${entry.pid}: not captured — ${entry.skipped}`);
      lines.push("");
    }
  }
  writeFileSync(join(outDir, "residue-report.md"), lines.join("\n"));
  return { jsonPath: join(outDir, "residue-report.json"), mdPath: join(outDir, "residue-report.md") };
};

// --- The run ----------------------------------------------------------------

const parseArgs = (argv) => ({
  browserProcessOnly: argv.includes("--browser-process"),
  browser: argv.find((a, i) => argv[i - 1] === "--browser") || "chrome",
  browserExplicit: argv.includes("--browser"),
});

const CHECKPOINT_TIMEOUT = 60000;
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// Normalize only on the host, after reading the input by value.
const normalizeSeed = (text) => String(text).trim().toLowerCase().replace(/\s+/g, " ");
const fingerprint = text => createHash("sha256").update(text, "utf8").digest("hex");
// Return only digests through CDP. Reading/hashing still creates renderer-side
// temporaries, so use this only AFTER the positive-control capture.
const digestValues = expression => `(async () => {
  const values = ${expression};
  return Promise.all(values.map(async value => {
    const bytes = new TextEncoder().encode(value);
    try {
      const digest = await crypto.subtle.digest("SHA-256", bytes);
      return [...new Uint8Array(digest)].map(byte => byte.toString(16).padStart(2, "0")).join("");
    } finally { bytes.fill(0); }
  }));
})()`;

// The only injected code suppresses the application's automatic tab close so
// that after-wipe can be captured. No fixture, driver state, or callback stays
// in the page; Node performs the drive over Chromium's debugging pipe.
export const driverScript = () => "<script>window.close = () => {};</script>";

// The page adapter accepts fixture text ONLY through native input events.
// Never interpolate it into evaluate(), function arguments, page globals, URLs,
// or clipboard instrumentation. Output and clipboard checks return only
// digests, and release protocol object groups after every evaluation.
export const driveSession = async (page, secrets, checkpoint) => {
  await page.waitFor(`document.documentElement?.dataset.selfTestsFailed === "0"`);
  await page.waitFor(`document.querySelector('#workspace [data-workspace="calc"]')`);
  // Dismiss the real two-stage disclaimer without changing the release app.
  if (await page.evaluate(`!!document.getElementById("beta-disclaimer-accept")`)) {
    await page.click("#beta-disclaimer-accept");
    await page.evaluate(`(() => {
      const visible = [...document.querySelectorAll('[id^="beta-disclaimer-proof-text-"]')].find(el => !el.hidden);
      const input = document.getElementById("beta-disclaimer-proof");
      input.value = visible.id.split("-").at(-1);
      input.dispatchEvent(new Event("input", { bubbles: true }));
    })()`);
    await page.click("#beta-disclaimer-confirm");
    await page.waitFor(`!document.getElementById("beta-disclaimer")`);
  }
  await page.click('#workspace [data-workspace="calc"]');
  await page.evaluate(`(() => {
    const length = document.getElementById("seed-length-select");
    length.value = "12"; length.dispatchEvent(new Event("change", { bubbles: true }));
    [...document.querySelectorAll("#modes button")].find(el => el.textContent.includes("Seed phrase")).click();
  })()`);
  await page.waitFor(`document.getElementById("seed")`);
  await checkpoint("before-input");
  await page.type("#seed", secrets.mnemonic);
  await page.type("#pass", secrets.passphrase);
  const field = await page.evaluate(`document.getElementById("seed").value`);
  if (normalizeSeed(field) !== secrets.mnemonic) throw new ResidueToolError("refusing to derive: the seed field is not the public fixture");
  // The numbers view converts the entered words and exposes the app's real
  // Copy seed phrase button. Direct word entry has no such button.
  await page.click('input[name="seed-method"][value="numbers"]');
  await page.waitFor(`!document.getElementById("go").disabled`);
  await page.click("#go");
  await page.waitFor(`document.querySelector('#out [data-key-group="identity"] [data-copy-field]')`);
  await checkpoint("after-derive");
  if (!await page.evaluate(`document.getElementById("reveal").checked`)) await page.click("#reveal");
  // Capture before output verification or clipboard use can add observer copies.
  // In particular, neither derived private key has ever crossed the pipe here.
  await checkpoint("after-reveal");
  const output = await page.evaluate(digestValues(`[...document.querySelectorAll('#out [translate="no"]')].map(el => el.textContent.trim())`));
  for (const label of ["mnemonic", "xprv", "wif"]) {
    if (!output.includes(fingerprint(secrets[label]))) throw new ResidueToolError(`the revealed wallet does not match the fixture's ${label}`);
  }
  // Remove any pre-existing clipboard value, then verify the real write. An
  // xpub click, permission rejection, or a no-op must not pass this checkpoint.
  await page.evaluate(`navigator.clipboard.writeText("")`);
  await page.click("#form [data-copy-seed-phrase]");
  await page.waitForClipboard(secrets.mnemonic);
  await checkpoint("after-copy");
  await page.click("#end-session");
  await page.click("#end-session-confirm");
  await page.waitFor(`document.querySelector("[data-session-ended]")`);
  await checkpoint("after-wipe");
  await page.close();
  await checkpoint("after-tab-close");
};

// A small CDP pipe client: no new dependencies, WebSocket server, or debugging
// listener. Chromium reads NUL-delimited JSON on fd 3 and writes it on fd 4.
export const createPipeClient = (writer, reader, { timeoutMs = 15000 } = {}) => {
  let sequence = 0, buffer = "", closed = false;
  const pending = new Map();
  const fail = () => {
    closed = true;
    for (const { reject, timer } of pending.values()) { clearTimeout(timer); reject(new ResidueToolError("browser debugging pipe closed")); }
    pending.clear();
  };
  reader.setEncoding("utf8");
  reader.on("data", chunk => {
    buffer += chunk;
    let end;
    while ((end = buffer.indexOf("\0")) !== -1) {
      const line = buffer.slice(0, end); buffer = buffer.slice(end + 1);
      let reply;
      try { reply = JSON.parse(line); } catch { fail(); return; }
      const waiter = pending.get(reply.id);
      if (!waiter) continue;
      pending.delete(reply.id); clearTimeout(waiter.timer);
      if (reply.error) waiter.reject(new ResidueToolError(`browser command failed: ${waiter.method}`));
      else waiter.resolve(reply.result);
    }
  });
  reader.on("end", fail); reader.on("error", fail); writer.on("error", fail);
  return {
    send(method, params = {}, sessionId) {
      if (closed) return Promise.reject(new ResidueToolError("browser debugging pipe closed"));
      return new Promise((resolve, reject) => {
        const id = ++sequence;
        const timer = setTimeout(() => { pending.delete(id); reject(new ResidueToolError(`browser command timed out: ${method}`)); }, timeoutMs);
        pending.set(id, { method, resolve, reject, timer });
        writer.write(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }) + "\0");
      });
    },
    dispose() { fail(); writer.destroy(); reader.destroy(); },
  };
};

export const createPage = async (client, origin) => {
  const { targetId } = await client.send("Target.createTarget", { url: "about:blank" });
  const { sessionId } = await client.send("Target.attachToTarget", { targetId, flatten: true });
  const send = (method, params) => client.send(method, params, sessionId);
  await client.send("Browser.grantPermissions", { origin, permissions: ["clipboardReadWrite", "clipboardSanitizedWrite"] });
  await send("Page.navigate", { url: origin });
  const page = {
    async evaluate(expression) {
      try {
        const reply = await send("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true, userGesture: true, objectGroup: "residue" });
        if (reply.exceptionDetails) throw new ResidueToolError(`browser evaluation failed in ${expression}`);
        return reply.result.value;
      } finally { await send("Runtime.releaseObjectGroup", { objectGroup: "residue" }); }
    },
    async click(selector) {
      await page.evaluate(`document.querySelector(${JSON.stringify(selector)}).click()`);
    },
    async type(selector, text) {
      await page.evaluate(`(() => { const el = document.querySelector(${JSON.stringify(selector)}); el.focus(); el.select(); })()`);
      await send("Input.insertText", { text });
    },
    async waitFor(expression) {
      const deadline = Date.now() + CHECKPOINT_TIMEOUT;
      while (Date.now() < deadline) {
        if (await page.evaluate(`Boolean(${expression})`)) return;
        await sleep(100);
      }
      throw new ResidueToolError("timed out waiting for a browser state transition");
    },
    async waitForClipboard(expected) {
      const deadline = Date.now() + 5000;
      const expectedDigest = fingerprint(expected);
      while (Date.now() < deadline) {
        const [actual] = await page.evaluate(digestValues(`[await navigator.clipboard.readText()]`));
        if (actual === expectedDigest) return;
        await sleep(100);
      }
      throw new ResidueToolError("secret copy did not succeed; after-copy was not captured");
    },
    async close() {
      const { success } = await client.send("Target.closeTarget", { targetId });
      if (!success) throw new ResidueToolError("could not close the fixture tab");
      const deadline = Date.now() + 15000;
      while (true) {
        const { targetInfos } = await client.send("Target.getTargets");
        if (!targetInfos.some(target => target.targetId === targetId)) break;
        if (Date.now() >= deadline) throw new ResidueToolError("fixture tab still exists after close");
        await sleep(100);
      }
      await sleep(1500);
    },
  };
  return page;
};

// Binary resolution for the supported Chromium engines, mirroring the browser suite.
const ENGINES = [
  {
    id: "chrome", kind: "chromium",
    envVars: ["CHROME_BINARY", "CHROMIUM_BINARY"],
    pathNames: ["google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome"],
    extraPaths: {
      darwin: ["/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"],
      win32: [
        "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
      ],
      linux: ["/usr/bin/google-chrome", "/usr/bin/google-chrome-stable", "/usr/bin/chromium", "/snap/bin/chromium"],
    },
  },
  {
    id: "edge", kind: "chromium",
    envVars: ["EDGE_BINARY"],
    pathNames: ["microsoft-edge", "microsoft-edge-stable", "msedge"],
    extraPaths: {
      darwin: ["/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"],
      win32: ["C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"],
      linux: ["/usr/bin/microsoft-edge", "/opt/microsoft/msedge/msedge"],
    },
  },
];

const pickEngine = (definition) => {
  for (const name of definition.envVars) if (process.env[name]) return { ...definition, binary: process.env[name] };
  for (const bin of definition.pathNames) {
    try {
      const probe = spawnSync(bin, ["--version"], { stdio: "pipe", timeout: 15000 });
      if (probe.status === 0) return { ...definition, binary: bin };
    } catch { /* not on PATH */ }
  }
  for (const candidate of definition.extraPaths[platform] ?? []) {
    if (existsSync(candidate)) return { ...definition, binary: candidate };
  }
  return null;
};

export const resolveBrowser = ({ browser: want, browserExplicit } = {}) => {
  if (want === "firefox") throw new ResidueToolError("Firefox residue capture is unsupported: it needs an external driver that does not retain fixture literals. Use --browser chrome or edge.");
  const definition = ENGINES.find((engine) => engine.id === want);
  if (!definition) throw new ResidueToolError(`unknown --browser "${want}" (use chrome or edge)`);
  const found = pickEngine(definition);
  if (found) return found;
  if (browserExplicit) throw new ResidueToolError(`no ${want} binary found (set ${definition.envVars.join(" or ")})`);
  // Default preference is chrome; fall back to an installed engine.
  for (const engine of ENGINES) {
    if (engine.id === want) continue;
    const alternative = pickEngine(engine);
    if (alternative) return alternative;
  }
  throw new ResidueToolError("no browser found (set CHROME_BINARY or EDGE_BINARY)");
};

const chromiumSandboxArgs = () => {
  if (process.env.BROWSER_TEST_NO_SANDBOX || (typeof process.getuid === "function" && process.getuid() === 0)) return ["--no-sandbox"];
  return [];
};

export const spawnBrowser = (engine, { profile, logPath }) => {
  const logFd = openSync(logPath, "w");
  const args = [
    "--headless", ...chromiumSandboxArgs(), "--no-first-run", "--no-default-browser-check",
    "--disable-gpu", "--disable-dev-shm-usage", "--window-size=1280,800",
    `--user-data-dir=${profile}`, "--remote-debugging-pipe", "about:blank",
  ];
  const child = spawn(engine.binary, args, { stdio: ["ignore", logFd, logFd, "pipe", "pipe"] });
  closeSync(logFd);
  child.on("error", () => {}); // surfaced by the missing pid check in main()
  return child;
};

// Shut the browser down through the protocol first: it then stops its helper
// processes and flushes the profile before it exits. SIGKILL on the browser
// pid alone leaves helpers that can still write into the profile, and a
// recursive delete racing them fails with ENOTEMPTY (seen under CI load).
// SIGKILL stays the fallback for a browser that does not exit in time.
export const stopBrowser = async (child, client, { timeoutMs = 10000 } = {}) => {
  if (!child?.pid) return;
  const running = () => child.exitCode === null && child.signalCode === null;
  if (!running()) return;
  const exited = new Promise(resolve => child.once("exit", resolve));
  // The reply may never arrive: the pipe closes as the browser exits.
  client?.send("Browser.close").catch(() => {});
  let timer;
  const stopped = await Promise.race([
    exited.then(() => true),
    new Promise(resolve => { timer = setTimeout(resolve, timeoutMs, false); }),
  ]);
  clearTimeout(timer);
  if (!stopped) {
    try { child.kill("SIGKILL"); } catch { /* already gone */ }
    await exited;
  }
};

// rmSync's own retries only repeat the final rmdir, so a file a late browser
// helper writes after the walk keeps failing ENOTEMPTY however long it waits.
// Retry the whole walk instead, and return the last error rather than throw:
// a cleanup problem must never replace the outcome of the run it follows.
export const removeWorkDir = async (dir, { attempts = 5, delayMs = 500, remove = rmSync } = {}) => {
  let last = null;
  for (let attempt = 1; attempt <= attempts; attempt++) {
    try {
      remove(dir, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
      return null;
    } catch (error) {
      last = error;
      if (attempt < attempts) await sleep(attempt * delayMs);
    }
  }
  return last;
};

// Stage the release build, without test hooks or fixture literals. The only
// bootstrap change delays window.close() until after the wipe capture.
export const stageRun = async (secrets = makeSecrets()) => {
  const workDir = mkdtempSync(join(tmpdir(), "residue-audit-"));
  try {
    execFileSync(process.execPath, [join(root, "scripts", "build.mjs"), "--out", workDir], { stdio: "pipe" });
    const html = readFileSync(join(workDir, "entropylab.html"), "utf8");
    const page = html.replace(/<\/body>\s*<\/html>\s*$/, () => `${driverScript(secrets)}</body></html>\n`);
    if (page === html) throw new ResidueToolError("could not find </body></html> in the staged page to inject the driver");
    writeFileSync(join(workDir, "residue.html"), page);
    if ((await scanFile(join(workDir, "residue.html"), makeNeedles(secrets))).size) {
      throw new ResidueToolError("fixture bytes already occur in the staged application; choose a distinct public fixture");
    }
    const profile = join(workDir, "profile");
    mkdirSync(profile, { recursive: true });
    return { workDir, pagePath: join(workDir, "residue.html"), profile };
  } catch (error) {
    rmSync(workDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
    throw error;
  }
};

// Read-only loopback hosting. No checkpoint URLs or input values ever travel
// through the page's network stack; the host controls checkpoint ordering.
export const createHarnessServer = ({ pagePath }) => {
  const server = createServer((request, response) => {
    if (request.url !== "/") { response.writeHead(404); response.end(); return; }
    response.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
    response.end(readFileSync(pagePath));
  });
  const listen = () => new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve(server.address().port));
  });
  return { server, listen };
};

const addHits = (hits, pid, found) => {
  for (const [key, value] of found) {
    const [label, encoding] = key.split("|");
    hits.push({ pid, label, encoding, count: value.count, offsets: value.offsets });
  }
};

// MemProcFS live scanning: walk the mount's per-process directory where the
// layout exposes one, scan every regular file under the size cap, and record
// an explicit skip (with the paths tried) where it does not — never a silent
// zero.
const scanLive = async ({ mount, pid, needles, hits }) => {
  const tried = [join(mount, String(pid)), join(mount, "proc", String(pid))];
  const dir = tried.find((candidate) => existsSync(candidate));
  const complaints = [];
  if (!dir) return { pid, out: null, skipped: `MemProcFS: no live pages at ${tried.join(" or ")}` };
  let scanned = 0;
  for (const name of readdirSync(dir)) {
    const file = join(dir, name);
    try {
      const stat = statSync(file);
      if (!stat.isFile()) continue;
      if (stat.size > MAX_DUMP_BYTES) {
        complaints.push(`${name}: over the ${MAX_DUMP_BYTES} byte cap`);
        continue;
      }
      addHits(hits, pid, await scanFile(file, needles));
      scanned++;
    } catch (error) {
      complaints.push(`${name}: ${error.message}`);
    }
  }
  if (!scanned) return { pid, out: null, skipped: `MemProcFS: nothing scannable in ${dir}${complaints.length ? ` (${complaints.join("; ")})` : ""}` };
  return { pid, out: null, scanned, ...(complaints.length ? { skipped: complaints.join("; ") } : {}) };
};

const captureAll = async ({ tool, pids, outDir, checkpoint, needles }) => {
  const entries = [], hits = [];
  for (const pid of pids) {
    let entry;
    if (tool.memprocfs) {
      entry = await scanLive({ mount: tool.memprocfs, pid, needles, hits });
    } else {
      // One PID refusing a dump (access denied, already exited) must not kill
      // the audit: record the failure per process. Incomplete captures still
      // invalidate the run even when other processes contain control hits.
      try {
        entry = await capture({ tool, pid, outDir, checkpoint });
        if (entry.out) {
          try {
            addHits(hits, pid, await scanFile(entry.out, needles));
            entry.scanned = 1;
          } catch (error) {
            entry.skipped = `scan failed: ${error.message}`;
          }
        }
      } catch (error) {
        entry = { pid, out: null, skipped: `capture failed: ${error.message}` };
      }
    }
    entries.push(entry);
  }
  return { entries, hits };
};

export const main = async (argv = process.argv.slice(2), { log = console.log, detect = detectTools, stage = stageRun, browser: browserOverride = null } = {}) => {
  const options = parseArgs(argv);
  const tool = detect(); // throws ResidueToolError with install instructions
  const secrets = makeSecrets();
  const needles = makeNeedles(secrets);
  const outDir = join(root, "out", "residue");
  mkdirSync(outDir, { recursive: true });
  log(`residue-audit: ${tool.kind} at ${tool.binary}; report dir ${outDir}`);
  log("NOTE: " + DISCLAIMER);
  const browser = browserOverride || resolveBrowser(options);
  log(`residue-audit: driving ${browser.id} at ${browser.binary}`);
  const startedAt = new Date().toISOString();
  const staged = await stage(secrets);
  let child = null, served = null, client = null;
  const results = [];
  const meta = { platform, browser: browser.id, browserBinary: browser.binary, tool: tool.kind, captureBinary: tool.binary, startedAt };
  try {
    served = createHarnessServer(staged);
    const port = await served.listen();
    const origin = `http://127.0.0.1:${port}`;
    const logPath = join(staged.workDir, "browser.log");
    child = spawnBrowser(browser, { profile: staged.profile, logPath });
    if (!child.pid) throw new ResidueToolError(`the browser failed to start: ${browser.binary}`);
    meta.pid = child.pid;
    client = createPipeClient(child.stdio[3], child.stdio[4]);
    log(`residue-audit: browser pid ${child.pid}; log ${logPath}`);
    const page = await createPage(client, origin);
    await driveSession(page, secrets, async checkpoint => {
      if (checkpoint !== CHECKPOINTS[results.length]) throw new ResidueToolError("unexpected checkpoint order");
      const pids = options.browserProcessOnly ? [child.pid] : processTree({ pid: child.pid });
      const captured = await captureAll({ tool, pids, outDir, checkpoint, needles });
      const result = { name: checkpoint, ...captured };
      results.push(result);
      log(`residue-audit: ${checkpoint}: ${captured.entries.length} process(es), ${captured.hits.reduce((sum, hit) => sum + hit.count, 0)} hit(s)`);
      if (checkpoint === "before-input" && !cleanBaseline(result)) {
        throw new ResidueToolError("baseline is contaminated or incompletely captured; refusing to enter fixture data");
      }
    });
    const paths = writeReports({ outDir, meta, results });
    const assessment = assessRun(results);
    if (!assessment.valid) throw new ResidueToolError(`run INVALID: ${assessment.reasons.join("; ")}. See ${paths.mdPath}`);
    log(`residue-audit: controls passed; report ${paths.mdPath}. Uncalibrated needles prove nothing about erasure.`);
    return { tool, options, browser, outDir, checkpoints: results, ...paths };
  } catch (error) {
    writeReports({ outDir, meta: { ...meta, error: error.message }, results });
    throw error;
  } finally {
    await stopBrowser(child, client);
    client?.dispose();
    if (served) { try { served.server.close(); } catch { /* already closed */ } }
    // The browser log lives inside the work dir; failure messages point at it,
    // so keep a copy where the reports land (out/residue is gitignored).
    try {
      const logPath = join(staged.workDir, "browser.log");
      if (existsSync(logPath)) copyFileSync(logPath, join(outDir, "browser.log"));
    } catch { /* nothing to keep */ }
    // Windows can release profile file handles late; removeWorkDir retries.
    const leftover = await removeWorkDir(staged.workDir);
    if (leftover) log(`residue-audit: could not remove ${staged.workDir}: ${leftover.message}`);
  }
};

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  main().catch((error) => {
    if (error instanceof ResidueToolError) {
      console.error(`residue-audit: ${error.message}`);
      process.exit(2);
    }
    throw error;
  });
}
