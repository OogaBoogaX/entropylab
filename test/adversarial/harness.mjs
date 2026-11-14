// harness.mjs — Jev adversarial browser-testing harness for entropylab.
// Launches ONE headless Chrome and runs every scenario in its own isolated
// tab, in parallel by default (--serial disables). Records console errors,
// uncaught exceptions, unhandled rejections, and wrapped-network attempts,
// then asks Jev (TypeSafe System One) for an ok/suspect/broken verdict and
// prints a table. Zero npm dependencies — native WebSocket + fetch.
import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SCENARIOS, HELPER } from "./scenarios.mjs";
import { verdict, jevAvailable } from "./jev.mjs";
import { judgeFailures, judgeWarnings, runFailures } from "./outcome.mjs";

// The app under test: the built page at the repo root, resolved relative to
// this file so the harness works in any checkout (override with --app=<path>).
import { fileURLToPath } from "node:url";
const REPO_ROOT = join(fileURLToPath(import.meta.url), "..", "..", "..");
const PAGE_URL = "file:///" + join(REPO_ROOT, "entropylab.html").replace(/\\/g, "/");
// Binary resolution mirrors test/browser.test.mjs's chrome engine entry:
// CHROME/CHROME_BINARY/CHROMIUM_BINARY env vars first (the CI workflow sets
// CHROME=google-chrome), then common names on PATH, then the usual platform
// install locations. Windows-only paths here previously meant the scheduled
// CI job — which runs on ubuntu-latest — could never find a browser at all.
const CHROME_ENV_VARS = ["CHROME", "CHROME_BINARY", "CHROMIUM_BINARY"];
const CHROME_PATH_NAMES = ["google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome", "headless_shell"];
const CHROME_EXTRA_PATHS = {
  darwin: ["/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", "/Applications/Chromium.app/Contents/MacOS/Chromium"],
  win32: [
    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
  ],
  linux: ["/usr/bin/google-chrome", "/usr/bin/google-chrome-stable", "/usr/bin/chromium", "/usr/local/bin/chromium", "/snap/bin/chromium"],
};
const resolveChromeBinary = () => {
  for (const name of CHROME_ENV_VARS) {
    if (process.env[name]) return process.env[name];
  }
  for (const bin of CHROME_PATH_NAMES) {
    try {
      if (spawnSync(bin, ["--version"], { stdio: "pipe" }).status === 0) return bin;
    } catch {}
  }
  for (const p of CHROME_EXTRA_PATHS[process.platform] ?? []) {
    if (existsSync(p)) return p;
  }
  return null;
};
const TAP_SCRIPT = `
  (() => {
    window.__TAP = { net: [], errors: [], rejections: [] };
    const cap = 64;
    const recNet = (kind, what) => {
      if (window.__TAP.net.length < cap)
        window.__TAP.net.push({ kind, url: String(what).slice(0, 200) });
    };
    addEventListener("error", (e) => {
      if (window.__TAP.errors.length < cap)
        window.__TAP.errors.push(String(e.message || e.error || "").slice(0, 200));
    });
    addEventListener("unhandledrejection", (e) => {
      if (window.__TAP.rejections.length < cap)
        window.__TAP.rejections.push(String(e.reason || "").slice(0, 200));
    });
    if (typeof fetch === "function") {
      const orig = fetch.bind(window);
      window.fetch = (...a) => { recNet("fetch", a[0] ? (a[0].url ?? a[0]) : ""); return orig(...a); };
    }
    const origOpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function (m, u, ...rest) {
      recNet("xhr", m + " " + u);
      return origOpen.call(this, m, u, ...rest);
    };
    if (navigator.sendBeacon) {
      const origBeacon = navigator.sendBeacon.bind(navigator);
      navigator.sendBeacon = (u, d) => { recNet("sendBeacon", u); return origBeacon(u, d); };
    }
    if (window.WebSocket) {
      const OrigWS = WebSocket;
      window.WebSocket = function (u, p) { recNet("WebSocket", u); return new OrigWS(u, p); };
      window.WebSocket.prototype = OrigWS.prototype;
    }
    if (window.EventSource) {
      const OrigES = EventSource;
      window.EventSource = function (u, o) { recNet("EventSource", u); return new OrigES(u, o); };
      window.EventSource.prototype = OrigES.prototype;
    }
  })();
`;

const TAP_SNAPSHOT = `
  (() => {
    const t = window.__TAP || { net: [], errors: [], rejections: [] };
    return JSON.stringify({
      net: t.net, errors: t.errors, rejections: t.rejections,
      alive: !!document.body, title: document.title || "",
      delivery: window.__DELIVERY || [],
    });
  })()
`;

// ---------- minimal CDP client over native WebSocket ----------
class CDP {
  #nextId = 0;
  #pending = new Map();
  #listeners = [];
  constructor(ws) {
    this.ws = ws;
    ws.addEventListener("message", (ev) => {
      let msg;
      try { msg = JSON.parse(ev.data); } catch { return; }
      if (msg.id != null) {
        const p = this.#pending.get(msg.id);
        if (p) {
          this.#pending.delete(msg.id);
          if (msg.error) p.reject(new Error(`${msg.error.message} (${msg.error.code})`));
          else p.resolve(msg.result);
        }
      } else if (msg.method) {
        for (const l of this.#listeners) l(msg);
      }
    });
  }
  send(method, params = {}, sessionId) {
    const id = ++this.#nextId;
    const msg = { id, method, params };
    if (sessionId) msg.sessionId = sessionId;
    return new Promise((resolve, reject) => {
      this.#pending.set(id, { resolve, reject });
      this.ws.send(JSON.stringify(msg));
    });
  }
  onEvent(fn) { this.#listeners.push(fn); }
  waitFor(method, sessionId, predicate, timeoutMs) {
    return new Promise((resolve) => {
      const timer = setTimeout(() => { this.off(fn); resolve(null); }, timeoutMs);
      const fn = (msg) => {
        if (msg.method !== method) return;
        if (sessionId && msg.sessionId !== sessionId) return;
        if (predicate && !predicate(msg.params)) return;
        clearTimeout(timer);
        this.off(fn);
        resolve(msg.params);
      };
      this.onEvent(fn);
    });
  }
  off(fn) { this.#listeners = this.#listeners.filter((l) => l !== fn); }
}

const launchChrome = () => {
  const binary = resolveChromeBinary();
  if (!binary) {
    throw new Error(
      "No Chrome/Chromium binary found. Install one or set CHROME, CHROME_BINARY, or CHROMIUM_BINARY."
    );
  }
  const profile = mkdtempSync(join(tmpdir(), "jev-adversarial-"));
  // --remote-debugging-port=0: read the picked port from DevToolsActivePort.
  const proc = spawn(binary, [
    "--headless=new",
    // CI runners (and any containerized Linux) have no user namespaces and a
    // tiny /dev/shm; Chrome refuses to start without these.
    "--no-sandbox",
    "--disable-dev-shm-usage",
    "--remote-debugging-port=0",
    `--user-data-dir=${profile}`,
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-gpu",
  ], { stdio: "ignore" });
  return { proc, profile, binary };
};

const readDebugPort = async (profile, timeoutMs = 15000) => {
  const file = join(profile, "DevToolsActivePort");
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (existsSync(file)) {
      const port = parseInt(readFileSync(file, "utf8").split("\n")[0], 10);
      if (port > 0) return port;
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error("DevToolsActivePort never appeared");
};

const connect = async (endpoint) => {
  const ws = new WebSocket(endpoint);
  await new Promise((res, rej) => {
    ws.addEventListener("open", res);
    ws.addEventListener("error", rej);
  });
  return new CDP(ws);
};

const evaluate = (cdp, sessionId, expr, timeoutMs = 30000) => {
  const p = cdp.send("Runtime.evaluate", {
    expression: expr,
    returnByValue: true,
    awaitPromise: true,
  }, sessionId);
  return Promise.race([
    p,
    new Promise((_, rej) => setTimeout(() => rej(new Error(`evaluate timeout (script start: ${expr.slice(0, 80)})`)), timeoutMs)),
  ]);
};

const runScenario = async (cdp, scenario, onEvent) => {
  const log = {
    name: scenario.name,
    description: scenario.description || "",
    actions: [],
    consoleErrors: [],
    exceptions: [],
    rejections: [],
    network: [],
    invariantFailures: [],
    contractChecks: [],
    delivery: [],
    alive: null,
    title: "",
  };
  let { targetId } = await cdp.send("Target.createTarget", {
    url: "about:blank", newWindow: false,
  });
  const { sessionId } = await cdp.send("Target.attachToTarget", {
    targetId, flatten: true,
  });

  const collector = (msg) => {
    if (msg.sessionId !== sessionId) return;
    if (msg.method === "Runtime.consoleAPICalled" && msg.params.type === "error") {
      log.consoleErrors.push(
        (msg.params.args || []).map((a) => a.value ?? a.description ?? "").join(" ").slice(0, 200),
      );
    } else if (msg.method === "Runtime.exceptionThrown") {
      const d = msg.params.exceptionDetails;
      log.exceptions.push((d.exception?.description || d.text || "").slice(0, 200));
    } else if (msg.method === "Log.entryAdded") {
      const e = msg.params.entry;
      if (e.level === "error") log.consoleErrors.push(`[${e.source}] ${e.text}`.slice(0, 200));
    }
  };
  cdp.onEvent(collector);

  try {
    await cdp.send("Page.enable", {}, sessionId);
    await cdp.send("Runtime.enable", {}, sessionId);
    await cdp.send("Log.enable", {}, sessionId);
    await cdp.send("Page.addScriptToEvaluateOnNewDocument", { source: TAP_SCRIPT }, sessionId);

    const loaded = cdp.waitFor("Page.loadEventFired", sessionId, null, 20000);
    await cdp.send("Page.navigate", { url: APP_URL }, sessionId);
    if (!(await loaded)) log.invariantFailures.push("load event never fired (page hang?)");
    await evaluate(cdp, sessionId, "new Promise(r => setTimeout(r, 400))");

    for (const action of scenario.actions) {
      try {
        const expr = `(() => {\n${HELPER}\nreturn ${action};\n})()`;
        const res = await evaluate(cdp, sessionId, expr);
        if (res.exceptionDetails) log.actions.push("EXCEPTION: " + (res.exceptionDetails.exception?.description || res.exceptionDetails.text).slice(0, 160));
        else log.actions.push(String(res.result?.value ?? res.result?.description ?? ""));
      } catch (e) {
        log.actions.push("HARNESS: " + String(e.message || e).slice(0, 160));
      }
    }

    // In-page invariant assertions
    try {
      // The parentheses are load-bearing: every assert in scenarios.mjs is a
      // multi-line template literal that starts with a newline, so
      // `return ${...}` put the newline straight after `return` and automatic
      // semicolon insertion turned the whole hook into `return;` followed by
      // dead code. Failures were silently discarded for every scenario.
      const res = await evaluate(cdp, sessionId, `(() => {\n${HELPER}\nreturn (${scenario.assert});\n})()`);
      const out = res.result?.value ?? {};
      // A throw inside the page resolves the CDP call with exceptionDetails
      // rather than rejecting it, and a hook that returns no failures array
      // is not a passing hook — it is one that never ran. Both used to read
      // as a clean scenario.
      if (res.exceptionDetails) {
        log.invariantFailures.push(
          "assert hook threw: " + String(res.exceptionDetails.exception?.description || res.exceptionDetails.text).slice(0, 160),
        );
      } else if (Array.isArray(out.failures)) {
        log.invariantFailures.push(...out.failures);
        // Positive evidence: a scenario may report the contract checks it
        // PASSED, so a clean run shows proof, not just the absence of smoke.
        if (Array.isArray(out.passed)) log.contractChecks.push(...out.passed);
      } else {
        log.invariantFailures.push("assert hook returned no failures array (did it run?)");
      }
    } catch (e) {
      log.invariantFailures.push("assert hook failed to run: " + String(e.message || e).slice(0, 120));
    }

    // Common invariants from the tap
    try {
      const raw = await evaluate(cdp, sessionId, TAP_SNAPSHOT);
      const snap = JSON.parse(raw.result?.value ?? "{}");
      log.network = snap.net || [];
      log.rejections = snap.rejections || [];
      log.exceptions.push(...(snap.errors || []).filter((e) => !log.exceptions.includes(e)));
      log.alive = !!snap.alive;
      log.title = snap.title || "";
      if (snap.net?.length) log.invariantFailures.push(`network attempts: ${snap.net.length}`);
      // A scenario that never delivered its payload proved nothing about the
      // app: a stale selector reads as a clean run otherwise. Partial
      // filtering is the app's prerogative (the dice field keeps digits);
      // only a payload that landed nowhere is a failure.
      log.delivery = snap.delivery || [];
      for (const d of log.delivery) {
        if (d.sent > 0 && d.landed === 0) {
          log.invariantFailures.push(
            `payload never landed in ${d.label} (sent ${d.sent} chars, field holds 0) — scenario did not exercise its target`,
          );
        }
      }
    } catch (e) {
      log.invariantFailures.push("tap snapshot failed: " + String(e.message || e).slice(0, 120));
    }
  } finally {
    cdp.off(collector);
    await cdp.send("Target.closeTarget", { targetId }).catch(() => {});
  }
  return log;
};

// ---------- main ----------
const args = process.argv.slice(2);
const SERIAL = args.includes("--serial");
const ONLY = args.find((a) => a.startsWith("--scenario="))?.split("=")[1];
const APP_OVERRIDE = args.find((a) => a.startsWith("--app="))?.split("=")[1];
const APP_URL = APP_OVERRIDE ? (APP_OVERRIDE.startsWith("file:") ? APP_OVERRIDE : "file:///" + APP_OVERRIDE.replace(/\\/g, "/")) : PAGE_URL;

if (!jevAvailable()) {
  console.log("WARNING: TYPESAFE_API_KEY not found (process env or User scope). Verdicts will be skipped.");
}

let picked = SCENARIOS;
if (ONLY) {
  picked = SCENARIOS.filter((s) => s.name === ONLY || s.name.includes(ONLY));
  if (!picked.length) {
    console.log(`No scenario matches "${ONLY}". Available:`);
    for (const s of SCENARIOS) console.log("  " + s.name);
    process.exit(1);
  }
}

console.log(`Launching headless Chrome, ${picked.length} scenario(s), mode=${SERIAL ? "serial" : "parallel"}`);
const { proc, profile, binary } = launchChrome();
const port = await readDebugPort(profile);
let version;
try {
  version = await (await fetch(`http://127.0.0.1:${port}/json/version`)).json();
} catch {
  await new Promise((r) => setTimeout(r, 500));
  version = await (await fetch(`http://127.0.0.1:${port}/json/version`)).json();
}
const cdp = await connect(version.webSocketDebuggerUrl);
console.log(`Connected: ${version.Browser} via ${binary}`);

const started = Date.now();
let logs;
if (SERIAL) {
  logs = [];
  for (const s of picked) logs.push(await runScenario(cdp, s));
} else {
  logs = await Promise.all(picked.map((s) => runScenario(cdp, s)));
}

// Jev verdicts (serially to keep ordering deterministic)
const rows = [];
for (const log of logs) {
  let answers = null;
  try { answers = await verdict(log); } catch (e) { answers = { error: String(e) }; }
  const choice = answers?.verdict?.choice ?? "(none)";
  const severity = answers?.severity?.score != null ? Math.round(answers.severity.score * 100) / 100 : "-";
  const networkNoul = answers?.network_egress?.noul != null ? Math.round(answers.network_egress.noul * 100) / 100 : "-";
  const hangNoul = answers?.hang_or_freeze?.noul != null ? Math.round(answers.hang_or_freeze.noul * 100) / 100 : "-";
  rows.push({
    name: log.name,
    choice,
    severity,
    net: log.network.length,
    exceptions: log.exceptions.length,
    rejections: log.rejections.length,
    inv: log.invariantFailures.length,
    alive: log.alive,
    netq: networkNoul,
    hangq: hangNoul,
    actions: log.actions,
    failures: log.invariantFailures,
    answers,
  });
}

// The verdict table is Markdown: it pastes cleanly into chat, issues, and PR
// bodies, which is where people actually read these results.
const col = (s) => String(s).replace(/\|/g, "\\|");
console.log("\n=== Jev adversarial verdict table (took " + ((Date.now() - started) / 1000).toFixed(1) + "s) ===");
console.log("| scenario | verdict | sev | excp | rej | net | inv | net? | hang? |");
console.log("|---|---|---|---|---|---|---|---|---|");
for (const r of rows) {
  console.log(
    `| ${col(r.name)} | ${col(r.choice)} | ${col(r.severity)} | ${col(r.exceptions)} | ${col(r.rejections)} | ${col(r.net)} | ${col(r.inv)} | ${col(r.netq)} | ${col(r.hangq)} |`
  );
}
for (const r of rows) {
  if (r.failures.length) {
    console.log(`\n${r.name} invariant failures:`);
    for (const f of r.failures) console.log("  - " + f);
  }
  console.log(`\n${r.name} action log:`);
  for (const a of r.actions) console.log("  · " + a);
}

// The rubric asks Jev to cite the specific log line behind a suspect or
// broken verdict, but the table only carries the bare label — a column of
// "suspect" with no stated reason is not actionable. Dump the whole answer
// object for every non-ok verdict rather than reaching for a named field,
// so whatever justification the API returns is visible verbatim.
for (const r of rows) {
  if (!r.answers || r.choice === "ok") continue;
  let detail;
  try { detail = JSON.stringify(r.answers, null, 2); } catch { detail = String(r.answers); }
  console.log(`\n${r.name} Jev detail (verdict=${r.choice}):`);
  console.log(detail.length > 2000 ? detail.slice(0, 2000) + "\n  …truncated" : detail);
}

// Local verdict if Jev unavailable
if (!jevAvailable()) {
  for (const r of rows) {
    const local = r.net + r.exceptions + r.rejections + r.inv ? "would be broken locally" : "clean locally";
    console.log(`${r.name}: ${local}`);
  }
}

// The table is for reading; this is the run's result, and the exit status
// the workflow reports (see outcome.mjs for what fails it).
for (const warning of judgeWarnings(rows, jevAvailable())) {
  console.log(`\nWARNING: ${warning}`);
  // An annotation too, so the gap shows on the run page, not only in the log.
  if (process.env.GITHUB_ACTIONS) console.log(`::warning title=Jev verdicts missing::${warning}`);
}
const failed = [...runFailures(rows), ...judgeFailures(rows, jevAvailable())];
if (failed.length) {
  console.log(`\nRun FAILED, ${failed.length} reason(s):`);
  for (const failure of failed) console.log("  - " + failure);
} else {
  console.log("\nRun passed: no network attempts, exceptions, failed checks or broken verdicts.");
}

cdp.ws.close();
proc.kill();
setTimeout(() => {
  try { rmSync(profile, { recursive: true, force: true }); } catch {}
  process.exit(failed.length ? 1 : 0);
}, 500);
