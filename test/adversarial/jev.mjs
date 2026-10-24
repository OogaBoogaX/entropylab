// jev.mjs — minimal Jev (TypeSafe System One) client.
// The request/response shape mirrors entropylab-scratch/triage-issues.ps1
// verbatim: POST { state, model: "jev-latest", questions } to
// https://api.typesafe.ai/v1/systemone with a Bearer token, and read
// `response.answers` where each question resolves to one of
// { noul | choice | score }. The API key is never printed or logged.
import { spawnSync } from "node:child_process";

const JEV_URL = "https://api.typesafe.ai/v1/systemone";
const DEFAULT_MODEL = "jev-latest";
let cachedKey = null;

const getApiKey = () => {
  if (process.env.TYPESAFE_API_KEY) return process.env.TYPESAFE_API_KEY;
  if (cachedKey) return cachedKey;
  // Windows User-scoped env fallback, same as triage-issues.ps1.
  try {
    const out = spawnSync(
      "powershell.exe",
      [
        "-NoProfile",
        "-Command",
        "[Environment]::GetEnvironmentVariable('TYPESAFE_API_KEY','User')",
      ],
      { encoding: "utf8" },
    ).stdout.trim();
    if (out) cachedKey = out;
  } catch {}
  return cachedKey;
};

export const jevAvailable = () => !!getApiKey();

// Prefer portlandhodl's jev-cli when it's available — native on PATH, or
// via WSL on Windows hosts whose Rust toolchain lives there (this project's
// build host). Falls back to the direct HTTP client below. Probed once.
let cliTransport;
const detectCli = () => {
  if (cliTransport !== undefined) return cliTransport;
  const probe = (cmd) => {
    try {
      return spawnSync(cmd[0], [...cmd.slice(1), "--version"], {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      }).status === 0;
    } catch {
      return false;
    }
  };
  if (probe(["jev-cli"])) cliTransport = ["jev-cli"];
  else if (probe(["wsl", "-d", "Ubuntu", "--", "jev-cli"])) cliTransport = ["wsl", "-d", "Ubuntu", "--", "jev-cli"];
  else cliTransport = null;
  // Say which transport answers, once: a silent fallback here would leave
  // the log unable to tell a CLI run from an HTTP one.
  console.log(`Jev transport: ${cliTransport ? cliTransport.join(" ") : "HTTP (jev-cli not found)"}`);
  return cliTransport;
};

// The CLI's `ask` reads the whole request document on stdin and answers with
// the same { answers } shape as the direct API. It is handed the key
// getApiKey() resolved, which may have come from the Windows User scope and
// so be absent from process.env. WSL needs WSLENV to carry it across; any
// existing WSLENV entries are kept. Undefined => caller falls back, and every
// fallback is logged with the CLI's exit status and first stderr line (the
// key redacted), since a CLI that fails and an absent one otherwise look
// identical in the verdict table. Note a fallback after an API-side error
// sends the request a second time.
const askViaCli = (doc, key) => {
  const cmd = detectCli();
  if (!cmd) return undefined;
  const isWsl = cmd[0] === "wsl";
  const env = { ...process.env, TYPESAFE_API_KEY: key };
  if (isWsl) env.WSLENV = [process.env.WSLENV, "TYPESAFE_API_KEY"].filter(Boolean).join(":");
  const r = spawnSync(cmd[0], [...cmd.slice(1), "ask", "--format", "json", "-"], {
    input: JSON.stringify(doc),
    encoding: "utf8",
    maxBuffer: 32 * 1024 * 1024,
    stdio: ["pipe", "pipe", "pipe"],
    env,
  });
  const fallBack = (why) => {
    const detail = safe(String(r.stderr ?? "").split(key).join("[redacted]").split("\n")[0], 200);
    console.log(`Jev transport: jev-cli ${why}; falling back to HTTP${detail ? ` (${detail})` : ""}`);
    return undefined;
  };
  if (r.status !== 0) return fallBack(r.error ? `failed to run (${r.error.code ?? r.error.message})` : `exited ${r.status}`);
  try {
    const answers = JSON.parse(r.stdout).answers;
    return answers ?? fallBack("returned no answers");
  } catch {
    return fallBack("returned unparseable output");
  }
};

// Ask Jev a set of questions about `state`. Returns `answers` or null
// when no API key is configured. Throws on HTTP/API errors.
export const jev = async (state, questions) => {
  const key = getApiKey();
  if (!key) return null;
  const doc = { state, model: DEFAULT_MODEL, questions };
  const viaCli = askViaCli(doc, key);
  if (viaCli !== undefined) return viaCli;
  // Encode to UTF-8 bytes explicitly, same as the ps1 script.
  const utf8Body = Buffer.from(JSON.stringify(doc), "utf8");
  const res = await fetch(JEV_URL, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${key}`,
      "Content-Type": "application/json; charset=utf-8",
    },
    body: utf8Body,
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`Jev HTTP ${res.status}: ${text.slice(0, 300)}`);
  }
  const json = await res.json();
  return json.answers ?? null;
};

// Truncate to ASCII-ish characters, like Get-SafeTruncated in the ps1,
// so hostile page content cannot corrupt the wire payload.
const safe = (s, max = 1200) => {
  if (!s) return "";
  let out = "";
  for (const ch of String(s)) {
    const code = ch.codePointAt(0);
    if ((code >= 32 && code <= 126) || (code >= 160 && code <= 255)) {
      out += ch;
      if (out.length >= max) break;
    }
  }
  return out;
};

// verdict(runLog): given one scenario's compact run log, ask Jev whether
// the run is ok / suspect / broken and why. Only question types used by
// the ps1 script (noul, choice, score).
export const verdict = (runLog) => {
  const state = [
    `Scenario: ${runLog.name}`,
    `Intent (the contract this scenario checks — judge against this, not against generic expectations): ${runLog.description || "(unspecified)"}`,
    `Console errors: ${runLog.consoleErrors.length}`,
    `Uncaught exceptions: ${runLog.exceptions.length}`,
    `Unhandled rejections: ${runLog.rejections.length}`,
    `Network attempts (fetch/xhr/beacon/ws/es): ${runLog.network.length}`,
    `Invariant failures: ${runLog.invariantFailures.join("; ") || "none"}`,
    `Contract checks passed (positive evidence the app behaved per its contract): ${(runLog.contractChecks || []).join("; ") || "none reported"}`,
    `Actions: ${safe(runLog.actions.join(" | "), 600)}`,
    `Console errors: ${safe(runLog.consoleErrors.join(" | "), 400)}`,
    `Exceptions: ${safe(runLog.exceptions.join(" | "), 400)}`,
    `Network attempts: ${safe(
      runLog.network.map((n) => n.kind + ":" + n.url).join(" | "),
      400,
    )}`,
    `Page title: ${safe(runLog.title, 120)} | alive: ${runLog.alive}`,
  ].join("\n");

  return jev(state, {
    verdict: {
      type: "choice",
      instructions:
        "Did the app under test (an offline key-material tool that must NEVER network and must handle hostile input without crashing) survive this scenario? 'ok' = handled the input and reported an error through its own UI, 'suspect' = warning signs not provably bad, 'broken' = exception, hang, network egress, or an invariant violation.",
      criteria: {
        ok: "Input handled; errors surfaced through the app's own error UI; no exceptions, no network, page alive. Input size or weirdness ALONE is never a verdict against the app — only observable misbehavior counts",
        suspect:
          "Observable behavior that deviates from the app's contract but lacks a definitive failure signal (e.g. an error shown in a place a user would not look for it, a state that silently resets, a slowdown that outlives the input). Cite the specific log line as the reason",
        broken:
          "Exception/rejection, hang or unresponsive page, network egress attempt, invariant violation, or loss of user input without an error message. Cite the evidence",
      },
    },
    severity: {
      type: "score",
      instructions:
        "How severe is the observed behavior for an offline key-material tool?",
      criteria: [
        "none - fully clean run",
        "low - cosmetic or robustness nit",
        "medium - robustness problem worth fixing",
        "high - stability or security concern",
      ],
    },
    network_egress: {
      type: "noul",
      instructions:
        "Does the log show the page attempting network egress (fetch/XHR/sendBeacon/WebSocket/EventSource)? The app must never network.",
    },
    hang_or_freeze: {
      type: "noul",
      instructions:
        "Does the log show the page hanging, freezing, or failing to respond after the hostile input?",
    },
  });
};
