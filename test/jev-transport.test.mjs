// Tests for the verdict transport in test/adversarial/jev.mjs: which path
// answers (portlandhodl's jev-cli or the direct HTTP client), that the CLI is
// handed the key the harness actually resolved, and that every fallback is
// visible in the log without the key in it. The CLI and PowerShell are PATH
// stubs and fetch is stubbed, so nothing here touches the network or needs
// Rust. The stub CLI refuses to run without TYPESAFE_API_KEY, as jev-cli does.
// POSIX only (shebang stubs); skipped on Windows.
// Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

const skip = process.platform === "win32" ? "POSIX shebang stubs" : false;
const KEY = "tsk-test-0123456789abcdef";
const ANSWERS = { verdict: { type: "choice", choice: "ok", probabilities: { ok: 0.9 }, confidence: 0.9 } };

const stubDir = mkdtempSync(join(tmpdir(), "jev-transport-"));
const emptyDir = mkdtempSync(join(tmpdir(), "jev-transport-empty-"));
const record = join(stubDir, "record.json");
const stub = (name, body) => {
  const path = join(stubDir, name);
  writeFileSync(path, `#!/usr/bin/env node\n${body}\n`);
  chmodSync(path, 0o755);
};
stub(
  "jev-cli",
  `const fs = require("fs");
const args = process.argv.slice(2);
if (args.includes("--version")) { console.log("jev-cli 0.1.0"); process.exit(0); }
const key = process.env.TYPESAFE_API_KEY;
const doc = JSON.parse(fs.readFileSync(0, "utf8"));
fs.writeFileSync(${JSON.stringify(record)}, JSON.stringify({ args, key: key ?? null, doc }));
if (!key) { process.stderr.write("error: no API key: set TYPESAFE_API_KEY\\n"); process.exit(2); }
if (process.env.JEV_STUB_MODE === "fail") { process.stderr.write("error: API 401 for key " + key + "\\nmore detail\\n"); process.exit(2); }
console.log(JSON.stringify({ model: "jev-latest", answers: ${JSON.stringify(ANSWERS)}, usage: {} }, null, 2));`,
);
// The Windows User-scope lookup in getApiKey(), for a key absent from the
// process environment.
stub("powershell.exe", `console.log(${JSON.stringify(KEY)});`);

const nodeDir = dirname(process.execPath);
const saved = { PATH: process.env.PATH, TYPESAFE_API_KEY: process.env.TYPESAFE_API_KEY, JEV_STUB_MODE: process.env.JEV_STUB_MODE, fetch: globalThis.fetch, log: console.log };
let fresh = 0;

// Runs one jev() call in a fresh module instance (the transport and key are
// cached per module) and returns what happened.
const run = async ({ path, envKey, mode }) => {
  rmSync(record, { force: true });
  process.env.PATH = path;
  if (envKey) process.env.TYPESAFE_API_KEY = envKey;
  else delete process.env.TYPESAFE_API_KEY;
  if (mode) process.env.JEV_STUB_MODE = mode;
  else delete process.env.JEV_STUB_MODE;
  const fetches = [];
  globalThis.fetch = async (url, init) => {
    fetches.push({ url, auth: init.headers.Authorization });
    return { ok: true, json: async () => ({ answers: { via: "http" } }) };
  };
  const logs = [];
  console.log = (...parts) => logs.push(parts.join(" "));
  try {
    const { jev } = await import(`../test/adversarial/jev.mjs?case=${++fresh}`);
    const answers = await jev("state", { verdict: { type: "noul", instructions: "ok?" } });
    return { answers, fetches, logs, cli: existsSync(record) ? JSON.parse(readFileSync(record, "utf8")) : null };
  } finally {
    console.log = saved.log;
    globalThis.fetch = saved.fetch;
    for (const name of ["PATH", "TYPESAFE_API_KEY", "JEV_STUB_MODE"]) {
      if (saved[name] === undefined) delete process.env[name];
      else process.env[name] = saved[name];
    }
  }
};

test.after(() => {
  rmSync(stubDir, { recursive: true, force: true });
  rmSync(emptyDir, { recursive: true, force: true });
});

test("jev-cli answers when present, and says so", { skip }, async () => {
  const r = await run({ path: `${stubDir}:${nodeDir}`, envKey: KEY });
  assert.deepEqual(r.answers, ANSWERS);
  assert.equal(r.fetches.length, 0, "HTTP must not be used when the CLI answered");
  assert.deepEqual(r.cli.args, ["ask", "--format", "json", "-"]);
  assert.deepEqual(Object.keys(r.cli.doc).sort(), ["model", "questions", "state"], "jev-cli's ask rejects unknown top-level fields");
  assert.ok(r.logs.some((line) => /^Jev transport: jev-cli$/.test(line)), r.logs.join("\n"));
});

test("a key found only in the Windows User scope reaches jev-cli", { skip }, async () => {
  const r = await run({ path: `${stubDir}:${nodeDir}` });
  assert.equal(r.cli?.key, KEY, "the CLI must be handed the key getApiKey() resolved");
  assert.deepEqual(r.answers, ANSWERS);
  assert.equal(r.fetches.length, 0, "a silent HTTP fallback means the CLI never got the key");
});

test("a failing jev-cli falls back to HTTP visibly, without logging the key", { skip }, async () => {
  const r = await run({ path: `${stubDir}:${nodeDir}`, envKey: KEY, mode: "fail" });
  assert.deepEqual(r.answers, { via: "http" });
  assert.equal(r.fetches.length, 1);
  const line = r.logs.find((entry) => entry.includes("falling back to HTTP"));
  assert.ok(line, `the fallback must be logged:\n${r.logs.join("\n")}`);
  assert.match(line, /exited 2/);
  assert.match(line, /\[redacted\]/);
  assert.doesNotMatch(line, /more detail/, "only the first stderr line is logged");
  for (const entry of r.logs) assert.ok(!entry.includes(KEY), "the API key must never reach the log");
});

test("without jev-cli, HTTP answers and the log says so", { skip }, async () => {
  const r = await run({ path: emptyDir, envKey: KEY });
  assert.deepEqual(r.answers, { via: "http" });
  assert.equal(r.fetches.length, 1);
  assert.equal(r.fetches[0].auth, `Bearer ${KEY}`);
  assert.ok(r.logs.some((line) => /^Jev transport: HTTP \(jev-cli not found\)$/.test(line)), r.logs.join("\n"));
});
