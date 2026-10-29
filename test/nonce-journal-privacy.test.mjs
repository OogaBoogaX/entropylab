// Nonce runs never log r values or public keys: the Inspect Nonces journal
// entry carries only the kind, and the session snapshot holds no key material.
// Run with: npm run test:ci
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { loadAppFunctions } from "./app-slice-harness.mjs";

const root = dirname(fileURLToPath(import.meta.url));
const app = readFileSync(join(root, "..", "src/js/app.js"), "utf8");

test("the Inspect Nonces journal entry carries only the kind, never a nonce or key", async () => {
  const events = [];
  // The three globals are stubbed rather than set: their real declarations
  // would run their initializers at import and would be assigned to.
  const slice = await loadAppFunctions(["hodlJournalLog"], {
    stubs: {
      hodlJournal: {},
      hodlWorkspace: "psbt",
      hodlJournalTool: "session",
      hodlJournalAppend: (journal, event) => events.push(event),
      hodlJournalMarkDirty: () => {},
      hodlScheduleJournalStateRefresh: () => {},
      hodlRenderJournalLog: () => {},
    },
  });
  for (const kind of ["psbt", "transaction"]) slice.hodlJournalLog("inspect-nonces", kind, "psbt");
  assert.equal(events.length, 2);
  assert.deepEqual(events.map((event) => event.detail), ["psbt", "transaction"]);
  for (const event of events) {
    assert.ok(event.detail === "psbt" || event.detail === "transaction");
    assert.doesNotMatch(event.detail, /[0-9a-f]{64}/i);
  }
});

test("every nonce journal call passes a bare kind or literal, never key material", () => {
  const calls = [...app.matchAll(/hodlJournalLog\(\s*("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[^,)]*)\s*,\s*([^,)]*)/g)];
  let checked = 0;
  for (const call of calls) {
    if (!/nonce/i.test(call[1])) continue;
    checked++;
    const detail = call[2].trim();
    assert.ok(detail, `nonce journal call has no detail: ${call[0]}`);
    assert.match(detail, /^(?:[A-Za-z_$][\w$]*|"[^"]*"|'[^']*')$/, `nonce journal detail is not a bare identifier or literal: ${call[0]}`);
    assert.doesNotMatch(detail, /\.hex|\.r\b|pubkey|`/, `nonce journal detail may carry key material: ${call[0]}`);
  }
  assert.ok(checked > 0, "found the Inspect Nonces journal call");
});

test("the journal session snapshot's psbt part holds only the five non-secret fields", () => {
  const match = app.match(/let psbt = \{([\s\S]*?)\n  \};/);
  assert.ok(match, "found the snapshot's psbt object");
  const keys = [...match[1].matchAll(/^\s*(\w+):/gm)].map((key) => key[1]);
  assert.deepEqual(keys, ["loaded", "nonce", "nonceKind", "historyCount", "historyVerdict"]);
});

test("app.js never touches the console object", () => {
  // Any access counts, not a fixed list of methods: console.debug, .trace,
  // console["log"], console?.x, globalThis/window/self.console, and an alias
  // such as `const c = console`. The one prose mention (Bitcoin Core's
  // console, in on-screen help) is not code and matches none of these.
  const access = [
    /\bconsole\s*(?:\?\.|\.|\[)/,
    /\b(?:globalThis|window|self)\s*(?:\?\.|\.)\s*console\b/,
    /\b(?:globalThis|window|self)\s*\[\s*["'`]console["'`]\s*\]/,
    /[=,(:]\s*console\b(?!\s*\()/,
  ];
  for (const pattern of access) {
    const hit = app.match(pattern);
    assert.equal(hit, null, `app.js must not touch console: ${hit?.[0]}`);
  }
  // The patterns do catch real access (guards against a regex that matches nothing).
  for (const sample of ["console.debug(x)", "console.trace()", 'console["log"](x)', "console?.warn(x)", "window.console.log(x)", 'globalThis["console"]', "const c = console;"]) {
    assert.ok(access.some((pattern) => pattern.test(sample)), `pattern set misses: ${sample}`);
  }
});
