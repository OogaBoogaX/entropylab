// Job A of the translation workflow, with the LLM behind a stub: the schema
// contract, the audit drop path, the validator's arrival check, and the
// sidecar bookkeeping are all deterministic and must hold on every run.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, existsSync, cpSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { CONTEXT_PATH, chat, contextProblems, languageWorkload, loadContext, translateLanguage, translationSchema } from "../scripts/i18n-translate.mjs";
import { collectSources } from "../scripts/i18n-sources.mjs";
import { contentProblems, gateProblems } from "../scripts/i18n-gate.mjs";
import { hashSource, sidecarProblems, catalogProblems, valueProblems } from "../scripts/i18n-validate.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const quiet = () => {};

const tmp = () => mkdtempSync(join(tmpdir(), "i18n-translate-"));

// A stub chat client: translates every requested key by appending a marker
// (placeholders and markup survive byte-for-byte, so the values validate) and
// audits every pair ok unless told otherwise. Records every call.
const stubClient = ({ failKeys = [], auditFail = [] } = {}) => {
  const calls = [];
  return {
    calls,
    async chat(request) {
      calls.push(request);
      if (request.name === "translate") {
        const keys = request.messages[1] ? JSON.parse(request.messages[1].content).strings : [];
        return { translations: keys.filter((k) => !failKeys.includes(k)).map((k) => ({ key: k, translation: `${k} [translated]` })) };
      }
      if (request.name === "audit") {
        const pairs = JSON.parse(request.messages[1].content).pairs;
        return { verdicts: pairs.map(({ key }) => ({ key, ok: !auditFail.includes(key), problem: auditFail.includes(key) ? "dropped negation" : "" })) };
      }
      throw new Error(`unexpected call ${request.name}`);
    },
  };
};

// The committed catalog can be nearly complete. These tests need a known
// number of missing keys, so they punch holes in a copy instead of assuming
// the live Spanish file still has a backlog.
const gappedRoot = async (gaps) => {
  const dir = tmp();
  mkdirSync(join(dir, "src/locales/.sources"), { recursive: true });
  // Copy the extraction inputs so Windows does not need symlink privileges.
  cpSync(join(root, "src/js"), join(dir, "src/js"), { recursive: true });
  cpSync(join(root, "src/shell.html"), join(dir, "src/shell.html"));
  cpSync(join(root, "src/index.html"), join(dir, "src/index.html"));
  writeFileSync(join(dir, "package.json"), '{"type":"module"}');
  const { sources, catalog } = await languageWorkload(root, "es");
  const removable = Object.keys(catalog).filter((key) => sources.has(key));
  assert.ok(removable.length >= gaps, "need translated keys to punch out");
  const next = { ...catalog };
  const punched = removable.slice(0, gaps);
  for (const key of punched) delete next[key];
  writeFileSync(join(dir, "src/locales/es.json"), JSON.stringify(next, null, 2) + "\n");
  const sidecarPath = join(root, "src/locales/.sources/es.json");
  if (existsSync(sidecarPath)) {
    const sidecar = JSON.parse(readFileSync(sidecarPath, "utf8"));
    for (const key of punched) delete sidecar[key];
    writeFileSync(join(dir, "src/locales/.sources/es.json"), JSON.stringify(sidecar, null, 2) + "\n");
  }
  return dir;
};

test("the workload derives from the same extraction as the sync check", async () => {
  const { sources, catalog, keep, stale, dead, missing } = await languageWorkload(root, "es");
  // The committed es catalog is partial by design; the invariants that must
  // hold regardless of how many keys are missing or awaiting post-merge
  // dead-key pruning after an English UI change:
  // Most of the committed catalog still matches live source text. A share
  // rather than a fixed count: an English UI pass retires real entries, and the
  // post-merge translation run refills them, so a hard floor fails on honest
  // copy changes while saying nothing about the extraction being sound.
  assert.ok(Object.keys(keep).length > Object.keys(catalog).length * 0.8, "most committed entries survive");
  assert.ok(Object.keys(keep).every((key) => sources.has(key)), "kept entries come from the shared source extraction");
  assert.equal(Object.keys(keep).length + stale.length + dead, Object.keys(catalog).length, "every committed entry is retained, pinned for retranslation (scripts/i18n-context.json), or queued for dead-key pruning");
  for (const key of stale) assert.ok(missing.includes(key), "a pinned entry is translated again");
  for (const key of missing) assert.equal(typeof key, "string");
});

test("translation requests are schema-constrained to exactly the requested keys", async () => {
  const outDir = tmp();
  const tree = await gappedRoot(5);
  try {
    const client = stubClient();
    await translateLanguage({ root: tree, lang: "es", outDir, client, limit: 5, log: quiet });
    const translateCall = client.calls.find((c) => c.name === "translate");
    assert.equal(translateCall.schema.additionalProperties, false);
    assert.deepEqual(translateCall.schema.required, ["translations"]);
    const item = translateCall.schema.properties.translations.items;
    assert.deepEqual(item.required, ["key", "translation"]);
    assert.equal(item.additionalProperties, false);
    // Key coverage is enforced on arrival, not by property names: providers
    // escape string fields correctly, and quoted keys no longer break JSON.
    const requested = JSON.parse(translateCall.messages[1].content).strings;
    assert.equal(requested.length, 5);
    const auditCall = client.calls.find((c) => c.name === "audit");
    assert.equal(auditCall.schema.additionalProperties, false);
  } finally {
    rmSync(outDir, { recursive: true, force: true });
    rmSync(tree, { recursive: true, force: true });
  }
});

test("translated catalogs and sidecars are written consistently; audit-flagged keys stay missing", async () => {
  const outDir = tmp();
  const tree = await gappedRoot(5);
  try {
    const { missing } = await languageWorkload(tree, "es", 4);
    assert.ok(missing.length >= 4, "fixture needs at least 4 missing keys");
    const flagged = missing[1];
    const client = stubClient({ auditFail: [flagged] });
    const report = await translateLanguage({ root: tree, lang: "es", outDir, client, limit: 4, log: quiet });

    assert.equal(report.requested, 4);
    assert.equal(report.translated, 3);
    assert.equal(report.stillMissing, 1);
    assert.ok(report.dropped.some((d) => d.key === flagged && d.problem.includes("semantic audit")));
    assert.equal(report.changed, true);

    const catalog = JSON.parse(readFileSync(join(outDir, "es.json"), "utf8"));
    const sidecar = JSON.parse(readFileSync(join(outDir, ".sources", "es.json"), "utf8"));
    assert.ok(!(flagged in catalog), "flagged key never reaches the proposal");
    for (const key of missing.filter((k) => k !== flagged)) {
      assert.equal(catalog[key], `${key} [translated]`);
    }
    // The proposal validates clean — catalog content and sidecar together.
    assert.deepEqual(catalogProblems(catalog), []);
    assert.deepEqual(sidecarProblems(catalog, sidecar), { invalid: [], drift: [] });
    for (const key of Object.keys(catalog)) assert.equal(sidecar[key], hashSource(key));
  } finally {
    rmSync(outDir, { recursive: true, force: true });
    rmSync(tree, { recursive: true, force: true });
  }
});

test("validator-rejected values are dropped on arrival, never audited or written", async () => {
  const outDir = tmp();
  const tree = await gappedRoot(3);
  try {
    // Corrupt every translation with an invented placeholder: valueProblems
    // rejects them before the audit call.
    const calls = [];
    const client = {
      calls,
      async chat(request) {
        calls.push(request);
        const keys = JSON.parse(request.messages[1].content).strings;
        return { translations: keys.map((k) => ({ key: k, translation: `${k} {bogus}` })) };
      },
    };
    const report = await translateLanguage({ root: tree, lang: "es", outDir, client, limit: 3, log: quiet });
    assert.equal(report.translated, 0);
    assert.equal(report.dropped.length, 3);
    assert.ok(report.dropped.every((d) => d.problem.includes("placeholders")));
    assert.ok(!calls.some((c) => c.name === "audit"), "no audit call when nothing survived validation");
    // Only dead-key pruning / sidecar repair can remain; with a clean es
    // catalog there is nothing to publish.
    assert.equal(existsSync(join(outDir, "es.json")), report.changed);
  } finally {
    rmSync(outDir, { recursive: true, force: true });
    rmSync(tree, { recursive: true, force: true });
  }
});

test("a missing model response key is dropped, not invented", async () => {
  const outDir = tmp();
  const tree = await gappedRoot(2);
  try {
    const client = {
      async chat(request) {
        if (request.name === "translate") return { translations: [] }; // model returned nothing usable
        return { verdicts: [] };
      },
    };
    const report = await translateLanguage({ root: tree, lang: "es", outDir, client, limit: 2, log: quiet });
    assert.equal(report.translated, 0);
    assert.equal(report.dropped.length, 2);
  } finally {
    rmSync(outDir, { recursive: true, force: true });
    rmSync(tree, { recursive: true, force: true });
  }
});

// --- committed per-string context (issue #862) ------------------------------

const writeContext = (tree, context) => {
  mkdirSync(join(tree, "scripts"), { recursive: true });
  writeFileSync(join(tree, CONTEXT_PATH), JSON.stringify(context, null, 2) + "\n");
};
// The first live es entry short enough to sit in the glossary, so the tests
// can see a pinned value leave it. Taken before any context file exists.
const glossaryEntry = async (tree) => {
  const { keep, sources } = await languageWorkload(tree, "es");
  const [key, value] = Object.entries(keep).find(([k, v]) => k.length <= 80 && v.length <= 80);
  return { key, value, live: Object.keys(JSON.parse(readFileSync(join(tree, "src/locales/es.json"), "utf8"))).filter((k) => sources.has(k)) };
};

test("the committed context file names current English strings, known languages and well-formed fields", async () => {
  const context = loadContext(root);
  assert.deepEqual(contextProblems(context, await collectSources(root)), []);
  for (const [key, entry] of Object.entries(context)) {
    for (const [lang, terms] of Object.entries(entry.mustContain ?? {})) {
      // A required term must survive the validator, so it can never carry
      // markup or a placeholder.
      for (const term of terms) assert.ok(!/[<>{}]/.test(term), `${key} ${lang}: ${term}`);
    }
    for (const [lang, exact] of Object.entries(entry.exact ?? {})) {
      // An exact correction must be committable as it stands, and must
      // differ from the value it replaces.
      assert.deepEqual(valueProblems(key, exact), [], `${key} ${lang}`);
      assert.notEqual(exact, entry.retranslate?.[lang], `${key} ${lang}: the correction changes something`);
    }
  }
});

test("a malformed context file fails the run and writes nothing", async () => {
  const outDir = tmp();
  const tree = await gappedRoot(1);
  try {
    assert.deepEqual(contextProblems([], null), ["the context file must be a JSON object"]);
    const bad = {
      "no such string": { note: "x" },
      "Output public key": { note: "", retranslate: { xx: "y" }, mustContain: { es: [] }, exact: { de: 7 }, notes: "typo" },
    };
    const problems = contextProblems(bad, await collectSources(root));
    for (const expected of ["is not a current English source string", "note must be non-empty text", "unknown language \"xx\"", "mustContain.es has the wrong shape", "exact.de has the wrong shape", "unknown field \"notes\""]) {
      assert.ok(problems.some((problem) => problem.includes(expected)), expected);
    }
    writeContext(tree, { "Output public key": { retranslate: ["de"] } });
    await assert.rejects(translateLanguage({ root: tree, lang: "es", outDir, client: stubClient(), log: quiet }), /i18n-context\.json is malformed/);
    assert.equal(existsSync(join(outDir, "es.json")), false);
  } finally {
    rmSync(outDir, { recursive: true, force: true });
    rmSync(tree, { recursive: true, force: true });
  }
});

test("without a context file, the translate request is unchanged", async () => {
  const outDir = tmp();
  const tree = await gappedRoot(1);
  try {
    const client = stubClient();
    await translateLanguage({ root: tree, lang: "es", outDir, client, limit: 1, log: quiet });
    const translateCall = client.calls.find((c) => c.name === "translate");
    assert.deepEqual(Object.keys(JSON.parse(translateCall.messages[1].content)), ["glossary", "strings"]);
    assert.doesNotMatch(translateCall.messages[0].content, /notes/);
    const auditCall = client.calls.find((c) => c.name === "audit");
    assert.ok(JSON.parse(auditCall.messages[1].content).pairs.every((pair) => !("note" in pair)));
  } finally {
    rmSync(outDir, { recursive: true, force: true });
    rmSync(tree, { recursive: true, force: true });
  }
});

test("a pinned value is retranslated in place with its note, then goes quiet", async () => {
  const outDir = tmp();
  const tree = await gappedRoot(0);
  try {
    const { key, value, live } = await glossaryEntry(tree);
    writeContext(tree, { [key]: { note: "Context for every language.", noteByLanguage: { es: "Spanish only.", de: "German only." }, retranslate: { es: value, de: "not this" } } });
    const client = stubClient();
    const report = await translateLanguage({ root: tree, lang: "es", outDir, client, log: quiet });
    assert.equal(report.stale, 1);

    const translateCall = client.calls.find((c) => c.name === "translate" && JSON.parse(c.messages[1].content).strings.includes(key));
    const request = JSON.parse(translateCall.messages[1].content);
    assert.deepEqual(request.notes, { [key]: "Context for every language. Spanish only." });
    assert.ok(!(key in request.glossary), "the pinned value is not offered back as terminology");
    assert.match(translateCall.messages[0].content, /"notes"/);
    const auditCall = client.calls.find((c) => c.name === "audit" && JSON.parse(c.messages[1].content).pairs.some((pair) => pair.key === key));
    const pair = JSON.parse(auditCall.messages[1].content).pairs.find((p) => p.key === key);
    assert.equal(pair.note, "Context for every language. Spanish only.");
    assert.match(auditCall.messages[0].content, /"note"/);

    // The replacement takes the old value's place among the live entries;
    // nothing else moves.
    const catalog = JSON.parse(readFileSync(join(outDir, "es.json"), "utf8"));
    assert.equal(catalog[key], `${key} [translated]`);
    assert.deepEqual(Object.keys(catalog).slice(0, live.length), live);
    assert.deepEqual(catalogProblems(catalog), []);
    const sidecar = JSON.parse(readFileSync(join(outDir, ".sources", "es.json"), "utf8"));
    assert.deepEqual(sidecarProblems(catalog, sidecar), { invalid: [], drift: [] });

    // Once the replacement is committed the pin no longer matches: the next
    // run leaves the string alone.
    cpSync(join(outDir, "es.json"), join(tree, "src/locales/es.json"));
    cpSync(join(outDir, ".sources", "es.json"), join(tree, "src/locales/.sources/es.json"));
    const next = await languageWorkload(tree, "es");
    assert.deepEqual(next.stale, []);
    assert.ok(!next.missing.includes(key));
  } finally {
    rmSync(outDir, { recursive: true, force: true });
    rmSync(tree, { recursive: true, force: true });
  }
});

test("a value-only correction becomes a catalog-only diff that the translation gate accepts", async () => {
  const outDir = tmp();
  const tree = await gappedRoot(0);
  try {
    // A UI change can add English strings that rock's catalogs do not hold
    // yet; the next run would translate those too and move the sidecar. It can
    // also retire a string, which the post-merge run prunes. Give this tree's
    // es catalog every source and no dead entry, so the correction is all it
    // does.
    const { missing, sources } = await languageWorkload(tree, "es");
    const catalog = JSON.parse(readFileSync(join(tree, "src/locales/es.json"), "utf8"));
    const sidecar = JSON.parse(readFileSync(join(tree, "src/locales/.sources/es.json"), "utf8"));
    let normalized = false;
    for (const source of missing) {
      catalog[source] = source;
      sidecar[source] = hashSource(source);
      normalized = true;
    }
    for (const key of Object.keys(catalog)) {
      if (sources.has(key)) continue;
      delete catalog[key];
      delete sidecar[key];
      normalized = true;
    }
    if (normalized) {
      writeFileSync(join(tree, "src/locales/es.json"), JSON.stringify(catalog, null, 2) + "\n");
      writeFileSync(join(tree, "src/locales/.sources/es.json"), JSON.stringify(sidecar, null, 2) + "\n");
    }
    const { key, value } = await glossaryEntry(tree);
    writeContext(tree, { [key]: { retranslate: { es: value } } });
    const report = await translateLanguage({ root: tree, lang: "es", outDir, client: stubClient(), log: quiet });
    assert.equal(report.translated, 1);
    // The files a pull request of this proposal would change, as git sees
    // them: a byte difference against the committed tree.
    const changedFiles = [
      ["es.json", "src/locales/es.json"],
      [".sources/es.json", "src/locales/.sources/es.json"],
    ]
      .filter(([proposal, committed]) => !readFileSync(join(outDir, proposal)).equals(readFileSync(join(tree, committed))))
      .map(([, committed]) => committed);
    assert.deepEqual(changedFiles, ["src/locales/es.json"], "the key-hash sidecar does not move");
    const slug = "entropylab-translate";
    assert.deepEqual(gateProblems({ author: `${slug}[bot]`, appSlug: slug, baseRef: "rock", headRef: "i18n/translate-es", changedFiles }), []);
    cpSync(join(outDir, "es.json"), join(tree, "src/locales/es.json"));
    assert.deepEqual(contentProblems(tree, "es"), [], "the unchanged sidecar still validates the corrected catalog");
  } finally {
    rmSync(outDir, { recursive: true, force: true });
    rmSync(tree, { recursive: true, force: true });
  }
});

// The es catalog a run would publish: its proposal if it wrote one, else the
// committed catalog unchanged.
const resultCatalog = (outDir, tree) => JSON.parse(readFileSync(existsSync(join(outDir, "es.json")) ? join(outDir, "es.json") : join(tree, "src/locales/es.json"), "utf8"));

test("a retranslation without a required term or its exact wording is dropped, and the committed value stays", async () => {
  for (const [label, field, problem] of [
    ["mustContain", { mustContain: { es: ["Término exacto"] } }, 'context: must contain "Término exacto"'],
    ["exact", { exact: { es: "Una frase exacta" } }, "context: must be exactly the committed correction"],
  ]) {
    const outDir = tmp();
    const tree = await gappedRoot(0);
    try {
      const { key, value } = await glossaryEntry(tree);
      writeContext(tree, { [key]: { retranslate: { es: value }, ...field } });
      const client = stubClient();
      const report = await translateLanguage({ root: tree, lang: "es", outDir, client, log: quiet });
      assert.ok(report.dropped.some((d) => d.key === key && d.problem === problem), label);
      const audited = client.calls.filter((c) => c.name === "audit").flatMap((c) => JSON.parse(c.messages[1].content).pairs.map((p) => p.key));
      assert.ok(!audited.includes(key), `${label}: a rejected value never reaches the audit`);
      // A failed correction changes nothing a reader sees; the pin still
      // matches, so the next run tries again.
      assert.equal(resultCatalog(outDir, tree)[key], value, label);
      if (existsSync(join(outDir, "es.json"))) cpSync(join(outDir, "es.json"), join(tree, "src/locales/es.json"));
      assert.deepEqual((await languageWorkload(tree, "es")).stale, [key], label);
    } finally {
      rmSync(outDir, { recursive: true, force: true });
      rmSync(tree, { recursive: true, force: true });
    }
  }
});

test("a retranslation that matches its exact wording is written", async () => {
  const outDir = tmp();
  const tree = await gappedRoot(0);
  try {
    const { key, value } = await glossaryEntry(tree);
    writeContext(tree, { [key]: { retranslate: { es: value }, exact: { es: `${key} [translated]` } } });
    const report = await translateLanguage({ root: tree, lang: "es", outDir, client: stubClient(), log: quiet });
    assert.equal(report.dropped.length, 0);
    assert.equal(resultCatalog(outDir, tree)[key], `${key} [translated]`);
  } finally {
    rmSync(outDir, { recursive: true, force: true });
    rmSync(tree, { recursive: true, force: true });
  }
});

test("an arrival equal to its exact correction lands even when the audit rejects it", async () => {
  // The audit has rejected reviewed corrections as different from the
  // identical text they had to equal (#918 es, #958 pt). An exact value is
  // the committed, reviewed text, so it skips the audit; every other arrival
  // in the same batch is still audited.
  const outDir = tmp();
  const tree = await gappedRoot(1);
  try {
    const { key, value } = await glossaryEntry(tree);
    writeContext(tree, { [key]: { retranslate: { es: value }, exact: { es: `${key} [translated]` } } });
    const { missing } = await languageWorkload(tree, "es");
    const unpinned = missing.find((k) => k !== key);
    assert.ok(unpinned, "the gapped tree has an unpinned missing key");
    const client = stubClient({ auditFail: [key, unpinned] });
    const report = await translateLanguage({ root: tree, lang: "es", outDir, client, log: quiet });
    const catalog = resultCatalog(outDir, tree);
    assert.equal(catalog[key], `${key} [translated]`, "the reviewed correction is written");
    assert.equal(catalog[unpinned], undefined, "an audit-rejected unpinned key stays missing");
    assert.ok(report.dropped.some((d) => d.key === unpinned && /semantic audit/.test(d.problem)), "the unpinned key is dropped by the audit");
    assert.ok(!report.dropped.some((d) => d.key === key), "the exact value is not dropped");
    const audited = client.calls.filter((c) => c.name === "audit").flatMap((c) => JSON.parse(c.messages[1].content).pairs.map((p) => p.key));
    assert.ok(!audited.includes(key), "the exact value is not sent to the audit");
    assert.ok(audited.includes(unpinned), "the unpinned value still is");
  } finally {
    rmSync(outDir, { recursive: true, force: true });
    rmSync(tree, { recursive: true, force: true });
  }
});

test("chat(): wire format carries the strict JSON schema and bearer auth, and retries 5xx once", async () => {
  const seen = [];
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", () => {
      seen.push({ auth: req.headers.authorization, body: JSON.parse(body) });
      if (seen.length === 1) {
        res.writeHead(500).end("boom");
        return;
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ choices: [{ message: { content: JSON.stringify({ ok: true }) } }] }));
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const url = `http://127.0.0.1:${server.address().port}/v1/chat/completions`;
    const schema = translationSchema(["Save", "Cancel"]);
    const out = await chat({ url, key: "sk-test", model: "m/test", name: "translate", schema, messages: [{ role: "user", content: "x" }] });
    assert.deepEqual(out, { ok: true });
    assert.equal(seen.length, 2, "one retry after the 500");
    const sent = seen[1];
    assert.equal(sent.auth, "Bearer sk-test");
    assert.equal(sent.body.model, "m/test");
    assert.equal(sent.body.temperature, 0);
    assert.equal(sent.body.response_format.type, "json_schema");
    assert.equal(sent.body.response_format.json_schema.strict, true);
    assert.equal(sent.body.response_format.json_schema.schema.additionalProperties, false);
    assert.deepEqual(sent.body.response_format.json_schema.schema.required, ["translations"]);
    assert.deepEqual(sent.body.response_format.json_schema.schema.properties.translations.items.required, ["key", "translation"]);
  } finally {
    server.close();
  }
});

test("chat(): a non-retryable 4xx fails immediately", async () => {
  const server = createServer((req, res) => res.writeHead(401).end("unauthorized"));
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const url = `http://127.0.0.1:${server.address().port}/`;
    await assert.rejects(() => chat({ url, key: "k", model: "m", name: "t", schema: translationSchema(["a"]), messages: [] }), /HTTP 401/);
  } finally {
    server.close();
  }
});

// The real chat(): fence-wrapped JSON parses, and a truncated response is
// retried rather than failing the whole language on a transient.
const stubFetch = (bodies) => {
  const calls = [];
  return [calls, async (url, init) => {
    calls.push(init.body);
    const body = bodies[Math.min(calls.length - 1, bodies.length - 1)];
    return { ok: true, status: 200, json: async () => ({ choices: [{ message: { content: body } }] }) };
  }];
};

test("chat strips markdown fences and retries a truncated response", async () => {
  const realFetch = globalThis.fetch;
  try {
    const [calls, fenced] = stubFetch(["```json\n{\"a\": 1}\n```"]);
    globalThis.fetch = fenced;
    assert.deepEqual(await chat({ url: "https://x", key: "k", model: "m", name: "n", schema: {}, messages: [] }), { a: 1 });

    const [retryCalls, truncThenGood] = stubFetch(["{\"a\": ", "{\"a\": 2}"]);
    globalThis.fetch = truncThenGood;
    assert.deepEqual(await chat({ url: "https://x", key: "k", model: "m", name: "n", schema: {}, messages: [] }), { a: 2 });
    assert.equal(retryCalls.length, 2, "a truncated response was not retried");

    const [garbageCalls, garbage] = stubFetch(["not json at all"]);
    globalThis.fetch = garbage;
    await assert.rejects(() => chat({ url: "https://x", key: "k", model: "m", name: "n", schema: {}, messages: [] }));
    assert.equal(garbageCalls.length, 2, "persistent garbage was not attempted exactly twice");
  } finally {
    globalThis.fetch = realFetch;
  }
});

test("chat(): an empty response retries like a truncated one", async () => {
  const realFetch = globalThis.fetch;
  try {
    const calls = [];
    globalThis.fetch = async () => {
      calls.push(1);
      // First call: no message content at all (provider cut the stream).
      // Second: a good payload.
      return { ok: true, status: 200, json: async () => (calls.length === 1
        ? { choices: [{ message: {} }] }
        : { choices: [{ message: { content: "{\"ok\": true}" } }] }) };
    };
    assert.deepEqual(await chat({ url: "https://x", key: "k", model: "m", name: "n", schema: {}, messages: [] }), { ok: true });
    assert.equal(calls.length, 2, "an empty response was not retried");
  } finally {
    globalThis.fetch = realFetch;
  }
});
