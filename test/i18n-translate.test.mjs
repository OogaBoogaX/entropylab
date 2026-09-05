// Job A of the translation workflow, with the LLM behind a stub: the schema
// contract, the audit drop path, the validator's arrival check, and the
// sidecar bookkeeping are all deterministic and must hold on every run.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtempSync, readFileSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { chat, languageWorkload, translateLanguage, translationSchema } from "../scripts/i18n-translate.mjs";
import { hashSource, sidecarProblems, catalogProblems } from "../scripts/i18n-validate.mjs";

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
        const keys = request.schema.required;
        return Object.fromEntries(keys.filter((k) => !failKeys.includes(k)).map((k) => [k, `${k} [translated]`]));
      }
      if (request.name === "audit") {
        const pairs = JSON.parse(request.messages[1].content).pairs;
        return { verdicts: pairs.map(({ key }) => ({ key, ok: !auditFail.includes(key), problem: auditFail.includes(key) ? "dropped negation" : "" })) };
      }
      throw new Error(`unexpected call ${request.name}`);
    },
  };
};

test("the workload derives from the same extraction as the sync check", async () => {
  const { keep, dead, missing } = await languageWorkload(root, "es");
  // The committed es catalog is partial by design; the invariants that must
  // hold regardless of how many keys are missing today:
  assert.ok(Object.keys(keep).length > 800, "committed entries survive");
  assert.equal(dead, 0, "sync --write keeps dead keys pruned");
  for (const key of missing) assert.equal(typeof key, "string");
});

test("translation requests are schema-constrained to exactly the requested keys", async () => {
  const outDir = tmp();
  try {
    const client = stubClient();
    await translateLanguage({ root, lang: "es", outDir, client, limit: 5, log: quiet });
    const translateCall = client.calls.find((c) => c.name === "translate");
    assert.equal(translateCall.schema.additionalProperties, false);
    assert.equal(translateCall.schema.required.length, 5);
    for (const key of translateCall.schema.required) {
      assert.deepEqual(translateCall.schema.properties[key], { type: "string" });
    }
    const auditCall = client.calls.find((c) => c.name === "audit");
    assert.equal(auditCall.schema.additionalProperties, false);
  } finally {
    rmSync(outDir, { recursive: true, force: true });
  }
});

test("translated catalogs and sidecars are written consistently; audit-flagged keys stay missing", async () => {
  const outDir = tmp();
  try {
    const { missing } = await languageWorkload(root, "es", 4);
    assert.ok(missing.length >= 4, "fixture needs at least 4 missing keys");
    const flagged = missing[1];
    const client = stubClient({ auditFail: [flagged] });
    const report = await translateLanguage({ root, lang: "es", outDir, client, limit: 4, log: quiet });

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
  }
});

test("validator-rejected values are dropped on arrival, never audited or written", async () => {
  const outDir = tmp();
  try {
    // Corrupt every translation with an invented placeholder: valueProblems
    // rejects them before the audit call.
    const calls = [];
    const client = {
      calls,
      async chat(request) {
        calls.push(request);
        return Object.fromEntries(request.schema.required.map((k) => [k, `${k} {bogus}`]));
      },
    };
    const report = await translateLanguage({ root, lang: "es", outDir, client, limit: 3, log: quiet });
    assert.equal(report.translated, 0);
    assert.equal(report.dropped.length, 3);
    assert.ok(report.dropped.every((d) => d.problem.includes("placeholders")));
    assert.ok(!calls.some((c) => c.name === "audit"), "no audit call when nothing survived validation");
    // Only dead-key pruning / sidecar repair can remain; with a clean es
    // catalog there is nothing to publish.
    assert.equal(existsSync(join(outDir, "es.json")), report.changed);
  } finally {
    rmSync(outDir, { recursive: true, force: true });
  }
});

test("a missing model response key is dropped, not invented", async () => {
  const outDir = tmp();
  try {
    const client = {
      async chat(request) {
        if (request.name === "translate") return {}; // model returned nothing usable
        return { verdicts: [] };
      },
    };
    const report = await translateLanguage({ root, lang: "es", outDir, client, limit: 2, log: quiet });
    assert.equal(report.translated, 0);
    assert.equal(report.dropped.length, 2);
  } finally {
    rmSync(outDir, { recursive: true, force: true });
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
    assert.deepEqual(sent.body.response_format.json_schema.schema.required, ["Save", "Cancel"]);
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

