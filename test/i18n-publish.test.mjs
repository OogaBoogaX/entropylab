// Job B against a stub GitHub API: the branch/PR/label/auto-merge call
// sequence is the automation's contract with the gate — if it drifts (wrong
// namespace, wrong files, no expected head SHA), the gate it feeds fails too.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { publishLanguage, BRANCH_PREFIX, TRANSLATION_LABEL } from "../scripts/i18n-publish.mjs";
import { hashSource } from "../scripts/i18n-validate.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const quiet = () => {};

// A tiny proposals directory: catalog of two keys plus its sidecar.
const proposals = (dir, catalog) => {
  mkdirSync(join(dir, ".sources"), { recursive: true });
  writeFileSync(join(dir, "es.json"), JSON.stringify(catalog, null, 2) + "\n");
  writeFileSync(join(dir, ".sources", "es.json"), JSON.stringify(Object.fromEntries(Object.keys(catalog).map((k) => [k, hashSource(k)])), null, 2) + "\n");
};

const CATALOG = { Save: "Guardar", Cancel: "Cancelar" };

// A stub GitHub API with scriptable state. Returns { server, calls, state }.
const stubGitHub = async ({ branchExists = false, prExists = false, contentsMatch = false } = {}) => {
  const calls = [];
  const state = { branchSha: "base0000", prNumber: 7, prNode: "PR_node_7", writes: [] };
  const b64 = (text) => Buffer.from(text, "utf8").toString("base64");
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", () => {
      const parsed = body ? JSON.parse(body) : undefined;
      calls.push({ method: req.method, url: req.url, body: parsed });
      const reply = (status, data) => res.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify(data));
      const url = req.url;
      if (url === "/repos/o/r/git/ref/heads/rock") return reply(200, { object: { sha: "base0000" } });
      if (url.startsWith("/repos/o/r/git/ref/heads/")) {
        return branchExists ? reply(200, { object: { sha: state.branchSha } }) : reply(404, { message: "Not Found" });
      }
      if (url === "/repos/o/r/git/refs" && req.method === "POST") {
        branchExists = true;
        return reply(201, { ref: parsed.ref });
      }
      if (url.startsWith("/repos/o/r/contents/") && req.method === "GET") {
        if (contentsMatch && url.includes("es.json") && !url.includes(".sources")) {
          return reply(200, { sha: "filesha", content: b64(JSON.stringify(CATALOG, null, 2) + "\n") });
        }
        return reply(404, { message: "Not Found" });
      }
      if (url.startsWith("/repos/o/r/contents/") && req.method === "PUT") {
        state.writes.push({ path: url.slice("/repos/o/r/contents/".length), content: Buffer.from(parsed.content, "base64").toString("utf8"), sha: parsed.sha ?? null });
        state.branchSha = `commit${state.writes.length}`;
        return reply(201, { commit: { sha: state.branchSha } });
      }
      if (url.startsWith("/repos/o/r/pulls?")) {
        return reply(200, prExists ? [{ number: state.prNumber, node_id: state.prNode }] : []);
      }
      if (url === "/repos/o/r/pulls" && req.method === "POST") return reply(201, { number: state.prNumber, node_id: state.prNode });
      if (url === `/repos/o/r/pulls/${state.prNumber}` && req.method === "PATCH") return reply(200, { number: state.prNumber, node_id: state.prNode });
      if (url === `/repos/o/r/labels/${TRANSLATION_LABEL}`) return reply(404, { message: "Not Found" });
      if (url === "/repos/o/r/labels" && req.method === "POST") return reply(201, { name: parsed.name });
      if (url === `/repos/o/r/issues/${state.prNumber}/labels` && req.method === "PUT") return reply(200, parsed.labels);
      if (url === "/repos/o/r" && req.method === "GET") return reply(200, { allow_squash_merge: true, allow_merge_commit: false, allow_rebase_merge: false });
      if (url === "/graphql") return reply(200, { data: { enablePullRequestAutoMerge: { pullRequest: { autoMergeRequest: { enabledAt: "now", mergeMethod: parsed.variables.method } } } } });
      return reply(404, { message: `unstubbed ${req.method} ${url}` });
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { server, calls, state, url: `http://127.0.0.1:${server.address().port}` };
};

const publish = (dir, apiUrl) =>
  publishLanguage({ dir, lang: "es", repoRoot: root, repo: "o/r", token: "tok", apiUrl, log: quiet });

test("fresh run: branch from rock tip, two file writes, PR opened, labelled, auto-merge on the exact head SHA", async () => {
  const dir = mkdtempSync(join(tmpdir(), "i18n-pub-"));
  const { server, calls, state, url } = await stubGitHub();
  try {
    proposals(dir, CATALOG);
    const summary = await publish(dir, url);
    assert.match(summary, /PR #7 .* auto-merge enabled \(squash\)/);

    const refCreate = calls.find((c) => c.method === "POST" && c.url === "/repos/o/r/git/refs");
    assert.deepEqual(refCreate.body, { ref: `refs/heads/${BRANCH_PREFIX}es`, sha: "base0000" });

    assert.deepEqual(
      state.writes.map((w) => w.path),
      ["src/locales/es.json", "src/locales/.sources/es.json"],
      "exactly the catalog and its sidecar are written",
    );
    assert.deepEqual(JSON.parse(state.writes[0].content), CATALOG);
    assert.deepEqual(JSON.parse(state.writes[1].content), { Save: hashSource("Save"), Cancel: hashSource("Cancel") });

    const prCreate = calls.find((c) => c.method === "POST" && c.url === "/repos/o/r/pulls");
    assert.equal(prCreate.body.head, `${BRANCH_PREFIX}es`);
    assert.equal(prCreate.body.base, "rock");
    assert.equal(prCreate.body.maintainer_can_modify, false);

    const labels = calls.find((c) => c.method === "PUT" && c.url.includes("/labels"));
    assert.deepEqual(labels.body, { labels: [TRANSLATION_LABEL] });

    const graphql = calls.find((c) => c.url === "/graphql");
    assert.match(graphql.body.query, /enablePullRequestAutoMerge/);
    assert.equal(graphql.body.variables.id, "PR_node_7");
    assert.equal(graphql.body.variables.sha, state.branchSha, "auto-merge binds the exact head SHA after the writes");
    assert.equal(graphql.body.variables.method, "SQUASH", "repo allows only squash in this stub");
  } finally {
    server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("rerun: existing branch and PR are updated, never duplicated", async () => {
  const dir = mkdtempSync(join(tmpdir(), "i18n-pub-"));
  const { server, calls, url } = await stubGitHub({ branchExists: true, prExists: true });
  try {
    proposals(dir, CATALOG);
    await publish(dir, url);
    assert.ok(!calls.some((c) => c.method === "POST" && c.url === "/repos/o/r/git/refs"), "no second branch");
    assert.ok(!calls.some((c) => c.method === "POST" && c.url === "/repos/o/r/pulls"), "no second PR");
    assert.ok(calls.some((c) => c.method === "PATCH" && c.url === "/repos/o/r/pulls/7"), "existing PR updated");
  } finally {
    server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("an identical proposal is a no-op with zero writes", async () => {
  const dir = mkdtempSync(join(tmpdir(), "i18n-pub-"));
  const { server, calls, url } = await stubGitHub();
  try {
    // Proposal equals the committed es catalog (repoRoot is the real tree):
    const committed = JSON.parse(readFileSync(join(root, "src/locales/es.json"), "utf8"));
    proposals(dir, committed);
    const summary = await publish(dir, url);
    assert.match(summary, /nothing to publish/);
    assert.equal(calls.length, 0, "no API traffic at all");
  } finally {
    server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a hostile proposal is rejected before any API call", async () => {
  const dir = mkdtempSync(join(tmpdir(), "i18n-pub-"));
  const { server, calls, url } = await stubGitHub();
  try {
    proposals(dir, { "Save {seed}": "Guardar sin placeholder" }); // dropped placeholder
    await assert.rejects(() => publish(dir, url), /failed validation/);
    assert.equal(calls.length, 0, "validation happens before the network");
  } finally {
    server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a proposal whose sidecar disagrees with its catalog is rejected", async () => {
  const dir = mkdtempSync(join(tmpdir(), "i18n-pub-"));
  const { server, calls, url } = await stubGitHub();
  try {
    proposals(dir, CATALOG);
    const sidecar = JSON.parse(readFileSync(join(dir, ".sources", "es.json"), "utf8"));
    sidecar.Save = "0".repeat(64); // well-formed but wrong hash
    writeFileSync(join(dir, ".sources", "es.json"), JSON.stringify(sidecar, null, 2) + "\n");
    await assert.rejects(() => publish(dir, url), /failed validation/);
    assert.equal(calls.length, 0);
  } finally {
    server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

