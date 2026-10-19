// Job B against a stub GitHub API: the branch/PR/label/auto-merge call
// sequence is the automation's contract with the gate — if it drifts (wrong
// namespace, wrong files, no expected head SHA), the gate it feeds fails too.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createServer } from "node:http";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { githubRequest, publishLanguage, BRANCH_PREFIX, TRANSLATION_LABEL } from "../scripts/i18n-publish.mjs";
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

// The stub's tree id: a digest of the base tree and the files written on it,
// so two requests for the same files on the same base get the same tree, as
// they do on GitHub.
const treeSha = ({ base_tree, tree }) =>
  `tree-${createHash("sha256").update(JSON.stringify([base_tree, [...tree].sort((a, b) => a.path.localeCompare(b.path)).map((entry) => [entry.path, entry.mode, entry.type, entry.content])])).digest("hex").slice(0, 12)}`;

// A stub GitHub API with scriptable state. Returns { server, calls, state }.
// rock sits at rockSha on tree "rocktree". An existing automation branch sits
// at branchSha, on a commit whose tree and parents are scriptable: a branch
// cut from an older rock, or one already holding a proposal on current rock.
// rockFiles is what rock's tree already holds, by path. notFoundPage names the
// lookups ("branch", "label") that answer with a 404 page instead of
// GitHub's JSON "Not Found".
const stubGitHub = async ({ branchExists = false, prExists = false, cleanStatus = false, rockSha = "base0000", branchSha = "stale000", branchTree = "oldtree", branchParents = ["older000"], rockFiles = {}, notFoundPage = [] } = {}) => {
  const calls = [];
  const state = { rockSha, branchSha, prNumber: 7, prNode: "PR_node_7", writes: [], trees: [], commits: { [rockSha]: { tree: "rocktree", parents: ["older000"] } } };
  if (branchExists) state.commits[branchSha] = { tree: branchTree, parents: branchParents };
  const branchRef = `/repos/o/r/git/refs/heads/${encodeURIComponent(`${BRANCH_PREFIX}es`)}`;
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", () => {
      const parsed = body ? JSON.parse(body) : undefined;
      calls.push({ method: req.method, url: req.url, body: parsed });
      const reply = (status, data) => res.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify(data));
      const page404 = () => res.writeHead(404, { "content-type": "text/html" }).end("<!DOCTYPE html>\n<html><body>Not Found</body></html>");
      const url = req.url;
      if (url === "/repos/o/r/git/ref/heads/rock") return reply(200, { object: { sha: state.rockSha } });
      if (url.startsWith("/repos/o/r/git/ref/heads/")) {
        if (notFoundPage.includes("branch")) return page404();
        return branchExists ? reply(200, { object: { sha: state.branchSha } }) : reply(404, { message: "Not Found" });
      }
      if (url.startsWith("/repos/o/r/git/commits/") && req.method === "GET") {
        const sha = url.slice("/repos/o/r/git/commits/".length);
        const commit = state.commits[sha];
        return commit ? reply(200, { sha, tree: { sha: commit.tree }, parents: commit.parents.map((parent) => ({ sha: parent })) }) : reply(404, { message: "Not Found" });
      }
      if (url === "/repos/o/r/git/trees" && req.method === "POST") {
        state.trees.push(parsed);
        for (const entry of parsed.tree) state.writes.push({ path: entry.path, content: entry.content, mode: entry.mode, type: entry.type });
        // Content-addressed, as on GitHub: writing exactly what rock's tree
        // already holds yields rock's own tree id.
        if (parsed.tree.every((entry) => rockFiles[entry.path] === entry.content)) return reply(201, { sha: parsed.base_tree });
        return reply(201, { sha: treeSha(parsed) });
      }
      if (url === "/repos/o/r/git/commits" && req.method === "POST") {
        const sha = `commit${Object.keys(state.commits).length}`;
        state.commits[sha] = { tree: parsed.tree, parents: parsed.parents, message: parsed.message };
        return reply(201, { sha });
      }
      if (url === "/repos/o/r/git/refs" && req.method === "POST") {
        branchExists = true;
        state.branchSha = parsed.sha;
        return reply(201, { ref: parsed.ref, object: { sha: parsed.sha } });
      }
      if (url === branchRef && req.method === "PATCH") {
        state.branchSha = parsed.sha;
        return reply(200, { object: { sha: parsed.sha } });
      }
      // The Contents API: one commit per file onto the branch's own tip.
      if (url.startsWith("/repos/o/r/contents/") && req.method === "GET") return reply(404, { message: "Not Found" });
      if (url.startsWith("/repos/o/r/contents/") && req.method === "PUT") {
        state.writes.push({ path: url.slice("/repos/o/r/contents/".length), content: Buffer.from(parsed.content, "base64").toString("utf8") });
        const sha = `commit${Object.keys(state.commits).length}`;
        state.commits[sha] = { tree: "contents-tree", parents: [state.branchSha] };
        state.branchSha = sha;
        return reply(201, { commit: { sha } });
      }
      if (url.startsWith("/repos/o/r/pulls?")) {
        return reply(200, prExists ? [{ number: state.prNumber, node_id: state.prNode }] : []);
      }
      if (url === "/repos/o/r/pulls" && req.method === "POST") return reply(201, { number: state.prNumber, node_id: state.prNode });
      if (url === `/repos/o/r/pulls/${state.prNumber}` && req.method === "PATCH") return reply(200, { number: state.prNumber, node_id: state.prNode });
      if (url === `/repos/o/r/labels/${TRANSLATION_LABEL}`) return notFoundPage.includes("label") ? page404() : reply(404, { message: "Not Found" });
      if (url === "/repos/o/r/labels" && req.method === "POST") return reply(201, { name: parsed.name });
      if (url === `/repos/o/r/issues/${state.prNumber}/labels` && req.method === "PUT") return reply(200, parsed.labels);
      if (url === "/repos/o/r" && req.method === "GET") return reply(200, { allow_squash_merge: true, allow_merge_commit: false, allow_rebase_merge: false });
      if (url === "/graphql" && cleanStatus) return reply(200, { errors: [{ message: "Pull request Pull request is in clean status" }] });
      if (url === "/graphql") return reply(200, { data: { enablePullRequestAutoMerge: { pullRequest: { autoMergeRequest: { enabledAt: "now", mergeMethod: parsed.variables.method } } } } });
      if (url === `/repos/o/r/pulls/${state.prNumber}/merge` && req.method === "PUT") return reply(200, { merged: true, sha: parsed.sha });
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

    // One commit whose only parent is rock's tip, on rock's tree plus the two
    // files; the new branch points at it.
    const refCreate = calls.find((c) => c.method === "POST" && c.url === "/repos/o/r/git/refs");
    assert.deepEqual(refCreate.body, { ref: `refs/heads/${BRANCH_PREFIX}es`, sha: state.branchSha });
    assert.deepEqual(state.commits[state.branchSha].parents, ["base0000"], "the branch is one commit on rock's tip");
    assert.equal(state.trees.length, 1);
    assert.equal(state.trees[0].base_tree, "rocktree", "the files are written on rock's own tree");
    assert.ok(state.trees[0].tree.every((entry) => entry.mode === "100644" && entry.type === "blob"), "plain file blobs");

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
    assert.match(prCreate.body.body, /Touches exactly `src\/locales\/es\.json` and `src\/locales\/\.sources\/es\.json`/);

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

test("a value-only refresh says its sidecar stays as is", async () => {
  // The committed tree already holds these keys and their sidecar; only a
  // value changes, as a scripts/i18n-context.json correction does (#862).
  const dir = mkdtempSync(join(tmpdir(), "i18n-pub-"));
  const repoRoot = mkdtempSync(join(tmpdir(), "i18n-pub-root-"));
  const { server, calls, url } = await stubGitHub();
  try {
    proposals(join(repoRoot, "src/locales"), CATALOG);
    proposals(dir, { ...CATALOG, Cancel: "Anular" });
    await publishLanguage({ dir, lang: "es", repoRoot, repo: "o/r", token: "tok", apiUrl: url, log: quiet });
    const prCreate = calls.find((c) => c.method === "POST" && c.url === "/repos/o/r/pulls");
    assert.match(prCreate.body.title, /\(\+0 −0 ~1\)$/);
    assert.match(prCreate.body.body, /Touches only `src\/locales\/es\.json`: its English keys are unchanged/);
  } finally {
    server.close();
    rmSync(dir, { recursive: true, force: true });
    rmSync(repoRoot, { recursive: true, force: true });
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
    assert.ok(calls.some((c) => c.method === "PATCH" && c.url === `/repos/o/r/git/refs/heads/${encodeURIComponent(`${BRANCH_PREFIX}es`)}`), "existing branch moved in place");
  } finally {
    server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

// Each run rebuilds the language's whole catalog from rock's committed copy,
// so the branch must sit on rock's current tip. Commits stacked on a branch
// cut from an older rock conflict with rock as soon as another translation
// merges there (#566, #568, #569 and #575 sat unmergeable that way).
test("rerun on a branch cut from an older rock: one commit on rock's current tip replaces it", async () => {
  const dir = mkdtempSync(join(tmpdir(), "i18n-pub-"));
  const { server, calls, state, url } = await stubGitHub({ branchExists: true, prExists: true, rockSha: "rock0002", branchSha: "stale000", branchTree: "oldtree", branchParents: ["base0000"] });
  try {
    proposals(dir, CATALOG);
    await publish(dir, url);
    const move = calls.find((c) => c.method === "PATCH" && c.url === `/repos/o/r/git/refs/heads/${encodeURIComponent(`${BRANCH_PREFIX}es`)}`);
    assert.ok(move, "the stale branch was never moved onto rock's current tip");
    assert.equal(move.body.force, true, "the move replaces the stale history");
    assert.deepEqual(state.commits[move.body.sha].parents, ["rock0002"], "one commit whose only parent is rock's current tip");
    assert.equal(state.trees.at(-1).base_tree, "rocktree", "written on rock's current tree");
    assert.deepEqual(state.trees.at(-1).tree.map((entry) => entry.path).sort(), ["src/locales/.sources/es.json", "src/locales/es.json"], "exactly the catalog and its sidecar");
    assert.ok(!calls.some((c) => c.method === "PUT" && c.url.startsWith("/repos/o/r/contents/")), "nothing is written onto the stale tip");
    const graphql = calls.find((c) => c.url === "/graphql");
    assert.equal(graphql.body.variables.sha, move.body.sha, "auto-merge binds the rebuilt head");
  } finally {
    server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("rerun with the same proposal already on rock's current tip leaves the branch alone", async () => {
  const dir = mkdtempSync(join(tmpdir(), "i18n-pub-"));
  proposals(dir, CATALOG);
  const file = (path) => readFileSync(join(dir, path), "utf8");
  const pending = treeSha({ base_tree: "rocktree", tree: [
    { path: "src/locales/es.json", mode: "100644", type: "blob", content: file("es.json") },
    { path: "src/locales/.sources/es.json", mode: "100644", type: "blob", content: file(".sources/es.json") },
  ] });
  const { server, calls, url } = await stubGitHub({ branchExists: true, prExists: true, rockSha: "rock0002", branchSha: "same0000", branchTree: pending, branchParents: ["rock0002"] });
  try {
    await publish(dir, url);
    assert.ok(!calls.some((c) => c.method === "POST" && c.url === "/repos/o/r/git/commits"), "no new commit");
    assert.ok(!calls.some((c) => c.url.startsWith("/repos/o/r/git/refs")), "the branch does not move");
    assert.ok(!calls.some((c) => c.method === "PUT" && c.url.startsWith("/repos/o/r/contents/")), "nothing written");
    const graphql = calls.find((c) => c.url === "/graphql");
    assert.equal(graphql.body.variables.sha, "same0000", "auto-merge binds the unchanged head");
  } finally {
    server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a proposal rock's tip already holds publishes nothing (the #902/#903 race)", async () => {
  // This run's checkout predates the merge of another run's PR for es, so
  // its committed-catalog check still sees a change; rock's live tip already
  // holds the files. With or without a branch left from that merged PR, no
  // commit, branch move, PR, label or auto-merge may follow.
  for (const branchExists of [false, true]) {
    const dir = mkdtempSync(join(tmpdir(), "i18n-pub-"));
    proposals(dir, CATALOG);
    const file = (path) => readFileSync(join(dir, path), "utf8");
    const rockFiles = { "src/locales/es.json": file("es.json"), "src/locales/.sources/es.json": file(".sources/es.json") };
    const { server, calls, url } = await stubGitHub({ branchExists, rockFiles });
    try {
      const summary = await publish(dir, url);
      assert.match(summary, /rock's tip already holds this proposal — nothing to publish/, `branch exists: ${branchExists}`);
      for (const [method, prefix] of [["POST", "/repos/o/r/git/commits"], ["POST", "/repos/o/r/git/refs"], ["PATCH", "/repos/o/r/git/refs"], ["POST", "/repos/o/r/pulls"], ["PATCH", "/repos/o/r/pulls"]]) {
        assert.ok(!calls.some((c) => c.method === method && c.url.startsWith(prefix)), `branch exists: ${branchExists}: no ${method} ${prefix}`);
      }
      assert.ok(!calls.some((c) => c.url === "/graphql" || c.url.includes("/labels")), `branch exists: ${branchExists}: no label, no auto-merge`);
    } finally {
      server.close();
      rmSync(dir, { recursive: true, force: true });
    }
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


test("an immediately mergeable PR merges directly when auto-merge has nothing to wait on", async () => {
  // With no required checks, GitHub refuses enablePullRequestAutoMerge with
  // "clean status" (run 36307213357 failed all four languages there). The
  // publisher must merge directly, pinned to the exact head SHA.
  const dir = mkdtempSync(join(tmpdir(), "i18n-pub-"));
  try {
    proposals(dir, { Save: "Guardar", Cancel: "Cancelar" });
    const { server, calls, state, url } = await stubGitHub({ cleanStatus: true });
    try {
      const summary = await publish(dir, url);
      assert.match(summary, /merged directly/);
      const merge = calls.find((call) => call.method === "PUT" && call.url === `/repos/o/r/pulls/${state.prNumber}/merge`);
      assert.ok(merge, "the PR was not merged directly");
      assert.equal(merge.body.sha, state.branchSha, "the direct merge binds the exact head SHA");
      assert.equal(merge.body.merge_method, "squash");
    } finally {
      server.close();
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a GitHub error page is reported with its status and call, not as a JSON parse error", async () => {
  // Run 39066081254 (fr) failed with only "Unexpected token '<'": GitHub had
  // answered with an HTML page, and the body was parsed before the status
  // was read.
  const replies = {
    "/html-502": [502, "text/html", "<!DOCTYPE html>\n<html><body>Unicorn!</body></html>"],
    "/html-200": [200, "text/html", "<!DOCTYPE html>\n<html></html>"],
    "/json-422": [422, "application/json", JSON.stringify({ message: "Reference already exists" })],
    "/json-200": [200, "application/json", JSON.stringify({ ok: true })],
  };
  const server = createServer((req, res) => {
    const [status, type, body] = replies[req.url];
    res.writeHead(status, { "content-type": type }).end(body);
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const apiUrl = `http://127.0.0.1:${server.address().port}`;
  const request = (path) => githubRequest({ apiUrl, token: "tok", method: "GET", path });
  try {
    await assert.rejects(request("/html-502"), (error) => {
      assert.equal(error.message, "GitHub GET /html-502 → HTTP 502: a non-JSON response (an HTML page)");
      assert.equal(error.status, 502);
      return true;
    });
    await assert.rejects(request("/html-200"), { message: "GitHub GET /html-200 → HTTP 200: a non-JSON response (an HTML page)" });
    await assert.rejects(request("/json-422"), { message: "GitHub GET /json-422 → HTTP 422: Reference already exists" });
    assert.deepEqual(await request("/json-200"), { ok: true });
  } finally {
    server.close();
  }
});

test("a 404 page that is not GitHub's JSON stops the publish; it never reads as a missing branch or label", async () => {
  // GitHub's API says "Not Found" in JSON, and only that means "not there
  // yet". Reading a 404 page from anything in between as absence would cut a
  // new branch and open a pull request (branch lookup), or create the label
  // (label lookup), on a failed response.
  for (const [lookup, forbidden] of [
    ["branch", ["POST /repos/o/r/git/commits", "POST /repos/o/r/git/refs", "PATCH /repos/o/r/git/refs/", "POST /repos/o/r/pulls"]],
    ["label", ["POST /repos/o/r/labels", "PUT /repos/o/r/issues/", "POST /graphql"]],
  ]) {
    const dir = mkdtempSync(join(tmpdir(), "i18n-pub-"));
    const { server, calls, url } = await stubGitHub({ notFoundPage: [lookup] });
    try {
      proposals(dir, CATALOG);
      await assert.rejects(() => publish(dir, url), /→ HTTP 404: a non-JSON response \(an HTML page\)$/, `${lookup}: a 404 page did not stop the publish`);
      for (const prefix of forbidden) {
        assert.ok(!calls.some((call) => `${call.method} ${call.url}`.startsWith(prefix)), `${lookup}: ${prefix} after a 404 page`);
      }
    } finally {
      server.close();
      rmSync(dir, { recursive: true, force: true });
    }
  }
});
