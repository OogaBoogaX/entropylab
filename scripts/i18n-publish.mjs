// Translation publish — job B of the post-merge translation workflow: takes
// job A's validated proposals and opens the per-language pull requests. This
// job holds the GitHub App token; it never sees the LLM secret.
//
//   GH_TOKEN=<app installation token> GITHUB_REPOSITORY=owner/repo \
//     node scripts/i18n-publish.mjs --dir <proposals dir> [--lang es] [--dry-run]
//
// For every <lang>.json in the proposals directory:
//   1. independently re-validate the catalog and its sidecar (job A's output
//      is an artifact crossing a trust boundary — it is never trusted);
//   2. skip the language when the committed catalog on rock already matches;
//   3. point the automation branch i18n/translate-<lang> at one commit on
//      rock's current tip that changes exactly two files:
//      src/locales/<lang>.json and src/locales/.sources/<lang>.json;
//   4. create or update one pull request per language, labelled
//      translation-automated;
//   5. enable GitHub auto-merge for that exact PR number and head SHA — if
//      the branch moves afterwards, GitHub aborts the merge.
// The run is idempotent: an existing open automation PR for a language is
// updated in place, never duplicated.
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { catalogProblems, sidecarProblems } from "./i18n-validate.mjs";

const root = dirname(dirname(fileURLToPath(import.meta.url)));

export const BRANCH_PREFIX = "i18n/translate-";
export const TRANSLATION_LABEL = "translation-automated";
export const BRANCH_PATTERN = /^i18n\/translate-([a-z]{2}(?:-[a-z0-9]+)?)$/;

const DEFAULT_API_URL = "https://api.github.com";

export async function githubRequest({ apiUrl = DEFAULT_API_URL, token, method, path, body }) {
  const response = await fetch(`${apiUrl}${path}`, {
    method,
    headers: {
      accept: "application/vnd.github+json",
      "x-github-api-version": "2022-11-28",
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...(body !== undefined ? { "content-type": "application/json" } : {}),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await response.text();
  // GitHub answers some failures (a 5xx during an incident) with an HTML
  // page, not JSON. Parse after reading the status, so the error names the
  // status and the call instead of "Unexpected token '<'".
  let data = null, json = true;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      json = false;
    }
  }
  if (!response.ok || !json) {
    const detail = !json
      ? `a non-JSON response (${text.trimStart().startsWith("<") ? "an HTML page" : JSON.stringify(text.slice(0, 80))})`
      : (data && data.message) || text.slice(0, 200);
    const error = new Error(`GitHub ${method} ${path} → HTTP ${response.status}: ${detail}`);
    error.status = response.status;
    error.data = data;
    error.json = json;
    throw error;
  }
  return data;
}

// A lookup that answers 404 means "not there yet" only when GitHub's API said
// so in JSON. A 404 page from anything in between is a failure, not absence:
// treating it as absence would publish a new branch and pull request.
const tryRequest = async (request) => {
  try {
    return await request();
  } catch (error) {
    if (error.status === 404 && error.json) return null;
    throw error;
  }
};

export async function githubGraphql({ apiUrl = DEFAULT_API_URL, token, query, variables }) {
  const data = await githubRequest({
    apiUrl,
    token,
    method: "POST",
    path: "/graphql",
    body: { query, variables },
  });
  if (data.errors?.length) throw new Error(`GitHub GraphQL: ${data.errors.map((error) => error.message).join("; ")}`);
  return data.data;
}

// The auto-merge preference order; the repository's own merge settings filter
// it, and unknown settings (a private repo's flags are not always visible)
// fall through to trying each method in turn.
const MERGE_METHODS = [
  ["squash", "SQUASH", "allow_squash_merge"],
  ["merge", "MERGE", "allow_merge_commit"],
  ["rebase", "REBASE", "allow_rebase_merge"],
];

const ensureLabel = async (ctx) => {
  const existing = await tryRequest(() => githubRequest({ ...ctx, method: "GET", path: `/repos/${ctx.repo}/labels/${TRANSLATION_LABEL}` }));
  if (!existing) {
    await githubRequest({
      ...ctx,
      method: "POST",
      path: `/repos/${ctx.repo}/labels`,
      body: {
        name: TRANSLATION_LABEL,
        color: "1d76db",
        description: "Automated translation PR — merges without human review by design (issue #286)",
      },
    });
  }
};

// Point the branch at one commit on rock's current tip that writes the given
// files, and return the branch's head SHA. Each run rebuilds the language's
// whole catalog from rock's committed copy, so nothing on the branch's
// previous tip is lost; a branch cut from an older rock would conflict with
// rock as soon as another translation merged there. The commit is built
// before the branch moves, so the head never passes through rock itself (a
// PR whose head is already on its base reads as merged). A branch already
// holding these files on rock's tip is left alone. Returns null, touching
// nothing, when rock's tip already holds the files.
const commitOnRock = async (ctx, branch, files, message) => {
  const rockSha = (await githubRequest({ ...ctx, method: "GET", path: `/repos/${ctx.repo}/git/ref/heads/rock` })).object.sha;
  const rockCommit = await githubRequest({ ...ctx, method: "GET", path: `/repos/${ctx.repo}/git/commits/${rockSha}` });
  const tree = await githubRequest({
    ...ctx,
    method: "POST",
    path: `/repos/${ctx.repo}/git/trees`,
    body: { base_tree: rockCommit.tree.sha, tree: files.map(({ path, content }) => ({ path, mode: "100644", type: "blob", content })) },
  });
  // Trees are content-addressed: the same id as rock's own tree means rock's
  // tip already holds these files. The usual cause is a race: this run's
  // checkout was taken before another run's PR for the language merged, so
  // publishLanguage's committed-catalog check read stale content. Committing would
  // open a PR with no changes that auto-merges as an empty commit, as #902
  // and #903 did.
  if (tree.sha === rockCommit.tree.sha) return null;
  const existing = await tryRequest(() => githubRequest({ ...ctx, method: "GET", path: `/repos/${ctx.repo}/git/ref/heads/${encodeURIComponent(branch)}` }));
  if (existing) {
    const head = await githubRequest({ ...ctx, method: "GET", path: `/repos/${ctx.repo}/git/commits/${existing.object.sha}` });
    if (head.tree.sha === tree.sha && head.parents.length === 1 && head.parents[0].sha === rockSha) return existing.object.sha;
  }
  const commit = await githubRequest({ ...ctx, method: "POST", path: `/repos/${ctx.repo}/git/commits`, body: { message, tree: tree.sha, parents: [rockSha] } });
  if (existing) {
    await githubRequest({ ...ctx, method: "PATCH", path: `/repos/${ctx.repo}/git/refs/heads/${encodeURIComponent(branch)}`, body: { sha: commit.sha, force: true } });
  } else {
    await githubRequest({ ...ctx, method: "POST", path: `/repos/${ctx.repo}/git/refs`, body: { ref: `refs/heads/${branch}`, sha: commit.sha } });
  }
  return commit.sha;
};

const enableAutoMerge = async (ctx, pr, headSha) => {
  const repo = await githubRequest({ ...ctx, method: "GET", path: `/repos/${ctx.repo}` });
  const candidates = MERGE_METHODS.filter(([, , flag]) => repo[flag] !== false);
  const mutation = `mutation ($id: ID!, $sha: GitObjectID!, $method: PullRequestMergeMethod!) {
    enablePullRequestAutoMerge(input: { pullRequestId: $id, expectedHeadOid: $sha, mergeMethod: $method }) {
      pullRequest { autoMergeRequest { enabledAt mergeMethod } }
    }
  }`;
  let lastError;
  for (const [name, method] of candidates) {
    try {
      await githubGraphql({ ...ctx, query: mutation, variables: { id: pr.node_id, sha: headSha, method } });
      return name;
    } catch (error) {
      if (/already enabled/i.test(error.message)) return `${name} (already enabled)`;
      // Nothing to wait for: with no required checks pending, GitHub refuses
      // auto-merge on an immediately mergeable PR ("clean status"). Merge it
      // directly, pinned to the same exact head SHA.
      if (/clean status/i.test(error.message)) {
        await githubRequest({ ...ctx, method: "PUT", path: `/repos/${ctx.repo}/pulls/${pr.number}/merge`, body: { merge_method: name, sha: headSha } });
        return `${name} (merged directly — nothing pending)`;
      }
      lastError = error;
    }
  }
  throw new Error(`could not enable auto-merge for PR #${pr.number}: ${lastError?.message}`);
};

// Publish one language. Returns a summary line; throws on any validation or
// API failure (the workflow run must go red, not silently skip).
export async function publishLanguage({ dir, lang, repoRoot = root, repo, token, apiUrl, dryRun = false, log = console.log }) {
  const catalogNext = JSON.parse(readFileSync(join(dir, `${lang}.json`), "utf8"));
  const sidecarPath = join(dir, ".sources", `${lang}.json`);
  if (!existsSync(sidecarPath)) throw new Error(`${lang}: proposal is missing its sidecar ${sidecarPath}`);
  const sidecarNext = JSON.parse(readFileSync(sidecarPath, "utf8"));

  // Independent revalidation — this job, not job A, is the last validator.
  const problems = catalogProblems(catalogNext);
  const side = sidecarProblems(catalogNext, sidecarNext);
  const failures = [...problems, ...side.invalid, ...side.drift];
  if (failures.length) {
    throw new Error(`${lang}: proposal failed validation:\n${failures.slice(0, 10).join("\n")}`);
  }

  const catalogText = JSON.stringify(catalogNext, null, 2) + "\n";
  const sidecarText = JSON.stringify(sidecarNext, null, 2) + "\n";
  const committedPath = join(repoRoot, "src/locales", `${lang}.json`);
  const committed = existsSync(committedPath) ? JSON.parse(readFileSync(committedPath, "utf8")) : {};
  if (JSON.stringify(committed) === JSON.stringify(catalogNext)) {
    return `${lang}: committed catalog already matches — nothing to publish`;
  }

  const branch = `${BRANCH_PREFIX}${lang}`;
  const added = Object.keys(catalogNext).filter((key) => !(key in committed)).length;
  const removed = Object.keys(committed).filter((key) => !(key in catalogNext)).length;
  const changed = Object.keys(catalogNext).filter((key) => key in committed && committed[key] !== catalogNext[key]).length;
  const title = `i18n(${lang}): automated translation update (+${added} −${removed} ~${changed})`;
  // The sidecar hashes English keys only: a refresh of values alone leaves it
  // byte-identical, so the PR's diff holds the catalog by itself.
  const committedSidecarPath = join(repoRoot, "src/locales/.sources", `${lang}.json`);
  const sidecarChanged = !existsSync(committedSidecarPath) || readFileSync(committedSidecarPath, "utf8") !== sidecarText;
  const body = [
    `Automated translation update for \`${lang}\` from the post-merge i18n workflow (issue #286).`,
    "",
    `- **+${added}** new translations, **−${removed}** obsolete keys pruned, **~${changed}** refreshed`,
    sidecarChanged
      ? "- Touches exactly `src/locales/" + lang + ".json` and `src/locales/.sources/" + lang + ".json`"
      : "- Touches only `src/locales/" + lang + ".json`: its English keys are unchanged, so `src/locales/.sources/" + lang + ".json` stays as is",
    "- Catalog and sidecar validated before publication; the translation-only CI gate re-checks both, plus the full suite",
    "- Auto-merge is enabled for the exact head SHA; missing or rejected strings fall back to English",
    "",
    "No human translation review by design — see the issue for the residual-risk statement.",
  ].join("\n");

  if (dryRun) return `${lang}: dry run — would publish +${added} −${removed} ~${changed} to ${branch}`;

  const ctx = { repo, token, apiUrl };

  // Branch: one commit on rock's current tip, whether the branch is new or
  // left from an earlier run (the branch name is kept, so reruns stay one PR).
  const message = `i18n(${lang}): automated translation update`;
  const headSha = await commitOnRock(ctx, branch, [
    { path: `src/locales/${lang}.json`, content: catalogText },
    { path: `src/locales/.sources/${lang}.json`, content: sidecarText },
  ], message);
  if (!headSha) return `${lang}: rock's tip already holds this proposal — nothing to publish`;
  log(`${lang}: ${branch} at ${headSha.slice(0, 10)} on rock`);

  const owner = repo.split("/")[0];
  const open = await githubRequest({ ...ctx, method: "GET", path: `/repos/${ctx.repo}/pulls?head=${owner}:${encodeURIComponent(branch)}&base=rock&state=open` });
  let pr;
  if (open.length) {
    pr = await githubRequest({ ...ctx, method: "PATCH", path: `/repos/${ctx.repo}/pulls/${open[0].number}`, body: { title, body } });
    log(`${lang}: updated PR #${pr.number}`);
  } else {
    pr = await githubRequest({ ...ctx, method: "POST", path: `/repos/${ctx.repo}/pulls`, body: { title, head: branch, base: "rock", body, maintainer_can_modify: false } });
    log(`${lang}: opened PR #${pr.number}`);
  }

  await ensureLabel(ctx);
  await githubRequest({ ...ctx, method: "PUT", path: `/repos/${ctx.repo}/issues/${pr.number}/labels`, body: { labels: [TRANSLATION_LABEL] } });

  const method = await enableAutoMerge(ctx, pr, headSha);
  return `${lang}: PR #${pr.number} at ${headSha.slice(0, 10)} — auto-merge enabled (${method})`;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const args = process.argv.slice(2);
  const value = (flag) => {
    const at = args.indexOf(flag);
    return at === -1 ? undefined : args[at + 1];
  };
  const dir = value("--dir");
  const repo = process.env.GITHUB_REPOSITORY;
  const token = process.env.GH_TOKEN;
  if (!dir || !repo || (!token && !args.includes("--dry-run"))) {
    console.error("usage: GH_TOKEN=… GITHUB_REPOSITORY=owner/repo node scripts/i18n-publish.mjs --dir <dir> [--lang es] [--dry-run]");
    process.exit(2);
  }
  const onlyLang = value("--lang");
  const langs = onlyLang
    ? [onlyLang]
    : readdirSync(dir)
        .filter((name) => /^[a-z]{2}(?:-[a-z0-9]+)?\.json$/.test(name))
        .map((name) => name.replace(/\.json$/, ""));
  if (!langs.length) {
    console.log("no language proposals — nothing to publish");
    process.exit(0);
  }
  let failed = 0;
  for (const lang of langs) {
    try {
      console.log(await publishLanguage({ dir, lang, repo, token, dryRun: args.includes("--dry-run") }));
    } catch (error) {
      failed++;
      console.error(`${lang}: FAILED — ${error.message}`);
    }
  }
  process.exit(failed ? 1 : 0);
}

