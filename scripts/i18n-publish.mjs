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
//   3. create or update the automation branch i18n/translate-<lang> with
//      exactly two files: src/locales/<lang>.json and
//      src/locales/.sources/<lang>.json;
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
  const data = text ? JSON.parse(text) : null;
  if (!response.ok) {
    const error = new Error(`GitHub ${method} ${path} → HTTP ${response.status}: ${(data && data.message) || text.slice(0, 200)}`);
    error.status = response.status;
    error.data = data;
    throw error;
  }
  return data;
}

const tryRequest = async (request) => {
  try {
    return await request();
  } catch (error) {
    if (error.status === 404) return null;
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
        description: "Automated translation PR from the post-merge i18n workflow — merges without human review by design (issue #286)",
      },
    });
  }
};

// Write one file onto the branch via the Contents API, skipping no-op writes.
// Returns the branch tip SHA after the write (or the unchanged tip).
const writeFile = async (ctx, branch, path, content, message) => {
  const current = await tryRequest(() => githubRequest({ ...ctx, method: "GET", path: `/repos/${ctx.repo}/contents/${path}?ref=${encodeURIComponent(branch)}` }));
  if (current && current.content && Buffer.from(current.content.replace(/\n/g, ""), "base64").toString("utf8") === content) {
    return null; // identical — nothing to commit
  }
  const result = await githubRequest({
    ...ctx,
    method: "PUT",
    path: `/repos/${ctx.repo}/contents/${path}`,
    body: {
      message,
      content: Buffer.from(content, "utf8").toString("base64"),
      branch,
      ...(current?.sha ? { sha: current.sha } : {}),
    },
  });
  return result.commit.sha;
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
  const body = [
    `Automated translation update for \`${lang}\` from the post-merge i18n workflow (issue #286).`,
    "",
    `- **+${added}** new translations, **−${removed}** obsolete keys pruned, **~${changed}** refreshed`,
    "- Touches exactly `src/locales/" + lang + ".json` and `src/locales/.sources/" + lang + ".json`",
    "- Catalog and sidecar validated before publication; the translation-only CI gate re-checks both, plus the full suite",
    "- Auto-merge is enabled for the exact head SHA; missing or rejected strings fall back to English",
    "",
    "No human translation review by design — see the issue for the residual-risk statement.",
  ].join("\n");

  if (dryRun) return `${lang}: dry run — would publish +${added} −${removed} ~${changed} to ${branch}`;

  const ctx = { repo, token, apiUrl };

  // Branch: create from rock's current tip, or reuse the existing automation
  // branch (the Contents API commits onto its tip, so reruns stay one PR).
  const baseRef = await githubRequest({ ...ctx, method: "GET", path: `/repos/${ctx.repo}/git/ref/heads/rock` });
  const existingBranch = await tryRequest(() => githubRequest({ ...ctx, method: "GET", path: `/repos/${ctx.repo}/git/ref/heads/${encodeURIComponent(branch)}` }));
  if (!existingBranch) {
    await githubRequest({ ...ctx, method: "POST", path: `/repos/${ctx.repo}/git/refs`, body: { ref: `refs/heads/${branch}`, sha: baseRef.object.sha } });
    log(`${lang}: created branch ${branch}`);
  }

  const message = `i18n(${lang}): automated translation update`;
  await writeFile(ctx, branch, `src/locales/${lang}.json`, catalogText, message);
  await writeFile(ctx, branch, `src/locales/.sources/${lang}.json`, sidecarText, message);

  const headRef = await githubRequest({ ...ctx, method: "GET", path: `/repos/${ctx.repo}/git/ref/heads/${encodeURIComponent(branch)}` });
  const headSha = headRef.object.sha;

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

