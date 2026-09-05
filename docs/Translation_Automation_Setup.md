# Translation automation — operator setup

One-time setup for the post-merge translation pipeline (issue #286). Until
these steps are done, `.github/workflows/translate.yml` skips itself (it
checks `vars.TRANSLATION_APP_ID`) and the `translation-gate` CI job is inert
(it has no App identity to check against, so locale-changing PRs stay
ordinary human-reviewed PRs), so the repo stays green either way. The gate
starts failing closed the moment `TRANSLATION_APP_SLUG` is set — configure
the slug only together with the rest of this setup.

The pipeline in one paragraph: after English UI text changes on `rock`, job A
(read-only token, LLM secret) generates schema-constrained, audited,
validated translation proposals; job B (GitHub App token, no LLM secret)
revalidates them and opens one `translation-automated` PR per language from
the `i18n/translate-<lang>` branch namespace; the `translation-gate` CI job
plus the normal suite run on that PR; GitHub auto-merge lands it once
everything passes. No human reviews translations by design — see the issue
for the explicit residual-risk statement.

## 1. Create the GitHub App

Settings → Developer settings → GitHub Apps → **New GitHub App**:

- **Name:** anything; the slug (e.g. `entropylab-translate`) becomes the bot
  identity `<slug>[bot]`. Record the slug.
- **Homepage URL:** the repository URL.
- **Webhook:** disable (uncheck *Active*) — the App never receives events.
- **Repository permissions:**
  - Contents: **Read and write** (creates the `i18n/translate-*` branches)
  - Pull requests: **Read and write** (opens/updates the per-language PRs)
  - Issues: **Read and write** (applies the `translation-automated` label)
  - Metadata: Read (automatic)
- **Where can this GitHub App be installed?** Only on this account.

Create it, then:

- **Generate a private key** — the downloaded `.pem` is the
  `TRANSLATION_APP_PRIVATE_KEY` secret.
- Record the **App ID** from the App's settings page — it becomes the
  `TRANSLATION_APP_ID` variable.
- **Install App** → install it on this repository only.

## 2. Configure the repository

Settings → Secrets and variables → Actions:

| Kind | Name | Value |
| --- | --- | --- |
| Secret | `TRANSLATION_APP_PRIVATE_KEY` | full `.pem` contents, including the BEGIN/END lines |
| Secret | `TRANSLATE_API_KEY` | API key for the chat-completions endpoint (e.g. an OpenRouter key) |
| Variable | `TRANSLATION_APP_ID` | the App ID from step 1 |
| Variable | `TRANSLATION_APP_SLUG` | the App's slug, without `[bot]` |
| Variable | `TRANSLATE_MODEL` | model id, e.g. `anthropic/claude-sonnet-4` on OpenRouter |
| Variable | `TRANSLATE_API_URL` | optional; defaults to `https://openrouter.ai/api/v1/chat/completions` |

The `translation-automated` label is created by the workflow on first use
(color, description included) — no manual step. If you prefer to pre-create
it: a label named exactly `translation-automated`.

## 3. Repository settings that make auto-merge work

Settings → General:

- **Allow auto-merge** — required; the publish job calls
  `enablePullRequestAutoMerge` for the exact PR number and head SHA.
- **Allow squash merging** — the preferred merge method (the publisher falls
  back to merge commits, then rebase, if disabled).

Settings → Branches → branch protection rule for `rock`:

- **Require a pull request before merging** — optional for the repo overall,
  but if enabled, do **not** require approving reviews for the automation:
  translation PRs merge with zero reviews by design. GitHub branch protection
  cannot exempt one author, so the simplest working configuration is
  *required status checks without required reviews*.
- **Require status checks to pass** — required. Add `translation-gate` (the
  check name is `Gate · translation-only PR scope`) alongside the existing
  suite checks (`Test · complete dependency-free suite (ubuntu-latest)`,
  `Test · Firefox integration suite (ubuntu-latest)`, `Build · compile site +
  Pages artifact`, `Verify · site artifact (snapshot, manifest, assets)`,
  and the rest of the ci-cd.yml jobs you already require).
  **This is the load-bearing step**: auto-merge only lands a translation PR
  after every required check passes, and the gate is what proves the PR is
  the automation's own, in-scope, and valid.
- Do not add `src/locales/` to any CODEOWNERS review requirement — the whole
  point is that locale PRs merge unattended.

## 4. Verify the pipeline

Actions → **Translation automation** → Run workflow. A green run that finds
nothing to translate ends with `no language proposals — nothing to publish`.
A run with pending work opens one PR per language; each should show the
`translation-automated` label, pass the gate, and merge by itself.

If a translation PR stalls: check that auto-merge is allowed (step 3), that
the gate and suite checks are required *and* passing, and read the job log —
the publish step fails loudly with the reason.

## Security boundaries (what not to weaken)

- Job A has `contents: read` and the LLM secret; it cannot write the repo.
- Job B has the App token and never receives `TRANSLATE_API_KEY`.
- The model receives only committed English strings and committed catalog
  examples — never issue/PR text or web content — and returns
  schema-constrained JSON.
- The gate checks App identity, branch namespace, the exact two-file scope
  (`src/locales/<lang>.json` + `src/locales/.sources/<lang>.json`), and
  catalog/sidecar validity — the label alone is never trusted.
- Auto-merge binds the exact head SHA; a branch that moves after publication
  aborts the merge.
- The runtime sanitizer (`src/js/i18n-sanitize.js`) remains the final
  boundary if hostile catalog content ever reaches the tree.

