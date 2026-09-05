# AGENTS.md

Guidelines for AI coding agents.

- Read [CONTRIBUTING.md](CONTRIBUTING.md) before making changes. The short
  version: never generate entropy used for key material, no network egress, output stays a single
  self-contained `entropylab.html`.
- **Read before acting:** read a file before editing or overwriting it — edit
  what is actually on disk, not what you assume.
- **Never assume:** when something is unknown, check the documentation or the
  code first, then proceed.
- Edit sources in `src/` (and the Rust crates in `entropylab-wasm/`,
  `psbt-wasm/`, and `vanity-wasm/`), never generated build artifacts — that
  includes `entropylab.html` and the `src/js/*-wasm-b64.js` modules
  (regenerate them with `npm run build:wasm`; it needs Rust, toolchain pinned
  by each crate's `rust-toolchain.toml`).
- The page body lives once in `src/shell.html`: the build injects it into
  `index.html`, and `app.js` assigns it at boot. Edit markup there, never in
  two places.
- Translations are content-keyed: the English text at the call site is the
  catalog key (`t("Save watch-only sheet")`); there is no `en.json`. Static
  markup needs nothing — a content sweep translates text nodes and
  aria/placeholder attributes; use `data-i18n-rich` only on blocks whose
  translation carries markup, `data-i18n-skip` on brand/technical content.
  Enum-indexed labels live in `src/js/i18n-labels.js`. Catalog values pass
  through an allowlist sanitizer at load (`src/js/i18n-sanitize.js`); pick the
  helper for the sink — `hodlT` in HTML template content, `hodlTText` for
  textContent/setAttribute, `hodlTAttr` inside quoted template attributes
  (enforced by `test/i18n-attribute-guard.test.mjs`). After adding or editing
  user-facing strings, do NOT touch the locale catalogs or their
  `.sources/<lang>.json` provenance sidecars: missing translations fall back
  to English per string and the post-merge translation workflow
  (`.github/workflows/translate.yml`, setup in
  `docs/Translation_Automation_Setup.md`) fills them and opens one
  auto-merging PR per language. Locale files change ONLY through that
  automation — once the operator configures `TRANSLATION_APP_SLUG`, the
  `translation-gate` CI job rejects any other PR touching `src/locales/`
  (until then the gate is inert and locale PRs get ordinary human review).
  CI fails only on invalid catalog content
  (`scripts/i18n-validate.mjs`, run via `scripts/i18n-sync.mjs`) or on source
  markup outside the sanitizer table — a new link or formatting form means
  extending `hodlCatalogAllowedTags` first. `npm run i18n:sync` prunes dead
  entries.
- The whole development environment is also a docker image (`Dockerfile` +
  `compose.yaml`): pinned Node, the pinned Rust wasm toolchain + clang,
  Firefox, and Chrome. `docker compose up --build` mounts the repo at
  `/workspace`; `npm test` and `npm run test:browser` run fully inside it
  (the browser suite runs every installed engine — Firefox,
  Chrome/Chromium, Microsoft Edge — and skips the absent ones).
- Make the smallest change that works. No refactors, reformatting, or new
  dependencies.
- Don't weaken or skip tests. New behaviour needs a test.
- Before finishing, run `npm run build && npm test` and make sure they pass.
