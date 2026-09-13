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
  dependencies. This governs logic and functionality.
- **UI and design work is the exception**, and is currently a site-wide
  cleanup led by the project's design lead. There, reuse outranks minimalism:
  before adding a style or a block of markup, look for the paradigm it
  belongs to and extend that instead. A repeating interaction, control, or
  layout should be expressed once — behaviour in a single CSS rule with the
  parts that vary passed as custom properties, repeated markup in a shared
  builder alongside the existing ones (`hodlSeedCopyRowMarkup`,
  `hodlKeyboardToggleMarkup`) — rather than copied per component.
  Consolidating existing duplication is in scope for this work;
  keep such a pass in its own commit, make no visual change in it, and let
  the suite prove nothing moved. Tests follow the same shape: assert shared
  behaviour once, and per component assert only what it supplies.
- Don't weaken or skip tests, and new behaviour needs a test. This too is
  about logic and functionality — parsing, derivation, wiring, state, and the
  contracts between components.
- **Presentational detail is not unit-tested.** Colours, spacing, sizes,
  radii, weights and transitions are design values: a designer tunes them by
  eye, and a regex asserting one only restates the stylesheet in a second
  syntax. Such assertions cannot see the cascade, specificity or computed
  values, so they pass while the layout is visibly wrong, and they go stale
  on every refactor — which makes the reuse asked for above more expensive,
  not safer. Do assert what a value cannot express: DOM structure and
  ordering, aria wiring, cross-component contracts (two controls reading one
  token), and guards against real hazards (a status line that must never
  become an HTML sink). Where a presentational invariant genuinely matters —
  the shared spacing rhythm, say — put it in the browser suite as a
  `getComputedStyle` check, which tests the outcome rather than the source
  text. Removing existing value assertions is in scope for design work, but
  opportunistically: delete one when a change would otherwise make you update
  it, rather than sweeping the suite, so the design diff stays reviewable and
  the count comes down as the work moves through each surface.
- Before finishing, run `npm run build && npm test` and make sure they pass.

### Security-sensitive test coverage

For changes to verification, cryptography, consensus-sensitive behaviour,
scripts, or transaction/PSBT parsing:

- Include tests for both accepted and rejected inputs.
- For bug fixes, add a regression case that fails before the fix and passes
  afterward when practicable.
- Cover applicable negative cases identified in the issue or review. Explain
  in the pull request when a listed case is intentionally out of scope.

Documentation-only and presentation-only changes do not need test vectors
solely to satisfy this section.
