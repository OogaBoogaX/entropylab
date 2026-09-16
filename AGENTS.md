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
- **Front-end presentation is not unit-tested.** Three things must never be
  asserted: CSS declarations, markup and class attributes, and user-facing
  copy. A regex over any of them only restates the source in a second syntax:
  it cannot see the cascade, specificity or computed values, so it passes
  while the layout is visibly wrong, and it breaks on every rename or
  rewording. Assert instead what a rename cannot change — DOM structure and
  ordering, aria wiring, cross-component contracts (two controls reading one
  token), and guards against real hazards (a status line that must never
  become an HTML sink). Where a presentational invariant genuinely matters —
  the shared spacing rhythm, say — put it in the browser suite as a
  `getComputedStyle` check, which tests the outcome rather than the source
  text. Delete value assertions on sight during design work; no replacement
  is required.
- **Tests hook on ids and `data-*` attributes, never on classes.** A class is
  a styling decision and design work renames them freely; an id or a
  `data-*` attribute is an interface. If a component has no stable handle,
  add one rather than selecting `.some-class`. A renamed class that breaks a
  selector does not just fail its own test — in the browser suite it aborts
  that test part-way and leaves the shared page mid-state, so unrelated tests
  after it fail too, and the time goes into chasing a product bug that is not
  there.
- **Copy is content, not contract, until v1.** Safety-critical wording may be
  pinned by a short stable substring ("cannot spend", "offline",
  "unencrypted") so it cannot quietly vanish. All other copy is asserted only
  for presence and for a valid translation key, never verbatim. While the app
  is in beta, user-facing copy, layout values and class names are outside
  regression coverage entirely: tests guard derivation, parsing, state,
  wiring and security invariants.
- **Design iteration is not a test loop.** During UI work, do not run the
  suite per change: make the change, rebuild, and let the designer look. Run
  `npm run build && npm test` once before a commit. A design commit may
  delete presentational assertions outright, and a refactor that must not
  move anything is proven by a rendered before/after comparison rather than
  by the assertions it would otherwise have to update.
- **Commit attribution:** all commits must be co-authored with the LLM used
  to generate the code, via a `Co-authored-by:` trailer carrying the model
  name and a stable noreply email — GitHub credits a co-author only when
  both are present (`Co-authored-by: Model Name <model-noreply@host>`). Do
  not spoof this or strip attribution to your clanker — the data is used to
  evaluate model performance. If multiple models contributed code, add a
  trailer for each. Commit messages and reviews may be written by humans,
  but any LLM-assisted review must include attribution in the comment
  itself.
- Before finishing, run `npm run build && npm test` and make sure they pass.

### Security-sensitive test coverage

For changes to derivation, parsing, validation, verification, cryptography,
consensus-sensitive behaviour, scripts, transaction/PSBT handling,
network-silence, or "we do not invent entropy":

- State the security contract in one sentence: what must be accepted and what
  must be refused.
- Write or extend the test before changing production code.
- Run that test against the current sources before the implementation change.
  For a bug fix or tighter validation, it must fail for the claimed reason.
  A failure caused only by a missing import/export or unrelated setup does not
  establish the claimed defect. If it is already green, the test has not
  pinned a new contract — tighten it.
- For a new capability, a missing export/API is an acceptable first red, but
  the test must already contain an independently determined expected result or
  rejection condition.
- Expected results must be established independently of the implementation
  under test. Prefer published BIP / Bitcoin Core vectors, protocol
  specifications, stated rejection conditions, or behaviour already pinned by
  existing repository tests for the same contract. Never compute the expected
  answer by running the code under test and copying its output. Do not add a
  second implementation in the test and compare the two.
- Include meaningful accepted and rejected inputs where both apply. Cover
  negative cases named in the issue or review; if one is intentionally out of
  scope, explain why in the PR.
- Only then make the smallest production change that makes the test pass.
- Do not delete, skip, weaken, or soften a test to make it pass.
- In the PR, record the command/test used for the initial red and the same
  test/command after the implementation is green.

Documentation-only and presentation-only changes do not need test vectors solely
to satisfy this section. "When practicable" is not an exemption for the
security-sensitive changes covered above.

As optional additional evidence, contributors may use targeted fault injection
when a small, meaningful weakening can be tested cleanly: temporarily change a
comparison boundary, remove a required condition or check, or otherwise weaken
the protected behaviour, confirm that the focused test fails, and revert the
temporary change. Never commit or push the temporary change to the pull request.

This provides additional evidence of test adequacy, not proof of completeness
or correctness. It does not require exhaustive mutations, a mutation score, or
a mutation-testing framework.
