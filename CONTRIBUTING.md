# Contributing to EntropyLab

EntropyLab is small on purpose; its value comes from being auditable. Read this
before opening a pull request.

## 1. EntropyLab does not generate entropy

It converts entropy the *user* supplies — dice rolls, coin flips, hex, seed
phrases, private keys — into wallet recovery information. It is a calculator,
not a key generator.

The reason is trust: the user must be able to see, verify, and reproduce every
step of a derivation from randomness they produced themselves. The moment the
tool manufactures randomness, "I verified the output" stops being true.

**Will be closed, not merged:**

- "Generate key / seed / entropy" buttons.
- `Math.random()` or `crypto.getRandomValues()` used as a *source of secret
  material* (keys, seeds, passphrases, salts, defaults that end up in private
  material).
- Auto-filled, pre-generated, or server-supplied randomness.

**In policy:** deterministic transformations of user input (same input → same
output), user-typed randomness, and fixed published test vectors.

**The one exception (already in the code):** the Heads/Tails control uses
`crypto.getRandomValues()` only to pick which *equivalent* die face to display
(1–3 = Heads, 4–6 = Tails). The number is discarded on render and carries zero
entropy. New exceptions: argue them in an issue first, never in a pull request.

## 2. Keep it simple

- The smallest change that fixes the problem is the right change.
- No unreviewed dependencies: exact versions in `package.json`, integrity
  hashes in the committed `package-lock.json`, installed with `npm ci`.
- No frameworks, transpilers, or bundler abstractions beyond
  `scripts/build.mjs`.
- Delete code rather than add it.
- Optimise for the auditor, not for elegance. If a change needs a paragraph of
  justification, it is too clever.

## 3. No network egress

The tool runs air-gapped and must not phone home: no `fetch`, WebSocket,
remote `<img>`/`<script>`/`<link>`, fonts, CDNs, or analytics. Everything the
app loads must be same-origin or inlined at build time, and the headless
browser test that asserts this must stay green.

## 4. Build and artifact

- The final build artifact is **`entropylab.html`** — a single self-contained
  HTML file with no runtime requirements (server, network, storage, or
  extensions). Any change must keep this true.
- Edit sources in `src/`, never the build output. `entropylab.html` is
  generated, git-ignored, and not committed. The crypto WASM artifact
  (`src/js/entropylab-wasm-b64.js`) is also generated (from `entropylab-wasm/`);
  regenerate it with `npm run build:wasm`, never edit it by hand.
- CI rebuilds from `src/`, proves the output is byte-for-byte reproducible, and
  publishes it to the `pages` branch and GitHub Pages. CI likewise rebuilds
  the WASM artifact from the pinned Rust crate (`Cargo.lock`,
  `rust-toolchain.toml`), runs its test suite against the fresh build, and
  commits the artifact back to `rock` after each merge (same flow as
  `entropylab.html`).

```sh
git clone https://github.com/OogaBoogaX/entropylab.git && cd entropylab
node --version   # >= 20.19
npm ci
npm run build    # src/ → entropylab.html
npm test
```

Useful commands (same as CI): `npm run build`, `npm run verify`,
`npm run test:validate`, `npm run test:browser` (runs every installed
engine: Firefox, Chrome/Chromium, Microsoft Edge — an installed browser
is required; set `FIREFOX_BINARY` / `CHROME_BINARY` / `EDGE_BINARY` to
point the harness at a specific one), `npm run ci`. `npm run build:wasm`
additionally needs Rust (the pinned toolchain installs itself via
`entropylab-wasm/rust-toolchain.toml`) and is only required when changing
the Rust bindings in `entropylab-wasm/`.

### The development container (no host prerequisites)

The entire environment — Node 22 (pinned), the pinned Rust 1.95.0 wasm
toolchain with clang, Firefox ESR (pinned tarball), and Chrome — is
packaged as a container image (`Dockerfile`, wired up by `compose.yaml`).
The only host requirement is Docker; the repository is bind-mounted at
`/workspace`:

```sh
docker compose up --build        # builds the image, drops into a shell
npm ci && npm run build && npm test
# or from the host, without a shell:
docker compose run --rm dev npm test
docker compose run --rm dev npm run build:wasm
```

Inside the image, `npm test` is fully green (the optional SQLite checks
need Python, which is included) and `npm run test:browser` runs both
Firefox and Chrome; a locally installed Microsoft Edge is picked up
automatically when present (it is a Chromium fork sharing Chrome's engine
and code path, so the image does not ship a second copy). The Rust
toolchain and crate registry, and the npm cache, are pre-fetched into the
image, so `npm ci` and `npm run build:wasm` work without further downloads.

### Local UI test mode

For layout work that needs a populated Key Station, run:

```sh
npm run testmode -- --keys=18
```

This builds a temporary test-hooks-only artifact and serves it on loopback at
the printed URL. `--keys` accepts 1–100 and defaults to 12; `--port` defaults
to 4173. The fixtures are deliberately insecure hashed-dice transcripts in
the sequence `1` through `6`, `11` through `66`, `111`, and so on. They are
for UI testing only and must never receive funds. The loader and its
`?test-keys=` URL flag are compiled out of the release artifact.

## 5. Working agreements

- **Versioning:** declared once in `package.json`; `README.md` must match it (a
  test enforces this). Bump only when asked.
- **Docs:** user-facing or security-model changes require `README.md` /
  `SECURITY.md` updates in the same pull request.
- **Tests:** new or changed behaviour needs a test; published vectors (BIP39,
  BIP32, Bitcoin Core) are preferred. Never weaken, skip, or delete an existing
  test to make CI pass — if it is wrong, say why.
- **Translations:** user-facing text is written in English and translated
  content-keyed — the English string at the call site is the catalog key
  (`t("Save watch-only sheet")`), and a content sweep translates static markup
  in place. There is no key naming and no `en.json`. After adding or editing
  user-facing text, run `npm run i18n:sync` and fill the entries it appends to
  all four catalogs in `src/locales/` (es, pt, fr, de); CI fails on missing or
  dead entries. If you cannot translate a string competently, flag it in the
  pull request — do not leave the catalogs silently incomplete.
- **Pull requests:** small and focused, one change each. No drive-by
  reformatting or refactors. Describe what and why, and list the commands you
  ran. Comments explain intent and security reasoning, not the code.
- **Not accepted:** anything violating sections 1 or 3; license/authorship
  changes (the software is public domain); changes that obscure what the
  compiled `entropylab.html` does.
- **Security issues:** report privately via GitHub Security Advisories
  ([SECURITY.md](SECURITY.md)), not as public issues.
- **License:** public domain ([LICENSE](LICENSE)). By opening a pull request
  you confirm your contribution can be public domain; if not, open an issue
  instead. Exception: `src/js/lifehash.js` is an adaptation of the LifeHash
  reference implementations and is *not* public domain — the MIT
  (AndreasGassmann/lifehash) and BSD-2-Clause-Patent
  (BlockchainCommons/bc-lifehash) notices in its header must be preserved in
  copies and derivative works, including the built `entropylab.html`.

## 6. UI layout and spacing

Use the spacing tokens in `src/css/styles.css`; do not add one-off inline
margins. The shared rhythm is 8px between a label, its control, and help text;
16px between peer controls or an action row and its content; 20px between
distinct blocks inside a card; and 24px between a tool introduction and its
controls.

New tool markup should reuse the shared layout classes:

```html
<div class="tool-intro">...</div>
<section class="card no-print tool-card">
  <div class="tool-section">...</div>
  <label class="field">Label <input ...><span class="field-note">Help</span></label>
  <div class="row tool-actions"><button class="btn primary">Run</button></div>
</section>
```

`tool-card` normalizes its first and last edges, `tool-section` separates a
meaningful group, and `tool-actions` separates actions from the content they
operate on. Compact tables, grids, and visualizations may use tighter local
spacing internally, but their outer boundary should still follow this rhythm.

## Adding a workspace

Use this checklist when adding a tool to the top-level workspace strip:

- **Markup:** add the tab and its panel, introduction, and controls in
  `src/shell.html`. Keep IDs consistent with the runtime code; the build and
  boot render both use this shell, so do not duplicate the body in `index.html`.
- **Registration and switching:** update `hodlWorkspaceTabs` in
  `src/js/app.js` (ID, full label, short label). `hodlInitWorkspace` builds
  the runtime strip; `hodlShowWorkspace` controls panel/manager and intro
  visibility and entry/exit behavior. Wire initialization and event handlers
  into the existing boot flow. Check keyboard navigation and switching away
  from the new tool as well as opening it. PSBT and Journal have separate
  subtool synchronization; a subtool is not necessarily a new workspace.
- **Styles:** use `src/css/styles.css` and the shared classes described above.
  Check hidden panels, narrow-screen labels, overflow, and print behavior.
- **Bundling:** ordinary imports from `src/js/app.js` are bundled by
  `scripts/build.mjs`. Check `src/index.html` and that build script if adding
  a separate script or resource; keep the output self-contained and offline.
  Rust/WASM changes also need the relevant crate and `scripts/build-wasm.mjs`
  integration. Never hand-edit or submit generated artifacts.
- **Explicit test expectations:** review `test/ui-defaults.test.mjs`
  (workspace order, labels, panel containment, and switcher assertions) and
  `test/browser-suite.html` (tab count/names, keyboard navigation, visibility,
  and layout checks). Search these files for `workspace`, `data-workspace`,
  and `tool-intro`. An intentional addition may require updating their
  hard-coded lists/counts together; retain coverage for existing tools and
  add checks for the new one, rather than removing assertions.
- **Finish:** update user-facing documentation as required above, then run
  `npm run build && npm test`. Run `npm run test:browser` with an installed
  browser to exercise the workspace interactions.

## A final sanity check

1. Does this keep EntropyLab a calculator that never invents entropy?
2. Does the app stay silent on the network?
3. Is the output still a single self-contained `entropylab.html`?
4. Is it smaller, or at least no bigger, than it was?
5. Did you rebuild, keep docs/version in sync, and commit no generated files?
6. Could an auditor follow the change in one pass?

If yes to all six, send it. Thanks.
