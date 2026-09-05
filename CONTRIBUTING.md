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

## A final sanity check

1. Does this keep EntropyLab a calculator that never invents entropy?
2. Does the app stay silent on the network?
3. Is the output still a single self-contained `entropylab.html`?
4. Is it smaller, or at least no bigger, than it was?
5. Did you rebuild, keep docs/version in sync, and commit no generated files?
6. Could an auditor follow the change in one pass?

If yes to all six, send it. Thanks.
