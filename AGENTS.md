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
