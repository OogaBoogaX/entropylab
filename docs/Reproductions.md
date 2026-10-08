# Reproductions

CI proves every build reproducible inside GitHub. The page builds to the same
bytes on the runner and inside the pinned dev image, and the WASM modules build
to the same bytes twice in that image and match the modules CI publishes. What
CI cannot prove is that someone else's machine gets those bytes too. This log
records each rebuild outside GitHub that matched the published hashes, so the
cross-machine claim in SECURITY.md and the README rests on recorded evidence.

To add a row, rebuild a published commit and compare:

- **The page:** check out the commit stamped in the page's footer, run
  `npm ci --ignore-scripts && npm run build` (in the dev image with
  `docker compose run --rm dev`, or on the host), and compare
  `sha256sum entropylab.html` with `SHA256SUMS.txt` — the published hash
  for a source commit is recorded in the artifact commit that follows
  it, not at the source commit itself.
- **The WASM modules:** at the same commit, run `npm run build:wasm` inside
  the dev image, and compare `sha256sum src/js/*-wasm-b64.js` with
  `WASM-SHA256SUMS.txt`. A host clang is a different compiler, so only a
  rebuild in the image counts.

A row records one match: what was rebuilt, where, and the SHA-256 it matched.

| Date | Commit | Rebuilt | SHA-256 | Environment | By |
|---|---|---|---|---|---|
| 2026-09-29 | `cb55bd9` (v1.0.0) | `entropylab.html`, from the committed WASM modules | `2b9828abadad8030588d2de512d73519f7ce06d3764fd5c3e1caaed34693131a` | Windows 11 Home 10.0.26200, x86_64, Node 24.14.0, on the host (no container) | MrHodlX |
| 2026-09-29 | `cb55bd9` (v1.0.0) | `src/js/entropylab-wasm-b64.js`, `npm run build:wasm` | `6c5b1324b3d612eaac81470bbe4aa3a0bf11556b1c5a14a7f2aed5c4922e32df` | the dev image (see the note) in Docker 29.1.3, WSL2 Ubuntu 26.04 on the same laptop | MrHodlX |
| 2026-09-29 | `cb55bd9` (v1.0.0) | `src/js/psbt-wasm-b64.js`, `npm run build:wasm` | `98f801939635980600edfe9ab7320ee3f76c046cd2f90baa01a0dcf2defad468` | the dev image (see the note) in Docker 29.1.3, WSL2 Ubuntu 26.04 on the same laptop | MrHodlX |
| 2026-09-29 | `cb55bd9` (v1.0.0) | `src/js/vanity-wasm-b64.js`, `npm run build:wasm` | `8f9b26cf68b8f77584564b5ecc957d55db5ec7bcc75f3b1195046f69cb2a57f1` | the dev image (see the note) in Docker 29.1.3, WSL2 Ubuntu 26.04 on the same laptop | MrHodlX |
| 2026-09-29 | `cb55bd9` (v1.0.0) | `entropylab.html`, from the modules rebuilt above | `2b9828abadad8030588d2de512d73519f7ce06d3764fd5c3e1caaed34693131a` | the dev image (see the note) in Docker 29.1.3, WSL2 Ubuntu 26.04 on the same laptop | MrHodlX |
| 2026-09-29 | `cb55bd9` (v1.0.0) | `entropylab.html`, from the committed WASM modules | `2b9828abadad8030588d2de512d73519f7ce06d3764fd5c3e1caaed34693131a` | Ubuntu 26.04.1 LTS bare metal, x86_64, Node 22.22.1, npm 9.2.0, on the host (no container) | portlandhodl |
| 2026-09-29 | `cb55bd9` (v1.0.0) | `src/js/entropylab-wasm-b64.js`, `npm run build:wasm` | `6c5b1324b3d612eaac81470bbe4aa3a0bf11556b1c5a14a7f2aed5c4922e32df` | the dev image (see the note) in Docker 29.4.1 on the same Ubuntu 26.04.1 bare-metal host | portlandhodl |
| 2026-09-29 | `cb55bd9` (v1.0.0) | `src/js/psbt-wasm-b64.js`, `npm run build:wasm` | `98f801939635980600edfe9ab7320ee3f76c046cd2f90baa01a0dcf2defad468` | the dev image (see the note) in Docker 29.4.1 on the same Ubuntu 26.04.1 bare-metal host | portlandhodl |
| 2026-09-29 | `cb55bd9` (v1.0.0) | `src/js/vanity-wasm-b64.js`, `npm run build:wasm` | `8f9b26cf68b8f77584564b5ecc957d55db5ec7bcc75f3b1195046f69cb2a57f1` | the dev image (see the note) in Docker 29.4.1 on the same Ubuntu 26.04.1 bare-metal host | portlandhodl |
| 2026-09-29 | `cb55bd9` (v1.0.0) | `entropylab.html`, from the modules rebuilt above | `2b9828abadad8030588d2de512d73519f7ce06d3764fd5c3e1caaed34693131a` | the dev image (see the note) in Docker 29.4.1 on the same Ubuntu 26.04.1 bare-metal host | portlandhodl |
| 2026-09-29 | `cb55bd9` (v1.0.0) | `entropylab.html`, from the committed WASM modules | `2b9828abadad8030588d2de512d73519f7ce06d3764fd5c3e1caaed34693131a` | macOS 26.6.1 (25G76), ARM64, Node v22.23.2, on the host (no container) | w-s-bitcoin |
| 2026-09-29 | `cb55bd9` (v1.0.0) | `src/js/entropylab-wasm-b64.js`, `npm run build:wasm` | `6c5b1324b3d612eaac81470bbe4aa3a0bf11556b1c5a14a7f2aed5c4922e32df` | the dev image (see the note), linux/amd64 under Rosetta in Colima 0.10.3 on the same Mac, network off | w-s-bitcoin |
| 2026-09-29 | `cb55bd9` (v1.0.0) | `src/js/psbt-wasm-b64.js`, `npm run build:wasm` | `98f801939635980600edfe9ab7320ee3f76c046cd2f90baa01a0dcf2defad468` | the dev image (see the note), linux/amd64 under Rosetta in Colima 0.10.3 on the same Mac, network off | w-s-bitcoin |
| 2026-09-29 | `cb55bd9` (v1.0.0) | `src/js/vanity-wasm-b64.js`, `npm run build:wasm` | `8f9b26cf68b8f77584564b5ecc957d55db5ec7bcc75f3b1195046f69cb2a57f1` | the dev image (see the note), linux/amd64 under Rosetta in Colima 0.10.3 on the same Mac, network off | w-s-bitcoin |
| 2026-09-29 | `cb55bd9` (v1.0.0) | `entropylab.html`, from the modules rebuilt above | `2b9828abadad8030588d2de512d73519f7ce06d3764fd5c3e1caaed34693131a` | the dev image (see the note), linux/amd64 under Rosetta in Colima 0.10.3 on the same Mac, network off | w-s-bitcoin |

For MrHodlX's rows, the dev image was built on his laptop on 2026-09-24
from the Dockerfile as it stands at `cb55bd9` (unchanged since `8a9eae4`):
Node v22.23.2, clang 18.1.3, the 20260916 Ubuntu snapshot. Image
`sha256:fc1c4cd530d05822c76e5d8dadb48642bad3eb7df4cc7ce31ae00b404ab9181b`.
The modules were compiled from a clean clone with one cargo job
(`CARGO_BUILD_JOBS=1`, for memory; the job count does not change the
output).

For portlandhodl's rows, the dev image was likewise built on his machine
from the same Dockerfile at `cb55bd9`: image
`sha256:2de3d6fd71670ea5e814ff4b30ad061e43cd51b2daf51d974eb4158d5061fb42`,
Node v22.23.2, clang 18.1.3. Default cargo parallelism — the output
matches, consistent with the job count not changing the bytes.

For w-s-bitcoin's rows, the dev image was built on his Mac from the same
Dockerfile at `cb55bd9`: image config
`sha256:80e61f97e5a4f14713387486fdbe8a598fe2ac6dc7a92519384fd42344cbd361`,
Node v22.23.2, Rust 1.95.0, clang 18.1.3, the 20260916 Ubuntu snapshot. It
ran as linux/amd64 under Rosetta (Colima 0.10.3, Lima 2.2.0,
Virtualization.framework) with four cargo jobs and networking off
(`--network none`, `CARGO_NET_OFFLINE=true`, `npm ci --offline`). The page
was also built natively on the ARM64 host. His report is on #630.
Here's the Reproductions edit page. Paste this row at the very end of the table:
| 2026-10-07 | `7f48ec4` (v1.0.0rc2) | `entropylab.html`, from the committed WASM modules | `93295d7a001ec831f70b649e4078206a2f2eec7ffcacade8af9f8339a8e26361` | Debian GNU/Linux 13.7 (trixie) virtual machine run by an AI assistant, x86_64, Linux 6.12, Node v22.23.2, npm 10.9.8, on the host (no container) | breagoth |
