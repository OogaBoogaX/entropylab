# EntropyLab security posture

EntropyLab is one self-contained HTML file that turns entropy you supply into Bitcoin keys and wallet data, built to run on a computer that never goes online. This page lists what protects it, where to check each claim, and the limits we know of. Check every claim against the code at the commit you are evaluating: `rock` is the development line, and [v1.0.0](https://github.com/OogaBoogaX/entropylab/releases/tag/v1.0.0) is the latest signed release.

## How a change gets in

No pull request reaches `rock` on one author's word. This is the maintainers' process, not a GitHub setting: the record of it is the triage comment on each pull request. Automated changes (translation pull requests, the rebuilt site artifact, timestamp proofs) are checked by CI instead.

- **Five model reviewers and a red team on every pull request a person or model writes.** DeepSeek V4.1, Kimi K3, GLM 5.3, MiniMax M3.1 Flash and Nemotron 3.5 Lightning review each change. An adversarial red-team pass then tries to break it.
- **A merge bar.** A pull request merges only with a clean approval from at least one of Kimi K3, GLM 5.3 or DeepSeek V4.1. Every finding must first be fixed or refuted against the code, and the triage is posted on the pull request.
- **A second red team on anything that touches keys, seeds, signing or the PSBT Inspector,** by Gemini.
- **A test that fails without the fix.** Every fix lands with a regression test, run against the code before the fix to show it fails there.
- **Untrusted code never runs on a maintainer's machine.** Code written by a model, and code from outside pull requests, runs only in an isolated sandbox: a VM with no network and no access to the host's files, with each test run under gVisor.
- **The full suite runs twice.** About 5,500 tests run in that sandbox before every push, and again in CI. CI also runs a browser test suite and a Bitcoin Core interoperability job.
- **New user-facing text is agreed by four models from three labs:** Claude, Astra, Fable and Grok.
- **Who does what:** the reviewers and red teams are open-weight and hosted models run by the maintainers. Claude coordinates, writes many of the fixes, and checks every finding by hand. Human maintainers sign the releases.

## Red-team sweeps

Besides the per-change review, the whole repository is swept: each file is audited by several model families, and every claimed finding is then checked by hand against the code.

- **21–22 October 2026:** a deep sweep of every source file, followed by delta sweeps of each change.
- **4–5 November 2026,** before v1.1.0: 45 findings were claimed high and none held at that severity. Six were real mediums, fixed in [#1455](https://github.com/OogaBoogaX/entropylab/pull/1455) and [#1457](https://github.com/OogaBoogaX/entropylab/pull/1457) to [#1461](https://github.com/OogaBoogaX/entropylab/pull/1461). About 45 lows are being fixed in batches, a few of them after the v1.1.0 release.
- **Other tools that test the tests:** mutation testing (Stryker), differential fuzzers against independent implementations (HD keys, PSBTs, sighashes), and a [residue harness](Residue_Audit.md) that captures browser memory at fixed checkpoints and searches it for a fixture's secrets.

The rounds and the merged fixes are logged publicly in the [EntropyLab red-team log](https://github.com/MrHodlX/security-reviews/blob/main/entropylab-red-team.md). Findings still being fixed stay private until they merge.

To our knowledge (November 2026), no other open-source Bitcoin key tool publishes a per-change, multi-model review and red-team record like this one.

## Releases you can verify

- **Signed by four maintainers.** v1.0.0 carries 4 of 4 signatures (russeree, MrHodlX, w-s-bitcoin, timechainb) over its `SHA256SUMS.txt`, plus an OpenTimestamps proof.
- **Byte-for-byte reproducible inside the pinned build image.** CI rebuilds the page in two environments and requires identical bytes. The image itself is not bit-for-bit reproducible, and its compilers are trusted as a seed: see [Verifying the download](../README.md#verifying-the-download). Rebuilds outside GitHub that matched the published hashes are logged in [Reproductions](Reproductions.md).
- **Checked before it is deployed.** The release workflow checks the signatures, and that the commit named in the page's footer is in the tag's history, before it publishes anything (`.github/workflows/pages-release.yml`).
- **Development builds say so.** A `rock` build is an unsigned `-dev` build and shows a banner that cannot be dismissed.

How to check a download yourself: [Verifying the download](../README.md#verifying-the-download).

## What the design does

| Property | How | Where to check |
| --- | --- | --- |
| **No network** | One HTML file, no runtime dependencies. The page makes no network requests of its own: its Content Security Policy sets `default-src 'none'; connect-src 'none'; form-action 'none'`. Links to outside pages load only when you follow them, and the hosted copy's service worker checks for updates (see Known limits). | `src/index.html`, [threat model](Threat_Model.md) |
| **Your entropy, not ours** | The app never generates key entropy. You supply dice, coins, cards, words or keys. For hashed dice it shows how many rolls it recommends (100 D6 for 24 words). | [contribution rules](../CONTRIBUTING.md), [dice fairness tests](../test/dice-fairness.test.mjs) |
| **Private values stay off the system clipboard** | The app's copy buttons for private values copy into an in-app clipboard held as bytes, never the OS clipboard. It is overwritten on replacement, conceal and End Session, and private readouts can't be selected. Public values can go to the OS clipboard. | [clipboard rules](UI_Patterns.md#copying-to-the-clipboard), [`app-clipboard.js`](../src/js/app-clipboard.js), [clipboard tests](../test/app-clipboard.test.mjs) |
| **Secure entry** (optional, off by default) | Seed words, keys and dice can be entered on in-page pads that keep the values out of page text fields. | [seed picker](../src/js/seed-picker.js), [passphrase vault](../src/js/passphrase-vault.js), [secure dice pad](../src/js/secure-dice-pad.js), [wiring tests](../test/secure-entry-wiring.test.mjs) |
| **Journal** | The Journal stays in page memory unless you download it. A password-protected download uses AES-256-GCM. Its key comes from PBKDF2-SHA-256 at 600,000 rounds, and its IV is synthetic: an HMAC-SHA-256 of the contents under a second derived key, so an IV repeats only for identical contents. The salt comes from the password, so the same contents under the same password give the same file: see Known limits. | [`journal.js`](../src/js/journal.js), [backup tests](../test/journal-backup.test.mjs), [complete-backup tests](../test/journal-complete-backup.test.mjs) |
| **Cleanup** | End Session and leaving the page overwrite the secret bytes the app holds, including WebAssembly memory, and clear the in-app clipboard. This is best effort: see Known limits. Hiding the tab or going idle conceals revealed secrets. | [end-session tests](../test/end-session.test.mjs), [conceal tests](../test/conceal-on-leave.test.mjs), [residue harness](Residue_Audit.md) |

## Known limits

These are stated once, here, so a review can weigh them:

- **The host is trusted.** A browser's "offline" label is not an air gap, and loading the hosted site is itself a network request, as is its service worker's update check: for secrets, use the downloaded file on a computer that stays offline. A compromised operating system, browser, extension, USB device or copy of the HTML file can see everything the page sees. Swap, hibernation and crash dumps can keep secrets on disk. See [Computer hardening](Computer_Hardening_Checklist.md).
- **Memory clearing is best effort.** It covers the bytes the app owns. JavaScript strings can't be overwritten, and the browser and OS keep copies of their own.
- **The in-app clipboard covers the app's copy controls.** It doesn't stop you selecting and copying text from an editable field, and it can't control software on the host.
- **The Journal password is optional.** A file saved without one is not protected. The PBKDF2 salt comes from the password, not from a random value, so one guessing run covers every Journal file at once, and the same contents under the same password give the same file. Use a long, unique password.
- **Dice statistics can't prove dice fair.** The fairness check can flag a biased transcript, but it can't prove a transcript was unpredictable.
- **Reviews don't prove the absence of bugs.** Models can share blind spots, and passing CI is not a proof. A signed release proves who published it, not that it is bug-free. Before funding a wallet, reproduce the words, fingerprint and an address with an independent tool.

## For reviewers, human or AI

- **Read the code and tests at the commit you are evaluating.** A pending pull request is not shipped behaviour.
- **Check the known issues before you report.** Accepted issues and earlier findings are in [SECURITY.md](../SECURITY.md) and the [audit ledger](audits/README.md).
- **Report suspected vulnerabilities privately,** through [GitHub Security Advisories](https://github.com/OogaBoogaX/entropylab/security/advisories/new), not in a public issue. Every report is checked against the code, and real ones are fixed with a regression test.
