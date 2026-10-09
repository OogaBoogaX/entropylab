# EntropyLab feature guide: implementation plan

Status: implemented on feature-guide-wizard. Original planning base: upstream/rock at
2ee665940195bb61188e339fecfdbe18a80920b4. Branch: feature-guide-wizard.

## Goal

Give a Bitcoin novice a clear explanation of every released main feature,
its useful outputs, and its limits. The guide is optional, repeatable,
entirely bundled, and implemented in plain JavaScript without additional
dependencies. It explains the calculator; it never asks for secrets or
changes a wallet. Existing cryptography continues to use the app's WASM;
the guide itself needs no crypto or WASM calls.

## Experience

A permanently available **Guide** button opens a shared modal containing
three choices: **Start with the basics**, **Choose a feature**, and
**Continue learning** (when session progress exists). Each released
workspace also offers **Explain this tool**, opening its relevant lesson.
Do not automatically open the guide or put another gate after the existing
disclaimer. An optional first-use invitation is a dismissible line beside
Guide, never a blocking overlay. Completing the guide never hides its entry.

The beginner route has eight short stops: safety, wallet basics, input,
derivation, public/private information, checking results, backups, and a
map of advanced tools. Aim for 5–8 minutes, to be measured with novice
readers. Feature lessons have 2–4 steps and are individually selectable.
The full catalog covers all features; do not require reading it all in
one session. Back, Next, Contents, and Close remain available. Finishing
offers Choose another feature and Restart basics. No countdown, score,
confetti, or pressure to create a funded wallet.

Every step uses one shared renderer and this content structure:

1. A plain-language title and at most two short explanatory paragraphs.
2. A concrete analogy or fixed, clearly labeled example where useful.
3. **What to check**: one practical action or observation.
4. **Limits**: a relevant boundary, close to the claim it qualifies.
5. Optional **Learn the term** disclosure for technical vocabulary.

Use adult, friendly English. Introduce a term before using its abbreviation.
For example: “An address is like a payment destination. Your private key
is the secret that lets you spend. Checking an address does not prove that
the device holding its key is safe.” Keep jokes out of risk explanations.

## Beginner route content

| Stop | Explanation and practical takeaway |
| --- | --- |
| Before starting | Download and verify a copy; use an appropriately isolated device for real secrets. Offline browser status cannot prove an air gap. The app cannot protect a compromised computer, clipboard history, screenshots, printers, or all residual memory. |
| The wallet family | User-supplied randomness becomes recovery information; a seed phrase leads to a wallet, and a wallet can derive many keys and addresses. EntropyLab does not supply secret randomness, hold coins, or connect to Bitcoin. |
| Bring your own randomness | Explain dice, coins, and cards, sufficient input, and recording the exact method. Hashing does not add randomness; a fairness check cannot certify security. Human-picked phrases and short transcripts are unsuitable for real funds. |
| Follow the same recipe | Explain derivation path as a route to an address, network as the chosen address/checking rules, and receive versus change. Same complete inputs/settings reproduce the same result. A different BIP39 passphrase creates a different wallet, often without an error. |
| Know what can be shared | Addresses and watch-only descriptors cannot spend but expose financial privacy. Seed phrases, private keys, extended private keys, and passphrases are secrets. A fingerprint/LifeHash is a recognition aid, not authentication. |
| Check before trusting | Compare network, path, fingerprint, and addresses against an independent trusted wallet or signing device. Startup checks help detect some faults, not every attack. Never infer balance or ownership from a calculator result. |
| Keep a usable backup | Preserve the original recovery material, required passphrase, method/settings, and multisig policy as applicable. A watch-only sheet is not a spending backup. Explain print/download/clipboard exposure and session-loss limits. |
| Find the right tool | Present the selectable catalog below. Finish with an optional self-check: identify a secret, distinguish watch-only from spending recovery, and explain why offline status is not proof of safety. Completion reflects reading, never a security certification. |

## Feature catalog and coverage

| Lesson | Explain | Boundary to make explicit |
| --- | --- | --- |
| Keys: input methods | Dice variants, coins, cards, number bases, hex, seed phrases, extended keys, WIF/raw/mini keys; optional method sync and fairness panels | Methods encode/transform supplied material; hashing and longer word counts do not repair weak inputs. Brain-wallet lab text is unsafe for novice funding and distinct from a BIP39 passphrase. |
| Keys: wallet settings | Word count, passphrase, address types, standard/custom paths, indexes, hardening, receive/change and network picker | Settings affect recovery; network selection establishes formats/checks, not a connection. Advanced overrides can differ from defaults. No recommendation to change hardening casually. |
| Keys: results and stations | Fingerprint/LifeHash, public/private reveal, address QR, multiple keys, rename, edit/new/update | Similar icons or fingerprints do not prove identity; replacing a station key can change its wallet. |
| Recovery and exports | Descriptors, public extended keys, SLIP-132 prefixes, watch-only/private sheets, Bitcoin Core wallet.dat, birthday/rescan, static/animated QR where present on this branch | Public exports reveal wallet activity; private exports permit spending. Prefix swaps do not create a new key. The calculator cannot scan balances or verify a successful restore. QR is a transfer format, not protection. |
| Multi Signature | Several independent keys, m-of-n threshold, co-signer origins, policy/descriptor, key order, receive address verification, watch-only exports and BIP388 policies | No signing here; lost quorum can prevent recovery. Reusing one person's keys does not create independent custody. Preserve policy and required signer backups. Private descriptors are refused. |
| PSBT Inspector | A PSBT is a transaction worksheet; inputs, outputs, claimed amounts/fees, change matching, raw transaction inspection, inscription hints, completed/problem/incomplete checks | Claims in a file are not chain truth. Missing previous outputs limit checks. A completed check is not a safe-to-sign verdict; the guide must never suggest automatic approval. |
| PSBT Editor | Field editing, diagram, semantic comparison, validation, export/QR and advanced broken-file mode | Never signs or broadcasts. Editing may invalidate signatures or change where money goes. Differences/valid serialization are not safety judgments. Keep broken-file mode out of beginner exercises. |
| Nonce Inspector | Repeated signing randomness can endanger keys; ECDSA/Taproot analysis, supported deterministic comparisons, anti-exfil checks and optional history | Scope depends on signature type and available data. No clean universal verdict; incomplete means unproven. History is correlation-sensitive; session key checks involve secrets. |
| BIP85 Child | One parent reproducibly derives child recovery material by application/index; supported phrases, keys, hex and passwords; child selection/removal | Parent compromise threatens children. Child recovery requires its exact recipe or its own backup. Derivation does not add randomness. |
| Silent Payments | Reusable payment code, receive labels, scan/spend roles, send calculation, pasted output verification, URI and DNS text | No chain scanning, DNS lookup, broadcasting or automatic payments. Scan secrets affect privacy; spend secrets control money. Publishing DNS text requires separate action outside the app. |
| Vanity Address | Deterministic passphrase/account search, expected time, stop/resume, found result and explicit Update key | Looks do not improve security. Time is an estimate. Preserve the found passphrase/path; Update key changes the wallet. Opening a lesson never starts a search or benchmark. |
| Session and safety controls | Clear/end session, reveal, on-screen keyboards, local security log, startup checks, theme/language and offline external-link QR behavior | No guaranteed secure erasure; browser keyboards are not malware protection. Security log records browser signals, not proof of network isolation. |
| Lightning: availability note | Explain node-identity recovery and supported aezeed/BIP39 conventions | Currently hidden from release navigation; not a payment/channel recovery promise and never creates seeds. Do not expose its hidden workspace through the guide. |
| Journal: availability note | Explain notebook, notepad, input-only key manager, snapshots/logs and explicit file download/restore | Currently hidden from release navigation. No browser wallet storage; blank-password files have no access protection. Imported inputs require review and fresh derivation. Closing loses unsaved work. Do not expose hidden controls. |

Before implementation, map every catalog row to current source behavior
and stable feature IDs on this branch. Coverage follows actual released
capabilities, not proposed features or the older PR branch. Hidden features
receive honest availability notes, with full lessons enabled only when
their release navigation becomes available.

## Implementation

- Add a small `src/js/feature-guide.js` controller and
  `src/js/feature-guide-content.js` catalog. Follow the existing build's
  module-inlining path; no runtime module fetch, dynamic import, CDN,
  third-party library, fonts, images, telemetry or remote documentation.
- Reuse `createModal()` for focus trapping, Escape/backdrop dismissal and
  focus return. Extend the existing button, note, disclosure and modal
  patterns; all styling uses documented global tokens. Entry markup lives
  in `src/shell.html` or the existing shared tool-intro builder as appropriate.
- Content records use stable lesson/step IDs, a section ID, translated
  English text, limits, optional glossary entries and an optional tool ID.
  Prefer plain text nodes with `hodlTText`. Follow established sanitized
  helpers for any rich content. Never interpolate wallet data into lessons.
  Locale catalogs and provenance files remain automation-owned.
- Keep state to lesson ID, step index and completion IDs in page memory.
  Closing preserves the step for this sitting; reload starts fresh. No
  secret, filename, transcript, PSBT bytes or free-form user input enters
  guide state. Cross-session progress is deferred to keep v1 small and
  avoid another storage contract. Replay always works without storage.
- No automatic navigation, derivation, import, export, clipboard action,
  reveal or wallet mutation. The existing workspace switch changes rendered
  results and starts Vanity benchmarking; explicit Open this tool closes
  the guide and uses the normal navigation path with those existing effects.
  Offer it only for released tools and make the action clear. Keep Back/Next
  completely separate from workspace switching.
- Use one delegated event handler and one render path. Render only the
  current step; lazily create the modal on first invocation. A missing or
  unavailable lesson returns to contents. Integrate with end-session/page
  teardown so it cannot retain input references or reopen after teardown.
- Keyboard and screen-reader support: titled dialog, meaningful focus on
  step changes, polite step-count announcement, disabled boundary controls,
  stable id/data hooks and ordinary disclosure semantics. Support narrow
  screens, zoom, both themes and reduced motion without positioned tooltips
  or a spotlight/scroll tracking engine.

## Size and verification

Provisional budget: at most 30 KiB additional uncompressed HTML artifact,
including initial English content, controller, markup and CSS. Target under
8 KiB for controller/CSS/entry markup, with the rest for teaching content.
Measure actual before/after artifact bytes; these are budgets, not current
measurements. Existing locale compression will apply to later automated
translations; report their separate growth when available. Avoid a
compression library, illustrations and bespoke animation. Adjust content
scope transparently if the measured budget and clarity conflict.

Test behavior, not wording/classes/CSS source: navigation boundaries,
contents/deep links, close/resume/replay, unavailable tools, translation
fallback, teardown, and no writes to wallet state or secret access while
opening or stepping. Independently authored malicious text must remain text.
Reuse the existing offline/network-silence checks and modal focus coverage;
browser tests verify entry points, keyboard focus/return, Escape, screen
widths and operation from the saved offline artifact. Use IDs/data hooks.
Do not pin complete lesson sentences or presentational values in unit tests.
Security-sensitive guards follow AGENTS.md's test-before-code requirements.

Review desktop/phone and dark/light captures. Have novice readers attempt
the three beginner self-checks without help and locate a feature lesson
again after completion. Revise confusing copy before expanding the catalog.
Run `npm run build && npm test` before finishing implementation, plus relevant
browser/offline checks and `npm run reproduce` for the final bundled change.

## Delivery slices

1. Approve this content map, entry points and memory-only progress behavior.
2. Implement/test the reusable controller and eight-stop basics route.
3. Fill feature lessons and contextual entries using the same renderer.
4. Complete visual/accessibility/offline/size checks and novice copy review;
   update README with invocation, replay and limitations. No dependencies.

Optional later additions: a shared in-guide glossary, “Which tool do I need?”
choice tree linking only to lessons, and fixed paper-style worked examples.
Avoid demo-wallet injection in v1; it adds unnecessary risk and state.


## Implementation and validation record

Implemented: 15 selectable lessons (37 steps), including the eight-step
basics route, released-feature lessons and honest Lightning/Journal
availability notes. Guide remains above the tool tabs after intro dismissal;
eight tool introductions share one contextual-entry builder. Close/resume,
completion/replay, keyboard focus and locale refresh use the shared modal.
The body scrolls while the header and navigation remain visible.

Security contract: known lesson IDs display bundled plain text without
reading secrets, using randomness/cryptography, storing data, contacting the
network, or changing wallet state; unknown IDs fall back to contents and
hidden tools have no navigation action. Only explicit Open this tool invokes
normal released-tool navigation. No demonstration wallet inputs are created.

Initial red: `node --test test/feature-guide.test.mjs` failed because the new
feature-guide module did not exist. This new-capability test already included
independent fixtures for bounded navigation, completion/replay, known and
unknown IDs, hidden-tool refusal, and sentinels rejecting secret access,
storage, network access and hostile text becoming markup.

Final validation:

- `node --test test/feature-guide.test.mjs`: six passing guide tests.
- `node --test test/secret-clear.test.mjs test/feature-guide.test.mjs`:
  87 passed, including wallet preservation during locale refresh.
- `npm run build && npm test`: 2,127 passed, zero failed, 10 skipped.
  Chrome's hosted/offline integration checks, including guide coverage, pass.
  Firefox and Edge are absent on this host; their engines were skipped.
- `npm run verify`: passed.
- `npm run reproduce`: both staged HTML and service-worker builds match.
- `node scripts/i18n-sync.mjs`: valid; missing lesson translations use English
  fallback. No locale catalog or provenance file was edited.
- Rendered before/after review: 1280px desktop and 320px phone, dark and
  light. No horizontal overflow; all navigation controls remain in view.
  The shared paragraph gap computes to the existing 16px component token.

The source-only addition grows the commit-stamped HTML from 6,888,000 to
6,918,463 bytes: 30,463 bytes (29.7 KiB), within the 30 KiB budget. No new
dependencies, media assets, runtime module requests or persistence were added.
This is a local build measurement; later automated translations can add size.

Copy was reviewed against the novice questions and source behavior above.
A study with independent novice readers has not been performed; that remains
useful human usability feedback, not a condition for using or replaying the
implemented guide. Optional glossary expansion, a goal-based choice tree and
worked-example illustrations remain future ideas.

### Optional UX follow-up

Four goal-based routes now organize the existing lessons. Browse all lessons
and unreleased availability notes are separate disclosures. Only Guide gains
these controls: core tool views retain their existing entry points. Routes
advance only when selected explicitly; closing and resuming preserves the route.
Expandable public-information diagrams highlight the current stage, and four
optional ungraded checks explain common misunderstandings without blocking Next.
Closed disclosures are excluded from keyboard focus traversal.

The unchanged security contract above also applies to route selection and
answers. Initial focused red failed on the missing route and answer controls;
the same eight focused tests now pass with I/O, secret-access and randomness
sentinels active. Hosted/offline browser coverage also exercises both answers.
The artifact grows by 4,113 bytes over the first guide implementation, to
6,922,576 bytes (33.8 KiB total over the pre-guide baseline). This extends the
original provisional 30 KiB budget by 3.8 KiB for the approved UX follow-up.
No dependencies, media, storage, or runtime requests were added. Verify and
reproduce pass; desktop/phone dark/light review retains visible navigation
and no horizontal overflow, including expanded optional sections.
Final follow-up `npm run build && npm test`: 2,129 passed, zero failed,
10 skipped; Chrome hosted/offline passes, Firefox/Edge remain unavailable.

### Feedback follow-up (2026-10-09)

Responded to [the submitted beginner review](https://github.com/OogaBoogaX/entropylab/pull/818#issuecomment-6074601934).
The reviewer’s reported runs are their evidence, not this follow-up’s tests.
Our Chrome reproduction confirmed clipped quiz feedback and touching desktop
finish buttons. Shared row spacing and focused/scrolled plain-text feedback
fix those outcomes, verified at desktop and 320px mobile widths in both themes.

Checks now appear once after the relevant lesson concepts. Completed-route
reopening offers an explicit next lesson; finish screens offer lesson links.
A direct basics entry, route summaries, a single combined progress line, and
first-use glossary terms improve discovery. Diagram stages are assigned to
concept IDs rather than inferred from step position. Exact UI labels and an
adjacent seed-equivalent warning clarify recorded-input handling. Download
instructions distinguish checksum integrity from artifact-attestation
provenance; they do not describe SHA256SUMS.txt as signed. The advanced-user
warning remains, and practice examples must never hold real recovery secrets.

Initial new focused regressions failed on early quiz rendering and completed
route reopening against 00f416b; all 11 focused tests pass after the change.
Local `npm run build && npm test`: 2,135 passed, zero failed, 10 skipped,
including all 130 Chrome hosted/offline integration checks. Verify, two-path
reproduce, and report-only i18n validation pass. Locale catalogs are unchanged.
Physical-phone, screen-reader, and further independent novice retesting remain
human validation gaps; desktop mobile emulation does not establish those.
