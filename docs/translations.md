# Translations

English is the single source of truth for interface copy. Feature pull requests
add or change `src/locales/en.json`, wire the key into the interface, and run:

```sh
npm run i18n:sync
npm run i18n:check
```

`i18n:sync` copies English into the inline HTML fallbacks for `data-i18n`,
`data-i18n-html`, `data-i18n-aria`, `data-i18n-placeholder`, `data-i18n-title`,
and `data-i18n-alt`. It also checks literal `hodlT()`, `hodlTText()`, and `hodlTAttr()`
references. CI runs the read-only check, so the catalog and fallback markup
cannot drift.

The wiring check rejects new hardcoded text. `scripts/i18n-unwired.json` is the
temporary inventory of older interface text that still needs keys in the next
rollout step. Do not add entries for new copy. Regenerate it only when a wiring
change intentionally shrinks that inventory.

## Missing and stale translations

Every translated catalog has its own source record:

```text
src/locales/es.json
src/locales/.sources/es.json
```

The source record stores `sha256(English text)` for each translated key. If a
translation is missing, or its recorded English hash no longer matches, the
built app uses the current English value for that key. The language remains in
the selector; one lagging string never hides the whole language.

The build injects the stale-key map into the bundled app. Serving modules
directly from `src/` is development-only and does not apply stale-key filtering;
verify production behavior with a freshly built `entropylab.html`.

Run `npm run i18n:status` to list missing and stale keys. Staleness is reported
for translation work but does not block an English-only feature pull request.
Malformed source records, unknown keys, unsafe markup, changed placeholders,
and catalog control characters do fail CI.

## Updating a translation

Change only one language at a time. After translating a key, record the exact
English source it was translated from:

```sh
npm run i18n:mark -- --locale es --key journal.saveEntry --key journal.cancel
npm run i18n:check
```

A language pull request should touch exactly its catalog and source record.
Do not manually copy current hashes onto translations that were not checked
against the current English; that would hide stale work.

The later translator workflow will use the same two-file shape and the same CI
checks. This pull request prepares those deterministic inputs; it does not call
a model, add an API secret, or change merge policy.

Translations are committed inputs to the normal build. No translation service
or model runs during `npm run build`, so the build remains reproducible.
Run `npm run build` before `npm test`; the browser suites exercise the generated
`entropylab.html`, not an older committed artifact.
