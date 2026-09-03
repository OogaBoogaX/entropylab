# Translations

English is the single source of truth for interface copy. Feature pull requests
add or change `src/locales/en.json`, wire the key into the interface, and run:

```sh
npm run i18n:sync
npm run i18n:check
```

`i18n:sync` copies English into the inline HTML fallbacks for `data-i18n`,
`data-i18n-html`, `data-i18n-aria`, `data-i18n-placeholder`, `data-i18n-title`,
and `data-i18n-alt`. It also validates direct and conditional `hodlT()`,
`hodlTText()`, and `hodlTAttr()` keys. Dynamic prefix construction is rejected;
deferred `hodlNote()` and `hodlError()` keys receive the same checks.
Variable-only calls are reported as requiring behavioral coverage and warn at
runtime if they resolve to a missing English key. CI runs the read-only check,
so the catalog and fallback markup cannot drift.

The wiring check rejects hardcoded interface text, including translated
attributes. `scripts/i18n-unwired.json` is intentionally empty and must stay
empty. New copy must be added to `en.json` and wired at the same time.
Elements whose text is owned and repeatedly replaced by runtime state are
explicitly excluded from the static wiring pass so a locale change cannot
replace a live result with its startup fallback.

Keys under `literal.*` are technical values such as paths, symbols, protocol
identifiers, and build metadata. They are copied unchanged by translation
automation. CI rejects a non-English `literal.*` value that differs from
English.

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
When a feature removes an English key, old locale values are reported as
obsolete and made inert in the build; translation automation can later remove
each value and its source hash together. This lets feature PRs add, change, and
remove interface elements without editing every locale. Malformed source
records, unsafe markup, changed placeholders, and catalog control characters
do fail CI.

## Updating a translation

Change only one language at a time. After translating a key, record the exact
English source it was translated from:

```sh
npm run i18n:mark -- --locale es --key journal.saveEntry --key journal.cancel
npm run i18n:check
```

A language pull request must touch exactly its catalog and source record. The
automated translator added in rollout Part 4 will create that two-file change,
run the same CI checks, and merge it only when the translation-only gate passes.
Do not manually copy current hashes onto translations that were not generated
from the current English; that would hide stale work.

The translator workflow uses the same two-file shape and deterministic checks.
The model runs only while preparing a translation commit; it never runs inside
the build.

Translations are committed inputs to the normal build. No translation service
or model runs during `npm run build`, so the build remains reproducible.
Run `npm run build` before `npm test`; the browser suites exercise the generated
`entropylab.html`, not an older committed artifact.
