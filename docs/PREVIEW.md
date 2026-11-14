# Preview flag

EntropyLab merges unreleased features hidden. A **preview build** turns them
on for the team; the release build ships without them. A preview build is
never deployed.

## Gating JavaScript

ES modules read the compile-time constant `__ENTROPYLAB_PREVIEW__`, which
esbuild replaces with `true` or `false`:

```js
if (__ENTROPYLAB_PREVIEW__) {
  // unreleased feature
}
```

Release builds define it as `false`, so the branch is dropped as dead code.
Classic scripts do not see the constant; none need it today.

## Gating markup

Wrap markup in the exact comment lines `<!-- preview -->` and
`<!-- /preview -->`:

```html
<!-- preview -->
<button id="unreleased">…</button>
<!-- /preview -->
```

`scripts/preview-blocks.mjs` removes the block (markers and contents) from a
release build and removes only the markers from a preview build. Markers must
be balanced and never nested; a stray, nested or unclosed marker fails the
build. `shell.html` reaches the artifact twice — injected into `index.html`
and inlined into the app bundle for the boot render — and the build applies
the same transform to both copies.

## Building

```sh
node scripts/build.mjs --preview --out /tmp/entropylab-preview
```

Like `--test-hooks`, `--preview` requires `--out` outside the repository root,
so the release artifact never carries unreleased features.

## Unhiding a feature

Unhiding is a team decision: remove the feature's gate (the
`if (__ENTROPYLAB_PREVIEW__)` branch or the `<!-- preview -->` block) in one
PR.
