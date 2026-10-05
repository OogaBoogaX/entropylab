# UI Patterns

How EntropyLab's interface is built: the design tokens, the shared patterns,
and the rules that keep them shared. Read this before changing any UI code
(`src/css/styles.css`, `src/shell.html`, or markup and styling built in
`src/js/`).

The short version:

- **Use a token, never a raw value.** Every font size, corner radius, space
  and colour in `styles.css` reads a custom property from `:root`.
- **Name by job, not by value.** Two tokens may hold the same value today;
  each says what it is for, so one can change without moving the other.
- **No per-tool tokens.** A tool uses the global tokens. If a tool seems to
  need its own, the global set is missing a job: add it there.
- **Find the pattern before adding a style.** A repeating control, layout or
  interaction is expressed once, as one rule or one builder, and extended.

## Contents

- [Working on the UI](#working-on-the-ui)
- [Tokens](#tokens)
  - [Text sizes](#text-sizes)
  - [Spacing](#spacing)
  - [Insets, indents and gutters](#insets-indents-and-gutters)
  - [Corner radii](#corner-radii)
  - [Colours](#colours)
  - [What stays raw](#what-stays-raw)
- [Surfaces](#surfaces)
- [Patterns](#patterns)
  - [Labels and help text](#labels-and-help-text)
  - [Notes](#notes)
  - [Buttons, tabs and hover](#buttons-tabs-and-hover)
  - [Boxed icon buttons](#boxed-icon-buttons)
  - [Dropdowns](#dropdowns)
  - [Modals](#modals)
  - [Copying to the clipboard](#copying-to-the-clipboard)
  - [Disclosures and section bands](#disclosures-and-section-bands)
- [Themes](#themes)
- [Translation and markup](#translation-and-markup)
- [Testing UI changes](#testing-ui-changes)

## Working on the UI

- Markup lives once, in `src/shell.html`. The build injects it into
  `index.html`; never edit markup in two places.
- Edit sources only. `entropylab.html` is a build artifact: rebuild it with
  `npm run build` to look at a change, and never commit it.
- Design work is reviewed visually. Make the change, rebuild, and show it.
  Anything that alters what is on screen is shown as a before/after capture
  (desktop and phone width, dark and light theme) before it is kept.
- A pass that must not move anything (a refactor, a tokenisation) is proven
  by measurement: compare every element's computed styles before and after,
  across the app's states and widths. It is not proven by tests.

## Tokens

All tokens are defined in the first `:root` block of `src/css/styles.css`,
each with a comment naming its job. The light theme redefines colours under
`:root[data-theme="light"]`. The tables below summarise them; the comments in
the stylesheet are the reference.

### Text sizes

`--text-*`, grouped by job.

| Group | Tokens |
|---|---|
| Base and running text | `--text-base` 16 · `--text-body` 14 · `--text-note` 12 · `--text-compact` 13 |
| Names of things | `--text-label` 14 · `--text-label-small` 12 · `--text-caption` 11 · `--text-tag` 11 |
| Controls and fields | `--text-control` 16 · `--text-control-compact` 15 · `--text-control-small` 14 · `--text-field` 14 · `--text-field-small` 12 |
| Values | `--text-readout` 18 · `--text-readout-small` 16 · `--text-data` 13 · `--text-data-small` 12 · `--text-micro` 10 · `--text-micro-narrow` 9 |
| Headings and brand | `--text-heading` 24 · `--text-heading-small` 18 · `--text-heading-note` 16 · `--text-brand` 22 / `-compact` 19 / `-narrow` 17 |
| Entry pads and dealt cards | `--text-keypad` 18 · `--text-keypad-small` 15 · `--text-card-suit` 16 · `--text-card-rank` 13 |
| Glyphs that act as icons | `--text-icon-large` 28 · `-medium` 26 · `-small` 24 · `-inline` 18 · `--footer-emoji` 21 |

Pick by what the text is, not by the size you want: a field note is
`--text-note`, a monospace value is `--text-data`, a label is `--text-label`.

### Spacing

`--space-*`, for gaps and margins between things:

`--space-hairline` 2 · `--space-tight` 4 · `--space-snug` 6 ·
`--space-control` 8 · `--space-related` 12 · `--space-component` 16 ·
`--space-section` 20 · `--space-intro` 24 · `--space-major` 32 ·
`--space-lede` 48

Rhythm: `control` joins a label to its help, `component` separates peer
controls and action rows, `section` separates blocks inside a card, `intro`
follows context before a tool, `major` and `lede` are page-level seams. Every
action row (`.tool-actions`) opens on `--space-component`.

### Insets, indents and gutters

Padding is named after the box it pads, because it is a pair (vertical,
horizontal) that belongs to a component:

| Token | Box |
|---|---|
| `--inset-field` | inputs, selects, anything that must line up with them |
| `--inset-compact` | compact fields and cells |
| `--inset-option` | menu options, word slots, tooltips |
| `--inset-note` | notes and panels in the note pattern |
| `--inset-box` | choice boxes, list items, QR frames |
| `--inset-card` / `--inset-modal` | cards / modal cards and the overlay |
| `--inset-button` / `--inset-tab` | buttons and tabs (height is set separately) |
| `--inset-cell`, `--inset-panel`, `--inset-menu`, `--inset-banner`, `--inset-toolbar`, `--inset-icon-button`, `--inset-chip`, `--inset-tag`, `--inset-button-tight` | as named in their comments |

`--indent-list` is a bulleted list's left indent. `--gutter-page`,
`--gutter-panel` and `--gutter-panel-compact` are side padding that shrinks on
narrow screens: they are redefined inside the 719px and 400px media blocks,
so a rule uses the token and never restates the breakpoint values.

### Corner radii

| Token | Value | For |
|---|---|---|
| `--radius-panel` | 20 | the outer card and workspace panel |
| `--radius-field` | 12 | what you type into or pick from |
| `--radius-container` | 12 | surfaces that hold controls: modal cards, menus, trays |
| `--radius-control` | 8 | what you click: buttons, tabs, chips, toggles, pads |
| `--radius-small` | 6 | small controls and compact inputs |
| `--radius-tiny` | 4 | LifeHash icons, checkboxes, focus rings |
| `--radius-pill` | 999px | tracks, progress bars, scrollbar thumbs |
| `--radius-round` | 50% | circles |

A shape rounded on some corners only (tabs, the workspace panel, segmented
control ends) uses the same token on those corners: `0 0 var(--radius-panel)
var(--radius-panel)`.

### Colours

Theme colours (`--bg`, `--surface`, `--surface-2`, `--fg`, `--muted`,
`--faint`, `--border`, `--accent`, the `--danger`, `--ok`, `--warn`, `--blue`
families) are defined per theme. Derived and fixed colours:

| Token | For |
|---|---|
| `--muted-strong` | secondary text that must still read easily (halfway from `--muted` to `--fg`) |
| `--selection-accent-ink` | the bright hover ink every control uses |
| `--option-hover-ground` / `--option-selected-ground` | dropdown option states |
| `--image-ground` | the white matte behind LifeHash icons and QR codes (QR codes need it to scan) |
| `--on-color` | ink on a coloured ground |
| `--wordmark` | the EntropyLab wordmark (pure white, pure black in light) |
| `--progress-start` / `--progress-end` | the derive progress gradient |
| `--scrim` | the modal overlay; floating menu and modal shadows |
| `--print-paper` / `--print-ink` / `--print-highlight` | print only |

A colour that needs a step between two theme colours is a `color-mix()` of
theme tokens, so it follows the theme on its own. If the same mix is needed
twice, it becomes a token.

### What stays raw

Some values are geometry, not design decisions, and stay raw px on purpose
(the stylesheet lists them in `:root`):

- negative offsets and 1px border overlaps;
- the number-base and D++ calculation panels, fitted to their grids;
- room reserved for an overlay or button (the derivation index fields, the
  Journal log's copy button);
- position nudges (`top`, `left`, `translate`);
- the PSBT diagram's column gap, a few shadow strengths, and the 1px
  fairness marker;
- the network status tag's `1px 2px`, a deliberate exception.

Picker spacing inside the footer pickers is also fitted to those controls.

## Surfaces

- **Interactive surfaces are rounded and have a painted border:** fields,
  buttons, tabs, chips, dropdowns.
- **Readouts and notes are square and edgeless:** values you read, not touch
  (the Vanity formula terms, notes). QR codes are the one exception: they keep
  their 8px radius and border.
- Cards that only group content (`.static-card`) drop their border.

## Patterns

### Labels and help text

- A field or section name is `.label` (or `label.field`, which wraps its
  control). A sentence written to sit directly under a label is
  `.label-description`; small help under a field is `.field-note`. The
  label-to-description spacing is set once, for every pair.
- Dropdowns, fields and buttons set their own font weight; a control inside a
  bold `label.field` must not inherit the label's weight.

### Notes

One note pattern for every warning, tip and intro: `.edge-note`, a square
block with a coloured left edge and a lightly tinted ground.

- Colour by meaning: `.is-private` (red, secrets and danger), `.is-public`
  (green, safe to share), `.is-info` (orange, intros), `.is-muted` (grey).
- A note with a title wraps in `.edge-note-titled`, with `.edge-note-title`
  (and its matching `.is-private` / `.is-public`) above the note.
- A note with no message draws nothing: an empty or `[hidden]` note is not
  displayed.
- Do not build a new banner or bordered box for a message. Use a note, or a
  bullet in the Important list if it is page-wide advice (the browser
  translation warning is one, revealed only when translation is detected).

### Buttons, tabs and hover

- `.btn` with its variants is the only button. Secondary actions and small
  controls take `--text-control-small`.
- Hover is shared: controls declare only which colours they use, through
  `--hover-edge` and `--hover-ink`, and one rule applies them. Do not write a
  per-control `:hover` colour.
- `.segmented-control` is the one segmented switch; its end corners take
  `--radius-control`.

### Boxed icon buttons

Copy, theme and keyboard toggles are `.boxed-copy-button` /
`.theme-toggle` / `.seed-keyboard-toggle`: one square chrome, sized by
`--box-size` (44px by default, smaller where a table needs it). An
icon-only button carries an accessible name and a `title` for its hover
label.

### Dropdowns

Every `<select>` is replaced at runtime by the shared custom dropdown
(`src/js/enhanced-inputs.js`, `.custom-select`).

- The base sets regular mono at `--text-field`; a dropdown overrides it only
  for a real need.
- One set of option states for every list, the footer network menu
  included: the chosen option sits on `--option-selected-ground` in the
  accent with a check at its right edge; the hovered or focused option is
  raised on `--option-hover-ground` in `--selection-accent-ink`. The short
  language list omits the check.
- Footer menus open upward; the network menu centres on the footer row so it
  stays on screen.

### Modals

- Every bundled modal is built by `createModal()` in `src/js/modal.js`, which
  owns the overlay, Escape and click-outside dismissal, the focus trap and
  returning focus. Do not build an overlay by hand (a test guards this).
- The card is `.modal-card`. A warning wears `.is-warning` (red frame, tinted
  ground, centred icon, red uppercase `.modal-warning-title`).
- The disclaimer gate's card (`.disclaimer-card`, `.disclaimer-text`) is
  shared: the End Session dialog and the screen it leaves use the same rules
  through their own classes in the same selectors, rather than a copy.
- Viewer modals end on `.modal-actions`: copy on the left, Close on the
  right.

### Copying to the clipboard

All copying goes through `copyText()` in `src/js/clipboard.js`; the icon
confirmation is `showCopiedIcon()`. A secret is built at the moment of the
click and handed straight to `copyText()`, never stored on the control. No
other module writes the clipboard (a test guards this).

### Disclosures and section bands

- Collapsible sections are `<details>`; one whose open state should persist
  uses `hodlInitRememberedDisclosures`.
- Long forms mark where a section begins with `.section-band`, a faint
  full-width band behind its label.
- Repeated markup has one builder in `app.js`, for example
  `hodlKeyGroupMarkup`, `hodlPrivacyBarMarkup`, `hodlSeedCopyRowMarkup` and
  `hodlKeyboardToggleMarkup`. Extend a builder rather than copying its
  output.

## Themes

- Dark is the default; light redefines the theme colours under
  `:root[data-theme="light"]`, which the page always sets for light (including
  when it follows the system).
- Prefer colours mixed from theme tokens, so one rule works in both themes.
  When a theme needs a different step, override the token in the light block
  rather than writing a second rule per component.
- Check every visible change in both themes.

## Translation and markup

- User-facing text in markup is translated by a content sweep; the English
  text is the catalog key. Use `data-i18n-rich` on a block whose translation
  carries markup (bold leads, links) and `data-i18n-skip` on brand or
  technical content (prefixes, version stamps).
- Decoration that is not words (separator dots, checks) is drawn in CSS so
  it stays out of the translated strings.
- Do not edit the locale catalogs; new strings fall back to English until
  the translation workflow fills them.

## Testing UI changes

- Presentation is not unit-tested. Do not assert CSS declarations, class
  names or user-facing copy. Safety-critical wording may be pinned by a short
  stable phrase.
- Tests hook on ids and `data-*` attributes, never on classes.
- What is tested is behaviour and contracts: structure and order, aria
  wiring, a control that must stay hidden until something happens, two
  controls reading one token. A presentational rule that genuinely matters
  goes in the browser suite as a `getComputedStyle` check.
- Do not run the suite on every iteration. Run `npm run build && npm test`
  once before a commit and update any test that pinned changed wording to
  the contract it was guarding.
