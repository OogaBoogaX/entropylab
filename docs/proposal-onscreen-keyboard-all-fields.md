# Proposal: On-screen keyboard for all text/number input fields on touch devices

## Problem

EntropyLab already solves the **hard problem**: restricted-charset on-screen
keyboards for sensitive key-material inputs (seed phrase, BIP39 passphrase,
private key, Base64, Bech32). These keyboards are curated input surfaces that
prevent invalid characters — a security feature, not a UX convenience. They're
the right tool for their job.

But there's a **missing use case**: what if there's no system keyboard at all?

The existing keyboards cover fields where *security demands* a restricted
input surface. They don't cover fields where the assumption was simply "the
platform provides a keyboard." On a phone, the system IME handles the rest.
On a desktop, the physical keyboard. On an **air-gapped touch kiosk** —
EntropyLab's stated deployment target — those ~25 non-sensitive fields are
inaccessible.

The gap isn't an oversight in a rapidly evolving codebase. It's a
**complementary use case** that the existing architecture doesn't address:
a general-purpose on-screen keyboard for non-sensitive inputs on touch-only
devices where no system keyboard exists.

## Proposed approach

**Add a lightweight, general-purpose on-screen keyboard for non-sensitive
text/number inputs, shown only on touch devices.**

### Detection

Use `window.matchMedia("(pointer: coarse)")` or `"ontouchstart" in window`
to detect touch-only devices. On desktop/laptop, nothing changes — no
keyboard button appears, no DOM added. This keeps the hosted site
unaffected.

### Scope

Add the keyboard toggle button to `<input>` elements that:
- Are `type="text"`, `type="number"`, or have no type (defaults to text)
- Are **not** already covered by an existing on-screen keyboard (seed,
  passphrase, private key, Base64, Bech32)
- Are not `disabled`, `readonly`, or `hidden`
- Are not `type="checkbox"`, `type="radio"`, `type="hidden"`, etc.

### Keyboard layout

A simple numeric + minimal-symbol layout is sufficient for the fields
in scope (derivation paths, numeric parameters):

```
1 2 3 4 5 6 7 8 9 0
/ ' ⌫
```

For fields that also need letters (e.g. `msig-account` is `type="text"`),
a full lowercase layout with a mode toggle (aA1) — same pattern as the
existing passphrase keyboard.

### Implementation shape

Following the AGENTS.md guidance on reuse:

1. **One CSS rule** for the toggle button (extend the existing
   `.seed-keyboard-toggle` paradigm, or add a `.general-keyboard-toggle`
   alongside it)
2. **One builder function** (`hodlGeneralKeyboardToggleMarkup`) alongside
   the existing `hodlKeyboardToggleMarkup`
3. **One keyboard renderer** (`hodlGeneralKeyboardMarkup`) alongside
   `hodlKeyboardMarkup`
4. **One binding function** (`hodlBindGeneralKeyboard`) alongside
   `hodlBindPassphraseKeyboard`
5. **One init call** in `hodlBoot()` that scans for eligible inputs and
   attaches toggle buttons — event delegation, same pattern as the
   existing QR-references module (no per-field registration)

### What stays the same

- The existing specialized keyboards (seed, passphrase, private key,
  Base64, Bech32) are untouched — their security properties (restricted
  charset, no system IME) are critical and must not be weakened
- The `data-on-screen-keyboard` attribute system is reused
- The toggle button SVG icon is the same visual language
- The keyboard panel CSS (`.seed-keyboard`) is extended, not duplicated
- No new dependencies — pure DOM, same as the existing system

### What this does NOT do

- Does not replace the OS/compositor keyboard (wvkbd, system IME) —
  those are complementary; this is app-level for fields that don't need
  the restricted-charset keyboards
- Does not add keyboards to sensitive fields — the existing ones stay
- Does not change behavior on non-touch devices

## Why this matters for EntropyLab

EntropyLab's tagline is "Self-contained, air-gapped Bitcoin key and
wallet calculator." The air-gapped use case is overwhelmingly touch-only
tablets and kiosks. Today, a user on such a device can generate entropy
(dice, card draws) and enter seed phrases (via the specialized keyboard),
but **cannot**:

- Set a custom derivation path
- Configure multisig parameters
- Adjust vanity search parameters
- Set BIP85 parameters

These are real features that are simply inaccessible on the target
platform. This PR makes them usable.

## Testing

- Unit tests for the keyboard builder and binding (same shape as existing
  tests)
- Browser suite: verify toggle buttons appear on touch simulation,
  absent on non-touch
- Manual: verify on a RockOS kiosk (cage + wlroots + touchscreen)

## Scope of this PR

This is a **feature addition**, not a refactor. No existing code is
restructured — the new keyboard system is additive, alongside the
existing one. The smallest change that covers all eligible fields.
