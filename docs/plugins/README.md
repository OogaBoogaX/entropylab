# Plugin System

Plugins extend EntropyLab without touching the air-gapped core.

## Architecture

- The core (`entropylab.html`) stays air-gapped and never loads remote code.
- A plugin is a hosted page loaded in a sandboxed iframe.
- Communication happens over a versioned `postMessage` bridge with an
  allowlisted message set.

## Trust boundary

Seeds, private keys, and xpubs never leave the parent page. The plugin only
ever receives data the core explicitly grants — for example, an already-signed
transaction or a watch-only descriptor.

## Message API (v0, read-only)

| Message | Direction | Purpose |
|---|---|---|
| `entropy.ready` | plugin → core | Handshake |
| `entropy.getVersion` | plugin → core | Bridge version check |
| `entropy.getXpub` | plugin → core | Request a watch-only xpub |
| `entropy.getAddress` | plugin → core | Request a derived address |
| `entropy.onResult` | core → plugin | Response to a request |

Action requests ("please sign this PSBT") are deferred to a later version.

## SDK

A small JS helper wraps `postMessage` so authors write
`entropy.getAddress(...)` instead of raw message plumbing. Versioned so
plugins don't break when the core updates.

## First plugin: Slipstream

Receives signed transaction bytes from the core, posts them to
`slipstream.mara.com`, returns relay status. MARA sees the transaction and
the caller's IP — route through Tor when possible.
