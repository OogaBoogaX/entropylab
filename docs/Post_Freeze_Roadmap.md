# Post-Freeze Roadmap

This is the proposed order of work once the current feature freeze lifts.

## 1. MuSig2 (FROST)

First priority. Integrate MuSig2 for multisig key aggregation and signing.
This replaces the earlier "Frost pieces" plan — MuSig2 is the concrete scheme
we want, built on FROST. It changes how transactions are constructed and signed,
so it lands before anything that depends on signing assumptions.

## 2. Miniscript / Liana (`wsh()` policies)

Decode, summarize, and inspect `wsh()` Miniscript descriptors in the
air-gapped core. Target the same v1 scope SeedSigner #1026 is landing:
policy review plus address derivation for `wsh()`, not taproot signing.

Concrete first wallet: Liana-style inheritance
`wsh(or_d(pk(primary), and_v(v:pkh(recovery), older(N))))`.

The UI must show a plain-English policy, not just the descriptor string —
e.g. "primary key now, or recovery key after N blocks." Hidden script
paths must never be described as single-signature.

Reuse the existing miniscript descriptor work already in-tree. Do not
talk to Liana or any coordinator from the HTML file. File or QR import
of a descriptor / PSBT is enough. Any Liana file-to-QR helper is a
plugin later, not core.

Out of scope for this slice: `tr()` address derivation and signing,
persistent wallet registration, proof-of-registration.

## 3. Tor-friendly mode

Add a Tor-only toggle in settings. When enabled, every outbound request —
plugins, Slipstream, update checks — routes through the Tor daemon via SOCKS5,
with a clear "connected via Tor" indicator in the UI.

Longer term: host the online version as an onion service so air-gapped users
can load it without touching clearnet DNS or certificates.

## 4. Plugin system

Sandboxed iframes talking to the core over a versioned postMessage bridge.
Narrow allowlisted messages only — seeds and private keys never leave the
parent page. Ship a tiny SDK so plugin authors aren't hand-rolling plumbing.
Read-only first; action requests (e.g. "please sign") come later.

## 5. Slipstream (first plugin)

MARA's direct-to-miner relay. The plugin receives already-signed transaction
bytes, posts them to slipstream.mara.com, and returns status. Trust model is
explicit: MARA sees the transaction and the caller's IP, so Tor routing is the
recommended path.

## 6. Watch-only wallet plugin

A companion wallet plugin that turns the air-gapped core into a usable
wallet without moving the trust boundary. The plugin builds transactions
from the core's xpubs and addresses, hands the unsigned PSBT to the core
for signing, receives the signed bytes back, and broadcasts them — via
Slipstream, a node, or a public mempool relay.

The plugin never holds keys, never signs, and never sees seed material.
Signing stays in the air-gapped core; the plugin only displays and
orchestrates. This is the same trust split as Slipstream: the plugin is
the online half, the core is the offline half.

Depends on the plugin system (item 4) and benefits from Tor-friendly mode
(item 3) for the broadcast path.

## 7. Nonce reuse journal

Every time the PSBT inspector decodes a signature, log the R-value (the
public nonce commitment), the message hash, and the key origin into a local
journal. R-values are public by design, so the journal syncs between the
air-gapped core and the online sister app for cross-referencing across
devices. A repeated R with a different message hash under the same key
origin is a nonce reuse, and the private key is recoverable in one step.
The journal flags it the moment it appears.

Storage is cheap: 32 bytes per signature. The journal lives in both places
so a collision on one device catches a reused nonce from another.

## Deferred

Liquid, Lightning, and Ark stay out until their interfaces stabilize. Pull in
only a thin adapter if something becomes a hard dependency.
Taproot (`tr()`) signing stays deferred with Miniscript v1.
