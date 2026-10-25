# Threat model

EntropyLab is an offline calculator and checker. It turns entropy you supply into wallet material, and it inspects PSBTs and transactions that other software built or signed. This page says who it defends against, what it checks against each of them, and what it leaves to you. How each mechanism works, and its limits, is in [SECURITY.md](../SECURITY.md).

## What you must trust

- **The machine that runs EntropyLab:** its hardware, operating system and browser. If that machine is compromised, nothing below holds: it can show you a different result or read every secret you type. EntropyLab is meant to run on a dedicated computer that is disconnected from every network; see the [computer hardening checklist](Computer_Hardening_Checklist.md).
- **The copy of EntropyLab you run.** Check `entropylab.html` against `SHA256SUMS.txt`, its maintainer signatures (`SHA256SUMS.asc`) and the OpenTimestamps proof before moving it to the offline machine, or build it yourself: builds are reproducible (see [Reproductions](Reproductions.md)).
- **Your own inputs.** EntropyLab never generates entropy ([CONTRIBUTING.md](../CONTRIBUTING.md) §1). A key is only as random and as secret as the dice rolls, phrase or key you typed in.

Everything else in this page is treated as untrusted.

## Adversaries

### The coordinator: the wallet software that builds the PSBT

Assume it can be buggy or malicious: wrong outputs, a hidden fee, a change output that isn't yours, a sighash flag that lets someone change the transaction after you sign.

What EntropyLab checks:

- **Sighash policy.** Every input's declared sighash type and every readable signature's sighash byte must commit to all outputs. A malformed, unsafe or conflicting policy raises a blocking warning.
- **Output ownership.** With your key loaded in the session, outputs are matched against your addresses (accounts 0–2, 50 receive and 50 change addresses, four script types). Anything outside that range stays unclassified, never "yours".
- **Fee.** The fee is computed from the amounts the PSBT itself claims for its inputs, and a PSBT whose outputs exceed those inputs is flagged as inconsistent.
- **Structure.** rust-bitcoin, compiled into the page, parses the file and reports BIP-174 and consensus errors, as a cross-check on the built-in parser.
- **Payload outputs.** Taproot inscription envelopes and OP_RETURN outputs are detected and shown.
- **Compare.** Two PSBTs can be compared field by field, so you can see what changed between the file you reviewed and the file you got back.

What it does not check:

- **Input amounts against the chain.** The amounts are the PSBT's own claims. EntropyLab has no node and does not check them against previous transactions.
- **Your intent.** It shows you the outputs. Whether those are the addresses and amounts you meant to pay is yours to decide.

### The signer: the hardware wallet or software that signs

Assume it can be buggy, compromised, or leaking keys through its nonces.

What EntropyLab checks:

- **Signature validity.** ECDSA signatures on SegWit v0 inputs (P2WPKH and P2WSH, SIGHASH_ALL) are verified against a digest EntropyLab rebuilds from the PSBT. A signature on a script containing OP_CODESEPARATOR is reported as unverifiable rather than verified.
- **Repeated nonces.** A repeated ECDSA `r` for the same key within a file is flagged, because two such signatures on different messages reveal the private key. An optional nonce-history file, kept offline, extends the ECDSA check across files. Repeated BIP340 nonces among Taproot signatures (key path, and single-key or `multi_a` script path) are flagged too.
- **Deterministic nonces (RFC 6979).** With the signing key loaded in the session, each supported ECDSA signature's nonce is recomputed with RFC 6979 (plain, with Bitcoin Core-style low-r grinding, or with 32 zero bytes of extra entropy). A nonce that matches none of them stands out. Without the key this check cannot run, and the report says so.
- **Jade anti-exfil.** With a Jade transcript, the sign-to-contract commitment is verified, so host entropy provably went into the nonce.
- **Compare.** A signed PSBT can be compared with the PSBT you reviewed. Signature fields are reported separately from changes to the transaction itself.

What it does not check:

- **A raw signed transaction against the PSBT you reviewed.** Compare works PSBT to PSBT. If the signer hands back a raw transaction, EntropyLab inspects its signatures and nonces but does not confirm it is the transaction you reviewed.
- **Nonces without the key.** A signer that leaks a key through nonces that look random will pass the repeated-nonce checks. Only the RFC 6979 recompute, which needs the key, pins the nonce down.
- **Taproot nonces and validity.** BIP340 signatures may mix in their own randomness, so their nonces cannot be recomputed; they are checked for sighash policy and repeated nonces only, and their validity is not verified here.
- **Other signatures**, for example on legacy (non-SegWit) inputs, are not verified or recomputed.

### Whoever sends you a file

PSBTs, transactions, descriptors and wallet files can be crafted to crash the page, hang it, or slip markup into it.

- Files are parsed by rust-bitcoin in WebAssembly as well as by the built-in parser.
- The work a file can cause is bounded. A file past the digest-reconstruction budget is reported incomplete, and one that needs more than 32,768 same-`r` pair comparisons is refused; neither is passed as clean. Long reports are also capped in how much they render.
- Text from a file is escaped before it is shown.
- Imported Key Manager vaults are treated as unverified until their inputs are loaded and freshly derived.

### The network

- EntropyLab makes no network requests. Everything it loads is inside the one HTML file, and a headless browser test asserts that nothing leaves the page ([CONTRIBUTING.md](../CONTRIBUTING.md) §3).
- The downloaded `entropylab.html`, opened on a disconnected machine, is the recommended way to use it. The hosted site's service worker only caches the app so it can reopen offline. It has no network fallback.
- The Security log records browser-reported connectivity changes and detected browser translation, which would send page text to a translation service. Neither proves an air gap.

### Someone who glimpses your screen or reaches your session

- Private values are hidden until you reveal them, and revealed values are hidden again when you leave the page or after 5 idle minutes.
- End session wipes the page's state, retires the WebAssembly modules, empties a clipboard the page wrote, and asks the browser to close the tab.
- Secret bytes are overwritten after use, on a best-effort basis. JavaScript strings and browser-managed memory cannot be erased; SECURITY.md lists exactly what can and cannot be.

### The build and release pipeline

- Dependencies are pinned to exact versions with integrity hashes.
- The page and its WebAssembly modules rebuild to identical bytes in the pinned build image. Three people have reproduced the 1.0.0 release on three different machines.
- WebAssembly digests are published in `WASM-SHA256SUMS.txt`. Releases carry `SHA256SUMS.txt`, maintainer signatures and an OpenTimestamps proof.
- The compilers inside the build image are prebuilt binaries, trusted as a seed. This is not a full-source bootstrap.

## Out of scope

- A compromised computer, operating system or browser running EntropyLab.
- Weak, reused or leaked entropy that you supplied.
- An attacker with physical access during your session, and side channels such as power, electromagnetic or acoustic leakage.
- Chain data: there is no node or indexer, so EntropyLab cannot tell you whether an input exists, is unspent, or is worth what the PSBT claims.
- Deciding whether a transaction is what you meant. EntropyLab reports what is in the file; you decide.

## Reading a report

- Each check in a PSBT report is marked Completed, Incomplete or Problem found.
- Incomplete means part of the check could not run: no matching key for RFC 6979, missing input data, an unsupported script, or a file past a limit.
- A completed check is a statement about that check only, not a verdict on the transaction.

To report a security issue, see [SECURITY.md](../SECURITY.md).
