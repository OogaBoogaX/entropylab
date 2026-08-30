# Security Policy

## Supported Versions

Only the most recent release receives security fixes. Users are encouraged to
always use the latest version, available from the
[releases page](https://github.com/w-s-bitcoin/entropylab/releases) and the
[official website](https://entropylab.online).

| Version | Supported          |
| ------- | ------------------ |
| 0.1.3   | :white_check_mark: |
| < 0.1.3 | :x:                |

## Security Considerations

EntropyLab handles Bitcoin private keys, seed phrases, and other secret wallet
material. Its security posture rests on the following model:

- The tool is self-contained and designed for offline, air-gapped use. It does
  not intentionally transmit sensitive data to any server.
- EntropyLab's own secp256k1 curve operations (public-key derivation, ECDSA
  signing and verification in PSBT inspection, curve point math) run on
  bitcoin-core/libsecp256k1 (the library securing Bitcoin Core), compiled to
  WebAssembly from the pinned, lockfiled Rust crate in `secp256k1-wasm/` and
  executed entirely in-process — no network access, and the module never
  generates randomness (signing is RFC 6979 with caller-fixed extra entropy).
  The bundled `@scure` libraries still carry `@noble/curves` internally for
  BIP32 extended-key derivation and address/script construction. CI rebuilds
  the WASM from the committed Rust sources and runs its test suite against
  the fresh build before any deployment; the artifact job then commits the
  runner's copy back to the repository, the same flow as the site artifact.
  Cross-machine byte identity is not claimed — the C side compiles with the
  builder's clang, and build-host paths are remapped out of the binary.
- The on-screen result of any derivation can only be as trustworthy as the
  code that produced it. Review the source, build from `src/`, and test the
  tool with published vectors before relying on it.
- Wallet security depends on the quality and secrecy of the entropy, seed
  phrase, passphrase, or private key supplied by the user, and on the
  integrity of the machine it runs on.
- Low-entropy dice and card transcripts are accepted intentionally so the
  calculator can be used for deterministic tests, demonstrations, and
  recovery experiments. EntropyLab does not claim that hashing a short input
  makes it secure. When the entered transcript is below the recommended
  entropy target, the result displays a prominent warning with the estimated
  supplied entropy and says to use it only for testing. Users who intend to
  secure funds must meet the displayed roll/card recommendation and verify
  their procedure independently.
- Card deck backup is a deterministic encoding of BIP39 entropy as a
  without-replacement deal. Cards never loads it by switching tabs. Restoring
  it requires an explicit Show stacked deck or Restore a stacked-deck backup
  action. Hashed card transcripts, Ian Coleman, and camera-signer card
  schemes are different encodings and will not reproduce the same seed.
- The single-file design inlines all scripts (`script-src 'unsafe-inline'`),
  and the secp256k1 WebAssembly module adds `wasm-unsafe-eval` to the
  content security policy: Chromium and WebKit engines refuse to compile a
  WebAssembly module from JS without it. Application scripts are still all
  bundled at build time, so any inline script injected after packaging is
  outside the threat model this policy addresses.
- Material involving loss of funds (incorrect derivations, exfiltration of
  secret data, injected script execution in the generated HTML, unexpected
  network egress) is treated as a security issue.

## Reporting a Vulnerability

Please report suspected security issues privately through
[GitHub Security Advisories](https://github.com/w-s-bitcoin/entropylab/security/advisories/new)
rather than opening a public issue. If private reporting is unavailable, reach
the maintainers through the [official website](https://entropylab.online).

Include the version, the affected input type and derivation path if relevant,
and a description of the impact. A maintainer will acknowledge the report and
coordinate a fix; scope it as narrowly as needed to reproduce responsibly.

## Disclaimer

This software is provided without warranty of any kind — no express, no
implied, no promise it work or fit any purpose — under
[The Ooga Booga License](LICENSE), which dedicates it to the public domain. The
caveman words mean what The Unlicense means. Keep verified backups, and use it
at your own risk.
