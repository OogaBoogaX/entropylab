# qr-eval

The evaluation that picks the QR decoder for EntropyLab's planned "Scan QR"
import. It compares two pure-Rust decoders, `rqrr` and `quircs`, on the same
images. **Nothing here is built into the app.**

- **Byte fidelity:** each decoder must return the exact payload bytes. That
  includes CompactSeedQR NUL and CR/LF bytes, bytes at or above 0x80, numeric
  leading zeros, ECI and mixed modes.
- **Robustness:** blur, noise, tilt, glare, low contrast, occlusion, a small
  code in a large frame, two codes in one frame, and SeedSigner's published
  test images and photos.
- **Failures:** a decoder must never return wrong bytes without an error,
  panic, or hang.

The synthetic codes come from the `qrcode` crate, an encoder independent of
the app's `uqr`. The fixtures in `fixtures/seedsigner/` are SeedSigner's
SeedQR spec images (MIT, see `fixtures/seedsigner/LICENSE`), with their
expected payloads in `fixtures/manifest.tsv`.

Run it with `cargo run --release --locked`; `cargo test --release` checks the
harness itself. `RESULTS.md` records a real run and the decision taken from
it. Regenerate it from a run; never edit the numbers by hand.
