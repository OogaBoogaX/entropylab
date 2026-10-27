# QR decoder evaluation: results and decision

**Decision: quircs 0.10.3** for Scan QR, with two cheap pre-passes to cover its gaps (below).
- **Run:** `cargo run --release --locked`, rustc 1.95.0, offline in the WSL sandbox with the vendored crates in `Cargo.lock`, 2026-10-27.
- **Code:** the harness at the commit that adds this file.

## Why quircs
- **Neither decoder ever returned wrong bytes.** A frame counts as exact only if every code decoded from it is the expected payload. Both had 0 Wrong across 783 synthetic cases and 150 flipped-module cases, 0 panics, and 0 false positives on noise, checkerboards, fake finder patterns and random grids.
- **Both preserve bytes exactly:** NUL, CR/LF, 0x80–0x9F, numeric leading zeros, mixed modes, ECI and Kanji, at D1.
- **quircs is far better on camera-like images:**

  | case | rqrr | quircs |
  |---|---|---|
  | webcam combination (D26) | 1/29 | 16/29 |
  | noise σ45 (D11) | 7/29 | 29/29 |
  | dim and noisy (D13) | 13/29 | 29/29 |
  | JPEG-like blockiness (D27) | 7/29 | 29/29 |
  | strong blur (D9) | 4/29 | 12/29 |
  | occlusion (D25) | 1/29 | 5/29 |

- **quircs is about 3× faster:** median 2.0 ms against 6.1 ms; worst synthetic case 14.4 ms against 50.0 ms; a blank 4096×4096 frame 58 ms against 283 ms.
- **SeedSigner's known-payload images:** quircs 19/19 exact, rqrr 18/19. rqrr missed the phone-screenshot CompactSeedQR as-is.

## Where quircs is weaker, and the mitigation
- **No quiet zone (D6: 0/29) and one-pixel modules (D3: 0/29).** rqrr gets 29/29 on both. Mitigation: pad every frame with a white border before decoding, and retry a small frame upscaled 2×.
- **Mirrored codes (D23: 0/29).** These come from front-facing cameras; rqrr gets 29/29. Mitigation: retry the frame flipped horizontally when nothing decodes.
- **Glare (D14):** 10/29 against rqrr's 15/29.
- **Neither decoder** reads inverted codes (D22), steep keystone (D20), the logo-covered SeedQR, the hand-drawn photo or the metal-plate photo.

## Notes on reading the report
- **"FalsePositive" on `standard_24word.png` / `compact_24word.png`** means a payload was decoded where the manifest lists none (`-`). Both decoders agree on both images, and the Standard SeedQR's 24 indices carry a valid BIP39 checksum, so these are correct reads, not false detections.
- **Two codes in one frame:** both decoders return both codes and no unexpected payload.
- **Flipped modules:** at 5% damage both decoders refuse every code (Error). At 1% both decode every code exactly. Damage beyond the error-correction capacity never produced wrong bytes.

## Full report

# QR decoder evaluation
rqrr 0.11.0 · quircs 0.10.3 · encoder qrcode 0.14.1

## Summary

| metric | rqrr | quircs |
|---|---|---|
| synthetic Exact | 482/783 | 489/783 |
| synthetic Wrong | 0 | 0 |
| synthetic NotFound | 179 | 131 |
| synthetic Error | 122 | 163 |
| synthetic Panic | 0 | 0 |
| flipped-module Wrong | 0 | 0 |
| known-payload fixtures Exact | 18/19 | 19/19 |
| robustness Panic | 0 | 0 |
| robustness FalsePositive | 0 | 0 |
| robustness max ms | 282.8 | 57.8 |
| synthetic median ms | 6.1 | 2.0 |
| synthetic max ms | 50.0 | 14.4 |

## Byte fidelity (D1, EC M)

| payload | rqrr | rqrr bytes | quircs | quircs bytes | quircs type | quircs ECI |
|---|---|---|---|---|---|---|
| P1 std12-leading-zero | Exact | `303733333138393530373339303635343135393631363032303039393037363730343238313837323132323631313136` | Exact | `303733333138393530373339303635343135393631363032303039393037363730343238313837323132323631313136` | numeric |  |
| P2 std24 | Exact | `30313135313332353131353430313237313139303037373130343135303734323132383931393036323030383038373030323636313334333134323032303136` | Exact | `30313135313332353131353430313237313139303037373130343135303734323132383931393036323030383038373030323636313334333134323032303136` | numeric |  |
| P3 std12-index-zero | Exact | `303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303033` | Exact | `303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303033` | numeric |  |
| P4 compact16-all-nul | Exact | `00000000000000000000000000000000` | Exact | `00000000000000000000000000000000` | byte |  |
| P5 compact32-nul | Exact | `0e59dde276009317f1275f1389888078c99368d1e82489b5f629531fc5b6a56e` | Exact | `0e59dde276009317f1275f1389888078c99368d1e82489b5f629531fc5b6a56e` | byte |  |
| P6 compact16-crlf | Exact | `f55cf587f2543d01090d0ae710bd3b6d` | Exact | `f55cf587f2543d01090d0ae710bd3b6d` | byte |  |
| P7 high-bytes | Exact | `808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f` | Exact | `808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f` | byte |  |
| P8 words | Exact | `666f72756d20756e646f2066726167696c65206661646520736879207369676e20617272657374206761726d656e742063756c747572652074756265206f6666` | Exact | `666f72756d20756e646f2066726167696c65206661646520736879207369676e20617272657374206761726d656e742063756c747572652074756265206f6666` | byte |  |
| P9 wif | Exact | `4b77446942663839516747626a45684b6e68584a7548374c72636956725a693371596a6764394d3772465537337356486e6f576e` | Exact | `4b77446942663839516747626a45684b6e68584a7548374c72636956725a693371596a6764394d3772465537337356486e6f576e` | byte |  |
| P10 ur-alnum | Exact | `55523a42595445532f454743485342514c45444f4141414e52434a53435a484b454f505056514b5844425747574341504a5141555455465248594c5143475141` | Exact | `55523a42595445532f454743485342514c45444f4141414e52434a53435a484b454f505056514b5844425747574341504a5141555455465248594c5143475141` | alpha |  |
| P11 binary-1000 | Exact | `ccd7455db429d3b32c4a77041b1995e6560c963381fae4126f63bdcdda97ca1c0653c0bb2ad15295757486ed826ceeb3c9786d5ce4bef00670f6655524201683` | Exact | `ccd7455db429d3b32c4a77041b1995e6560c963381fae4126f63bdcdda97ca1c0653c0bb2ad15295757486ed826ceeb3c9786d5ce4bef00670f6655524201683` | byte |  |
| P12 mixed | Exact | `3031323334353637383900616263ff48454c4c4f20574f524c44` | Exact | `3031323334353637383900616263ff48454c4c4f20574f524c44` | byte |  |
| P13 eci-utf8 | Exact | `c3a974c3a9` | Exact | `c3a974c3a9` | byte | Utf8 |
| P14 eci-latin1 | Exact | `e974e9` | Exact | `e974e9` | byte |  |
| P15 kanji | Exact | `935fe4aa` | Exact | `935fe4aa` | kanji |  |

## By degradation

| degradation | rqrr Exact/total | quircs Exact/total |
|---|---|---|
| D1 | 29/29 | 29/29 |
| D2 | 29/29 | 29/29 |
| D3 | 29/29 | 0/29 |
| D4 | 29/29 | 29/29 |
| D5 | 29/29 | 29/29 |
| D6 | 29/29 | 0/29 |
| D7 | 21/29 | 26/29 |
| D8 | 2/29 | 3/29 |
| D9 | 4/29 | 12/29 |
| D10 | 26/29 | 29/29 |
| D11 | 7/29 | 29/29 |
| D12 | 29/29 | 29/29 |
| D13 | 13/29 | 29/29 |
| D14 | 15/29 | 10/29 |
| D15 | 28/29 | 29/29 |
| D16 | 22/29 | 24/29 |
| D17 | 29/29 | 29/29 |
| D18 | 29/29 | 29/29 |
| D19 | 16/29 | 15/29 |
| D20 | 0/29 | 0/29 |
| D21 | 0/29 | 1/29 |
| D22 | 0/29 | 0/29 |
| D23 | 29/29 | 0/29 |
| D24 | 29/29 | 29/29 |
| D25 | 1/29 | 5/29 |
| D26 | 1/29 | 16/29 |
| D27 | 7/29 | 29/29 |

## Fixtures

| file | format | rqrr as-is | rqrr blur | rqrr rotate | quircs as-is | quircs blur | quircs rotate |
|---|---|---|---|---|---|---|---|
| seedsigner/vector1_standard_24word.png | standard-seedqr | Exact | Exact | Exact | Exact | Exact | Exact |
| seedsigner/vector1_compact_24word.png | compact-seedqr | Exact | Exact | Exact | Exact | Exact | Exact |
| seedsigner/vector2_standard_24word.png | standard-seedqr | Exact | Exact | Exact | Exact | Exact | Exact |
| seedsigner/vector2_compact_24word.png | compact-seedqr | Exact | Exact | Exact | Exact | Exact | Exact |
| seedsigner/vector3_standard_24word.png | standard-seedqr | Exact | Exact | Exact | Exact | Exact | Exact |
| seedsigner/vector3_compact_24word.png | compact-seedqr | Exact | Exact | Exact | Exact | Exact | Exact |
| seedsigner/vector4_standard_12word.png | standard-seedqr | Exact | Exact | Exact | Exact | Exact | Exact |
| seedsigner/vector4_compact_12word.png | compact-seedqr | Exact | Error | Exact | Exact | Error | Exact |
| seedsigner/vector5_standard_12word.png | standard-seedqr | Exact | Exact | Exact | Exact | Exact | Exact |
| seedsigner/vector5_compact_12word.png | compact-seedqr | Exact | Error | Exact | Exact | Exact | Error |
| seedsigner/vector6_standard_12word.png | standard-seedqr | Exact | Exact | Exact | Exact | Exact | Exact |
| seedsigner/vector6_compact_12word.png | compact-seedqr | Exact | Error | Exact | Exact | Error | Exact |
| seedsigner/vector7_compact_12word.png | compact-seedqr | Exact | Exact | Exact | Exact | Exact | Exact |
| seedsigner/vector8_compact_12word.png | compact-seedqr | Exact | Exact | Exact | Exact | Exact | Exact |
| seedsigner/vector9_compact_12word.png | compact-seedqr | Exact | Exact | Exact | Exact | Exact | Exact |
| seedsigner/standard_12word.png | standard-seedqr | Exact | Exact | Exact | Exact | Exact | Exact |
| seedsigner/compact_12word.png | compact-seedqr | Exact | Exact | Exact | Exact | Error | Exact |
| seedsigner/phone_screenshot_standard.jpg | standard-seedqr | Exact | Exact | Exact | Exact | Exact | Exact |
| seedsigner/phone_screenshot_compact.jpg | compact-seedqr | Error | Exact | Exact | Exact | Error | Exact |
| seedsigner/standard_24word.png | standard-seedqr | FalsePositive | FalsePositive | FalsePositive | FalsePositive | FalsePositive | FalsePositive |
| seedsigner/compact_24word.png | compact-seedqr | FalsePositive | FalsePositive | FalsePositive | FalsePositive | FalsePositive | FalsePositive |
| seedsigner/standard_24word_with_logo.png | standard-seedqr | Error | Error | FalsePositive | Error | Error | Error |
| seedsigner/handmade_qr.jpg | standard-seedqr | NotFound | NotFound | NotFound | NotFound | NotFound | NotFound |
| seedsigner/seedqr_plate.jpg | unknown | NotFound | NotFound | NotFound | NotFound | NotFound | NotFound |

### Unknown payloads

- `seedsigner/standard_24word.png`: rqrr `303130333033363931383134303539353039313531313237313737313030393930303733323030323136323631303134303732393035313230313733303139363131313630323232303631393034363030323138303133393135393130383333`, quircs `303130333033363931383134303539353039313531313237313737313030393930303733323030323136323631303134303732393035313230313733303139363131313630323232303631393034363030323138303133393135393130383333`, agree: true
- `seedsigner/compact_24word.png`: rqrr `0ce5c78b25372719f75863093f4b2d3f65b2800568c48b8379359cc1b422f1bb`, quircs `0ce5c78b25372719f75863093f4b2d3f65b2800568c48b8379359cc1b422f1bb`, agree: true
- `seedsigner/standard_24word_with_logo.png`: rqrr `-`, quircs `-`, agree: true
- `seedsigner/handmade_qr.jpg`: rqrr `-`, quircs `-`, agree: true
- `seedsigner/seedqr_plate.jpg`: rqrr `-`, quircs `-`, agree: true

## Two codes in one frame

### P8 + P9

- rqrr: 2 code(s) returned; expected 1 found; expected 2 found; unexpected payloads 0
- quircs: 2 code(s) returned; expected 1 found; expected 2 found; unexpected payloads 0

### P5 + P6

- rqrr: 2 code(s) returned; expected 1 found; expected 2 found; unexpected payloads 0
- quircs: 2 code(s) returned; expected 1 found; expected 2 found; unexpected payloads 0

## Flipped modules

| case | rqrr Exact | rqrr Wrong | rqrr NotFound | rqrr Error | quircs Exact | quircs Wrong | quircs NotFound | quircs Error |
|---|---|---|---|---|---|---|---|---|
| P11 binary-1000 L 5% | 0 | 0 | 0 | 50 | 0 | 0 | 0 | 50 |
| P8 words M 5% | 0 | 0 | 0 | 50 | 0 | 0 | 0 | 50 |
| P8 words M 1% | 50 | 0 | 0 | 0 | 50 | 0 | 0 | 0 |

## Robustness

| case | rqrr | rqrr ms | quircs | quircs ms |
|---|---|---|---|---|
| uniform white 640x480 | NotFound | 5.2 | NotFound | 0.9 |
| uniform black 640x480 | NotFound | 5.6 | NotFound | 0.7 |
| degenerate 1x1 | NotFound | 0.0 | NotFound | 0.0 |
| degenerate 2x2 | NotFound | 0.0 | NotFound | 0.0 |
| degenerate 4000x1 | NotFound | 0.1 | NotFound | 0.0 |
| degenerate 1x4000 | NotFound | 0.1 | NotFound | 0.0 |
| uniform noise 640x480 | NotFound | 9.0 | NotFound | 4.8 |
| checkerboard 1px | NotFound | 5.9 | NotFound | 2.7 |
| checkerboard 8px | NotFound | 5.4 | NotFound | 0.8 |
| 64 fake finders | Error | 106.1 | Error | 14.6 |
| random grid 0 | Error | 6.4 | Error | 2.1 |
| random grid 1 | Error | 6.8 | Error | 2.1 |
| random grid 2 | Error | 6.8 | Error | 2.5 |
| random grid 3 | Error | 9.8 | Error | 2.0 |
| random grid 4 | Error | 6.5 | Error | 2.0 |
| random grid 5 | Error | 6.2 | Error | 2.1 |
| random grid 6 | Error | 6.8 | Error | 2.0 |
| random grid 7 | Error | 6.4 | Error | 2.2 |
| random grid 8 | Error | 7.0 | Error | 2.2 |
| random grid 9 | Error | 6.5 | Error | 2.4 |
| random grid 10 | Error | 6.6 | Error | 2.2 |
| random grid 11 | Error | 6.6 | Error | 2.0 |
| random grid 12 | Error | 6.7 | Error | 2.2 |
| random grid 13 | Error | 7.2 | Error | 2.1 |
| random grid 14 | Error | 6.6 | Error | 2.2 |
| random grid 15 | Error | 6.8 | Error | 2.1 |
| random grid 16 | Error | 6.7 | Error | 2.2 |
| random grid 17 | Error | 6.7 | Error | 2.1 |
| random grid 18 | Error | 6.5 | Error | 2.1 |
| random grid 19 | Error | 7.0 | Error | 2.1 |
| random grid 20 | Error | 6.5 | Error | 2.2 |
| random grid 21 | Error | 6.2 | Error | 2.0 |
| random grid 22 | Error | 6.8 | Error | 2.4 |
| random grid 23 | Error | 7.7 | Error | 2.3 |
| random grid 24 | Error | 6.9 | Error | 2.2 |
| random grid 25 | Error | 7.7 | Error | 2.5 |
| random grid 26 | Error | 7.6 | Error | 2.5 |
| random grid 27 | Error | 6.9 | Error | 2.2 |
| random grid 28 | Error | 7.4 | Error | 2.1 |
| random grid 29 | Error | 6.6 | Error | 2.1 |
| random grid 30 | Error | 6.5 | Error | 2.1 |
| random grid 31 | Error | 6.7 | Error | 2.2 |
| random grid 32 | Error | 6.4 | Error | 2.1 |
| random grid 33 | NotFound | 0.4 | Error | 1.9 |
| random grid 34 | Error | 7.2 | Error | 2.2 |
| random grid 35 | Error | 7.0 | Error | 2.1 |
| random grid 36 | Error | 6.6 | Error | 2.0 |
| random grid 37 | Error | 6.8 | Error | 2.3 |
| random grid 38 | Error | 6.4 | Error | 2.0 |
| random grid 39 | Error | 7.7 | Error | 3.8 |
| random grid 40 | Error | 8.8 | Error | 2.9 |
| random grid 41 | Error | 9.7 | Error | 3.5 |
| random grid 42 | Error | 7.2 | Error | 2.2 |
| random grid 43 | Error | 6.6 | Error | 2.0 |
| random grid 44 | Error | 6.8 | Error | 2.2 |
| random grid 45 | Error | 6.8 | Error | 2.3 |
| random grid 46 | Error | 6.6 | Error | 2.3 |
| random grid 47 | Error | 6.3 | Error | 2.0 |
| random grid 48 | Error | 6.9 | Error | 2.2 |
| random grid 49 | Error | 6.8 | Error | 2.2 |
| large blank 4096x4096 | NotFound | 282.8 | NotFound | 57.8 |
| striped P8 | NotFound | 0.6 | NotFound | 0.1 |

## Findings

None.
