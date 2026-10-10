# Residue audit report (illustrative)

> Zero hits is not proof of erasure. Hits describe the scanned bytes and do
> not distinguish application, browser, or automation copies.

This is an invented example of the report format, not a captured measurement.
PIDs, offsets and exact counts are omitted.

Controls passed. Zero hits still do not prove erasure.

| Needle | Pre-wipe calibration |
|---|---|
| mnemonic | Observed after a clean baseline |
| passphrase | Observed after a clean baseline |
| seedHex | NOT CALIBRATED — a later zero is inconclusive |
| xprv | Observed after a clean baseline |
| wif | Observed after a clean baseline |
| privateKeyHex | Observed after a clean baseline |
| mnemonic-base64 | NOT CALIBRATED — a later zero is inconclusive |

| Checkpoint | Example observation |
|---|---|
| before-input | Complete captures; no fixture hits |
| after-derive | Mnemonic and private-key material found |
| after-reveal | Mnemonic, xprv and WIF found before output/clipboard verification; positive control passed |
| after-copy | Mnemonic found after the verified seed-copy action |
| after-wipe | Mnemonic still found in a captured process |
| after-tab-close | No hits in the surviving processes |

The after-wipe hit demonstrates bytes present in that capture. It does not
attribute them to an application-owned allocation. The final zero is not
proof of erasure, especially for needles that were never calibrated.

A run with a dirty baseline, missing control or failed capture instead begins
**INVALID RUN** and lists the reasons. Its zeros must not be read as cleanup.
