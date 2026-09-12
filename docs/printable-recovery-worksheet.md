# EntropyLab Printable Recovery Worksheet

This printer-friendly worksheet complements EntropyLab's existing digital recovery/export functionality by providing a structured offline paper record for user-supplied entropy and derived wallet information.

## Included fields

- entropy method and exact input/transcript
- BIP39 mnemonic word positions
- passphrase-use indicator (without recording the passphrase)
- master fingerprint
- master extended keys
- derivation root and paths
- extended public keys
- descriptors
- receive/change addresses
- independent verification checklist
- offline storage and backup notes

## Security intent

The worksheet does not generate entropy and contains no network functionality. Users should complete it only in an appropriate offline workflow and treat a completed copy as wallet-secret material. Do not photograph, email, upload, or enter recovery words/private keys into an internet-connected service.

## Printable version

Open `printable-recovery-worksheet.html` in a browser and print at US Letter size. The HTML is intentionally self-contained so it can be reviewed and printed without remote assets.

A PDF version of the worksheet is also included in the contribution package supplied with this change for maintainer review.

## Scope

Documentation/printable artifact only. No EntropyLab runtime code or entropy-generation behavior is changed.
