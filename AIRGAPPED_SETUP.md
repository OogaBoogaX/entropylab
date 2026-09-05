# Setting up a trusted air-gapped machine

EntropyLab is built to be run on a computer that is never connected to a
network while it handles wallet secrets. This is a step-by-step guide for
turning a spare laptop into that machine. It complements
[README.md's "Verifying the download"](README.md#verifying-the-download);
read that section for the exact verification commands.

None of this is required to use EntropyLab casually. It matters when the
seed phrases, private keys, or extended keys you plan to enter secure real
funds.

## 1. Hardware

- Use an existing laptop rather than buying one for this purpose alone — a
  machine's history and provenance don't add security here, only the fact
  that it will never touch a network again.
- Physically remove the Wi-Fi/Bluetooth card if practical, or disable both
  in BIOS/UEFI settings. Also disable them in the OS once installed, as a
  second layer.
- Cover the camera and microphone if present.
- Fully wipe the disk (not just reformat) before installing anything.

## 2. Get the OS on a separate, networked machine

Do the download, verification, and USB flashing on a different, ordinary
computer — never on the air-gapped laptop, which should never see a
network in the first place.

- [Tails](https://tails.net/) is a live, amnesic OS: nothing persists
  between boots, which is a reasonable default for key generation since it
  leaves no trace on disk. A persistent install (e.g. Debian) is only
  needed if you have a reason to keep files across sessions.
- Verify the OS image's checksum and signature against the project's
  official keys before flashing it — see Tails' own
  [verification instructions](https://tails.net/install/expert/index.en.html).
  Do not skip this step; it is the only thing standing between you and a
  tampered installer image.
- Flash the verified image to a USB stick (e.g. with `balenaEtcher` or
  `dd`), then boot the target laptop from it.

## 3. Verify EntropyLab before it ever reaches the air-gapped machine

Do this on the same networked machine, before transferring anything to the
laptop. Two independent ways to get a verified copy of `entropylab.html`,
either is sufficient:

**A. Download and verify the release**

```sh
# from a release or entropylab.online, then in the download directory:
sha256sum -c SHA256SUMS.txt
gh attestation verify entropylab.html -R w-s-bitcoin/entropylab
```

The checksum alone only catches accidental corruption. Pairing it with the
[Sigstore attestation](https://github.com/w-s-bitcoin/entropylab/attestations)
authenticates that the exact bytes came from this repository's release
workflow.

**B. Build it yourself and confirm it's reproducible**

```sh
git clone https://github.com/w-s-bitcoin/entropylab.git
cd entropylab
node --version   # >= 20.19
npm ci
npm run ci       # test:ci + build + verify — same checks CI runs
```

`npm run ci` builds `entropylab.html` from `src/` and checks the result
against the project's invariants (no network egress, no entropy
generation, artifact integrity — see [CONTRIBUTING.md](CONTRIBUTING.md)).
`entropylab.html` is generated and git-ignored, not committed to the repo,
so there is no committed copy to diff your build against — the published
`SHA256SUMS.txt` and attestation in option A are what let you confirm an
independently-built copy matches what CI produced.

For either path, the [development container](CONTRIBUTING.md#the-development-container-no-host-prerequisites)
(`docker compose up --build`) gives you a pinned Node/Rust/browser
environment with no host prerequisites, so the build isn't at the mercy of
whatever happens to be installed on the networked machine.

## 4. Transfer and use

- Copy the verified `entropylab.html` to a USB stick and carry it to the
  air-gapped laptop. Nothing else needs to cross that gap.
- Boot the laptop, confirm networking is off, and open the file in a
  browser.
- Before entering any seed phrase, private key, or other secret, follow
  README's [Usage](README.md#usage) guidance: disconnect all networks and
  verify important addresses and descriptors with an independent wallet or
  signing device before receiving funds. EntropyLab is a calculator, not a
  signer — see [SECURITY.md](SECURITY.md) for the full threat model.
- If the OS is Tails (amnesic), nothing you did persists after shutdown; if
  it's a persistent install, treat the laptop itself as sensitive material
  going forward and store it accordingly.
