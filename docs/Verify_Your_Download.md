# Verify your download

EntropyLab handles keys, so check that your copy is the real one before you
use it. It takes a few minutes, and you only need to do it once per copy.

**The one rule:** check a file with tools *outside* that file. A tampered copy
of EntropyLab could show you a fake "all good", so never use a copy to check
itself.

## Which file to get

- **A signed release** (strongest): the
  [GitHub Releases](https://github.com/OogaBoogaX/entropylab/releases) page.
  Download `entropylab.html`, `SHA256SUMS.txt`, `SHA256SUMS.asc`, `KEYS` and
  `entropylab.html.ots` into one folder.
- **The live site** (`entropylab.online`) changes with every update. Each
  build has a checksum, a GitHub attestation and a Bitcoin timestamp (steps
  1, 3 and 4), but no release signatures.

## Step 1: check the checksum

The checksum is a fingerprint of the file. If one byte changed, it would be
completely different. Open a terminal in the folder with your downloads.

**Windows** (PowerShell):

```powershell
Get-FileHash .\entropylab.html -Algorithm SHA256
```

Compare the long `Hash` it prints with the line in `SHA256SUMS.txt`. Upper or
lower case doesn't matter. Or let PowerShell compare for you. It prints
`True` when they match:

```powershell
(Get-FileHash .\entropylab.html -Algorithm SHA256).Hash.ToLower() -eq (Get-Content .\SHA256SUMS.txt).Split(" ")[0]
```

**Mac** (Terminal):

```sh
shasum -a 256 -c SHA256SUMS.txt
```

**Linux:**

```sh
sha256sum -c SHA256SUMS.txt
```

**A good result** on Mac and Linux is `entropylab.html: OK`. Anything else
means the file is not the one that was published. Stop and don't use it.

A checksum alone only proves the file matches `SHA256SUMS.txt`. Someone who
could change the file could change that list too. Step 2 shows who vouches
for the list.

## Step 2: check the release signatures (signed releases)

Several people signed `SHA256SUMS.txt` independently. You need GnuPG:
[Gpg4win](https://www.gpg4win.org/) on Windows, GPG Suite or
`brew install gnupg` on a Mac, and it is usually already installed on Linux.

```sh
gpg --import KEYS
gpg --verify SHA256SUMS.asc SHA256SUMS.txt
```

**A good result** is one `Good signature from …` line per signer. GnuPG also
prints `WARNING: This key is not certified with a trusted signature!` That is
normal: it only means you haven't personally certified these keys. What
matters is that each `Primary key fingerprint` matches this list:

| Signer | Primary key fingerprint |
| --- | --- |
| Portland.HODL | `3428 CBB5 4C36 9D8A F14E  F600 C801 EE1D 5285 101E` |
| MrHodlX | `6443 4EE4 8A96 C38E 78B7  875F 4E7E 416E E17D 237C` |
| w-s-bitcoin | `542E CCA3 B5CB 74CE C957  29B3 92C2 1496 202E 3774` |
| timechainb | `63EF 760E E641 A585 16D5  4930 F0B7 D606 C6FD 9D52` |

Check these fingerprints in more than one place, such as this page on GitHub
and the signers' own profiles. A tampered download page could swap them.

`BAD signature`, or a fingerprint that is not in this list, means stop.

## Step 3 (optional): check that GitHub's CI built it

With the [GitHub CLI](https://cli.github.com/):

```sh
gh attestation verify entropylab.html -R OogaBoogaX/entropylab
```

A good result says the verification succeeded. This proves this repository's
build system produced exactly these bytes.

## Step 4 (optional): check the Bitcoin timestamp

`entropylab.html.ots` proves the file's checksum existed as of a Bitcoin
block, independently of GitHub. With the
[OpenTimestamps client](https://github.com/opentimestamps/opentimestamps-client)
and a Bitcoin Core node (pruned is fine):

```sh
ots verify entropylab.html
```

A freshly published proof can still be *pending*. Wait until
`ots info entropylab.html.ots` shows a Bitcoin attestation. Windows needs one
extra step; see [Verifying the download](../README.md#verifying-the-download)
in the README.

## Already have a verified copy?

You can rebuild the file yourself from the source commit in its footer, and
compare checksums. See the reproducible-build steps in
[Verifying the download](../README.md#verifying-the-download). Independent
rebuilds are listed in [Reproductions](Reproductions.md).

## If something doesn't match

Don't use the file. Download it again from the release page. If it still
doesn't match, report it privately as [SECURITY.md](../SECURITY.md)
describes.
