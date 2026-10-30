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
  1, 3 and 4), but no release signatures. Its `SHA256SUMS.txt` and
  `entropylab.html.ots` are next to `entropylab.html` in the
  [`rock` branch](https://github.com/OogaBoogaX/entropylab/tree/rock). Each
  update replaces all three, so download them at the same time as the page.

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

## Step 2: check the team's signatures (GPG, signed releases)

EntropyLab maintainers sign each release. Their signatures cover
`SHA256SUMS.txt`, the file that lists the hash of `entropylab.html`. The
release notes list who signed; v1.0.0 and its release candidates were signed
by all four maintainers below. If the signatures are good and your file's hash
matches that list (step 1), the file you downloaded is the one they signed.

> **Use the files from the release page only.** Download `entropylab.html`,
> `SHA256SUMS.txt`, `SHA256SUMS.asc` and `KEYS` together from the same release
> on the [Releases page](https://github.com/OogaBoogaX/entropylab/releases).
> Don't use `SHA256SUMS.txt` or `SHA256SUMS.asc` from the `rock` branch to
> check a release. Those files change between releases and won't match each
> other.

### 1. Install GPG

- **Windows:** install [Gpg4win](https://www.gpg4win.org/), then use PowerShell.
- **Mac:** install [GPG Suite](https://gpgtools.org/), or run `brew install gnupg`.
- **Linux:** usually installed already. If not, run `sudo apt install gnupg`
  (Debian/Ubuntu) or use your distro's package manager.

### 2. Import the signers' keys

Open a terminal in the folder with your downloads and run:

```sh
gpg --import KEYS
```

The `KEYS` file is a release download. It is not in the repository.

### 3. Verify the signatures

```sh
gpg --verify SHA256SUMS.asc SHA256SUMS.txt
```

You should see one `Good signature from` line for each signer the release
notes list (four for v1.0.0). Then check that each fingerprint GPG prints
matches this list:

| Signer | Primary key fingerprint |
| --- | --- |
| Portland.HODL (russeree) | `3428 CBB5 4C36 9D8A F14E  F600 C801 EE1D 5285 101E` |
| MrHodlX | `6443 4EE4 8A96 C38E 78B7  875F 4E7E 416E E17D 237C` |
| w-s-bitcoin | `542E CCA3 B5CB 74CE C957  29B3 92C2 1496 202E 3774` |
| timechainb | `63EF 760E E641 A585 16D5  4930 F0B7 D606 C6FD 9D52` |

Portland.HODL and w-s-bitcoin sign with subkeys (`C0AF3AD083D6B40A` and
`EFBB6C556124B3DE`). GPG shows the subkey and its primary fingerprint, and the
primary fingerprint is the one to compare.

**What the results mean**

- **A good signature from every listed signer, with matching fingerprints:**
  the hash list is genuine. With step 1's matching checksum, your file is the
  one they signed.
- **`WARNING: This key is not certified with a trusted signature`:** this is
  normal. It only means you haven't personally marked these keys as trusted in
  GPG. What matters is that the fingerprints match the table.
- **`BAD signature`, or fewer good signatures than the release lists:** stop.
  Don't use the file. Download the release again and recheck, and if it still
  fails, report it.

Don't rely on fingerprints shown inside a copy of EntropyLab you haven't
verified. Compare them against this guide on GitHub, the release notes, or a
maintainer's own published key.

## Step 3 (optional): check that GitHub's CI built it

With the [GitHub CLI](https://cli.github.com/):

```sh
gh attestation verify entropylab.html -R OogaBoogaX/entropylab
```

A good result says the verification succeeded. It shows that this
repository's CI built exactly these bytes, but not which source it built them
from. Rebuilding the file yourself checks that (see below).

## Step 4 (optional): check the Bitcoin timestamp

`entropylab.html.ots` proves the file's checksum existed as of a Bitcoin
block, independently of GitHub. With the
[OpenTimestamps client](https://github.com/opentimestamps/opentimestamps-client)
and a Bitcoin Core node (pruned is fine):

```sh
ots verify entropylab.html.ots
```

It checks the `entropylab.html` in the same folder. A freshly published proof can still be *pending*. Wait until
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
