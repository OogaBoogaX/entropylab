# EntropyLab Android wrapper

This directory is a thin Android wrapper around the **release** file `entropylab.html`. It does not generate entropy, sign, store keys, or add a workspace tab. It does not rebuild WASM and it does not modify `src/`.

## Pinned release bytes

The APK embeds the published **v1.1.0** release HTML, vendored at
`app/src/main/assets/entropylab.html`, with SHA-256
`8461363a3e238a117246a78d03ad8e0655e7ae126b38aafd0955a1d00b9a93f6`.
The signed checksum manifest was verified with the keys from the reviewed
upstream tree, not the release download. The three matching primary
fingerprints are `3428CBB54C369D8AF14EF600C801EE1D5285101E`
(Portland.HODL), `542ECCA3B5CB74CEC95729B392C21496202E3774` (w-s-bitcoin)
and `DB19EF73487443AAEAC2668717ABDC5F9867B54F` (MrHodlX's current interim
key). The old MrHodlX key beginning `64434EE4` is revoked and is not
trusted. See [Release signing keys](../SECURITY.md#release-signing-keys).
`ENTROPYLAB_HTML.sha256` pins the digest and `ENTROPYLAB_HTML.version`
pins its displayed release identity independently of the root package version.

The wrapper deliberately does **not** package the `entropylab.html` at the repository root: that file is a CI artifact rebuilt and recommitted on every merge to `rock`, so a pin against it goes stale on merge. The vendored asset changes only when this module is deliberately updated to a new release.

The build and the app both fail closed on the pin:

- `verifyEntropylabHtml` (Gradle, wired into `preBuild`) hashes the vendored asset and refuses the build unless it matches `ENTROPYLAB_HTML.sha256`.
- At runtime the app re-hashes the packaged asset and compares it to the pin baked into `BuildConfig.HTML_SHA256`; a mismatch shows a blocking message and the calculator will not open.
- `HtmlPinTest` (below) additionally pins both to the attested release digest, so the pin file cannot drift from the release it claims to be.

### Updating to a future release

1. Download `entropylab.html`, `SHA256SUMS.txt` and `SHA256SUMS.asc` from
   the new release into an empty directory. Do not import the release's `KEYS`.
2. Verify using the committed public keys and active signer list from a
   separately trusted, reviewed upstream checkout, not the release tag or
   downloaded files. Check the list against
   [Release signing keys](../SECURITY.md#release-signing-keys). Run the
   following in Bash from the download directory, setting `TRUSTED_REPO`
   to the absolute path of that checkout. Stop if any command fails:

   ```sh
   (
     set -eu
     : "${TRUSTED_REPO:?Set TRUSTED_REPO to the reviewed upstream checkout}"
     GNUPGHOME=$(mktemp -d)
     export GNUPGHOME
     trap 'rm -rf "$GNUPGHOME"' EXIT
     for key in "$TRUSTED_REPO"/keys/*.asc; do
       gpg --batch --dearmor < "$key"
     done > "$GNUPGHOME/trusted.gpg"
     gpg --batch --no-auto-key-retrieve --no-default-keyring --keyring "$GNUPGHOME/trusted.gpg" \
       --status-fd 1 --verify SHA256SUMS.asc SHA256SUMS.txt > "$GNUPGHOME/status"
     awk '
       FNR == NR {
         if ($1 == "min-signers") minimum = $2
         if ($3 == "active") active[$1] = 1
         next
       }
       $1 == "[GNUPG:]" && $2 ~ /^(BADSIG|ERRSIG|REVKEYSIG|EXPKEYSIG|EXPSIG)$/ { bad = 1 }
       $1 == "[GNUPG:]" && $2 == "VALIDSIG" {
         primary = ($12 == "" ? $3 : $12)
         if (!(primary in active)) bad = 1
         else if (!seen[primary]++) {
           print "Verified primary signer:", primary
           count++
         }
       }
       END { if (bad || minimum < 1 || count < minimum) exit 1 }
     ' "$TRUSTED_REPO/.github/release-signers.txt" "$GNUPGHOME/status"
     awk '$2 == "entropylab.html" { print; count++ } END { if (count != 1) exit 1 }' \
       SHA256SUMS.txt > "$GNUPGHOME/html.sha256"
     sha256sum -c --strict "$GNUPGHOME/html.sha256"
   )
   ```

3. Replace `app/src/main/assets/entropylab.html` with the verified file.
4. Write the new digest into `ENTROPYLAB_HTML.sha256` (`<sha256>  entropylab.html`).
5. Update `ENTROPYLAB_HTML.version`, the release identity and digest in
   `app/src/test/java/online/entropylab/android/HtmlPinTest.java`, and the
   release evidence above and in the repository's README and SECURITY.md.
6. Run `HtmlPinTest`, build the unsigned release APK, and run the APK
   verifier below to check the packaged digest and non-debuggable manifest.

## What the app does

- Opens the bundled release HTML in a WebView. There is no URL bar. Loads that are not that asset (a `file:` URL with no host and exactly that path) are ignored. Network loads are blocked, and the manifest does not request `INTERNET`.
- The launch screen shows the EntropyLab version, the SHA-256 of the embedded HTML, the words `NO NETWORK`, and that this is a calculator, not a wallet, and it does not keep keys.
- `FLAG_SECURE` is set so the recents thumbnail is blank.
- On Android 15 and later the window draws edge to edge, so the app pads the launch screen and the page by the system-bar and display-cutout insets; the page's fixed header stays below the status bar. The pinned HTML is unchanged.
- Rotation, resizing and declared keyboard configuration changes redraw the same live WebView without reloading the calculator. Its session stays only in that in-memory instance.
- Leaving the app finishes the task and kills the process. The next open is a cold start. Process death and unhandled activity recreation also return to the launch screen.
- No calculator or view-hierarchy state is saved in an Android saved-state Bundle. Activity destruction detaches and destroys its WebView; this does not prove secure erasure inside the platform.
- DOM storage, WebView form-data saving (on by default on API 24–25) and the HTTP cache are off. Nothing is written to a keystore.

## Not available in the wrapper

The wrapper is deliberately a no-permission, in-memory calculator, so these release-HTML features do not work inside it, by design:

- **File import.** `<input type="file">` pickers do nothing: the WebView has no file chooser, so you cannot upload a PSBT or import a file.
- **Downloads.** Blob downloads are not saved: the WebView has no download handler, so the wallet.dat, journal, PSBT and recovery-sheet exports do not produce a file.
- **Print.** Printing (including recovery sheets) is not wired to Android's print framework.

For those flows, use the offline HTML (`entropylab.html` from the GitHub release, verified as above) in a desktop or mobile browser. A file chooser and download bridge may come in a follow-up; until then the wrapper requests no permissions and writes nothing to storage.

## Build

Use JDK 21 and an Android SDK with platform 36. Set `JAVA_HOME` and `PATH` to that JDK, and point `ANDROID_HOME` at the SDK. CI selects the runner’s installed JDK 21 explicitly; the pinned Gradle 8.11.1 does not support running on Java 25. From this directory:

```sh
./gradlew :app:assembleRelease
```

On a successful build, the unsigned, non-debuggable APK is
`app/build/outputs/apk/release/app-release-unsigned.apk`. It must be signed
separately before installation; signing and distribution are not configured.
The wrapper has not been tested on a physical device.

The JVM pin check does not need the SDK. From this directory:

```sh
javac -d build/pincheck app/src/main/java/online/entropylab/android/HtmlPin.java app/src/test/java/online/entropylab/android/HtmlPinTest.java
java -cp build/pincheck online.entropylab.android.HtmlPinTest
```

`HtmlPinTest` hashes `app/src/main/assets/entropylab.html` and compares it to `ENTROPYLAB_HTML.sha256` and the attested v1.1.0 release digest.

## CI and device acceptance

The Android wrapper workflow explicitly runs the standalone `HtmlPinTest` main,
builds `assembleRelease`, then hashes the HTML extracted from the APK and checks
`aapt dump permissions` on the merged APK for zero requested permissions.
It also reads the merged manifest with `aapt dump xmltree`: debugging and
backup must be off, the data-extraction rules the manifest names must exclude
every whole domain from cloud backup and device transfer, and `MainActivity`
must handle all six `configChanges`.
The workflow also runs `python3 android/lifecycle-check.py`: the actual wrapper callbacks execute against deterministic Android test doubles, covering all six declared `configChanges`, system-bar and cutout insets applied as padding, a packaged page that does not match the pin (or cannot be read) keeping Open disabled and never loading, explicit WebView debugging and form-data saving off, the bundled-page navigation check (including `file://<host>/android_asset/…`), launch and repeated rotation, empty saved-state output, background shutdown, cold creation/return and WebView cleanup. The pre-fix test failed because rotation recreated the WebView and discarded disposable input. Dispatch follows [Android’s documented configuration-change contract](https://developer.android.com/develop/adaptive-apps/cookbook/webview-state).

These callback tests are not an emulator and do not establish real device lifecycle or WebView behavior.

Device acceptance still requires opening the calculator, backgrounding and
returning (a cold launch), rotation, screenshot and recents protection, and
attempted external/file/content navigation. Record the device/API and actual
observations; source-text checks are not device evidence.
