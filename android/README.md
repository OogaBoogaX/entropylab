# EntropyLab Android wrapper

This directory is a thin Android wrapper around the **release** file `entropylab.html`. It does not generate entropy, sign, store keys, or add a workspace tab. It does not rebuild WASM and it does not modify `src/`.

## Pinned release bytes

The HTML the APK embeds is **vendored** at `app/src/main/assets/entropylab.html`. These are the published **v1.0.0rc1** release bytes, SHA-256 `7f8685814e2bab0c80f75dd6d2cff1b3354bee51faecd65942a73e12968808a0`, taken from the GitHub release and verified against that release's `SHA256SUMS.txt`/`SHA256SUMS.asc` before committing. The same digest is the pin in `ENTROPYLAB_HTML.sha256`; `ENTROPYLAB_HTML.version` pins its displayed release identity independently of the root package version.

The wrapper deliberately does **not** package the `entropylab.html` at the repository root: that file is a CI artifact rebuilt and recommitted on every merge to `rock`, so a pin against it goes stale on merge. The vendored asset changes only when this module is deliberately updated to a new release.

The build and the app both fail closed on the pin:

- `verifyEntropylabHtml` (Gradle, wired into `preBuild`) hashes the vendored asset and refuses the build unless it matches `ENTROPYLAB_HTML.sha256`.
- At runtime the app re-hashes the packaged asset and compares it to the pin baked into `BuildConfig.HTML_SHA256`; a mismatch shows a blocking message and the calculator will not open.
- `HtmlPinTest` (below) additionally pins both to the attested release digest, so the pin file cannot drift from the release it claims to be.

### Updating to a future release

1. Download `entropylab.html`, `SHA256SUMS.txt`, and `SHA256SUMS.asc` from the new GitHub release tag.
2. Verify: `gpg --verify SHA256SUMS.asc SHA256SUMS.txt`, then `sha256sum -c SHA256SUMS.txt`.
3. Replace `app/src/main/assets/entropylab.html` with the verified file.
4. Write the new digest into `ENTROPYLAB_HTML.sha256` (`<sha256>  entropylab.html`).
5. Update `ENTROPYLAB_HTML.version`, the `RELEASE_SHA256` constant in `app/src/test/java/online/entropylab/android/HtmlPinTest.java` and the tag named in this section.
6. Run `HtmlPinTest` and `./gradlew :app:assembleDebug`; the packaged asset must hash to the new digest.

## What the app does

- Opens the bundled release HTML in a WebView. There is no URL bar. Loads that are not that asset (a `file:` URL with no host and exactly that path) are ignored. Network loads are blocked, and the manifest does not request `INTERNET`.
- The launch screen shows the EntropyLab version, the SHA-256 of the embedded HTML, the words `NO NETWORK`, and that this is a calculator, not a wallet, and it does not keep keys.
- `FLAG_SECURE` is set so the recents thumbnail is blank.
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

JDK 17 or newer, and an Android SDK with platform 36. Point `ANDROID_HOME` at the SDK. From this directory:

```sh
./gradlew :app:assembleDebug
```

The debug APK is `app/build/outputs/apk/debug/app-debug.apk` only after that command succeeds. This README does not claim an APK exists. Only debug builds have been produced; the wrapper has not been tested on a physical device.

The JVM pin check does not need the SDK. From this directory:

```sh
javac -d build/pincheck app/src/main/java/online/entropylab/android/HtmlPin.java app/src/test/java/online/entropylab/android/HtmlPinTest.java
java -cp build/pincheck online.entropylab.android.HtmlPinTest
```

`HtmlPinTest` hashes `app/src/main/assets/entropylab.html` and compares it to `ENTROPYLAB_HTML.sha256` and the attested v1.0.0rc1 release digest.

## CI and device acceptance

The Android wrapper workflow explicitly runs the standalone `HtmlPinTest` main,
builds `assembleDebug`, then hashes the HTML extracted from the APK and checks
`aapt dump permissions` on the merged APK for zero requested permissions.
The workflow also runs `python3 android/lifecycle-check.py`: the actual wrapper callbacks execute against deterministic Android test doubles, covering all six declared `configChanges`, form-data saving off, the bundled-page navigation check (including `file://<host>/android_asset/…`), launch and repeated rotation, empty saved-state output, background shutdown, cold creation/return and WebView cleanup. The pre-fix test failed because rotation recreated the WebView and discarded disposable input. Dispatch follows [Android’s documented configuration-change contract](https://developer.android.com/develop/adaptive-apps/cookbook/webview-state).

These callback tests are not an emulator and do not establish real device lifecycle or WebView behavior.

Device acceptance still requires opening the calculator, backgrounding and
returning (a cold launch), rotation, screenshot and recents protection, and
attempted external/file/content navigation. Record the device/API and actual
observations; source-text checks are not device evidence.
