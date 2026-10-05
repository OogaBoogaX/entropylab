# EntropyLab Android wrapper

This directory is a thin Android wrapper around the release file `entropylab.html` that already sits at the repository root. It does not generate entropy, sign, store keys, or add a workspace tab. It does not rebuild WASM and it does not modify `src/`.

The wrapper embeds that HTML only after its SHA-256 matches both `SHA256SUMS.txt` and `ENTROPYLAB_HTML.sha256` (the pin file in this directory). A mismatch fails the build and, if one were ever packaged, blocks the calculator from opening.

## What the app does

- Opens the bundled release HTML in a WebView. There is no URL bar. Loads that are not that asset are ignored. Network loads are blocked, and the manifest does not request `INTERNET`.
- The launch screen shows the EntropyLab version, the SHA-256 of the embedded HTML, the words `NO NETWORK`, and that this is a calculator, not a wallet, and it does not keep keys.
- `FLAG_SECURE` is set so the recents thumbnail is blank.
- Leaving the app finishes the task and kills the process. The next open is a cold start.
- DOM storage and the HTTP cache are off. Nothing is written to a keystore.

## Build

JDK 17 or newer, and an Android SDK with platform 36. Point `ANDROID_HOME` at the SDK. From this directory:

```sh
./gradlew :app:assembleDebug
```

The debug APK is `app/build/outputs/apk/debug/app-debug.apk` only after that command succeeds. This README does not claim an APK exists.

The JVM pin check does not need the SDK:

```sh
javac -d build/pincheck app/src/main/java/online/entropylab/android/HtmlPin.java app/src/test/java/online/entropylab/android/HtmlPinTest.java
java -cp build/pincheck online.entropylab.android.HtmlPinTest ..
```

`HtmlPinTest` hashes `../entropylab.html` and compares it to `../SHA256SUMS.txt` and `ENTROPYLAB_HTML.sha256`.
