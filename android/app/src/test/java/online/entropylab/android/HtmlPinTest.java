package online.entropylab.android;

import java.nio.file.Files;
import java.nio.file.Path;

/** JVM check: the release HTML, SHA256SUMS.txt, and the pin file are one hash. */
public final class HtmlPinTest {
    public static void main(String[] args) throws Exception {
        Path root = Path.of(args.length > 0 ? args[0] : ".").toAbsolutePath().normalize();
        Path html = root.resolve("entropylab.html");
        String pinText = Files.readString(root.resolve("android/ENTROPYLAB_HTML.sha256"));
        String sumsText = Files.readString(root.resolve("SHA256SUMS.txt"));
        String actual;
        try (var input = Files.newInputStream(html)) {
            actual = HtmlPin.sha256(input);
        }
        HtmlPin.check(actual, pinText, sumsText);
        String manifest = Files.readString(root.resolve("android/app/src/main/AndroidManifest.xml"));
        if (manifest.contains("INTERNET")) {
            throw new IllegalStateException("manifest must not request INTERNET");
        }
        String activity = Files.readString(root.resolve("android/app/src/main/java/online/entropylab/android/MainActivity.java"));
        if (!activity.contains("FLAG_SECURE") || !activity.contains("killProcess")) {
            throw new IllegalStateException("activity must set FLAG_SECURE and kill the process on leave");
        }
        String layout = Files.readString(root.resolve("android/app/src/main/res/layout/activity_main.xml"));
        if (!layout.contains("NO NETWORK") || !layout.contains("not a wallet")) {
            throw new IllegalStateException("launch screen is missing the required wording");
        }
        System.out.println("HtmlPinTest OK " + actual);
    }
}
