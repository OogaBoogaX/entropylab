package online.entropylab.android;

import java.nio.file.Files;
import java.nio.file.Path;

/**
 * JVM check: the vendored release HTML and the pin file carry the attested
 * v1.0.0rc1 release digest. The expected digest is published in the release's
 * SHA256SUMS.txt/SHA256SUMS.asc — it is not derived from this repository's
 * CI-committed artifact, which is rewritten on every merge to rock.
 */
public final class HtmlPinTest {
    /** SHA-256 of the v1.0.0rc1 release entropylab.html, from that release's signed SHA256SUMS. */
    private static final String RELEASE_SHA256 =
        "7f8685814e2bab0c80f75dd6d2cff1b3354bee51faecd65942a73e12968808a0";

    public static void main(String[] args) throws Exception {
        Path root = Path.of(args.length > 0 ? args[0] : ".").toAbsolutePath().normalize();
        String pinText = Files.readString(root.resolve("ENTROPYLAB_HTML.sha256"));
        String pin = HtmlPin.hashToken(pinText);
        if (!RELEASE_SHA256.equals(pin)) {
            throw new IllegalStateException(
                "pin " + pin + " does not match the v1.0.0rc1 release digest " + RELEASE_SHA256);
        }
        String actual;
        try (var input = Files.newInputStream(root.resolve("app/src/main/assets/entropylab.html"))) {
            actual = HtmlPin.sha256(input);
        }
        HtmlPin.check(actual, pinText);
        String version = Files.readString(root.resolve("ENTROPYLAB_HTML.version")).trim();
        if (!"1.0.0rc1".equals(version)) {
            throw new IllegalStateException("embedded release identity does not match the attested release");
        }
        System.out.println("HtmlPinTest OK " + actual);
    }
}
