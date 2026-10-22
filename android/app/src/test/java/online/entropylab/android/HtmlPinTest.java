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
        // Fail closed: any other digest, or a pin file that names no entropylab.html, is refused.
        String other = (actual.charAt(0) == '0' ? "1" : "0") + actual.substring(1);
        expectRefused(() -> HtmlPin.check(other, pinText), IllegalStateException.class, "a different digest");
        expectRefused(() -> HtmlPin.hashToken(pin + "  other.html"), IllegalArgumentException.class, "a pin naming another file");
        String version = Files.readString(root.resolve("ENTROPYLAB_HTML.version")).trim();
        if (!"1.0.0rc1".equals(version)) {
            throw new IllegalStateException("embedded release identity does not match the attested release");
        }
        System.out.println("HtmlPinTest OK " + actual);
    }

    private static void expectRefused(Runnable check, Class<? extends RuntimeException> type, String what) {
        try {
            check.run();
        } catch (RuntimeException refused) {
            if (type.isInstance(refused)) return;
            throw refused;
        }
        throw new IllegalStateException("HtmlPin accepted " + what);
    }
}
