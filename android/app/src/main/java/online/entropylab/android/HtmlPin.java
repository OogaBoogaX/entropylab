package online.entropylab.android;

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/** SHA-256 pin for the release entropylab.html. No Android types, no java.nio.file. */
public final class HtmlPin {
    private HtmlPin() {}

    public static String sha256(InputStream input) throws IOException {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
        byte[] buffer = new byte[65536];
        int read;
        while ((read = input.read(buffer)) >= 0) digest.update(buffer, 0, read);
        byte[] raw = digest.digest();
        StringBuilder hex = new StringBuilder(raw.length * 2);
        for (byte value : raw) hex.append(String.format("%02x", value));
        return hex.toString();
    }

    public static String hashToken(String text) {
        for (String line : text.split("\\R")) {
            String trimmed = line.trim();
            if (trimmed.endsWith("entropylab.html")) return trimmed.split("\\s+")[0];
        }
        throw new IllegalArgumentException("pin does not name entropylab.html");
    }

    public static void check(String actual, String pinText) {
        String pin = hashToken(pinText);
        if (!actual.equals(pin)) {
            throw new IllegalStateException("Refusing entropylab.html: SHA-256 " + actual + " pin " + pin);
        }
    }
}
