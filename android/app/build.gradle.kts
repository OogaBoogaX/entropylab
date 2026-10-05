import java.security.MessageDigest

plugins {
    id("com.android.application")
}

val repoRoot = rootProject.projectDir.parentFile
// The packaged bytes are the vendored v1.0.0rc1 release asset, pinned by
// ENTROPYLAB_HTML.sha256 — not the repo-root entropylab.html, which CI
// rebuilds and recommits on every merge to rock.
val htmlFile = project.file("src/main/assets/entropylab.html")
val pinFile = rootProject.projectDir.resolve("ENTROPYLAB_HTML.sha256")

fun sha256Hex(file: File): String {
    val digest = MessageDigest.getInstance("SHA-256")
    file.inputStream().use { input ->
        val buffer = ByteArray(65536)
        while (true) {
            val read = input.read(buffer)
            if (read < 0) break
            digest.update(buffer, 0, read)
        }
    }
    return digest.digest().joinToString("") { "%02x".format(it) }
}

fun hashToken(text: String, label: String): String {
    val line = text.lineSequence().map { it.trim() }.firstOrNull { it.endsWith("entropylab.html") }
        ?: throw GradleException("$label does not name entropylab.html")
    return line.split(Regex("\\s+")).first()
}

val packageVersion = Regex("\"version\"\\s*:\\s*\"([^\"]+)\"")
    .find(repoRoot.resolve("package.json").readText())
    ?.groupValues?.get(1)
    ?: throw GradleException("package.json has no version")

val pinnedHash = hashToken(pinFile.readText(), "pin file")

tasks.register("verifyEntropylabHtml") {
    inputs.file(htmlFile)
    inputs.file(pinFile)
    doLast {
        val actual = sha256Hex(htmlFile)
        val pin = hashToken(pinFile.readText(), "pin file")
        if (actual != pin) {
            throw GradleException("Refusing to package entropylab.html: SHA-256 $actual pin $pin")
        }
    }
}

android {
    namespace = "online.entropylab.android"
    compileSdk = 36

    defaultConfig {
        applicationId = "online.entropylab.android"
        minSdk = 24
        targetSdk = 36
        versionCode = 1
        versionName = packageVersion
        buildConfigField("String", "HTML_SHA256", "\"$pinnedHash\"")
        buildConfigField("String", "ENTROPYLAB_VERSION", "\"$packageVersion\"")
    }

    buildFeatures {
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }
}

tasks.named("preBuild").configure { dependsOn("verifyEntropylabHtml") }
