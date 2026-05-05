// AGP 9.2.1 ships bundled KGP 2.2.10. The buildscript classpath pins the same KGP version
// explicitly so the KMP plugins resolve it. See:
// https://developer.android.com/build/releases/agp-9-0-0-release-notes#built-in-kotlin
buildscript {
    dependencies {
        classpath(libs.kotlin.gradle.plugin)
    }
}

plugins {
    alias(libs.plugins.android.kotlin.multiplatform.library) apply false
    alias(libs.plugins.kotlin.multiplatform) apply false
    alias(libs.plugins.kotlin.jvm) apply false
    alias(libs.plugins.detekt) apply false
    alias(libs.plugins.jmh) apply false
}

subprojects {
    apply(plugin = "dev.detekt")

    extensions.configure<dev.detekt.gradle.extensions.DetektExtension> {
        config.setFrom(rootProject.file("detekt.yml"))
        buildUponDefaultConfig = true
        autoCorrect = false
        parallel = true
    }

    // Vendored curve25519-kotlin source (under io/github/andreypfau/) is not subject to
    // our style rules. EC reference implementations use mathematical naming (XX, Y2, hi/lo
    // limb arrays) and structural conventions (long methods for loop unrolls, many small
    // helpers per FieldElement) that don't survive a Kotlin lint pass and shouldn't be
    // forced to. See library/src/commonMain/kotlin/io/github/andreypfau/curve25519/VENDORED.md.
    tasks.withType<dev.detekt.gradle.Detekt>().configureEach {
        exclude("**/io/github/andreypfau/**")
    }
    tasks.withType<dev.detekt.gradle.DetektCreateBaselineTask>().configureEach {
        exclude("**/io/github/andreypfau/**")
    }
}
