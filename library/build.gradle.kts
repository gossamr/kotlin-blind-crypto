import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.kotlin.multiplatform)
    // AGP 9+: KMP modules use the dedicated Android KMP library plugin; combining
    // com.android.library with org.jetbrains.kotlin.multiplatform is no longer allowed.
    // The jvm() target exists so pure-JVM consumers (:benchmarks JMH) can resolve this
    // project; Android consumers get the android target's AAR-equivalent variant.
    alias(libs.plugins.android.kotlin.multiplatform.library)
    alias(libs.plugins.detekt)
    `maven-publish`
}

kotlin {
    jvm {
        compilerOptions {
            jvmTarget.set(JvmTarget.JVM_17)
        }
    }

    android {
        namespace = "org.gossamr.crypto.blind"
        compileSdk = 36
        minSdk = 26

        compilerOptions {
            jvmTarget.set(JvmTarget.JVM_17)
        }
        // Host/device test source sets are opt-in under this plugin (withHostTestBuilder /
        // withDeviceTestBuilder); none are wired because the unit tests run on the jvm
        // target and no instrumentation tests exist yet.
    }

    compilerOptions {
        // Vendored curve25519 source uses ULong/UByte arithmetic for limb operations.
        // Matches upstream curve25519-kotlin's own build config.
        optIn.add("kotlin.ExperimentalUnsignedTypes")
    }

    sourceSets {
        commonMain.dependencies {
            // Curve25519 source is vendored under io.github.andreypfau.curve25519.* (see
            // VENDORED.md). The only remaining external from that author is the small
            // constant-time helpers module.
            implementation(libs.kotlinx.crypto.subtle)
            implementation(libs.cryptography.core)
            implementation(libs.cryptography.jdk)
            implementation(libs.cryptography.random)
        }

        jvmTest.dependencies {
            implementation(libs.junit.jupiter)
            implementation(kotlin("test"))
            // Gradle 9 no longer auto-provides the JUnit Platform launcher; declare it explicitly.
            // https://docs.gradle.org/9.5.0/userguide/java_testing.html#sec:configuring_jvm_test_tasks
            runtimeOnly(libs.junit.platform.launcher)
        }
    }
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform()
}

// --- Maven publication (mavenLocal) -----------------------------------------------------------
// KMP auto-registers one publication per target plus the umbrella `kotlinMultiplatform`
// publication, sources jars included, so consumers get jump-to-source in their IDE. Only the
// coordinates need remapping: the module is named `library`, but artifacts publish as
// kotlin-blind-crypto[-jvm|-android]. Coordinates default to the gradle.properties `publish.*`
// values; override with -P at the CLI.

group = providers.gradleProperty("publish.groupId").getOrElse("org.gossamr")
version = providers.gradleProperty("publish.version").getOrElse("0.1.0")

publishing {
    publications.withType<MavenPublication>().configureEach {
        artifactId = artifactId.replace(
            project.name,
            providers.gradleProperty("publish.artifactId").getOrElse("kotlin-blind-crypto"),
        )
        pom {
            name.set("kotlin-blind-crypto")
            description.set(
                "Two-party blind Schnorr signature on Ed25519 for Kotlin Multiplatform " +
                    "(Android + JVM), layered on cryptography-kotlin with vendored " +
                    "curve25519-kotlin primitives.",
            )
            licenses {
                license {
                    name.set("MIT License")
                }
            }
        }
    }
}
