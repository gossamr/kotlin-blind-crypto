# kotlin-blind-crypto

[![Test](https://github.com/gossamr/kotlin-blind-crypto/actions/workflows/test.yml/badge.svg)](https://github.com/gossamr/kotlin-blind-crypto/actions/workflows/test.yml)
[![Kotlin](https://img.shields.io/badge/kotlin-2.3.21-blue.svg?logo=kotlin)](https://kotlinlang.org)
[![Android](https://img.shields.io/badge/Android-minSdk%2026-3DDC84.svg?logo=android)](https://developer.android.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Gradle](https://img.shields.io/badge/Gradle-9.5.0-02303A.svg?logo=gradle)](https://gradle.org)

Two-party blind Schnorr signature on Ed25519 for Kotlin Multiplatform
(Android + JVM). Layered on
[cryptography-kotlin](https://github.com/whyoleg/cryptography-kotlin) for
hashing and CSPRNG, with vendored
[curve25519-kotlin](https://github.com/andreypfau/curve25519-kotlin)
Edwards-curve primitives.

## Install

After running `./gradlew :library:publishToMavenLocal` (see below):

```kotlin
// settings.gradle.kts
dependencyResolutionManagement {
    repositories {
        mavenLocal()
        mavenCentral()
        google()
    }
}

// app/build.gradle.kts
dependencies {
    implementation("org.gossamr:kotlin-blind-crypto:0.1.0")
}
```

## Quick start

The Alice (requester) side of a blind-signing flow:

```kotlin
import org.gossamr.crypto.blind.BlindSign
import org.gossamr.crypto.blind.Ed25519PublicKey

// Bob (the signer) sent us his public key Pb and a fresh nonce point Rb = [k]·G.
val alice = BlindSign(pb = bobPublicKey, rb = bobNonce)

// Hash the message we want signed and send the blinded challenge `e` to Bob.
val e = alice.transaction(message)
val s: Scalar = bob.sign(e)  // server round trip

// Assemble the standard 64-byte Ed25519 signature.
val signature: ByteArray = alice.signature(s)

// Verifies under Bob's *unblinded* public key — Bob never saw the message.
check(Ed25519PublicKey(bobPublicKey).verify(signature, message))
```

## Algorithm

Implements the 2-party blind Schnorr signature on Ed25519 described in
Stanisław Barański, [*Implementing blind signature on
ed25519*](https://stan.bar/blindsig/) (2021-02-13). See the KDoc on
[`BlindSign`](library/src/commonMain/kotlin/org/gossamr/crypto/blind/BlindSign.kt) for
the four-step protocol and a note on the known ROS-style attack surface.

## Modules

- `:library` — Kotlin Multiplatform library with `android` + `jvm` targets
  (`com.android.kotlin.multiplatform.library`, `minSdk 26`, `compileSdk 36`).
  Publishes `org.gossamr.crypto.blind`.
- `:benchmarks` — JVM-only JMH harness for measuring `BlindSign` throughput
  (consumes the `jvm` target).

## Build

```bash
./gradlew :library:build
./gradlew :library:allTests
./gradlew detekt
./gradlew :benchmarks:jmh
```

Requires JDK 17. Uses Gradle 9.5.0 via the wrapper. Built against AGP 9.1.1;
the bundled KGP 2.2.10 is overridden to Kotlin 2.3.21 via the root
`buildscript` classpath.

## Publish to mavenLocal

```bash
./gradlew :library:publishToMavenLocal
```

Produces the KMP publication set — umbrella `kotlin-blind-crypto` plus
per-target `kotlin-blind-crypto-jvm` / `kotlin-blind-crypto-android` artifacts
with sources jars and minimal POMs — under `~/.m2/repository/org/gossamr/`.
Coordinates default to the `publish.*` values in `gradle.properties`; override
per build with `-Ppublish.groupId=...`, `-Ppublish.artifactId=...`,
`-Ppublish.version=...`.

## Contributing

Issues and PRs welcome. Before opening a PR, run:

```bash
./gradlew :library:allTests detekt
```

## License

[MIT](LICENSE).

Sister Swift implementation:
[gossamr/SwiftEdDSA `vmc`](https://github.com/gossamr/SwiftEdDSA/tree/vmc).
