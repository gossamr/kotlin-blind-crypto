# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-06-11

Initial release. Two-party blind Schnorr signature on Ed25519 for Kotlin
Multiplatform (Android + JVM), implementing the four-step protocol from Stanisław Barański,
[*Implementing blind signature on ed25519*](https://stan.bar/blindsig/) (2021).

### Added

- `BlindSign` — Alice (requester) role: blinds the signer's nonce, computes
  the blinded challenge `e = (H(R' || P || M) + b) mod L`, and assembles the
  final 64-byte EdDSA signature `(R', s + a)` from Bob's response.
- `BlindSign.Companion.sign(e, sk, k)` — in-process Bob simulator for tests
  and any caller that holds the signing key.
- `Ed25519PublicKey` — verify wrapper.
- `Ed25519PrivateKey` — sign wrapper plus `asX25519()` (RFC 8032 §5.1.5
  buffer pruning) needed for the blind-signing math.
- `BlindCryptoException` — sealed hierarchy: `PointDecode`, `InvalidScalar`,
  `InvalidKeySize`, `InvalidSignatureSize`.
- Internal `Sha512` facade over cryptography-kotlin's hasher (single-shot,
  with a concatenating multi-part overload).
- Internal `SecureRandom` with `randomScalarModL()` via 64-byte wide
  reduction, matching the Swift `Ed.randomNonce(.ed25519)` distribution.
- Internal `Ed25519Basepoint` — lazy-decompressed cache of the basepoint
  (workaround for upstream's `internal`-scoped `ED25519_BASEPOINT_TABLE`).

### Tests

- RFC 8032 §7.1 sign/verify vectors (TEST 1, TEST 2, TEST 3, TEST 1024).
- BlindSign protocol roundtrip — random keys, plus a deterministic
  golden-vector variant asserting every intermediate (`pk`, `rb`, `e`, `s`,
  `sig`) against an independent RFC 8032 reference implementation; the
  sister Swift implementation asserts the same constants.
- Edge cases: empty message, 1 KB message, invalid `pb`/`rb` sizes.
- `asX25519()` bit-pruning sanity check.

### Build

- Kotlin Multiplatform library: `android` target (`minSdk 26`,
  `compileSdk 36`, via `com.android.kotlin.multiplatform.library`) plus a
  `jvm` target for pure-JVM consumers; JVM target 17 on both.
- Gradle 9.5.0, AGP 9.1.1, Kotlin 2.3.21 (root `buildscript` classpath pins
  KGP over AGP's bundled 2.2.10).
- detekt 2.0.0-alpha.3 with a crypto-tuned ruleset (magic numbers, long
  methods, generic catches relaxed; everything else strict); vendored
  curve25519 sources excluded.
- JMH 1.37 benchmark harness with four scenarios:
  `aliceBlindingAndTransaction`, `aliceSignatureAssembly`, `bobSign`,
  `fullRoundtrip`.
- GitHub Actions test workflow (JDK 17): assemble, `allTests`, detekt, and
  `jmhJar` (benchmark harness compile check; execution is local-only).

### Publishing

- mavenLocal-publishable as `org.gossamr:kotlin-blind-crypto:0.1.0` — KMP
  publication set (umbrella plus `-jvm`/`-android` artifacts, sources jars,
  minimal POM with name/description/license).
- Coordinates overridable via `-Ppublish.groupId=…` etc.

### Dependencies

- Vendored: `curve25519-kotlin` v0.0.8 source under
  `io.github.andreypfau.curve25519.*` — Edwards-curve primitives, including
  a fix to the variable-base lookup table (see VENDORED.md).
- `io.github.andreypfau:kotlinx-crypto-subtle:0.0.4` — constant-time helpers.
- `dev.whyoleg.cryptography:cryptography-core:0.6.0` + `cryptography-provider-jdk` + `cryptography-random` — SHA-512 + CSPRNG.

### Notes

- Sister Swift implementation:
  [gossamr/SwiftEdDSA `vmc`](https://github.com/gossamr/SwiftEdDSA/tree/vmc).
- Plain blind Schnorr is known to be vulnerable to ROS-style attacks under
  high signing concurrency (Benhamouda et al., eprint 2020/945). Callers
  must bound concurrent signing sessions per signer; the typical
  one-session-per-token-issuance flow is well within safe parameters.

[Unreleased]: https://github.com/gossamr/kotlin-blind-crypto/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/gossamr/kotlin-blind-crypto/releases/tag/v0.1.0
