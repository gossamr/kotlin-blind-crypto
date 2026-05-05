package org.gossamr.crypto.blind

import dev.whyoleg.cryptography.random.CryptographyRandom
import io.github.andreypfau.curve25519.scalar.Scalar
import org.openjdk.jmh.annotations.Benchmark
import org.openjdk.jmh.annotations.BenchmarkMode
import org.openjdk.jmh.annotations.Mode
import org.openjdk.jmh.annotations.OutputTimeUnit
import org.openjdk.jmh.annotations.Scope
import org.openjdk.jmh.annotations.Setup
import org.openjdk.jmh.annotations.State
import java.util.concurrent.TimeUnit

/**
 * JMH harness for [BlindSign]. Throughput, ops/s.
 *
 * Run: `./gradlew :benchmarks:jmh`. Results land in `benchmarks/build/results/jmh/`.
 *
 * Compare against the Swift baseline (`swift test --filter BlindBench` on the same
 * hardware) — the Kotlin port must equal-or-beat per the project plan.
 */
@State(Scope.Benchmark)
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
open class BlindBench {

    private lateinit var pb: ByteArray
    private lateinit var rb: ByteArray
    private lateinit var message: ByteArray
    private lateinit var skBob: Ed25519PrivateKey
    private lateinit var k: Scalar
    private lateinit var preBuiltAlice: BlindSign
    private lateinit var preBuiltE: ByteArray
    private lateinit var preBuiltS: Scalar

    @Setup
    fun setup() {
        skBob = Ed25519PrivateKey.generate()
        pb = skBob.publicKey().r
        // Uniform mod-L scalar via 64-byte wide reduction, same sampling the library uses.
        k = Scalar.fromWideByteArray(CryptographyRandom.nextBytes(64))
        rb = BlindSign.scalarToPoint(k)
        message = CryptographyRandom.nextBytes(256)
        preBuiltAlice = BlindSign(pb, rb)
        preBuiltE = preBuiltAlice.transaction(message)
        preBuiltS = BlindSign.sign(preBuiltE, skBob, k)
    }

    /** Construct + transaction(): the cost Alice pays per blind-auth flow. */
    @Benchmark
    fun aliceBlindingAndTransaction(): ByteArray {
        val alice = BlindSign(pb, rb)
        return alice.transaction(message)
    }

    /** signature(): the assembly step Alice runs after Bob responds. */
    @Benchmark
    fun aliceSignatureAssembly(): ByteArray = preBuiltAlice.signature(preBuiltS)

    /** sign(): the server-side step (Bob), kept here to track its cost too. */
    @Benchmark
    fun bobSign(): Scalar = BlindSign.sign(preBuiltE, skBob, k)

    /** Full one-shot Alice-Bob-Alice roundtrip ops/s. */
    @Benchmark
    fun fullRoundtrip(): ByteArray {
        val alice = BlindSign(pb, rb)
        val e = alice.transaction(message)
        val s = BlindSign.sign(e, skBob, k)
        return alice.signature(s)
    }
}
