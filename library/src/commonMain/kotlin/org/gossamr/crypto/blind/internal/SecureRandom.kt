package org.gossamr.crypto.blind.internal

import dev.whyoleg.cryptography.random.CryptographyRandom
import io.github.andreypfau.curve25519.scalar.Scalar

/** CSPRNG-backed helpers for sampling raw bytes and uniform mod-L scalars. */
internal object SecureRandom {
    /**
     * Uniform mod-L scalar sampled via 64-byte wide reduction.
     *
     * Matches Swift `Ed.randomNonce(.ed25519)` which samples uniformly in (1, L-1)
     * via rejection on `(L+1).randomLessThan() - 1`. Wide reduction gives the same
     * uniform distribution mod L with negligible bias and no rejection loop.
     */
    fun randomScalarModL(): Scalar {
        val wide = CryptographyRandom.nextBytes(64)
        return Scalar.fromWideByteArray(wide)
    }

    /** Returns `size` cryptographically random bytes. */
    fun nextBytes(size: Int): ByteArray = CryptographyRandom.nextBytes(size)
}
