package org.gossamr.crypto.blind.internal

import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.SHA512
import dev.whyoleg.cryptography.operations.Hasher

/** Thin SHA-512 facade over cryptography-kotlin's provider-resolved hasher. */
internal object Sha512 {
    private val hasher: Hasher = CryptographyProvider.Default.get(SHA512).hasher()

    /** Hash a single buffer. */
    fun hash(input: ByteArray): ByteArray = hasher.hashBlocking(input)

    /**
     * Hash the concatenation of `parts`. Concatenates manually and uses the same single-shot
     * path as [hash] (single-buffer overload), since the streaming `update`/`hashToByteArray`
     * pattern is not yet trusted in this library.
     */
    fun hash(vararg parts: ByteArray): ByteArray {
        val combined = ByteArray(parts.sumOf { it.size })
        var offset = 0
        for (p in parts) {
            p.copyInto(combined, offset)
            offset += p.size
        }
        return hasher.hashBlocking(combined)
    }
}
