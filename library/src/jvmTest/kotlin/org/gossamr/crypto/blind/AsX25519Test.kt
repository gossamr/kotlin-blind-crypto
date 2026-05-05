package org.gossamr.crypto.blind

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals

/**
 * Sanity-checks the RFC 8032 §5.1.5 buffer pruning produced by [Ed25519PrivateKey.asX25519].
 * The pruned scalar must satisfy:
 *  - low 3 bits of byte 0 are clear
 *  - high bit (bit 255) of byte 31 is clear
 *  - bit 254 of byte 31 is set
 */
class AsX25519Test {

    @Test
    fun bitPruningMatchesRfc8032() {
        // RFC 8032 §7.1 TEST 1 seed.
        val seed = hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        val pruned = Ed25519PrivateKey(seed).asX25519()

        assertEquals(32, pruned.size, "pruned scalar must be 32 bytes")
        assertEquals(0.toByte(), (pruned[0].toInt() and 0x07).toByte(), "low 3 bits not cleared")
        assertEquals(0.toByte(), (pruned[31].toInt() and 0x80).toByte(), "high bit not cleared")
        assertEquals(0x40.toByte(), (pruned[31].toInt() and 0x40).toByte(), "bit 254 not set")
    }
}

private fun hex(s: String): ByteArray =
    s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
