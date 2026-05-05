package org.gossamr.crypto.blind

import org.gossamr.crypto.blind.internal.Sha512
import org.gossamr.crypto.blind.internal.SecureRandom
import io.github.andreypfau.curve25519.ed25519.Ed25519 as UpstreamEd25519

/**
 * Ed25519 private key wrapper.
 *
 * Mirrors Swift's `SwiftEdDSA.PrivateKey` (Ed25519 path): a 32-byte seed `s`
 * from which the public key, signature, and X25519 scalar are derived.
 *
 * @property s The 32-byte seed.
 */
public class Ed25519PrivateKey(public val s: ByteArray) {
    init {
        if (s.size != UpstreamEd25519.SEED_SIZE_BYTES) {
            throw BlindCryptoException.InvalidKeySize(
                "Ed25519 seed must be ${UpstreamEd25519.SEED_SIZE_BYTES} bytes, got ${s.size}",
            )
        }
    }

    private val upstream = UpstreamEd25519.keyFromSeed(s)

    /** Derive the corresponding public key. */
    public fun publicKey(): Ed25519PublicKey =
        Ed25519PublicKey(upstream.publicKey().toByteArray())

    /**
     * Sign `message` and return the 64-byte EdDSA signature.
     *
     * `context` is accepted for parity with Swift's `PrivateKey.sign(message:context:)`,
     * but only the empty-context path (Ed25519 pure) is supported in v1 — the
     * blind-signature protocol always uses an empty context.
     */
    public fun sign(message: ByteArray, context: ByteArray = byteArrayOf()): ByteArray {
        require(context.isEmpty()) { "Ed25519 context-prefixed signing not supported in v1" }
        return upstream.sign(message)
    }

    /**
     * RFC 8032 §5.1.5 buffer pruning: returns the 32-byte X25519/Ed25519 secret
     * scalar derived from the seed.
     *
     * Equivalent to Swift `PrivateKey.asX25519()`:
     * ```
     * h = SHA-512(s); h0 = h[0..32]
     * h0[0]  &= 0xf8   // clear bottom 3 bits
     * h0[31] &= 0x7f   // clear top bit (bit 255)
     * h0[31] |= 0x40   // set bit 254
     * ```
     */
    public fun asX25519(): ByteArray {
        val h = Sha512.hash(s)
        val k = h.copyOfRange(0, 32)
        k[0] = (k[0].toInt() and 0xf8).toByte()
        k[31] = (k[31].toInt() and 0x7f).toByte()
        k[31] = (k[31].toInt() or 0x40).toByte()
        return k
    }

    public companion object {
        /** Generate a fresh private key with a CSPRNG-sampled 32-byte seed. */
        public fun generate(): Ed25519PrivateKey {
            val seed = SecureRandom.nextBytes(UpstreamEd25519.SEED_SIZE_BYTES)
            return Ed25519PrivateKey(seed)
        }
    }
}
