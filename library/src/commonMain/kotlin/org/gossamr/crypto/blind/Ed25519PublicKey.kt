package org.gossamr.crypto.blind

import io.github.andreypfau.curve25519.ed25519.Ed25519 as UpstreamEd25519
import io.github.andreypfau.curve25519.ed25519.Ed25519PublicKey as UpstreamPub

/**
 * Ed25519 public key wrapper.
 *
 * Mirrors the surface of Swift's `SwiftEdDSA.PublicKey` constrained to the
 * Ed25519 verify path used by the blind-signature protocol.
 *
 * @property r The 32-byte raw public key (compressed Edwards point).
 */
public class Ed25519PublicKey(public val r: ByteArray) {
    init {
        if (r.size != UpstreamEd25519.PUBLIC_KEY_SIZE_BYTES) {
            throw BlindCryptoException.InvalidKeySize(
                "Ed25519 public key must be ${UpstreamEd25519.PUBLIC_KEY_SIZE_BYTES} bytes, got ${r.size}",
            )
        }
    }

    private val upstream = UpstreamPub(r.copyOf())

    /**
     * Verify a 64-byte EdDSA signature over `message`.
     *
     * @return `true` iff the signature is valid; `false` for any size or decode error.
     */
    public fun verify(signature: ByteArray, message: ByteArray): Boolean {
        if (signature.size != UpstreamEd25519.SIGNATURE_SIZE_BYTES) return false
        return upstream.verify(message, signature)
    }
}
