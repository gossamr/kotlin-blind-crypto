package org.gossamr.crypto.blind.internal

import io.github.andreypfau.curve25519.edwards.CompressedEdwardsY
import io.github.andreypfau.curve25519.edwards.EdwardsPoint

/**
 * Standard Ed25519 basepoint, encoded per RFC 8032 §5.1.5 as the 32-byte
 * little-endian compression of `y = 4/5 mod p` with x even. Cached because
 * curve25519-kotlin keeps its `ED25519_BASEPOINT_TABLE` internal.
 */
private val ED25519_BASEPOINT_COMPRESSED = byteArrayOf(
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
)

/** Decompressed Ed25519 basepoint G, lazily decoded once and reused. */
internal val Ed25519Basepoint: EdwardsPoint by lazy {
    val compressed = CompressedEdwardsY(ED25519_BASEPOINT_COMPRESSED.copyOf())
    EdwardsPoint().apply { set(compressed) }
}
