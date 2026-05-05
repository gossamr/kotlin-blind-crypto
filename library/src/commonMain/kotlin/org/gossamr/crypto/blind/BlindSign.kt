package org.gossamr.crypto.blind

import org.gossamr.crypto.blind.internal.Ed25519Basepoint
import org.gossamr.crypto.blind.internal.SecureRandom
import org.gossamr.crypto.blind.internal.Sha512
import io.github.andreypfau.curve25519.edwards.CompressedEdwardsY
import io.github.andreypfau.curve25519.edwards.EdwardsPoint
import io.github.andreypfau.curve25519.scalar.Scalar

/**
 * 2-party blind Schnorr signature on Ed25519 — Alice (requester) role.
 *
 * Algorithm source: Stanisław Barański, *Implementing blind signature on ed25519*
 * (https://stan.bar/blindsig/, 2021-02-13). Notation below mirrors that post.
 * Sister Swift implementation: https://github.com/gossamr/SwiftEdDSA/tree/vmc.
 *
 * Let `G` be the Ed25519 basepoint, `L` the group order, `H` SHA-512, `M` the message,
 * `P = [x]·G` Bob's public key. The four-step protocol (Bob initiates):
 *
 * 1. Bob samples nonce `k ∈ (1, L-1)`, computes `R = [k]·G`, sends `R` to Alice.
 * 2. Alice samples `a, b ∈ (1, L-1)`, computes
 *    `R' = R + [a]·G + [b]·P`, `e' = H(R' || P || M)`, `e = (e' + b) mod L`,
 *    sends `e` to Bob.
 * 3. Bob computes `s = (e·x + k) mod L`, sends `s` to Alice.
 * 4. Alice computes `s' = (s + a) mod L`. The signature is the pair `(R', s')`,
 *    which verifies as a standard Ed25519 signature under Bob's public key `P`.
 *
 * In this class, `Pb` corresponds to `P`, `Rb` corresponds to `R`, `r` to `R'`, and
 * the scalar `x` Bob uses is his RFC 8032 §5.1.5 pruned secret scalar
 * (see [Ed25519PrivateKey.asX25519]).
 *
 * Note: Baranski's post and this implementation use the standard blind Schnorr scheme.
 * That scheme is known to be vulnerable to ROS-style attacks under high concurrency
 * (Benhamouda et al., eprint 2020/945). Callers must bound the number of concurrent
 * signing sessions per signer to avoid exposure; a typical device-auth flow that
 * issues at most one session per token request is well within safe parameters.
 *
 * @param pb Bob's 32-byte compressed Ed25519 public key (`P`).
 * @param rb Bob's 32-byte compressed nonce point `R = [k]·G`.
 * @param a Optional Alice-side blinding scalar (defaults to a CSPRNG-sampled mod-L scalar).
 * @param b Optional Alice-side blinding scalar (defaults to a CSPRNG-sampled mod-L scalar).
 *
 * @throws BlindCryptoException.PointDecode if `pb` or `rb` is not a valid Ed25519 point encoding.
 */
public class BlindSign(
    pb: ByteArray,
    rb: ByteArray,
    a: Scalar? = null,
    b: Scalar? = null,
) {
    private val a: Scalar = a ?: SecureRandom.randomScalarModL()
    private val b: Scalar = b ?: SecureRandom.randomScalarModL()
    private val p: EdwardsPoint = decodePoint(pb, "Pb")
    private val r: EdwardsPoint

    init {
        val rbPoint = decodePoint(rb, "Rb")
        val aG = scalarMulBasepoint(this.a)
        val bP = EdwardsPoint().also { it.mul(p, this.b) }
        val rbPlusAG = EdwardsPoint().also { it.add(rbPoint, aG) }
        r = EdwardsPoint().also { it.add(rbPlusAG, bP) }
    }

    /** The 32-byte little-endian encoding of Alice's blinding scalar `a`. */
    public fun getA(): ByteArray = a.toByteArray()

    /** The 32-byte little-endian encoding of Alice's blinding scalar `b`. */
    public fun getB(): ByteArray = b.toByteArray()

    /**
     * Compute the blinded challenge `e = (H(R' || P || M) + b) mod L` (steps 2b-2c of
     * https://stan.bar/blindsig/). `H` is SHA-512, wide-reduced mod L.
     *
     * Send the returned 32 bytes to Bob.
     */
    public fun transaction(message: ByteArray): ByteArray {
        val hash = Sha512.hash(compress(r), compress(p), message)
        val ePrime = Scalar.fromWideByteArray(hash)
        val e = Scalar().also { it.add(ePrime, this.b) }
        return e.toByteArray()
    }

    /**
     * Assemble the 64-byte EdDSA signature `(R' || (s + a) mod L)` from Bob's response `s`
     * (step 4 of https://stan.bar/blindsig/).
     *
     * The resulting signature verifies under Bob's public key `P` for the message that was
     * passed to [transaction].
     */
    public fun signature(s: Scalar): ByteArray {
        val sumScalar = Scalar().also { it.add(s, this.a) }
        return compress(r) + sumScalar.toByteArray()
    }

    /**
     * Assemble the 64-byte EdDSA signature from Bob's response `s` supplied as its little-endian
     * byte encoding — e.g. the buffer a signer transmits on the wire — rather than a [Scalar].
     * Accepts a 32-byte canonical or 64-byte wide little-endian encoding (the latter reduced mod L);
     * convenience for callers that receive `s` over a transport and don't hold a [Scalar].
     *
     * @throws BlindCryptoException.InvalidScalar if `s` is neither 32 nor 64 bytes.
     */
    public fun signature(s: ByteArray): ByteArray = signature(
        when (s.size) {
            Scalar.SIZE_BYTES -> Scalar.fromByteArray(s)
            Scalar.WIDE_SIZE_BYTES -> Scalar.fromWideByteArray(s)
            else -> throw BlindCryptoException.InvalidScalar(
                "s must be ${Scalar.SIZE_BYTES} or ${Scalar.WIDE_SIZE_BYTES} little-endian bytes, got ${s.size}",
            )
        },
    )

    public companion object {
        /**
         * Compute `[s]·G` and return its 32-byte compressed encoding.
         *
         * Convenience for callers that need to publish a scalar's basepoint product (e.g. tests
         * or a server simulator).
         */
        public fun scalarToPoint(s: Scalar): ByteArray = compress(scalarMulBasepoint(s))

        /**
         * Bob's signing step (server-side simulation): given Alice's blinded challenge `e`, the
         * private key `sk`, and the ephemeral nonce `k`, compute `s = (e · x + k) mod L` where
         * `x` is `sk`'s RFC 8032 §5.1.5 pruned scalar (step 3 of https://stan.bar/blindsig/).
         *
         * Exposed for tests and for any in-process Bob simulator. Production Bob runs server-side.
         */
        public fun sign(e: ByteArray, sk: Ed25519PrivateKey, k: Scalar): Scalar {
            val x = Scalar.fromByteArray(sk.asX25519())
            val eScalar = Scalar.fromByteArray(e)
            val product = Scalar().also { it.mul(eScalar, x) }
            return Scalar().also { it.add(product, k) }
        }

        private fun decodePoint(bytes: ByteArray, name: String): EdwardsPoint {
            if (bytes.size != 32) {
                throw BlindCryptoException.PointDecode(
                    "$name must be 32 bytes, got ${bytes.size}",
                )
            }
            val compressed = CompressedEdwardsY(bytes.copyOf())
            return try {
                EdwardsPoint().apply { set(compressed) }
            } catch (ex: Throwable) {
                throw BlindCryptoException.PointDecode("$name not a valid Ed25519 point", ex)
            }
        }

        private fun scalarMulBasepoint(scalar: Scalar): EdwardsPoint =
            EdwardsPoint().also { it.mul(Ed25519Basepoint, scalar) }

        private fun compress(p: EdwardsPoint): ByteArray =
            CompressedEdwardsY.from(p).data.copyOf()
    }
}
