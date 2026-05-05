package org.gossamr.crypto.blind

import org.gossamr.crypto.blind.internal.SecureRandom
import io.github.andreypfau.curve25519.scalar.Scalar
import org.junit.jupiter.api.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** End-to-end roundtrip of the Ed25519 2-party blind Schnorr protocol. */
class BlindSignTest {

    /** Direct port of `TestBlindSign.test1`: random keys, random message, full Alice<->Bob flow. */
    @Test
    fun roundtrip_random() {
        val message = SecureRandom.nextBytes(32)

        // Bob's setup.
        val skBob = Ed25519PrivateKey.generate()
        val pkBob = skBob.publicKey()
        val k = SecureRandom.randomScalarModL()
        val rb = BlindSign.scalarToPoint(k)

        // Sanity: Bob's standalone signing works under his own key.
        val standaloneSig = skBob.sign(message)
        assertTrue(pkBob.verify(standaloneSig, message), "standalone Ed25519 self-verify")

        // Bob -> Alice: (Pb, Rb). Alice runs the blinding.
        val alice = BlindSign(pb = pkBob.r, rb = rb)
        val e = alice.transaction(message)

        // Alice -> Bob: e. Bob signs.
        val s = BlindSign.sign(e, skBob, k)

        // Bob -> Alice: s. Alice assembles.
        val signature = alice.signature(s)

        // Final: signature must verify under Bob's public key for the message.
        assertEquals(64, signature.size, "blind signature must be 64 bytes")
        assertTrue(pkBob.verify(signature, message), "assembled blind signature failed to verify")

        // Negative: corrupted message must not verify.
        val tampered = message.copyOf().also { it[0] = (it[0].toInt() xor 0x01).toByte() }
        assertFalse(pkBob.verify(signature, tampered), "verify(corrupted message) returned true")
    }

    /**
     * Deterministic variant: fixed `a`, `b`, `k` scalars and a fixed seed. Catches regressions
     * where randomization papers over a deterministic bug in the protocol math.
     */
    @Test
    fun roundtrip_deterministic() {
        val seed = ByteArray(32) { it.toByte() }
        val message = "blind-auth deterministic test".toByteArray()
        val skBob = Ed25519PrivateKey(seed)
        val pkBob = skBob.publicKey()

        // Fixed scalars from a 64-byte deterministic input, wide-reduced mod L.
        val k = Scalar.fromWideByteArray(ByteArray(64) { (it + 1).toByte() })
        val a = Scalar.fromWideByteArray(ByteArray(64) { (it + 2).toByte() })
        val b = Scalar.fromWideByteArray(ByteArray(64) { (it + 3).toByte() })

        val rb = BlindSign.scalarToPoint(k)
        val alice = BlindSign(pb = pkBob.r, rb = rb, a = a, b = b)

        // getA / getB round-trip the supplied scalars.
        assertContentEquals(a.toByteArray(), alice.getA(), "getA round-trip")
        assertContentEquals(b.toByteArray(), alice.getB(), "getB round-trip")

        val e = alice.transaction(message)
        val s = BlindSign.sign(e, skBob, k)
        val signature = alice.signature(s)

        assertTrue(pkBob.verify(signature, message), "deterministic blind signature failed to verify")

        // Golden vectors computed by an independent RFC 8032 reference implementation of
        // the protocol; the Swift sibling asserts the same constants
        // (TestBlindSign.testDeterministicVectors). Byte-equality on every intermediate
        // means all three implementations agree on the full deterministic flow.
        assertContentEquals(hex("03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"), pkBob.r, "pk")
        assertContentEquals(hex("36bb0e309e7e9a82f1527df2c6b0e48181589097fe90c1282c558207ea27ce66"), rb, "rb")
        assertContentEquals(hex("beddb2333cf969192538756b19ae9fbb5a20f2958399240013447d4fd74bb60f"), e, "e")
        assertContentEquals(hex("cad45ba033c7bad08b529ee9a5f676108a8b4c00c681bd4b1bd3fb4d11a1a504"), s.toByteArray(), "s")
        assertContentEquals(
            hex(
                "c9c262f2b5e04e23f43c1e50f5703237985b7114bd98908ca921c2a456808b17" +
                    "f50116cfca5f6be0e76d786606eb15e425b2fa6ddec0956d21ab47605c56ca04",
            ),
            signature,
            "sig",
        )
    }

    @Test
    fun ctor_rejects_invalid_pb_size() {
        val rb = BlindSign.scalarToPoint(SecureRandom.randomScalarModL())
        assertFailsWith<BlindCryptoException.PointDecode> {
            BlindSign(pb = ByteArray(31), rb = rb)
        }
    }

    @Test
    fun ctor_rejects_invalid_rb_size() {
        val pb = Ed25519PrivateKey.generate().publicKey().r
        assertFailsWith<BlindCryptoException.PointDecode> {
            BlindSign(pb = pb, rb = ByteArray(33))
        }
    }

    @Test
    fun transaction_handles_empty_message() {
        val skBob = Ed25519PrivateKey.generate()
        val k = SecureRandom.randomScalarModL()
        val alice = BlindSign(pb = skBob.publicKey().r, rb = BlindSign.scalarToPoint(k))
        val e = alice.transaction(ByteArray(0))
        assertEquals(32, e.size, "transaction must return a 32-byte challenge even for empty msg")
    }

    @Test
    fun transaction_handles_large_message() {
        val skBob = Ed25519PrivateKey.generate()
        val k = SecureRandom.randomScalarModL()
        val message = ByteArray(1024) { (it and 0xff).toByte() }
        val alice = BlindSign(pb = skBob.publicKey().r, rb = BlindSign.scalarToPoint(k))
        val e = alice.transaction(message)
        val s = BlindSign.sign(e, skBob, k)
        val signature = alice.signature(s)
        assertTrue(skBob.publicKey().verify(signature, message))
    }

    /**
     * The `signature(ByteArray)` overload (for callers that receive `s` over the wire) must match
     * `signature(Scalar)` for both the 32-byte canonical and 64-byte wide little-endian encodings.
     * The 64-byte form is what a signer transmitting `s.toBuffer('le', 64)` sends.
     */
    @Test
    fun signature_from_le_bytes_matches_scalar() {
        val seed = ByteArray(32) { it.toByte() }
        val message = "blind-auth deterministic test".toByteArray()
        val skBob = Ed25519PrivateKey(seed)
        val pkBob = skBob.publicKey()
        val k = Scalar.fromWideByteArray(ByteArray(64) { (it + 1).toByte() })
        val a = Scalar.fromWideByteArray(ByteArray(64) { (it + 2).toByte() })
        val b = Scalar.fromWideByteArray(ByteArray(64) { (it + 3).toByte() })
        val alice = BlindSign(pb = pkBob.r, rb = BlindSign.scalarToPoint(k), a = a, b = b)

        val s = BlindSign.sign(alice.transaction(message), skBob, k)
        val fromScalar = alice.signature(s)

        val le32 = s.toByteArray()
        val le64 = le32 + ByteArray(32) // wide little-endian: low 32 carry the value, high 32 zero
        assertContentEquals(fromScalar, alice.signature(le32), "32-byte LE bytes overload")
        assertContentEquals(fromScalar, alice.signature(le64), "64-byte wide LE bytes overload")
        assertTrue(pkBob.verify(alice.signature(le64), message), "bytes-overload signature verifies")

        assertFailsWith<BlindCryptoException.InvalidScalar> { alice.signature(ByteArray(33)) }
    }

    private fun hex(s: String): ByteArray =
        ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
}
