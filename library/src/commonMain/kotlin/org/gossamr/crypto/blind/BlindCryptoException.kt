package org.gossamr.crypto.blind

/** Sealed root of all checked failures from the blind-crypto library. */
public sealed class BlindCryptoException(
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause) {
    /** A 32-byte buffer did not decode to a valid Edwards point. */
    public class PointDecode(message: String, cause: Throwable? = null) : BlindCryptoException(message, cause)

    /** A scalar value failed validation (e.g., not canonical mod L when required). */
    public class InvalidScalar(message: String) : BlindCryptoException(message)

    /** A key buffer had an unexpected length. */
    public class InvalidKeySize(message: String) : BlindCryptoException(message)

    /** A signature buffer had an unexpected length. */
    public class InvalidSignatureSize(message: String) : BlindCryptoException(message)
}
