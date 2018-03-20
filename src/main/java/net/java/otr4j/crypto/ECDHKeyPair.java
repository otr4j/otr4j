package net.java.otr4j.crypto;

import nl.dannyvanheumen.joldilocks.Point;

import javax.annotation.Nonnull;
import java.math.BigInteger;
import java.security.SecureRandom;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.crypto.OtrCryptoEngine4.kdf1;
import static net.java.otr4j.util.ByteArrays.clear;
import static nl.dannyvanheumen.joldilocks.Ed448.multiplyByBase;
import static nl.dannyvanheumen.joldilocks.Scalars.decodeLittleEndian;

/**
 * ECDH keypair based on Ed448-Goldilocks.
 */
public final class ECDHKeyPair {

    private static final int LENGTH_SECRET_KEY_BYTES = 57;

    private final BigInteger secretKey;
    private final Point publicKey;

    private ECDHKeyPair(@Nonnull final BigInteger secretKey) {
        this.secretKey = requireNonNull(secretKey);
        this.publicKey = multiplyByBase(secretKey);
    }

    /**
     * Generate an ECDH keypair.
     * <p>
     * Procedure implemented as described in "Generating ECDH and DH keys" in OTRv4 specification.
     *
     * @param random SecureRandom instance
     * @return Returns ECDH keypair.
     */
    public static ECDHKeyPair generate(@Nonnull final SecureRandom random) {
        //  - pick a random value r (57 bytes)
        //  - generate 'h' = KDF_1(0x01 || r, 57).
        final byte[] r = new byte[LENGTH_SECRET_KEY_BYTES + 1];
        random.nextBytes(r);
        r[0] = 0x01;
        final byte[] h = new byte[57];
        kdf1(h, 0, r, LENGTH_SECRET_KEY_BYTES);
        //  - prune 'h': the two least significant bits of the first byte are cleared, all
        //    eight bits of the last byte are cleared, and the highest bit of the second
        //    to last byte is set.
        h[0] &= 0b11111100;
        h[56] = 0;
        h[55] &= 0b01111111;
        //  - Interpret the buffer as the little-endian integer, forming the secret scalar
        //    's'.
        final BigInteger s = decodeLittleEndian(h);
        //  - Securely delete 'r' and 'h'.
        clear(r);
        clear(h);
        //  - return our_ecdh.public = G * s, our_ecdh.secret = s
        return new ECDHKeyPair(s);
    }

    /**
     * Get public key.
     *
     * @return Returns the public key.
     */
    @Nonnull
    public Point getPublicKey() {
        return publicKey;
    }
}
