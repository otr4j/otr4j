/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.crypto.ed448;

import org.bouncycastle.math.ec.rfc8032.Ed448;

import javax.annotation.Nonnull;
import java.security.SecureRandom;

import static net.java.otr4j.crypto.ed448.Point.decodePoint;
import static net.java.otr4j.crypto.ed448.Scalar.decodeScalar;
import static net.java.otr4j.crypto.ed448.Scalars.clamp;
import static net.java.otr4j.crypto.ed448.Shake256.shake256;
import static net.java.otr4j.util.ByteArrays.allZeroBytes;
import static net.java.otr4j.util.ByteArrays.clear;
import static net.java.otr4j.util.ByteArrays.requireLengthExactly;
import static net.java.otr4j.util.ByteArrays.requireNonZeroBytes;
import static org.bouncycastle.util.Arrays.copyOfRange;

/**
 * EdDSA key pair. (Backed by BouncyCastle)
 */
public final class EdDSAKeyPair implements AutoCloseable {
    private static final int SECRET_KEY_LENGTH_BYTES = Ed448.SECRET_KEY_SIZE;

    private static final int PUBLIC_KEY_LENGTH_BYTES = Ed448.PUBLIC_KEY_SIZE;

    /**
     * Context value as applied in OTRv4.
     */
    private static final byte[] ED448_CONTEXT = new byte[0];

    private final byte[] symmetricKey;
    private final byte[] publicKey;
    private boolean cleared = false;

    private EdDSAKeyPair(final byte[] symmetricKey) {
        assert !allZeroBytes(symmetricKey);
        this.symmetricKey = requireLengthExactly(SECRET_KEY_LENGTH_BYTES, symmetricKey);
        final byte[] publicKey = new byte[PUBLIC_KEY_LENGTH_BYTES];
        Ed448.generatePublicKey(symmetricKey, 0, publicKey, 0);
        assert !allZeroBytes(publicKey);
        this.publicKey = requireLengthExactly(PUBLIC_KEY_LENGTH_BYTES, publicKey);
    }

    /**
     * Generate a EdDSA (long-term) key pair. The key pair itself will be requested from the Engine host. This method is
     * there for convenience, to be used by host implementations.
     *
     * @param random Source of secure random data.
     * @return Returns the generated key pair.
     */
    @Nonnull
    public static EdDSAKeyPair generate(final SecureRandom random) {
        final byte[] symmetricKey = new byte[SECRET_KEY_LENGTH_BYTES];
        Ed448.generatePrivateKey(random, symmetricKey);
        return new EdDSAKeyPair(symmetricKey);
    }

    /**
     * Restore restores an EdDSA keypair from the symmetric key bytes.
     *
     * @param symmetricKey symmetric key
     * @return Returns an EdDSA keypair.
     */
    @Nonnull
    public static EdDSAKeyPair restore(final byte[] symmetricKey) {
        return new EdDSAKeyPair(requireNonZeroBytes(symmetricKey).clone());
    }

    /**
     * Export exports the key material of an EdDSA keypair for storage. (See also {@link #restore(byte[])}.)
     *
     * @param keypair the EdDSA keypair
     * @return returns the key material.
     */
    @Nonnull
    public static byte[] export(final EdDSAKeyPair keypair) {
        return keypair.symmetricKey.clone();
    }

    /**
     * Verify a signature for a message, given the public key.
     *
     * @param publicKey The public key of the key pair that generated the signature.
     * @param message   The message that was signed.
     * @param signature The signature.
     * @throws ValidationException In case we fail to validate the message against the provided signature.
     */
    public static void verify(final Point publicKey, final byte[] message, final byte[] signature)
            throws ValidationException {
        assert !allZeroBytes(signature) : "Expected random data for signature instead of all zero-bytes.";
        if (!Ed448.verify(signature, 0, publicKey.getEncoded(), 0, ED448_CONTEXT, message, 0, message.length)) {
            throw new ValidationException("Signature is not valid for provided message.");
        }
    }

    /**
     * Sign message.
     * <p>
     * Signs the message using the default context as used in OTRv4.
     *
     * @param message The message to be signed.
     * @return Returns the signature that corresponds to the message.
     */
    @Nonnull
    public byte[] sign(final byte[] message) {
        requireNotCleared();
        final byte[] signature = new byte[Ed448.SIGNATURE_SIZE];
        Ed448.sign(this.symmetricKey, 0, ED448_CONTEXT, message, 0, message.length, signature, 0);
        return signature;
    }

    /**
     * Acquire public key from the key pair.
     *
     * @return Returns the public key.
     */
    @Nonnull
    public Point getPublicKey() {
        try {
            return decodePoint(this.publicKey);
        } catch (final ValidationException e) {
            throw new IllegalStateException("BUG: The public key is expected to always be correct as it is part of the EdDSA key pair.", e);
        }
    }

    /**
     * Acquire secret key from the key pair.
     *
     * @return Returns secret key.
     */
    @Nonnull
    public Scalar getSecretKey() {
        requireNotCleared();
        final byte[] secretKey;
        {
            final byte[] h = shake256(2 * SECRET_KEY_LENGTH_BYTES, this.symmetricKey);
            secretKey = copyOfRange(h, 0, SECRET_KEY_LENGTH_BYTES);
            clear(h);
        }
        clamp(secretKey);
        try {
            return decodeScalar(secretKey);
        } finally {
            clear(secretKey);
        }
    }

    @Override
    public void close() {
        clear(this.symmetricKey);
        this.cleared = true;
    }

    private void requireNotCleared() {
        if (this.cleared) {
            throw new IllegalStateException("Scalar is already cleared.");
        }
    }
}
