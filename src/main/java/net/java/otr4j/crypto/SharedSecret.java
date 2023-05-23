/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.crypto;

import net.java.otr4j.io.OtrOutputStream;

import javax.annotation.Nonnull;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Arrays;

import static net.java.otr4j.crypto.OtrCryptoEngine.sha256Hash;
import static net.java.otr4j.util.ByteArrays.allZeroBytes;
import static net.java.otr4j.util.ByteArrays.clear;
import static net.java.otr4j.util.ByteArrays.constantTimeEquals;

/**
 * Container for the shared secret as defined by otr.
 * <p>
 * The container offers access to all the values used by the otr protocol that
 * are derived from the shared secret 's'.
 *
 * @author Danny van Heumen
 */
public final class SharedSecret implements AutoCloseable {

    private static final byte SSID_START = (byte) 0x00;
    private static final byte C_START = (byte) 0x01;
    private static final byte M1_START = (byte) 0x02;
    private static final byte M2_START = (byte) 0x03;
    private static final byte M1P_START = (byte) 0x04;
    private static final byte M2P_START = (byte) 0x05;
    private static final byte EXTRA_SYMMETRIC_KEY_START = (byte) 0xff;

    /**
     * Minimum-length MPI representation of shared secret s. secbytes is used to
     * derive shared knowledge from the original shared secret.
     */
    private final byte[] secbytes;

    SharedSecret(final byte[] secret) {
        assert !allZeroBytes(secret) : "Expected non-zero byte-array for a secret. Something critical might be going wrong.";
        final BigInteger s = new BigInteger(1, secret);
        this.secbytes = new OtrOutputStream().writeBigInt(s).toByteArray();
    }

    @Override
    public int hashCode() {
        int hash = 5;
        hash = 29 * hash + Arrays.hashCode(this.secbytes);
        return hash;
    }

    @Override
    public boolean equals(final Object obj) {
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        final SharedSecret other = (SharedSecret) obj;
        return constantTimeEquals(this.secbytes, other.secbytes);
    }

    /**
     * h1 derivate of of secbytes, a 160-bit output of SHA-1.
     *
     * @param b Variable byte b.
     * @return Returns the hash value.
     */
    @Nonnull
    public byte[] h1(final byte b) {
        return OtrCryptoEngine.sha1Hash(new byte[]{b}, this.secbytes);
    }

    /**
     * 64-bit (8-byte) secure session ID (ssid).
     *
     * @return Returns 8-byte ssid.
     */
    @Nonnull
    public byte[] ssid() {
        final byte[] dst = new byte[8];
        ByteBuffer.wrap(h2(SSID_START)).get(dst);
        return dst;
    }

    /**
     * 128-bit (16-byte) value c.
     *
     * @return Returns 16-byte c.
     */
    @SuppressWarnings("PMD.MethodNamingConventions")
    @Nonnull
    public byte[] c() {
        final byte[] c = new byte[OtrCryptoEngine.AES_KEY_LENGTH_BYTES];
        ByteBuffer.wrap(h2(C_START)).get(c);
        return c;
    }

    /**
     * 128-bit (16-byte) value c' (c-prime).
     *
     * @return Returns 16-byte c'.
     */
    @Nonnull
    public byte[] cp() {
        final byte[] cp = new byte[OtrCryptoEngine.AES_KEY_LENGTH_BYTES];
        final ByteBuffer buffer = ByteBuffer.wrap(h2(C_START));
        buffer.position(OtrCryptoEngine.AES_KEY_LENGTH_BYTES);
        buffer.get(cp);
        return cp;
    }

    /**
     * 256-bit (32-byte) value m1.
     *
     * @return Returns 32-byte m2.
     */
    @Nonnull
    public byte[] m1() {
        return h2(M1_START);
    }

    /**
     * 256-bit (32-byte) value m1' (m1-prime).
     *
     * @return Returns 32-byte m1'.
     */
    @Nonnull
    public byte[] m1p() {
        return h2(M1P_START);
    }

    /**
     * 256-bit (32-byte) value m2.
     *
     * @return Returns 32-byte m2.
     */
    @Nonnull
    public byte[] m2() {
        return h2(M2_START);
    }

    /**
     * 256-bit (32-byte) value m2' (m2-prime).
     *
     * @return Returns 32-byte m2'.
     */
    @Nonnull
    public byte[] m2p() {
        return h2(M2P_START);
    }

    /**
     * 256-bit (32-byte) extra symmetric key.
     *
     * @return Returns extra symmetric key.
     */
    @Nonnull
    public byte[] extraSymmetricKey() {
        return h2(EXTRA_SYMMETRIC_KEY_START);
    }

    /**
     * Calculate h2 based on secbytes and provided b.
     *
     * @param b parameter b.
     * @return Returns SHA-256 hash calculation result as byte-array based on
     * secbytes and provided parameter b.
     */
    @Nonnull
    private byte[] h2(final byte b) {
        return sha256Hash(new byte[]{b}, this.secbytes);
    }

    /**
     * Clear the shared secret. (This zeroes the secret, so if the SharedSecret instance is reused after clearing, you
     * will end up with "invalid" (unexpected) results.
     */
    @Override
    public void close() {
        clear(this.secbytes);
    }
}
