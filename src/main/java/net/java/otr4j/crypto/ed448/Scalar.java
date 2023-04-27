/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.crypto.ed448;

import com.google.errorprone.annotations.CheckReturnValue;
import net.java.otr4j.util.ConstantTimeEquality;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.Arrays;

import static java.lang.Integer.signum;
import static net.java.otr4j.util.ByteArrays.requireLengthExactly;
import static nl.dannyvanheumen.joldilocks.Ed448.primeOrder;
import static org.bouncycastle.util.Arrays.clear;
import static org.bouncycastle.util.Arrays.constantTimeAreEqual;
import static org.bouncycastle.util.Arrays.reverse;
import static org.bouncycastle.util.BigIntegers.asUnsignedByteArray;

/**
 * Scalar representation for Ed448 operations.
 * <p>
 * The scalar implementation is currently very inefficient as it converts to BigInteger and back in order to perform the
 * arithmetic operations, but it does have the benefit that the current bad implementation is isolated to the innermost
 * implementation details.
 */
// TODO implement arithmetic operations that operate directly on byte-arrays. (Needs to be compatible with constant-time selection use in OtrCryptoEngine4#ringSign.) ('toBigInteger' is workaround to make current implementation work.)
public final class Scalar implements Comparable<Scalar>, AutoCloseable, ConstantTimeEquality<Scalar> {

    /**
     * Length of scalar byte-representation in bytes.
     */
    public static final int SCALAR_LENGTH_BYTES = 57;

    private final byte[] encoded;

    private boolean cleared = false;

    Scalar(final byte[] encoded) {
        this.encoded = requireLengthExactly(SCALAR_LENGTH_BYTES, encoded);
    }

    /**
     * Decode scalar from byte representation.
     *
     * @param encoded encoded scalar value
     * @return Returns scalar instance.
     */
    @Nonnull
    public static Scalar decodeScalar(final byte[] encoded) {
        return fromBigInteger(new BigInteger(1, reverse(encoded)));
    }

    /**
     * Construct scalar from big integer value.
     *
     * @param value the value in BigInteger representation
     * @return Returns scalar instance.
     */
    @Nonnull
    static Scalar fromBigInteger(final BigInteger value) {
        // FIXME is it a problem if `value mod q` again contains clamped bits? See also <https://github.com/dalek-cryptography/curve25519-dalek/issues/514>
        return new Scalar(reverse(asUnsignedByteArray(SCALAR_LENGTH_BYTES, value.mod(primeOrder()))));
    }

    /**
     * Negate scalar value.
     *
     * @return Returns negated scalar value.
     */
    @Nonnull
    public Scalar negate() {
        requireNotCleared();
        return fromBigInteger(toBigInteger().negate());
    }

    /**
     * Multiply scalar value by provided long value.
     *
     * @param scalar value
     * @return Returns result of multiplication.
     */
    @Nonnull
    public Scalar multiply(final long scalar) {
        requireNotCleared();
        return fromBigInteger(toBigInteger().multiply(BigInteger.valueOf(scalar)));
    }

    /**
     * Multiple scalar with provided scalar.
     *
     * @param scalar the multiplicant
     * @return Returns the multiplication result.
     */
    @Nonnull
    public Scalar multiply(final Scalar scalar) {
        requireNotCleared();
        return fromBigInteger(toBigInteger().multiply(scalar.toBigInteger()));
    }

    /**
     * Add provided scalar to scalar.
     *
     * @param scalar the scalar to be added
     * @return Returns the addition result.
     */
    @Nonnull
    public Scalar add(final Scalar scalar) {
        requireNotCleared();
        return fromBigInteger(toBigInteger().add(scalar.toBigInteger()));
    }

    /**
     * Subtract provided scalar from scalar.
     *
     * @param scalar the scalar to be subtracted
     * @return Returns the subtraction result.
     */
    @Nonnull
    public Scalar subtract(final Scalar scalar) {
        requireNotCleared();
        return fromBigInteger(toBigInteger().subtract(scalar.toBigInteger()));
    }

    /**
     * Modulo operation on scalar.
     *
     * @param modulus the modulus
     * @return Returns result of modulo.
     */
    @Nonnull
    public Scalar mod(final Scalar modulus) {
        requireNotCleared();
        return fromBigInteger(toBigInteger().mod(modulus.toBigInteger()));
    }

    /**
     * Encode scalar value to byte-representation.
     *
     * @return Byte-representation of scalar value.
     */
    @Nonnull
    public byte[] encode() {
        requireNotCleared();
        return this.encoded.clone();
    }

    /**
     * Encode scalar value to byte-representation to provided destination.
     *
     * @param dst    the destination for the encoded value
     * @param offset the offset for the starting point to writing the encoded value
     */
    public void encodeTo(final byte[] dst, final int offset) {
        requireNotCleared();
        System.arraycopy(this.encoded, 0, dst, offset, SCALAR_LENGTH_BYTES);
    }

    /**
     * Encode scalar value to byte-representation and write to OutputStream.
     *
     * @param out the destination
     * @throws IOException In case of failure in OutputStream during writing.
     */
    public void encodeTo(final OutputStream out) throws IOException {
        requireNotCleared();
        out.write(this.encoded, 0, SCALAR_LENGTH_BYTES);
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        final Scalar scalar = (Scalar) o;
        return Arrays.equals(encoded, scalar.encoded);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(this.encoded);
    }

    @Override
    @CheckReturnValue
    public boolean constantTimeEquals(final Scalar o) {
        return constantTimeAreEqual(this.encoded, o.encoded);
    }

    @Override
    public int compareTo(final Scalar scalar) {
        assert this.encoded.length == SCALAR_LENGTH_BYTES && scalar.encoded.length == SCALAR_LENGTH_BYTES;
        int r = 0;
        for (int i = SCALAR_LENGTH_BYTES - 1; i >= 0; --i) {
            final int xi = this.encoded[i] & 0xff;
            final int yi = scalar.encoded[i] & 0xff;
            final int d = signum(xi - yi);
            r += (~r & 1) * d;
        }
        return r;
    }

    @Nonnull
    BigInteger toBigInteger() {
        requireNotCleared();
        return new BigInteger(1, reverse(this.encoded));
    }

    @Override
    public void close() {
        clear(this.encoded);
        this.cleared = true;
    }

    private void requireNotCleared() {
        if (this.cleared) {
            throw new IllegalStateException("Scalar is already cleared.");
        }
    }

    @Override
    public String toString() {
        return "Scalar{encoded=" + Arrays.toString(encoded) + '}';
    }
}
