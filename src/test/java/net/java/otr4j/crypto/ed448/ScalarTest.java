/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.crypto.ed448;

import net.java.otr4j.util.Classes;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;

import static net.java.otr4j.crypto.ed448.Ed448.primeOrder;
import static net.java.otr4j.crypto.ed448.Scalar.SCALAR_LENGTH_BYTES;
import static net.java.otr4j.crypto.ed448.Scalar.decodeScalar;
import static net.java.otr4j.crypto.ed448.Scalar.fromBigInteger;
import static net.java.otr4j.util.ByteArrays.allZeroBytes;
import static net.java.otr4j.util.Classes.readField;
import static net.java.otr4j.util.SecureRandoms.randomBytes;
import static org.bouncycastle.util.Arrays.reverse;
import static org.bouncycastle.util.BigIntegers.asUnsignedByteArray;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

@SuppressWarnings({"ConstantConditions", "EqualsWithItself"})
public final class ScalarTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    private static final Scalar Q_SCALAR = primeOrder();

    private static final BigInteger Q_BIGINT = Q_SCALAR.toBigInteger();

    @Test(expected = NullPointerException.class)
    public void testConstructNull() {
        new Scalar(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructValueTooSmall() {
        new Scalar(new byte[56]);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructValueTooLarge() {
        new Scalar(new byte[58]);
    }

    @Test
    public void testConstruct() {
        final Scalar scalar = new Scalar(new byte[57]);
        assertArrayEquals(Scalars.zero().encode(), scalar.encode());
    }

    @Test
    public void testProcessZeroScalar() {
        assertArrayEquals(Scalars.one().encode(), Scalars.zero().add(Scalars.one()).encode());
        assertArrayEquals(Scalars.zero().encode(), Scalars.zero().multiply(Scalars.one()).encode());
        assertArrayEquals(Scalars.one().encode(), Scalars.one().subtract(Scalars.zero()).encode());
        assertArrayEquals(Scalars.zero().encode(), Scalars.zero().mod(Scalars.one()).encode());
        assertArrayEquals(Scalars.zero().encode(), Scalars.zero().negate().encode());
        assertEquals(BigInteger.ZERO, Scalars.zero().toBigInteger());
        assertArrayEquals(new byte[SCALAR_LENGTH_BYTES], Scalars.zero().encode());
    }

    @Test
    public void testProcessOneScalar() {
        assertArrayEquals(Scalars.one().encode(), Scalars.one().add(Scalars.zero()).encode());
        assertArrayEquals(Scalars.one().encode(), Scalars.one().multiply(Scalars.one()).encode());
        assertArrayEquals(Scalars.one().encode(), Scalars.one().subtract(Scalars.zero()).encode());
        assertArrayEquals(Scalars.zero().encode(), Scalars.one().mod(Scalars.one()).encode());
        assertEquals(BigInteger.ONE, Scalars.one().toBigInteger());
    }

    @Test
    public void testNegateScalar() {
        final byte[] data1 = randomBytes(RANDOM, new byte[57]);
        final BigInteger value1 = new BigInteger(1, data1).mod(Q_BIGINT);
        final Scalar scalar1 = fromBigInteger(value1);
        assertArrayEquals(reverse(asUnsignedByteArray(SCALAR_LENGTH_BYTES, value1.negate().mod(Q_BIGINT))),
                scalar1.negate().mod(Q_SCALAR).encode());
    }

    @Test
    public void testDecodeRandomScalarModQ() {
        final byte[] bytes = randomBytes(RANDOM, new byte[57]);
        final Scalar scalar = Scalar.decodeScalar(bytes);
        final BigInteger value = new BigInteger(1, reverse(bytes)).mod(Q_BIGINT);
        assertEquals(value, scalar.toBigInteger());
    }

    @Test
    public void testDoubleNegation() {
        final Scalar scalar = Scalar.decodeScalar(randomBytes(RANDOM, new byte[57]));
        assertArrayEquals(scalar.encode(), scalar.negate().negate().encode());
    }

    @Test
    public void testAddScalars() {
        // Prepare scalar value 1
        final byte[] data1 = randomBytes(RANDOM, new byte[57]);
        final BigInteger value1 = new BigInteger(1, data1).mod(Q_BIGINT);
        final Scalar scalar1 = fromBigInteger(value1);
        assertArrayEquals(reverse(asUnsignedByteArray(SCALAR_LENGTH_BYTES, value1)), scalar1.encode());
        // Prepare scalar value 2
        final byte[] data2 = randomBytes(RANDOM, new byte[57]);
        final BigInteger value2 = new BigInteger(1, data2).mod(Q_BIGINT);
        final Scalar scalar2 = fromBigInteger(value2);
        assertArrayEquals(reverse(asUnsignedByteArray(SCALAR_LENGTH_BYTES, value2)), scalar2.encode());
        // Evaluate scalar addition
        assertArrayEquals(
                reverse(asUnsignedByteArray(SCALAR_LENGTH_BYTES, value1.add(value2).mod(Q_BIGINT))),
                scalar1.add(scalar2).mod(Q_SCALAR).encode());
    }

    @Test
    public void testSubtractScalars() {
        // Prepare scalar value 1
        final byte[] data1 = randomBytes(RANDOM, new byte[57]);
        final BigInteger value1 = new BigInteger(1, data1).mod(Q_BIGINT);
        final Scalar scalar1 = fromBigInteger(value1);
        assertArrayEquals(reverse(asUnsignedByteArray(SCALAR_LENGTH_BYTES, value1)), scalar1.encode());
        // Prepare scalar value 2
        final byte[] data2 = randomBytes(RANDOM, new byte[57]);
        final BigInteger value2 = new BigInteger(1, data2).mod(Q_BIGINT);
        final Scalar scalar2 = fromBigInteger(value2);
        assertArrayEquals(reverse(asUnsignedByteArray(SCALAR_LENGTH_BYTES, value2)), scalar2.encode());
        // Evaluate scalar addition
        assertArrayEquals(
                reverse(asUnsignedByteArray(SCALAR_LENGTH_BYTES, value1.subtract(value2).mod(Q_BIGINT))),
                scalar1.subtract(scalar2).mod(Q_SCALAR).encode());
    }

    @Test
    public void testMultiplyScalars() {
        // Prepare scalar value 1
        final byte[] data1 = randomBytes(RANDOM, new byte[57]);
        final BigInteger value1 = new BigInteger(1, data1).mod(Q_BIGINT);
        final Scalar scalar1 = fromBigInteger(value1);
        assertArrayEquals(reverse(asUnsignedByteArray(SCALAR_LENGTH_BYTES, value1)), scalar1.encode());
        // Prepare scalar value 2
        final byte[] data2 = randomBytes(RANDOM, new byte[57]);
        final BigInteger value2 = new BigInteger(1, data2).mod(Q_BIGINT);
        final Scalar scalar2 = fromBigInteger(value2);
        assertArrayEquals(reverse(asUnsignedByteArray(SCALAR_LENGTH_BYTES, value2)), scalar2.encode());
        // Evaluate scalar addition
        assertArrayEquals(
                reverse(asUnsignedByteArray(SCALAR_LENGTH_BYTES, value1.subtract(value2).mod(Q_BIGINT))),
                scalar1.subtract(scalar2).mod(Q_SCALAR).encode());
    }

    @Test
    public void testScalarModulo() {
        assertArrayEquals(Scalars.zero().encode(), decodeScalar(new byte[] {8}).mod(decodeScalar(new byte[] {4})).encode());
    }

    @Test
    public void testScalarModuloQ() {
        assertArrayEquals(Scalars.zero().encode(), Q_SCALAR.mod(Q_SCALAR).encode());
    }

    @Test
    public void testScalarModuloRandom() {
        // bytes intentionally chosen smaller such that `mod q` does not come into effect
        final byte[] valueBytes = randomBytes(RANDOM, new byte[20]);
        final byte[] modulusBytes = randomBytes(RANDOM, new byte[20]);
        final BigInteger bigIntResult = new BigInteger(1, reverse(valueBytes)).mod(new BigInteger(1,
                reverse(modulusBytes)));
        final Scalar scalarResult = decodeScalar(valueBytes).mod(decodeScalar(modulusBytes));
        assertEquals(bigIntResult, scalarResult.toBigInteger());
    }

    @Test
    public void testScalarComparison() {
        assertEquals(1, Scalars.one().compareTo(Scalars.zero()));
        assertEquals(-1, Scalars.zero().compareTo(Scalars.one()));
        assertEquals(0, Scalars.one().compareTo(Scalars.one()));
    }

    @SuppressWarnings("SelfComparison")
    @Test
    public void testScalarComparisonSame() {
        final Scalar scalar = decodeScalar(randomBytes(RANDOM, new byte[57]));
        assertEquals(0, scalar.compareTo(scalar));
    }

    @Test
    public void testScalarComparisonEqual() {
        final Scalar scalar = decodeScalar(randomBytes(RANDOM, new byte[57]));
        final Scalar scalar2 = decodeScalar(scalar.encode());
        assertEquals(0, scalar.compareTo(scalar2));
    }

    @Test
    public void testScalarRandomComparison() {
        final byte[] valueBytes1 = randomBytes(RANDOM, new byte[57]);
        final byte[] valueBytes2 = randomBytes(RANDOM, new byte[57]);
        final Scalar scalar1 = decodeScalar(valueBytes1);
        final Scalar scalar2 = decodeScalar(valueBytes2);
        final BigInteger integer1 = new BigInteger(1, reverse(valueBytes1)).mod(Q_BIGINT);
        final BigInteger integer2 = new BigInteger(1, reverse(valueBytes2)).mod(Q_BIGINT);
        final int compInteger = integer1.compareTo(integer2);
        final int compScalar = scalar1.compareTo(scalar2);
        assertEquals(compInteger > 0, compScalar > 0);
        assertEquals(compInteger < 0, compScalar < 0);
    }

    @Test
    public void testEncodeTo() {
        final byte[] bytes = randomBytes(RANDOM, new byte[57]);
        bytes[55] = bytes[56] = 0;
        final Scalar scalar = decodeScalar(bytes);
        final byte[] encoded = new byte[57];
        scalar.encodeTo(encoded, 0);
        assertArrayEquals(bytes, encoded);
    }

    @Test
    public void testEncodeToOffset() {
        final byte[] bytes = randomBytes(RANDOM, new byte[57]);
        bytes[55] = bytes[56] = 0;
        final Scalar scalar = decodeScalar(bytes);
        final byte[] encoded = new byte[59];
        scalar.encodeTo(encoded, 2);
        final byte[] expected = new byte[59];
        System.arraycopy(bytes, 0, expected, 2, bytes.length);
        assertArrayEquals(expected, encoded);
    }

    @Test
    public void testEncodeToByteArrayOutputStream() throws IOException {
        final byte[] bytes = randomBytes(RANDOM, new byte[57]);
        bytes[55] = bytes[56] = 0;
        final Scalar scalar = decodeScalar(bytes);
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        scalar.encodeTo(out);
        assertArrayEquals(bytes, out.toByteArray());
    }

    @Test
    public void testSameScalarEquals() {
        final Scalar scalar = decodeScalar(randomBytes(RANDOM, new byte[57]));
        assertEquals(scalar, scalar);
    }

    @SuppressWarnings("SimplifiableJUnitAssertion")
    @Test
    public void testScalarNotEqualsNull() {
        final Scalar scalar = decodeScalar(randomBytes(RANDOM, new byte[57]));
        assertFalse(scalar.equals(null));
    }

    @SuppressWarnings({"EqualsBetweenInconvertibleTypes", "SimplifiableJUnitAssertion"})
    @Test
    public void testScalarNotEqualsDifferentType() {
        final Scalar scalar = decodeScalar(randomBytes(RANDOM, new byte[57]));
        assertFalse(scalar.equals(Scalar.class));
    }

    @Test
    public void testScalarTwoEqualScalars() {
        final Scalar scalar1 = decodeScalar(randomBytes(RANDOM, new byte[57]));
        final Scalar scalar2 = new Scalar(scalar1.encode());
        assertEquals(scalar1, scalar2);
    }

    @Test
    public void testScalarTwoInequalScalars() {
        final Scalar scalar1 = decodeScalar(randomBytes(RANDOM, new byte[57]));
        final Scalar scalar2 = decodeScalar(randomBytes(RANDOM, new byte[57]));
        assertNotEquals(scalar1, scalar2);
    }

    @SuppressWarnings("ResultOfMethodCallIgnored")
    @Test
    public void testScalarHashCode() {
        // not sure what thing we can test for this, for now just call the method and see that it does not fail
        Scalars.zero().hashCode();
    }

    @Test
    public void testScalarClear() {
        final Scalar scalar = decodeScalar(randomBytes(RANDOM, new byte[57]));
        Scalar.clear(scalar);
        assertTrue(allZeroBytes(Classes.readField(byte[].class, scalar, "encoded")));
    }

    // FIXME right now we don't do checking of cleared scalar.

    //@Test(expected = IllegalStateException.class)
    //public void testScalarAddAfterClose() {
    //    final Scalar scalar = decodeScalar(randomBytes(RANDOM, new byte[57]));
    //    scalar.close();
    //    scalar.add(Scalars.zero());
    //}

    //@Test(expected = IllegalStateException.class)
    //public void testScalarSubtractAfterClose() {
    //    final Scalar scalar = decodeScalar(randomBytes(RANDOM, new byte[57]));
    //    scalar.close();
    //    scalar.subtract(Scalars.zero());
    //}

    //@Test(expected = IllegalStateException.class)
    //public void testScalarMultiplyAfterClose() {
    //    final Scalar scalar = decodeScalar(randomBytes(RANDOM, new byte[57]));
    //    scalar.close();
    //    scalar.multiply(Scalars.zero());
    //}

    //@Test(expected = IllegalStateException.class)
    //public void testScalarNegateAfterClose() {
    //    final Scalar scalar = decodeScalar(randomBytes(RANDOM, new byte[57]));
    //    scalar.close();
    //    scalar.negate();
    //}

    //@Test(expected = IllegalStateException.class)
    //public void testScalarModAfterClose() {
    //    final Scalar scalar = decodeScalar(randomBytes(RANDOM, new byte[57]));
    //    scalar.close();
    //    scalar.mod(Scalars.one());
    //}

    //@Test(expected = IllegalStateException.class)
    //public void testScalarEncodeAfterClose() {
    //    final Scalar scalar = decodeScalar(randomBytes(RANDOM, new byte[57]));
    //    scalar.close();
    //    scalar.encode();
    //}

    //@Test(expected = IllegalStateException.class)
    //public void testScalarToBigIntegerAfterClose() {
    //    final Scalar scalar = decodeScalar(randomBytes(RANDOM, new byte[57]));
    //    scalar.close();
    //    scalar.toBigInteger();
    //}

    //@Test(expected = IllegalStateException.class)
    //public void testScalarAddAfterCloseOther() {
    //    final Scalar scalar = decodeScalar(randomBytes(RANDOM, new byte[57]));
    //    scalar.close();
    //    Scalars.zero().add(scalar);
    //}

    //@Test(expected = IllegalStateException.class)
    //public void testScalarSubtractAfterCloseOther() {
    //    final Scalar scalar = decodeScalar(randomBytes(RANDOM, new byte[57]));
    //    scalar.close();
    //    Scalars.zero().subtract(scalar);
    //}

    //@Test(expected = IllegalStateException.class)
    //public void testScalarMultiplyAfterCloseOther() {
    //    final Scalar scalar = decodeScalar(randomBytes(RANDOM, new byte[57]));
    //    scalar.close();
    //    Scalars.zero().multiply(scalar);
    //}

    //@Test(expected = IllegalStateException.class)
    //public void testScalarModAfterCloseOther() {
    //    final Scalar scalar = decodeScalar(randomBytes(RANDOM, new byte[57]));
    //    scalar.close();
    //    Scalars.one().mod(scalar);
    //}
}