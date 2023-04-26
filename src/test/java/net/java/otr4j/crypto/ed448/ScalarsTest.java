/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.crypto.ed448;

import org.junit.Test;

import java.security.SecureRandom;
import java.util.Arrays;

import static java.util.Arrays.fill;
import static net.java.otr4j.crypto.ed448.Scalars.one;
import static net.java.otr4j.crypto.ed448.Scalars.clamp;
import static net.java.otr4j.crypto.ed448.Scalars.zero;
import static net.java.otr4j.util.ByteArrays.allZeroBytes;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@SuppressWarnings("ConstantConditions")
public final class ScalarsTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    @Test
    public void testZero() {
        final Scalar zero = zero();
        assertTrue(allZeroBytes(zero.encode()));
    }

    @Test
    public void testZeroImmutableOverEncoding() {
        final Scalar zero = zero();
        final byte[] encoded = zero.encode();
        RANDOM.nextBytes(encoded);
        assertFalse(Arrays.equals(zero.encode(), encoded));
    }

    @Test
    public void testZeroImmutableOverInstances() {
        final Scalar zero1 = zero();
        final Scalar zero2 = zero();
        zero1.close();
        assertEquals(zero(), zero2.add(zero2));
    }

    @Test
    public void testOne() {
        final Scalar one = one();
        final byte[] oneBytes = one.encode();
        assertEquals(1, oneBytes[0]);
        for (int i = 1; i < oneBytes.length; i++) {
            assertEquals(0, oneBytes[i]);
        }
    }

    @Test
    public void testOneImmutableOverEncoding() {
        final Scalar one = one();
        final byte[] encoded = one.encode();
        RANDOM.nextBytes(encoded);
        assertFalse(Arrays.equals(one.encode(), encoded));
    }

    @Test
    public void testOneImmutableOverInstances() {
        final Scalar one1 = one();
        final Scalar one2 = one();
        one1.close();
        assertEquals(one(), one2.add(zero()));
    }

    @Test(expected = NullPointerException.class)
    public void testPruneNull() {
        clamp(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testPruneZeroLengthArray() {
        clamp(new byte[0]);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testPrune56LengthArray() {
        clamp(new byte[56]);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testPrune58LengthArray() {
        clamp(new byte[58]);
    }

    @Test
    public void testPruneZeroBytes() {
        final byte[] expected = new byte[] {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 0x80, 0};
        final byte[] value = new byte[57];
        clamp(value);
        assertArrayEquals(expected, value);
    }

    @Test
    public void testPruneFFBytes() {
        final byte[] expected = new byte[] {(byte) 0xfc, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, 0};
        final byte[] value = new byte[57];
        fill(value, (byte) 0xff);
        clamp(value);
        assertArrayEquals(expected, value);
    }
}