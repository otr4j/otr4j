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

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

import static net.java.otr4j.crypto.ed448.ECDHKeyPair.generate;
import static net.java.otr4j.crypto.ed448.Ed448.identity;
import static net.java.otr4j.crypto.ed448.Ed448.multiplyByBase;
import static net.java.otr4j.crypto.ed448.Scalar.SCALAR_LENGTH_BYTES;
import static net.java.otr4j.crypto.ed448.Scalar.fromBigInteger;
import static net.java.otr4j.util.Classes.readField;
import static net.java.otr4j.util.SecureRandoms.randomBytes;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

@SuppressWarnings({"ConstantConditions", "ResultOfMethodCallIgnored", "resource"})
public class ECDHKeyPairTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    private static final Scalar sk = fromBigInteger(new BigInteger("201813413369092340303433879563900627958148970380718420601528361290790948759469372234812322817714647596845093618167700052967566766936416", 10));

    @Test(expected = NullPointerException.class)
    public void testGenerateNullSecureRandom() {
        generate((SecureRandom) null);
    }

    @Test(expected = NullPointerException.class)
    public void testGenerateNullBytes() {
        generate((byte[]) null);
    }

    @Test
    public void testGenerateKeyPair() {
        final ECDHKeyPair keypair = generate(RANDOM);
        assertNotNull(keypair);
        assertNotNull(keypair.publicKey());
    }

    @Test
    public void testPublicKeyRegeneratable() {
        final ECDHKeyPair keypair = generate(RANDOM);
        final Point expected = keypair.publicKey();
        final Point generated = multiplyByBase(Classes.readField(Scalar.class, keypair, "secretKey"));
        assertEquals(expected, generated);
    }

    @Test
    public void testGetPublicKeyAfterClose() {
        final ECDHKeyPair keypair = generate(RANDOM);
        keypair.close();
        keypair.publicKey();
    }

    @Test
    public void testGetSecretKey() {
        final ECDHKeyPair keypair = new ECDHKeyPair(sk);
        assertEquals(sk, Classes.readField(Scalar.class, keypair, "secretKey"));
    }

    @Test
    public void testGetSecretKeyAfterClose() {
        final ECDHKeyPair keypair = generate(RANDOM);
        keypair.close();
        assertNull(Classes.readField(Scalar.class, keypair, "secretKey"));
    }

    @Test
    public void testSharedSecretIsSymmetric() throws ValidationException {
        final ECDHKeyPair keypair1 = ECDHKeyPair.generate(RANDOM);
        final ECDHKeyPair keypair2 = ECDHKeyPair.generate(RANDOM);
        final Point shared1 = keypair1.generateSharedSecret(keypair2.publicKey());
        final Point shared2 = keypair2.generateSharedSecret(keypair1.publicKey());
        assertEquals(shared1, shared2);
    }

    @Test(expected = ValidationException.class)
    public void testSharedSecretDoesNotAcceptIdentity() throws ValidationException {
        final ECDHKeyPair keypair1 = ECDHKeyPair.generate(RANDOM);
        keypair1.generateSharedSecret(identity());
    }

    @Test(expected = IllegalStateException.class)
    public void testSharedSecretWithIllegalPoint() throws ValidationException {
        final Point other = multiplyByBase(new Scalar(randomBytes(RANDOM, new byte[SCALAR_LENGTH_BYTES])));
        Arrays.fill(other.getEncoded(), (byte) 1);
        final ECDHKeyPair keypair = ECDHKeyPair.generate(RANDOM);
        keypair.generateSharedSecret(other);
    }

    @Test(expected = IllegalStateException.class)
    public void testGenerateSharedSecretAfterClose() throws ValidationException {
        final ECDHKeyPair keypair = generate(RANDOM);
        final Point otherPoint = generate(RANDOM).publicKey();
        keypair.close();
        keypair.generateSharedSecret(otherPoint);
    }
}
