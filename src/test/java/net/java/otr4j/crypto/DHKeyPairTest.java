/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.crypto;

import org.junit.Test;

import java.math.BigInteger;
import java.security.SecureRandom;

import static java.math.BigInteger.ONE;
import static net.java.otr4j.crypto.DHKeyPair.checkPublicKey;
import static net.java.otr4j.crypto.DHKeyPairs.verifyDHPublicKey;
import static org.bouncycastle.math.ec.ECConstants.TWO;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

@SuppressWarnings({"ResultOfMethodCallIgnored", "ConstantConditions"})
public class DHKeyPairTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final BigInteger MODULUS = DHKeyPair.modulus();

    @Test(expected = NullPointerException.class)
    public void testGenerateKeyPairNullRandom() {
        DHKeyPair.generate((SecureRandom) null);
    }

    @Test(expected = NullPointerException.class)
    public void testGenerateKeyPairWithByteInput() {
        DHKeyPair.generate((byte[]) null);
    }

    @Test
    public void testGenerateKeyPair() {
        final DHKeyPair keypair = DHKeyPair.generate(RANDOM);
        assertNotNull(keypair);
        assertNotNull(keypair.publicKey());
    }

    @Test
    public void testGeneratingKeyPairs() {
        for (int i = 0; i < 50; i++) {
            final DHKeyPair keypair = DHKeyPair.generate(RANDOM);
            if (!checkPublicKey(keypair.publicKey())) {
                fail("Generated public key failed verification: " + keypair.publicKey());
            }
        }
    }

    @Test(expected = NullPointerException.class)
    public void testGenerateSharedSecretNullPk() {
        final DHKeyPair keypair = DHKeyPair.generate(RANDOM);
        keypair.generateSharedSecret(null);
    }

    @Test
    public void testGenerateSharedSecretSymmetry() {
        final DHKeyPair keypairA = DHKeyPair.generate(RANDOM);
        final DHKeyPair keypairB = DHKeyPair.generate(RANDOM);
        assertEquals(keypairA.generateSharedSecret(keypairB.publicKey()),
                keypairB.generateSharedSecret(keypairA.publicKey()));
    }

    @Test
    public void testVerifyPublicKey() throws OtrCryptoException {
        final DHKeyPair keypair = DHKeyPair.generate(RANDOM);
        verifyDHPublicKey(keypair.publicKey());
    }

    @Test(expected = NullPointerException.class)
    public void testVerifyNull() throws OtrCryptoException {
        verifyDHPublicKey(null);
    }

    @Test(expected = OtrCryptoException.class)
    public void testVerifyIllegalPublicKeyTooLow() throws OtrCryptoException {
        verifyDHPublicKey(ONE);
    }

    @Test(expected = OtrCryptoException.class)
    public void testVerifyIllegalPublicKeyTooHigh() throws OtrCryptoException {
        verifyDHPublicKey(MODULUS);
    }

    @Test(expected = OtrCryptoException.class)
    public void testVerifyIllegalPublicKeyTooHigh2() throws OtrCryptoException {
        verifyDHPublicKey(MODULUS.subtract(ONE));
    }

    @Test
    public void testVerifyPublicKeyLowerBound() throws OtrCryptoException {
        verifyDHPublicKey(TWO);
    }

    @Test(expected = NullPointerException.class)
    public void testCheckPublicKeyNull() {
        checkPublicKey(null);
    }

    @Test
    public void testCheckPublicKeyTooLow() {
        assertFalse(checkPublicKey(ONE));
    }

    @Test
    public void testCheckPublicKeyLowerBound() {
        assertTrue(checkPublicKey(TWO));
    }

    @Test
    public void testCheckPublicKeyTooHigh() {
        assertFalse(checkPublicKey(MODULUS));
        assertFalse(checkPublicKey(MODULUS.subtract(ONE)));
    }

    @Test(expected = NullPointerException.class)
    public void testGenerateSharedSecretWithCleanedKeyPair() {
        final DHKeyPair kp1 = DHKeyPair.generate(RANDOM);
        final DHKeyPair kp2 = DHKeyPair.generate(RANDOM);
        kp1.close();
        kp1.generateSharedSecret(kp2.publicKey());
    }
}
