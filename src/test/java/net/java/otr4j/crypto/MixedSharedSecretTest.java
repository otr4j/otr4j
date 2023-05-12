/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.crypto;

import net.java.otr4j.crypto.ed448.ECDHKeyPair;
import net.java.otr4j.crypto.ed448.Point;
import org.junit.Test;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

import static net.java.otr4j.util.ByteArrays.allZeroBytes;
import static org.bouncycastle.util.Arrays.fill;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.internal.util.reflection.Whitebox.getInternalState;

/**
 * The MixedSharedSecret tests currently do not perform a test that binary-exactly verifies that the right values are
 * produced. For now we verify immutability of values and that values change after rotation.
 */
@SuppressWarnings({"ConstantConditions", "resource"})
public class MixedSharedSecretTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    private static final Point theirECDHPublicKey = ECDHKeyPair.generate(RANDOM).publicKey();

    private static final Point theirNextECDHPublicKey = ECDHKeyPair.generate(RANDOM).publicKey();

    private static final BigInteger theirDHPublicKey = DHKeyPair.generate(RANDOM).publicKey();

    private static final BigInteger theirNextDHPublicKey = DHKeyPair.generate(RANDOM).publicKey();

    @Test(expected = NullPointerException.class)
    public void testConstructionNullSecureRandom() {
        final DHKeyPair ourDHKeyPair = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        new MixedSharedSecret(null, ourDHKeyPair, ourECDHKeyPair, theirDHPublicKey, theirECDHPublicKey);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructionNullDHKeyPair() {
        final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        new MixedSharedSecret(RANDOM, null, ourECDHKeyPair, theirDHPublicKey, theirECDHPublicKey);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructionNullECDHKeyPair() {
        final DHKeyPair ourDHKeyPair = DHKeyPair.generate(RANDOM);
        new MixedSharedSecret(RANDOM, ourDHKeyPair, null, theirDHPublicKey, theirECDHPublicKey);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructionNullECDHandDHKeyPair() {
        new MixedSharedSecret(RANDOM, null, null, theirDHPublicKey, theirECDHPublicKey);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructionNullTheirDHPublicKey() {
        final DHKeyPair ourDHKeyPair = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        new MixedSharedSecret(RANDOM, ourDHKeyPair, ourECDHKeyPair, null, theirECDHPublicKey);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructionNullTheirECDHPublicKey() {
        final DHKeyPair ourDHKeyPair = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        new MixedSharedSecret(RANDOM, ourDHKeyPair, ourECDHKeyPair, theirDHPublicKey, null);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructionNullTheirECDHandDHPublicKey() {
        final DHKeyPair ourDHKeyPair = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        new MixedSharedSecret(RANDOM, ourDHKeyPair, ourECDHKeyPair, null, null);
    }

    @Test
    public void testConstruction() {
        final DHKeyPair ourDHKeyPair = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        final MixedSharedSecret ss = new MixedSharedSecret(RANDOM, ourDHKeyPair, ourECDHKeyPair, theirDHPublicKey, theirECDHPublicKey);
        assertEquals(ourECDHKeyPair.publicKey(), ss.getECDHPublicKey());
        assertEquals(ourDHKeyPair.publicKey(), ss.getDHPublicKey());
        assertEquals(theirECDHPublicKey, ss.getTheirECDHPublicKey());
        assertEquals(theirDHPublicKey, ss.getTheirDHPublicKey());
        assertNotNull(ss.getK());
    }

    @Test
    public void testRotateOurKeysNoDHRatchet() {
        final DHKeyPair ourDHKeyPair = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        final MixedSharedSecret ss = new MixedSharedSecret(RANDOM, ourDHKeyPair, ourECDHKeyPair, theirDHPublicKey, theirECDHPublicKey);
        final Point firstECDHPublicKey = ss.getECDHPublicKey();
        final BigInteger firstDHPublicKey = ss.getDHPublicKey();
        final byte[] firstK = ss.getK();
        // Rotate our key pairs.
        ss.rotateOurKeys(false);
        // Ensure that k actually changes after rotation.
        assertNotEquals(firstECDHPublicKey, ss.getECDHPublicKey());
        assertEquals(firstDHPublicKey, ss.getDHPublicKey());
        assertFalse(Arrays.equals(firstK, ss.getK()));
    }

    @Test
    public void testRotateOurKeysDHRatchet() {
        final DHKeyPair ourDHKeyPair = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        final MixedSharedSecret ss = new MixedSharedSecret(RANDOM, ourDHKeyPair, ourECDHKeyPair, theirDHPublicKey, theirECDHPublicKey);
        final Point firstECDHPublicKey = ss.getECDHPublicKey();
        final BigInteger firstDHPublicKey = ss.getDHPublicKey();
        final byte[] firstK = ss.getK();
        // Rotate our key pairs.
        ss.rotateOurKeys(true);
        // Ensure that k actually changes after rotation.
        assertNotEquals(firstECDHPublicKey, ss.getECDHPublicKey());
        assertNotEquals(firstDHPublicKey, ss.getDHPublicKey());
        assertFalse(Arrays.equals(firstK, ss.getK()));
    }

    @Test
    public void testRotateTheirKeys() throws OtrCryptoException {
        final DHKeyPair ourDHKeyPair = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        final MixedSharedSecret ss = new MixedSharedSecret(RANDOM, ourDHKeyPair, ourECDHKeyPair, theirDHPublicKey, theirECDHPublicKey);
        final byte[] firstK = ss.getK();
        // Rotate our key pairs.
        ss.rotateTheirKeys(theirNextECDHPublicKey, null);
        // Ensure that k and ssid actually change after rotation.
        assertFalse(Arrays.equals(firstK, ss.getK()));
    }

    @Test(expected = NullPointerException.class)
    public void testRotateTheirKeysNullECDH() throws OtrCryptoException {
        final DHKeyPair ourDHKeyPair = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        final MixedSharedSecret ss = new MixedSharedSecret(RANDOM, ourDHKeyPair, ourECDHKeyPair, theirDHPublicKey, theirECDHPublicKey);
        ss.rotateTheirKeys(null, theirNextDHPublicKey);
    }

    @Test
    public void testRotateTheirKeysNullDHNonThirdIteration() throws OtrCryptoException {
        final DHKeyPair ourDHKeyPair = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        final MixedSharedSecret ss = new MixedSharedSecret(RANDOM, ourDHKeyPair, ourECDHKeyPair, theirDHPublicKey, theirECDHPublicKey);
        final byte[] firstK = ss.getK();
        final byte[] firstSSID = ss.generateSSID();
        // Rotate their public keys.
        ss.rotateTheirKeys(theirNextECDHPublicKey, null);
        // Ensure that k and ssid actually change after rotation.
        assertFalse(Arrays.equals(firstK, ss.getK()));
        assertFalse(Arrays.equals(firstSSID, ss.generateSSID()));
    }

    @Test
    public void testGetKNotModifiable() throws OtrCryptoException {
        final DHKeyPair ourDHKeyPair = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        final MixedSharedSecret ss = new MixedSharedSecret(RANDOM, ourDHKeyPair, ourECDHKeyPair, theirDHPublicKey, theirECDHPublicKey);
        ss.rotateTheirKeys(theirNextECDHPublicKey, theirNextDHPublicKey);
        final byte[] firstK = ss.getK();
        fill(firstK, (byte) 0xff);
        final byte[] secondK = ss.getK();
        assertFalse(Arrays.equals(firstK, secondK));
    }

    @Test(expected = OtrCryptoException.class)
    public void testRotateSamePublicKeysEveryThirdIteration() throws OtrCryptoException {
        final DHKeyPair ourDHKeyPair = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        final MixedSharedSecret ss = new MixedSharedSecret(RANDOM, ourDHKeyPair, ourECDHKeyPair, theirDHPublicKey, theirECDHPublicKey);
        ss.rotateOurKeys(true);
        final byte[] firstK = ss.getK();
        ss.rotateTheirKeys(theirECDHPublicKey, theirDHPublicKey);
        assertArrayEquals(firstK, ss.getK());
    }

    @Test
    public void testRotateDifferentPublicKeysEveryThirdIteration() throws OtrCryptoException {
        final DHKeyPair ourDHKeyPair = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        final MixedSharedSecret ss = new MixedSharedSecret(RANDOM, ourDHKeyPair, ourECDHKeyPair, theirDHPublicKey, theirECDHPublicKey);
        ss.rotateOurKeys(true);
        final byte[] firstK = ss.getK();
        ss.rotateTheirKeys(theirNextECDHPublicKey, theirNextDHPublicKey);
        assertFalse(Arrays.equals(firstK, ss.getK()));
    }

    @Test(expected = OtrCryptoException.class)
    public void testRotateSamePublicKeysEveryNonThirdIteration() throws OtrCryptoException {
        final DHKeyPair ourDHKeyPair = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        final MixedSharedSecret ss = new MixedSharedSecret(RANDOM, ourDHKeyPair, ourECDHKeyPair, theirDHPublicKey, theirECDHPublicKey);
        final byte[] firstK = ss.getK();
        ss.rotateTheirKeys(theirECDHPublicKey, null);
        assertFalse(Arrays.equals(firstK, ss.getK()));
    }

    @Test
    public void testRotateOurKeysWithoutTheirKeysNoDHKeyPairRotation() {
        final DHKeyPair ourDHKeyPair = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        final BigInteger theirDHPublicKey = DHKeyPair.generate(RANDOM).publicKey();
        final Point theirECDHPublicKey = ECDHKeyPair.generate(RANDOM).publicKey();
        final MixedSharedSecret shared = new MixedSharedSecret(RANDOM, ourDHKeyPair, ourECDHKeyPair, theirDHPublicKey,
                theirECDHPublicKey);
        shared.rotateOurKeys(false);
    }

    @Test(expected = NullPointerException.class)
    public void testRotateTheirKeysWithNullECDHPoint() throws OtrCryptoException {
        final BigInteger theirDHPublicKey = DHKeyPair.generate(RANDOM).publicKey();
        final Point theirECDHPublicKey = ECDHKeyPair.generate(RANDOM).publicKey();
        final MixedSharedSecret shared = new MixedSharedSecret(RANDOM, DHKeyPair.generate(RANDOM), ECDHKeyPair.generate(RANDOM),
                theirDHPublicKey, theirECDHPublicKey);
        shared.rotateTheirKeys(null, DHKeyPair.generate(RANDOM).publicKey());
    }

    @Test(expected = NullPointerException.class)
    public void testRotateTheirKeysWithIllegalECDHPoint() throws OtrCryptoException {
        final BigInteger theirDHPublicKey = DHKeyPair.generate(RANDOM).publicKey();
        final Point theirECDHPublicKey = ECDHKeyPair.generate(RANDOM).publicKey();
        final MixedSharedSecret shared = new MixedSharedSecret(RANDOM, DHKeyPair.generate(RANDOM), ECDHKeyPair.generate(RANDOM),
                theirDHPublicKey, theirECDHPublicKey);
        shared.rotateTheirKeys(null, DHKeyPair.generate(RANDOM).publicKey());
    }

    @Test(expected = OtrCryptoException.class)
    public void testRotateTheirKeysWithOurECDHPublicKey() throws OtrCryptoException {
        final DHKeyPair ourDHKeyPair = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        final MixedSharedSecret shared = new MixedSharedSecret(RANDOM, ourDHKeyPair, ourECDHKeyPair,
                DHKeyPair.generate(RANDOM).publicKey(), ECDHKeyPair.generate(RANDOM).publicKey());
        shared.rotateTheirKeys(ourECDHKeyPair.publicKey(), DHKeyPair.generate(RANDOM).publicKey());
    }

    @Test(expected = OtrCryptoException.class)
    public void testRotateTheirKeysWithOurDHPublicKey() throws OtrCryptoException {
        final DHKeyPair ourDHKeyPair = DHKeyPair.generate(RANDOM);
        final ECDHKeyPair ourECDHKeyPair = ECDHKeyPair.generate(RANDOM);
        final MixedSharedSecret shared = new MixedSharedSecret(RANDOM, ourDHKeyPair, ourECDHKeyPair,
                DHKeyPair.generate(RANDOM).publicKey(), ECDHKeyPair.generate(RANDOM).publicKey());
        shared.rotateTheirKeys(ECDHKeyPair.generate(RANDOM).publicKey(), ourDHKeyPair.publicKey());
    }

    @Test(expected = OtrCryptoException.class)
    public void testRotateTheirKeysWithTheirCurrentECDHPublicKey() throws OtrCryptoException {
        final BigInteger theirDHPublicKey = DHKeyPair.generate(RANDOM).publicKey();
        final Point theirECDHPublicKey = ECDHKeyPair.generate(RANDOM).publicKey();
        final MixedSharedSecret shared = new MixedSharedSecret(RANDOM, DHKeyPair.generate(RANDOM),
                ECDHKeyPair.generate(RANDOM), theirDHPublicKey, theirECDHPublicKey);
        shared.rotateTheirKeys(theirECDHPublicKey, DHKeyPair.generate(RANDOM).publicKey());
    }

    @Test(expected = OtrCryptoException.class)
    public void testRotateTheirKeysWithTheirCurrentDHPublicKey() throws OtrCryptoException {
        final BigInteger theirDHPublicKey = DHKeyPair.generate(RANDOM).publicKey();
        final Point theirECDHPublicKey = ECDHKeyPair.generate(RANDOM).publicKey();
        final MixedSharedSecret shared = new MixedSharedSecret(RANDOM, DHKeyPair.generate(RANDOM), ECDHKeyPair.generate(RANDOM),
                theirDHPublicKey, theirECDHPublicKey);
        shared.rotateTheirKeys(ECDHKeyPair.generate(RANDOM).publicKey(), theirDHPublicKey);
    }

    @Test
    public void testCloseSharedSecret4() {
        final MixedSharedSecret shared = new MixedSharedSecret(RANDOM, DHKeyPair.generate(RANDOM), ECDHKeyPair.generate(RANDOM),
                theirDHPublicKey, theirECDHPublicKey);
        shared.close();
        assertTrue(allZeroBytes((byte[]) getInternalState(shared, "k")));
        assertTrue(allZeroBytes((byte[]) getInternalState(shared, "braceKey")));
    }

    @Test(expected = IllegalStateException.class)
    public void testRotateTheirKeysAfterClosing() throws OtrCryptoException {
        final MixedSharedSecret shared = new MixedSharedSecret(RANDOM, DHKeyPair.generate(RANDOM), ECDHKeyPair.generate(RANDOM),
                theirDHPublicKey, theirECDHPublicKey);
        shared.close();
        shared.rotateTheirKeys(ECDHKeyPair.generate(RANDOM).publicKey(), theirDHPublicKey);
    }

    @Test(expected = IllegalStateException.class)
    public void testRotateOurKeysAfterClosing() {
        final MixedSharedSecret shared = new MixedSharedSecret(RANDOM, DHKeyPair.generate(RANDOM), ECDHKeyPair.generate(RANDOM),
                theirDHPublicKey, theirECDHPublicKey);
        shared.close();
        shared.rotateOurKeys(true);
    }

    @Test
    public void testGetECDHPublicKeyAfterClosing() {
        final MixedSharedSecret shared = new MixedSharedSecret(RANDOM, DHKeyPair.generate(RANDOM), ECDHKeyPair.generate(RANDOM),
                theirDHPublicKey, theirECDHPublicKey);
        shared.close();
        assertNotNull(shared.getECDHPublicKey());
    }

    @Test
    public void testGetDHPublicKeyAfterClosing() {
        final MixedSharedSecret shared = new MixedSharedSecret(RANDOM, DHKeyPair.generate(RANDOM), ECDHKeyPair.generate(RANDOM),
                theirDHPublicKey, theirECDHPublicKey);
        shared.close();
        assertNotNull(shared.getDHPublicKey());
    }

    @Test
    public void testGetTheirECDHPublicKeyAfterClosing() {
        final MixedSharedSecret shared = new MixedSharedSecret(RANDOM, DHKeyPair.generate(RANDOM), ECDHKeyPair.generate(RANDOM),
                theirDHPublicKey, theirECDHPublicKey);
        shared.close();
        assertNotNull(shared.getTheirECDHPublicKey());
    }

    @Test
    public void testGetTheirDHPublicKeyAfterClosing() {
        final MixedSharedSecret shared = new MixedSharedSecret(RANDOM, DHKeyPair.generate(RANDOM), ECDHKeyPair.generate(RANDOM),
                theirDHPublicKey, theirECDHPublicKey);
        shared.close();
        assertNotNull(shared.getTheirDHPublicKey());
    }

    @Test(expected = IllegalStateException.class)
    public void testGenerateSSIDAfterClosing() {
        final MixedSharedSecret shared = new MixedSharedSecret(RANDOM, DHKeyPair.generate(RANDOM), ECDHKeyPair.generate(RANDOM),
                theirDHPublicKey, theirECDHPublicKey);
        shared.close();
        shared.generateSSID();
    }

    @Test(expected = IllegalStateException.class)
    public void testGetKAfterClosing() {
        final MixedSharedSecret shared = new MixedSharedSecret(RANDOM, DHKeyPair.generate(RANDOM), ECDHKeyPair.generate(RANDOM),
                theirDHPublicKey, theirECDHPublicKey);
        shared.close();
        shared.getK();
    }

    @Test
    public void testCorrectClearingOfFieldsWhenClosed() {
        final MixedSharedSecret secret = new MixedSharedSecret(RANDOM, DHKeyPair.generate(RANDOM),
                ECDHKeyPair.generate(RANDOM), theirDHPublicKey, theirECDHPublicKey);
        assertFalse(allZeroBytes((byte[]) getInternalState(secret, "k")));
        assertFalse(allZeroBytes((byte[]) getInternalState(secret, "braceKey")));
        assertFalse((Boolean) getInternalState(secret, "closed"));
        secret.close();
        assertTrue(allZeroBytes((byte[]) getInternalState(secret, "k")));
        assertTrue(allZeroBytes((byte[]) getInternalState(secret, "braceKey")));
        assertTrue((Boolean) getInternalState(secret, "closed"));
    }
}
