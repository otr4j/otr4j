/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.session.ake;

import net.java.otr4j.api.Version;
import net.java.otr4j.crypto.DHKeyPairOTR3;
import net.java.otr4j.crypto.SharedSecret;
import net.java.otr4j.crypto.SharedSecretTestUtil;
import org.junit.Test;

import java.security.SecureRandom;
import java.security.interfaces.DSAPublicKey;

import static net.java.otr4j.crypto.DHKeyPairOTR3.generateDHKeyPair;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;
import static org.mockito.Mockito.mock;

@SuppressWarnings("ConstantConditions")
public class SecurityParametersTest {
    
    private static final SecureRandom RANDOM = new SecureRandom();

    public SecurityParametersTest() {
    }

    @Test
    public void testConstruction() {
        final SharedSecret s = SharedSecretTestUtil.createTestSecret();
        final DHKeyPairOTR3 localDHKeyPair = generateDHKeyPair(RANDOM);
        final DHKeyPairOTR3 remoteDHKeyPair = generateDHKeyPair(RANDOM);
        final DSAPublicKey remoteLongTermPublicKey = mock(DSAPublicKey.class);
        final SecurityParameters params = new SecurityParameters(Version.THREE, localDHKeyPair, remoteLongTermPublicKey,
                remoteDHKeyPair.getPublic(), s);
        assertSame(s, params.getS());
        assertSame(localDHKeyPair, params.getLocalDHKeyPair());
        assertSame(remoteDHKeyPair.getPublic(), params.getRemoteDHPublicKey());
        assertSame(remoteLongTermPublicKey, params.getRemoteLongTermPublicKey());
        assertEquals(Version.THREE, params.getVersion());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructionIllegalVersion() {
        final SharedSecret s = SharedSecretTestUtil.createTestSecret();
        final DHKeyPairOTR3 localDHKeyPair = generateDHKeyPair(RANDOM);
        final DHKeyPairOTR3 remoteDHKeyPair = generateDHKeyPair(RANDOM);
        final DSAPublicKey remoteLongTermPublicKey = mock(DSAPublicKey.class);
        new SecurityParameters(Version.ONE, localDHKeyPair, remoteLongTermPublicKey, remoteDHKeyPair.getPublic(), s);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructionNegativeVersion() {
        final SharedSecret s = SharedSecretTestUtil.createTestSecret();
        final DHKeyPairOTR3 localDHKeyPair = generateDHKeyPair(RANDOM);
        final DHKeyPairOTR3 remoteDHKeyPair = generateDHKeyPair(RANDOM);
        final DSAPublicKey remoteLongTermPublicKey = mock(DSAPublicKey.class);
        new SecurityParameters(Version.NONE, localDHKeyPair, remoteLongTermPublicKey, remoteDHKeyPair.getPublic(), s);
    }

    @Test(expected = NullPointerException.class)
    public void testNullLocalDHKeyPair() {
        final SharedSecret s = SharedSecretTestUtil.createTestSecret();
        final DHKeyPairOTR3 remoteDHKeyPair = generateDHKeyPair(RANDOM);
        final DSAPublicKey remoteLongTermPublicKey = mock(DSAPublicKey.class);
        new SecurityParameters(Version.THREE, null, remoteLongTermPublicKey, remoteDHKeyPair.getPublic(), s);
    }

    @Test(expected = NullPointerException.class)
    public void testNullRemoteLongTermPublicKey() {
        final SharedSecret s = SharedSecretTestUtil.createTestSecret();
        final DHKeyPairOTR3 localDHKeyPair = generateDHKeyPair(RANDOM);
        final DHKeyPairOTR3 remoteDHKeyPair = generateDHKeyPair(RANDOM);
        new SecurityParameters(Version.THREE, localDHKeyPair, null, remoteDHKeyPair.getPublic(), s);
    }

    @Test(expected = NullPointerException.class)
    public void testNullRemoteDHPublicKey() {
        final SharedSecret s = SharedSecretTestUtil.createTestSecret();
        final DHKeyPairOTR3 localDHKeyPair = generateDHKeyPair(RANDOM);
        final DSAPublicKey remoteLongTermPublicKey = mock(DSAPublicKey.class);
        new SecurityParameters(Version.THREE, localDHKeyPair, remoteLongTermPublicKey, null, s);
    }

    @Test(expected = NullPointerException.class)
    public void testNullSharedSecret() {
        final DHKeyPairOTR3 localDHKeyPair = generateDHKeyPair(RANDOM);
        final DSAPublicKey remoteLongTermPublicKey = mock(DSAPublicKey.class);
        final DHKeyPairOTR3 remoteDHKeyPair = generateDHKeyPair(RANDOM);
        new SecurityParameters(Version.THREE, localDHKeyPair, remoteLongTermPublicKey, remoteDHKeyPair.getPublic(), null);
    }
}
