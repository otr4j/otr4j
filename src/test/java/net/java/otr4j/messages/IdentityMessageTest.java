/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.messages;

import net.java.otr4j.api.ClientProfileTestUtils;
import net.java.otr4j.crypto.DHKeyPair;
import net.java.otr4j.crypto.ed448.ECDHKeyPair;
import net.java.otr4j.crypto.ed448.Point;
import org.junit.Test;

import java.math.BigInteger;
import java.security.SecureRandom;

import static net.java.otr4j.api.InstanceTag.ZERO_TAG;
import static net.java.otr4j.crypto.ed448.Ed448.basePoint;

@SuppressWarnings({"ConstantConditions", "resource"})
public final class IdentityMessageTest {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final ClientProfileTestUtils profileTestUtils = new ClientProfileTestUtils();

    @Test
    public void testConstructIdentityMessage() {
        final ClientProfilePayload clientProfile = profileTestUtils.createTransitionalClientProfile();
        final Point y = basePoint();
        final BigInteger b = BigInteger.TEN;
        final Point firstECDHPublicKey = ECDHKeyPair.generate(RANDOM).publicKey();
        final BigInteger firstDHPublicKey = DHKeyPair.generate(RANDOM).publicKey();
        new IdentityMessage(ZERO_TAG, ZERO_TAG, clientProfile, y, b, firstECDHPublicKey, firstDHPublicKey);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructionNullUserProfile() {
        final Point y = basePoint();
        final BigInteger b = BigInteger.TEN;
        final Point firstECDHPublicKey = ECDHKeyPair.generate(RANDOM).publicKey();
        final BigInteger firstDHPublicKey = DHKeyPair.generate(RANDOM).publicKey();
        new IdentityMessage(ZERO_TAG, ZERO_TAG, null, y, b, firstECDHPublicKey, firstDHPublicKey);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructIdentityMessageNullY() {
        final ClientProfilePayload clientProfile = profileTestUtils.createClientProfile();
        final BigInteger b = BigInteger.TEN;
        final Point firstECDHPublicKey = ECDHKeyPair.generate(RANDOM).publicKey();
        final BigInteger firstDHPublicKey = DHKeyPair.generate(RANDOM).publicKey();
        new IdentityMessage(ZERO_TAG, ZERO_TAG, clientProfile, null, b, firstECDHPublicKey, firstDHPublicKey);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructIdentityMessageNullB() {
        final ClientProfilePayload clientProfile = profileTestUtils.createClientProfile();
        final Point y = basePoint();
        final Point firstECDHPublicKey = ECDHKeyPair.generate(RANDOM).publicKey();
        final BigInteger firstDHPublicKey = DHKeyPair.generate(RANDOM).publicKey();
        new IdentityMessage(ZERO_TAG, ZERO_TAG, clientProfile, y, null, firstECDHPublicKey, firstDHPublicKey);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructNullFirstECDHPublicKey() {
        final ClientProfilePayload clientProfile = profileTestUtils.createClientProfile();
        final Point y = basePoint();
        final BigInteger b = BigInteger.TEN;
        final BigInteger firstDHPublicKey = DHKeyPair.generate(RANDOM).publicKey();
        new IdentityMessage(ZERO_TAG, ZERO_TAG, clientProfile, y, b, null, firstDHPublicKey);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructNullFirstDHPublicKey() {
        final ClientProfilePayload clientProfile = profileTestUtils.createClientProfile();
        final Point y = basePoint();
        final BigInteger b = BigInteger.TEN;
        final Point firstECDHPublicKey = ECDHKeyPair.generate(RANDOM).publicKey();
        new IdentityMessage(ZERO_TAG, ZERO_TAG, clientProfile, y, b, firstECDHPublicKey, null);
    }
}
