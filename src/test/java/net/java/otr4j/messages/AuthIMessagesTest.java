/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.messages;

import net.java.otr4j.api.ClientProfile;
import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.api.Session;
import net.java.otr4j.api.Session.Version;
import net.java.otr4j.crypto.DHKeyPair;
import net.java.otr4j.crypto.DSAKeyPair;
import net.java.otr4j.crypto.OtrCryptoEngine4.Sigma;
import net.java.otr4j.crypto.ed448.ECDHKeyPair;
import net.java.otr4j.crypto.ed448.EdDSAKeyPair;
import net.java.otr4j.crypto.ed448.Point;
import org.junit.Test;

import java.math.BigInteger;
import java.security.SecureRandom;

import static java.math.BigInteger.ZERO;
import static java.util.Collections.singletonList;
import static net.java.otr4j.api.InstanceTag.HIGHEST_TAG;
import static net.java.otr4j.api.InstanceTag.SMALLEST_TAG;
import static net.java.otr4j.crypto.OtrCryptoEngine4.ringSign;
import static net.java.otr4j.messages.AuthIMessages.validate;
import static net.java.otr4j.messages.ClientProfilePayload.signClientProfile;

public final class AuthIMessagesTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    @Test
    public void testValidateSuccessful() throws ValidationException {
        // Our client profile
        final EdDSAKeyPair ourLongTermKeyPair = EdDSAKeyPair.generate(RANDOM);
        final Point ourForgingKey = EdDSAKeyPair.generate(RANDOM).getPublicKey();
        final DSAKeyPair ourDSAKeyPair = DSAKeyPair.generateDSAKeyPair(RANDOM);
        final Point ourFirstECDHPublicKey = ECDHKeyPair.generate(RANDOM).getPublicKey();
        final BigInteger ourFirstDHPublicKey = DHKeyPair.generate(RANDOM).getPublicKey();
        final ClientProfile ourProfile = new ClientProfile(HIGHEST_TAG, ourLongTermKeyPair.getPublicKey(),
                ourForgingKey, singletonList(Version.FOUR), ourDSAKeyPair.getPublic());
        final ClientProfilePayload ourProfilePayload = signClientProfile(ourProfile, Long.MAX_VALUE / 1000,
                ourDSAKeyPair, ourLongTermKeyPair);
        final Point ourX = ECDHKeyPair.generate(RANDOM).getPublicKey();
        final BigInteger ourA = DHKeyPair.generate(RANDOM).getPublicKey();
        // Their client profile
        final EdDSAKeyPair theirLongTermKeyPair = EdDSAKeyPair.generate(RANDOM);
        final DSAKeyPair theirDSAKeyPair = DSAKeyPair.generateDSAKeyPair(RANDOM);
        final Point theirFirstECDHPublicKey = ECDHKeyPair.generate(RANDOM).getPublicKey();
        final BigInteger theirFirstDHPublicKey = DHKeyPair.generate(RANDOM).getPublicKey();
        final Point theirForgingKey = EdDSAKeyPair.generate(RANDOM).getPublicKey();
        final ClientProfile theirProfile = new ClientProfile(SMALLEST_TAG, theirLongTermKeyPair.getPublicKey(),
                theirForgingKey, singletonList(Session.Version.FOUR), theirDSAKeyPair.getPublic());
        final ClientProfilePayload theirProfilePayload = signClientProfile(theirProfile, Long.MAX_VALUE / 1000,
                theirDSAKeyPair, theirLongTermKeyPair);
        final Point theirY = ECDHKeyPair.generate(RANDOM).getPublicKey();
        final BigInteger theirB = DHKeyPair.generate(RANDOM).getPublicKey();
        // The Auth-I message
        final byte[] m = MysteriousT4.encode(MysteriousT4.Purpose.AUTH_I, ourProfilePayload, theirProfilePayload, ourX,
                theirY, ourA, theirB, ourFirstECDHPublicKey, ourFirstDHPublicKey, theirFirstECDHPublicKey,
                theirFirstDHPublicKey, SMALLEST_TAG, HIGHEST_TAG, "alice@network", "bob@network");
        final Sigma sigma = ringSign(RANDOM, theirLongTermKeyPair, theirLongTermKeyPair.getPublicKey(),
                ourForgingKey, ourX, m);
        final AuthIMessage message = new AuthIMessage(Version.FOUR, SMALLEST_TAG, HIGHEST_TAG, sigma);
        validate(message, ourProfilePayload, ourProfile, theirProfilePayload, theirProfile, ourX, theirY, ourA, theirB,
                ourFirstECDHPublicKey, ourFirstDHPublicKey, theirFirstECDHPublicKey, theirFirstDHPublicKey,
                "alice@network", "bob@network");
    }

    @Test(expected = ValidationException.class)
    public void testValidateIllegalDHPublicKey() throws ValidationException {
        // Our client profile
        final EdDSAKeyPair ourLongTermKeyPair = EdDSAKeyPair.generate(RANDOM);
        final Point ourForgingKey = EdDSAKeyPair.generate(RANDOM).getPublicKey();
        final DSAKeyPair ourDSAKeyPair = DSAKeyPair.generateDSAKeyPair(RANDOM);
        final Point ourFirstECDHPublicKey = ECDHKeyPair.generate(RANDOM).getPublicKey();
        final BigInteger ourFirstDHPublicKey = DHKeyPair.generate(RANDOM).getPublicKey();
        final ClientProfile ourProfile = new ClientProfile(HIGHEST_TAG, ourLongTermKeyPair.getPublicKey(),
                ourForgingKey, singletonList(Session.Version.FOUR), ourDSAKeyPair.getPublic());
        final ClientProfilePayload ourProfilePayload = signClientProfile(ourProfile, Long.MAX_VALUE / 1000,
                ourDSAKeyPair, ourLongTermKeyPair);
        final Point ourX = ECDHKeyPair.generate(RANDOM).getPublicKey();
        final BigInteger ourA = DHKeyPair.generate(RANDOM).getPublicKey();
        // Their client profile
        final EdDSAKeyPair theirLongTermKeyPair = EdDSAKeyPair.generate(RANDOM);
        final DSAKeyPair theirDSAKeyPair = DSAKeyPair.generateDSAKeyPair(RANDOM);
        final Point theirFirstECDHPublicKey = ECDHKeyPair.generate(RANDOM).getPublicKey();
        final BigInteger theirFirstDHPublicKey = DHKeyPair.generate(RANDOM).getPublicKey();
        final Point theirForgingKey = EdDSAKeyPair.generate(RANDOM).getPublicKey();
        final ClientProfile theirProfile = new ClientProfile(SMALLEST_TAG, theirLongTermKeyPair.getPublicKey(),
                theirForgingKey, singletonList(Version.FOUR), theirDSAKeyPair.getPublic());
        final ClientProfilePayload theirProfilePayload = signClientProfile(theirProfile, Long.MAX_VALUE / 1000,
                theirDSAKeyPair, theirLongTermKeyPair);
        final Point theirY = ECDHKeyPair.generate(RANDOM).getPublicKey();
        final BigInteger theirB = DHKeyPair.generate(RANDOM).getPublicKey();
        // The Auth-I message
        final byte[] m = MysteriousT4.encode(MysteriousT4.Purpose.AUTH_I, ourProfilePayload, theirProfilePayload, ourX,
                theirY, ourA, theirB, ourFirstECDHPublicKey, ourFirstDHPublicKey, theirFirstECDHPublicKey,
                ourFirstDHPublicKey, SMALLEST_TAG, HIGHEST_TAG, "alice@network", "bob@network");
        final Sigma sigma = ringSign(RANDOM, theirLongTermKeyPair, theirLongTermKeyPair.getPublicKey(),
                ourForgingKey, ourX, m);
        final AuthIMessage message = new AuthIMessage(Session.Version.FOUR, SMALLEST_TAG, HIGHEST_TAG, sigma);
        validate(message, ourProfilePayload, ourProfile, theirProfilePayload, theirProfile, ourX, theirY, ourA, ZERO,
                ourFirstECDHPublicKey, ourFirstDHPublicKey, theirFirstECDHPublicKey, theirFirstDHPublicKey,
                "alice@network", "bob@network");
    }

    @Test(expected = ValidationException.class)
    public void testValidateBadSenderTag() throws ValidationException {
        // Our client profile
        final EdDSAKeyPair ourLongTermKeyPair = EdDSAKeyPair.generate(RANDOM);
        final Point ourForgingKey = EdDSAKeyPair.generate(RANDOM).getPublicKey();
        final DSAKeyPair ourDSAKeyPair = DSAKeyPair.generateDSAKeyPair(RANDOM);
        final Point ourFirstECDHPublicKey = ECDHKeyPair.generate(RANDOM).getPublicKey();
        final BigInteger ourFirstDHPublicKey = DHKeyPair.generate(RANDOM).getPublicKey();
        final ClientProfile ourProfile = new ClientProfile(HIGHEST_TAG, ourLongTermKeyPair.getPublicKey(),
                ourForgingKey, singletonList(Version.FOUR), ourDSAKeyPair.getPublic());
        final ClientProfilePayload ourProfilePayload = signClientProfile(ourProfile, Long.MAX_VALUE / 1000,
                ourDSAKeyPair, ourLongTermKeyPair);
        final Point ourX = ECDHKeyPair.generate(RANDOM).getPublicKey();
        final BigInteger ourA = DHKeyPair.generate(RANDOM).getPublicKey();
        // Their client profile
        final EdDSAKeyPair theirLongTermKeyPair = EdDSAKeyPair.generate(RANDOM);
        final DSAKeyPair theirDSAKeyPair = DSAKeyPair.generateDSAKeyPair(RANDOM);
        final Point theirFirstECDHPublicKey = ECDHKeyPair.generate(RANDOM).getPublicKey();
        final BigInteger theirFirstDHPublicKey = DHKeyPair.generate(RANDOM).getPublicKey();
        final Point theirForgingKey = EdDSAKeyPair.generate(RANDOM).getPublicKey();
        final ClientProfile theirProfile = new ClientProfile(new InstanceTag(257),
                theirLongTermKeyPair.getPublicKey(), theirForgingKey, singletonList(Version.FOUR), theirDSAKeyPair.getPublic());
        final ClientProfilePayload theirProfilePayload = signClientProfile(theirProfile, Long.MAX_VALUE / 1000,
                theirDSAKeyPair, theirLongTermKeyPair);
        final Point theirY = ECDHKeyPair.generate(RANDOM).getPublicKey();
        final BigInteger theirB = DHKeyPair.generate(RANDOM).getPublicKey();
        // The Auth-I message
        final byte[] m = MysteriousT4.encode(MysteriousT4.Purpose.AUTH_I, ourProfilePayload, theirProfilePayload, ourX,
                theirY, ourA, theirB, ourFirstECDHPublicKey, ourFirstDHPublicKey, theirFirstECDHPublicKey,
                theirFirstDHPublicKey, SMALLEST_TAG, HIGHEST_TAG, "alice@network", "bob@network");
        final Sigma sigma = ringSign(RANDOM, theirLongTermKeyPair, theirLongTermKeyPair.getPublicKey(),
                ourForgingKey, ourX, m);
        final AuthIMessage message = new AuthIMessage(Session.Version.FOUR, SMALLEST_TAG, HIGHEST_TAG, sigma);
        validate(message, ourProfilePayload, ourProfile, theirProfilePayload, theirProfile, ourX, theirY, ourA, theirB,
                ourFirstECDHPublicKey, ourFirstDHPublicKey, theirFirstECDHPublicKey, theirFirstDHPublicKey,
                "alice@network", "bob@network");
    }
}