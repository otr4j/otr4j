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
import net.java.otr4j.api.Version;
import net.java.otr4j.crypto.DHKeyPair;
import net.java.otr4j.crypto.DHKeyPairOTR3;
import net.java.otr4j.crypto.DSAKeyPair;
import net.java.otr4j.crypto.OtrCryptoEngine4;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.crypto.ed448.ECDHKeyPair;
import net.java.otr4j.crypto.ed448.EdDSAKeyPair;
import net.java.otr4j.crypto.ed448.Point;
import net.java.otr4j.io.EncodedMessage;
import net.java.otr4j.io.MessageProcessor;
import net.java.otr4j.io.OtrInputStream;
import net.java.otr4j.io.OtrInputStream.UnsupportedLengthException;
import net.java.otr4j.io.OtrOutputStream;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.ProtocolException;
import java.security.SecureRandom;
import java.util.Base64;

import static java.util.Arrays.copyOf;
import static java.util.Arrays.copyOfRange;
import static java.util.Collections.singletonList;
import static net.java.otr4j.api.InstanceTag.HIGHEST_TAG;
import static net.java.otr4j.api.InstanceTag.SMALLEST_TAG;
import static net.java.otr4j.api.InstanceTag.ZERO_TAG;
import static net.java.otr4j.crypto.DHKeyPairOTR3.generateDHKeyPair;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.AUTH_I_PHI;
import static net.java.otr4j.crypto.OtrCryptoEngine4.ringSign;
import static net.java.otr4j.io.MessageProcessor.writeMessage;
import static net.java.otr4j.messages.ClientProfilePayload.signClientProfile;
import static net.java.otr4j.messages.EncodedMessageParser.parseEncodedMessage;
import static net.java.otr4j.util.SecureRandoms.randomBytes;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

@SuppressWarnings({"BadImport", "resource"})
public class EncodedMessageParserTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    @Test(expected = ProtocolException.class)
    public void testParsingEmptyInputStream() throws IOException, OtrCryptoException, UnsupportedLengthException, ValidationException {
        parseEncodedMessage(new EncodedMessage(Version.FOUR, 0x35, ZERO_TAG, ZERO_TAG,
                new OtrInputStream(new byte[0])));
    }

    @Test(expected = ProtocolException.class)
    public void testParsingIncompleteInputStream() throws IOException, OtrCryptoException, UnsupportedLengthException, ValidationException {
        parseEncodedMessage(new EncodedMessage(Version.THREE, 0x35, ZERO_TAG, ZERO_TAG,
                new OtrInputStream(new byte[] {0x10, 0x20})));
    }

    @Test(expected = ProtocolException.class)
    public void testParsingUnsupportedMessageType() throws IOException, OtrCryptoException, UnsupportedLengthException, ValidationException {
        parseEncodedMessage(new EncodedMessage(Version.THREE, 0xff, ZERO_TAG, ZERO_TAG,
                new OtrInputStream(new byte[0])));
    }

    @Test(expected = IllegalStateException.class)
    public void testParsingUnsupportedVersion0() throws IOException, OtrCryptoException, UnsupportedLengthException, ValidationException {
        parseEncodedMessage(new EncodedMessage(Version.NONE, DataMessage.MESSAGE_DATA, ZERO_TAG, ZERO_TAG,
                new OtrInputStream(new byte[0])));
    }

    @SuppressWarnings("DataFlowIssue")
    @Test(expected = NullPointerException.class)
    public void testParsingUnsupportedNullVersion() throws IOException, OtrCryptoException, UnsupportedLengthException, ValidationException {
        parseEncodedMessage(new EncodedMessage(null, DataMessage.MESSAGE_DATA, ZERO_TAG, ZERO_TAG,
                new OtrInputStream(new byte[0])));
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testParsingUnsupportedOTRv1() throws IOException, OtrCryptoException, UnsupportedLengthException, ValidationException {
        parseEncodedMessage(new EncodedMessage(Version.ONE, DataMessage.MESSAGE_DATA, ZERO_TAG, ZERO_TAG,
                new OtrInputStream(new byte[0])));
    }

    @Test
    public void testConstructAndParseDHKeyMessage() throws IOException, OtrCryptoException, UnsupportedLengthException, ValidationException {
        final DHKeyPairOTR3 keypair = generateDHKeyPair(RANDOM);
        // Prepare output message to parse.
        final DHKeyMessage m = new DHKeyMessage(Version.THREE, keypair.getPublic(), new InstanceTag(12345),
                new InstanceTag(9876543));
        final ByteArrayOutputStream output = new ByteArrayOutputStream();
        final OtrOutputStream otrOutput = new OtrOutputStream(output);
        m.writeTo(otrOutput);
        // Parse produced message bytes.
        final EncodedMessage message = (EncodedMessage) MessageProcessor.parseMessage("?OTR:"
                + Base64.getEncoder().encodeToString(output.toByteArray()) + ".");
        final AbstractEncodedMessage parsedM = parseEncodedMessage(message);
        assertEquals(m, parsedM);
    }

    @Test(expected = ProtocolException.class)
    public void testConstructAndParseDHKeyMessageIllegalProtocolVersion() throws IOException, OtrCryptoException, UnsupportedLengthException, ValidationException {
        final String input = "?OTR:AAQKAAAwOQCWtD8AAADA7Z2lLvD52pq9eBg1YtUPKRzDhiJbugQjqWOGKCGy9n1nV7M9+4Xoev7wgEtsUMvY9UcbaXpNLXQMlcqSpZfwRNTogXk1lOir9h8NwaURj+/ruB2jq55STMfc11E4tBmyhATStwu5VPG+5iupUjagkhsdI6I1a3ZkGXp8gAr/Utx9IB2GeXDh7HRvqRacg96X1w69IQc1lH/dVFam/OpdxCMmME1QM6N6vRRh2y34oElNhlOMGwIO9tjKr2F9m9mC.";
        // Parse produced message bytes.
        final EncodedMessage message = (EncodedMessage) MessageProcessor.parseMessage(input);
        parseEncodedMessage(message);
    }

    @Test
    public void testConstructAndParsePartialDHKeyMessage() throws UnsupportedLengthException, ProtocolException, OtrCryptoException, ValidationException {
        final DHKeyPairOTR3 keypair = generateDHKeyPair(RANDOM);
        // Prepare output message to parse.
        final DHKeyMessage m = new DHKeyMessage(Version.THREE, keypair.getPublic(), new InstanceTag(12345),
                new InstanceTag(9876543));
        final OtrOutputStream output = new OtrOutputStream();
        m.writeTo(output);
        final byte[] fullMessage = output.toByteArray();
        final byte[] payload = copyOfRange(fullMessage, 11, fullMessage.length);
        for (int i = 0; i < payload.length; i++) {
            // Try every possible partial message by starting with 0 length message up to the full-length message and
            // try every substring in between.
            final byte[] partial = copyOf(payload, i);
            try {
                parseEncodedMessage(new EncodedMessage(Version.THREE, DHKeyMessage.MESSAGE_DHKEY,
                        new InstanceTag(12345), new InstanceTag(9876543), new OtrInputStream(partial)));
                fail("Expected exception due to parsing an incomplete message.");
            } catch (final ProtocolException | OtrCryptoException expected) {
                // Expected behavior for partial messages being parsed.
            }
        }
        final AbstractEncodedMessage dhKeyMessage = parseEncodedMessage(new EncodedMessage(Version.THREE,
                DHKeyMessage.MESSAGE_DHKEY, new InstanceTag(12345), new InstanceTag(9876543),
                new OtrInputStream(payload)));
        assertTrue(dhKeyMessage instanceof DHKeyMessage);
    }

    @Test
    public void testConstructAndParseDHCommitMessage() throws ProtocolException, UnsupportedLengthException, OtrCryptoException, ValidationException {
        final byte[] dhPublicKeyHash = randomBytes(RANDOM, new byte[40]);
        final byte[] dhPublicKeyEncrypted = randomBytes(RANDOM, new byte[55]);
        final DHCommitMessage message = new DHCommitMessage(Version.THREE, dhPublicKeyHash, dhPublicKeyEncrypted,
                SMALLEST_TAG, HIGHEST_TAG);
        final String content = writeMessage(message);
        final EncodedMessage encoded = (EncodedMessage) MessageProcessor.parseMessage(content);
        final DHCommitMessage parsed = (DHCommitMessage) parseEncodedMessage(encoded);
        assertEquals(message, parsed);
    }

    @Test
    public void testConstructAndParseRevealSignatureMessage() throws ProtocolException, UnsupportedLengthException, OtrCryptoException, ValidationException {
        final byte[] xEncrypted = randomBytes(RANDOM, new byte[40]);
        final byte[] xEncryptedMAC = randomBytes(RANDOM, new byte[20]);
        final byte[] revealedKey = randomBytes(RANDOM, new byte[40]);
        final RevealSignatureMessage message = new RevealSignatureMessage(Version.THREE, xEncrypted, xEncryptedMAC,
                revealedKey, SMALLEST_TAG, HIGHEST_TAG);
        final String content = writeMessage(message);
        final EncodedMessage encoded = (EncodedMessage) MessageProcessor.parseMessage(content);
        final RevealSignatureMessage parsed = (RevealSignatureMessage) parseEncodedMessage(encoded);
        assertEquals(message, parsed);
    }

    @Test
    public void testConstructAndParseSignatureMessage() throws ProtocolException, UnsupportedLengthException, OtrCryptoException, ValidationException {
        final byte[] xEncrypted = randomBytes(RANDOM, new byte[40]);
        final byte[] xEncryptedMAC = randomBytes(RANDOM, new byte[20]);
        final SignatureMessage message = new SignatureMessage(Version.THREE, xEncrypted, xEncryptedMAC, SMALLEST_TAG,
                HIGHEST_TAG);
        final String content = writeMessage(message);
        final EncodedMessage encoded = (EncodedMessage) MessageProcessor.parseMessage(content);
        final SignatureMessage parsed = (SignatureMessage) parseEncodedMessage(encoded);
        assertEquals(message, parsed);
    }

    @Test
    public void testParsingDataMessage() throws ProtocolException, OtrCryptoException, UnsupportedLengthException, ValidationException {
        final DHKeyPairOTR3 dhKeyPair = generateDHKeyPair(RANDOM);
        final int senderKeyID = RANDOM.nextInt();
        final int receiverKeyID = RANDOM.nextInt();
        final byte[] ctr = randomBytes(RANDOM, new byte[8]);
        final byte[] message = randomBytes(RANDOM, new byte[RANDOM.nextInt(1000)]);
        final byte[] mac = randomBytes(RANDOM, new byte[20]);
        final byte[] oldMacKeys = randomBytes(RANDOM, new byte[40]);
        final DataMessage input = new DataMessage(Version.THREE, (byte) 0, senderKeyID, receiverKeyID,
                dhKeyPair.getPublic(), ctr, message, mac, oldMacKeys, SMALLEST_TAG, HIGHEST_TAG);
        final byte[] fullPayload = new OtrOutputStream().write(input).toByteArray();
        final byte[] payload = copyOfRange(fullPayload, 11, fullPayload.length);
        final AbstractEncodedMessage result = parseEncodedMessage(new EncodedMessage(Version.THREE,
                DataMessage.MESSAGE_DATA, SMALLEST_TAG, HIGHEST_TAG, new OtrInputStream(payload)));
        assertEquals(input, result);
    }

    @Test
    public void testParsingDataMessage4() throws ProtocolException, OtrCryptoException, UnsupportedLengthException, ValidationException {
        final Point ecdhPublicKey = ECDHKeyPair.generate(RANDOM).publicKey();
        final BigInteger dhPublicKey = DHKeyPair.generate(RANDOM).publicKey();
        final byte[] content = randomBytes(RANDOM, new byte[RANDOM.nextInt(10000)]);
        final DataMessage4 input = new DataMessage4(SMALLEST_TAG, HIGHEST_TAG, (byte) 0, 0, 0, 0,
                ecdhPublicKey, dhPublicKey, content, randomBytes(RANDOM, new byte[64]), new byte[0]);
        final byte[] fullPayload = new OtrOutputStream().write(input).toByteArray();
        final byte[] payload = copyOfRange(fullPayload, 11, fullPayload.length);
        final AbstractEncodedMessage result = parseEncodedMessage(new EncodedMessage(Version.FOUR,
                DataMessage4.MESSAGE_DATA, SMALLEST_TAG, HIGHEST_TAG, new OtrInputStream(payload)));
        assertEquals(input, result);
    }

    @Test
    public void testParsingDataMessage4WithoutDHPublicKey() throws ProtocolException, OtrCryptoException, UnsupportedLengthException, ValidationException {
        final Point ecdhPublicKey = ECDHKeyPair.generate(RANDOM).publicKey();
        final byte[] content = randomBytes(RANDOM, new byte[RANDOM.nextInt(10000)]);
        final DataMessage4 input = new DataMessage4(SMALLEST_TAG, HIGHEST_TAG, (byte) 0, 0, 0, 0,
                ecdhPublicKey, null, content, randomBytes(RANDOM, new byte[64]), new byte[0]);
        final byte[] fullPayload = new OtrOutputStream().write(input).toByteArray();
        final byte[] payload = copyOfRange(fullPayload, 11, fullPayload.length);
        final AbstractEncodedMessage result = parseEncodedMessage(new EncodedMessage(Version.FOUR,
                DataMessage4.MESSAGE_DATA, SMALLEST_TAG, HIGHEST_TAG, new OtrInputStream(payload)));
        assertEquals(input, result);
    }

    @Test
    public void testParseIdentityMessage() throws ProtocolException, UnsupportedLengthException, OtrCryptoException, ValidationException {
        // Our client profile
        final EdDSAKeyPair ourLongTermKeyPair = EdDSAKeyPair.generate(RANDOM);
        final Point ourForgingKey = EdDSAKeyPair.generate(RANDOM).getPublicKey();
        final DSAKeyPair ourDSAKeyPair = DSAKeyPair.generateDSAKeyPair(RANDOM);
        final Point ourFirstECDHPublicKey = ECDHKeyPair.generate(RANDOM).publicKey();
        final BigInteger ourFirstDHPublicKey = DHKeyPair.generate(RANDOM).publicKey();
        final ClientProfile ourProfile = new ClientProfile(HIGHEST_TAG, ourLongTermKeyPair.getPublicKey(),
                ourForgingKey, singletonList(Version.FOUR), ourDSAKeyPair.getPublic());
        final ClientProfilePayload ourProfilePayload = signClientProfile(ourProfile, Long.MAX_VALUE / 1000,
                ourDSAKeyPair, ourLongTermKeyPair);
        final Point ourY = ECDHKeyPair.generate(RANDOM).publicKey();
        final BigInteger ourB = DHKeyPair.generate(RANDOM).publicKey();
        // Generate Identity message and parse result.
        final IdentityMessage message = new IdentityMessage(SMALLEST_TAG, HIGHEST_TAG, ourProfilePayload, ourY, ourB,
                ourFirstECDHPublicKey, ourFirstDHPublicKey);
        final String content = writeMessage(message);
        final EncodedMessage encoded = (EncodedMessage) MessageProcessor.parseMessage(content);
        final IdentityMessage parsed = (IdentityMessage) parseEncodedMessage(encoded);
        assertEquals(message, parsed);
    }

    @Test
    public void testParseAuthRMessage() throws ProtocolException, UnsupportedLengthException, OtrCryptoException, ValidationException {
        // Our client profile
        final EdDSAKeyPair ourLongTermKeyPair = EdDSAKeyPair.generate(RANDOM);
        final Point ourForgingKey = EdDSAKeyPair.generate(RANDOM).getPublicKey();
        final DSAKeyPair ourDSAKeyPair = DSAKeyPair.generateDSAKeyPair(RANDOM);
        final Point ourFirstECDHPublicKey = ECDHKeyPair.generate(RANDOM).publicKey();
        final BigInteger ourFirstDHPublicKey = DHKeyPair.generate(RANDOM).publicKey();
        final ClientProfile ourProfile = new ClientProfile(HIGHEST_TAG, ourLongTermKeyPair.getPublicKey(),
                ourForgingKey, singletonList(Version.FOUR), ourDSAKeyPair.getPublic());
        final ClientProfilePayload ourProfilePayload = signClientProfile(ourProfile, Long.MAX_VALUE / 1000,
                ourDSAKeyPair, ourLongTermKeyPair);
        final Point ourX = ECDHKeyPair.generate(RANDOM).publicKey();
        final BigInteger ourA = DHKeyPair.generate(RANDOM).publicKey();
        // Their client profile
        final EdDSAKeyPair theirLongTermKeyPair = EdDSAKeyPair.generate(RANDOM);
        final Point theirFirstECDHPublicKey = ECDHKeyPair.generate(RANDOM).publicKey();
        final BigInteger theirFirstDHPublicKey = DHKeyPair.generate(RANDOM).publicKey();
        final DSAKeyPair theirDSAKeyPair = DSAKeyPair.generateDSAKeyPair(RANDOM);
        final Point theirForgingKey = EdDSAKeyPair.generate(RANDOM).getPublicKey();
        final ClientProfile theirProfile = new ClientProfile(SMALLEST_TAG, theirLongTermKeyPair.getPublicKey(),
                theirForgingKey, singletonList(Version.FOUR), theirDSAKeyPair.getPublic());
        final ClientProfilePayload theirProfilePayload = signClientProfile(theirProfile, Long.MAX_VALUE / 1000,
                theirDSAKeyPair, theirLongTermKeyPair);
        final Point theirY = ECDHKeyPair.generate(RANDOM).publicKey();
        final BigInteger theirB = DHKeyPair.generate(RANDOM).publicKey();
        // The ring signature
        final byte[] phi = MysteriousT4.generatePhi(AUTH_I_PHI, SMALLEST_TAG, HIGHEST_TAG,
                ourFirstECDHPublicKey, ourFirstDHPublicKey, theirFirstECDHPublicKey, theirFirstDHPublicKey,
                "alice@network", "bob@network");
        final byte[] m = MysteriousT4.encode(MysteriousT4.Purpose.AUTH_I, ourProfilePayload, theirProfilePayload, ourX,
                theirY, ourA, theirB, phi);
        final OtrCryptoEngine4.Sigma sigma = ringSign(RANDOM, theirLongTermKeyPair, theirLongTermKeyPair.getPublicKey(),
                ourForgingKey, ourX, m);
        // Prepare Auth-R message and test parsing result.
        final AuthRMessage message = new AuthRMessage(SMALLEST_TAG, HIGHEST_TAG, ourProfilePayload, ourX, ourA, sigma,
                ourFirstECDHPublicKey, ourFirstDHPublicKey);
        final String content = writeMessage(message);
        final EncodedMessage encoded = (EncodedMessage) MessageProcessor.parseMessage(content);
        final AuthRMessage parsed = (AuthRMessage) parseEncodedMessage(encoded);
        assertEquals(message, parsed);
    }

    @Test
    public void testParseAuthIMessage() throws ProtocolException, UnsupportedLengthException, OtrCryptoException, ValidationException {
        // Our client profile
        final EdDSAKeyPair ourLongTermKeyPair = EdDSAKeyPair.generate(RANDOM);
        final Point ourForgingKey = EdDSAKeyPair.generate(RANDOM).getPublicKey();
        final DSAKeyPair ourDSAKeyPair = DSAKeyPair.generateDSAKeyPair(RANDOM);
        final Point ourFirstECDHPublicKey = ECDHKeyPair.generate(RANDOM).publicKey();
        final BigInteger ourFirstDHPublicKey = DHKeyPair.generate(RANDOM).publicKey();
        final ClientProfile ourProfile = new ClientProfile(HIGHEST_TAG, ourLongTermKeyPair.getPublicKey(),
                ourForgingKey, singletonList(Version.FOUR), ourDSAKeyPair.getPublic());
        final ClientProfilePayload ourProfilePayload = signClientProfile(ourProfile, Long.MAX_VALUE / 1000,
                ourDSAKeyPair, ourLongTermKeyPair);
        final Point ourX = ECDHKeyPair.generate(RANDOM).publicKey();
        final BigInteger ourA = DHKeyPair.generate(RANDOM).publicKey();
        // Their client profile
        final EdDSAKeyPair theirLongTermKeyPair = EdDSAKeyPair.generate(RANDOM);
        final Point theirFirstECDHPublicKey = ECDHKeyPair.generate(RANDOM).publicKey();
        final BigInteger theirFirstDHPublicKey = DHKeyPair.generate(RANDOM).publicKey();
        final DSAKeyPair theirDSAKeyPair = DSAKeyPair.generateDSAKeyPair(RANDOM);
        final Point theirForgingKey = EdDSAKeyPair.generate(RANDOM).getPublicKey();
        final ClientProfile theirProfile = new ClientProfile(SMALLEST_TAG, theirLongTermKeyPair.getPublicKey(),
                theirForgingKey, singletonList(Version.FOUR), theirDSAKeyPair.getPublic());
        final ClientProfilePayload theirProfilePayload = signClientProfile(theirProfile, Long.MAX_VALUE / 1000,
                theirDSAKeyPair, theirLongTermKeyPair);
        final Point theirY = ECDHKeyPair.generate(RANDOM).publicKey();
        final BigInteger theirB = DHKeyPair.generate(RANDOM).publicKey();
        // The Auth-I message
        final byte[] phi = MysteriousT4.generatePhi(AUTH_I_PHI, SMALLEST_TAG, HIGHEST_TAG,
                ourFirstECDHPublicKey, ourFirstDHPublicKey, theirFirstECDHPublicKey, theirFirstDHPublicKey,
                "alice@network", "bob@network");
        final byte[] m = MysteriousT4.encode(MysteriousT4.Purpose.AUTH_I, ourProfilePayload, theirProfilePayload, ourX,
                theirY, ourA, theirB, phi);
        final OtrCryptoEngine4.Sigma sigma = ringSign(RANDOM, theirLongTermKeyPair, theirLongTermKeyPair.getPublicKey(),
                ourForgingKey, ourX, m);
        final AuthIMessage message = new AuthIMessage(SMALLEST_TAG, HIGHEST_TAG, sigma);
        final String content = writeMessage(message);
        final EncodedMessage encoded = (EncodedMessage) MessageProcessor.parseMessage(content);
        final AuthIMessage parsed = (AuthIMessage) parseEncodedMessage(encoded);
        assertEquals(message, parsed);
    }
}
