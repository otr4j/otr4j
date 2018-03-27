package net.java.otr4j.io.messages;

import net.java.otr4j.api.Session;
import net.java.otr4j.crypto.OtrCryptoEngine;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.io.OtrInputStream;
import net.java.otr4j.io.OtrOutputStream;
import org.junit.Test;

import javax.crypto.interfaces.DHPublicKey;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.ProtocolException;
import java.security.KeyPair;
import java.security.SecureRandom;

import static java.util.Arrays.copyOf;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

// TODO Need to add tests for parsing various type of encoded messages.
public class EncodedMessageParserTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    @Test
    public void testInstanceAvailable() {
        assertNotNull(EncodedMessageParser.instance());
    }

    @Test(expected = NullPointerException.class)
    public void testParsingNullInputStream() throws IOException, OtrCryptoException {
        EncodedMessageParser.instance().read(null);
    }

    @Test(expected = ProtocolException.class)
    public void testParsingEmptyInputStream() throws IOException, OtrCryptoException {
        EncodedMessageParser.instance().read(new OtrInputStream(new ByteArrayInputStream(new byte[0])));
    }

    @Test(expected = ProtocolException.class)
    public void testParsingIncompleteInputStream() throws IOException, OtrCryptoException {
        EncodedMessageParser.instance().read(new OtrInputStream(new ByteArrayInputStream(new byte[] { 0x00, 0x03 })));
    }

    @Test
    public void testConstructAndParseDHKeyMessage() throws IOException, OtrCryptoException {
        final KeyPair keypair = OtrCryptoEngine.generateDHKeyPair(RANDOM);
        // Prepare output message to parse.
        final DHKeyMessage m = new DHKeyMessage(Session.OTRv.THREE, (DHPublicKey) keypair.getPublic(), 12345, 9876543);
        final ByteArrayOutputStream output = new ByteArrayOutputStream();
        final OtrOutputStream otrOutput = new OtrOutputStream(output);
        m.write(otrOutput);
        // Parse produced message bytes.
        final ByteArrayInputStream input = new ByteArrayInputStream(output.toByteArray());
        final OtrInputStream otrInput = new OtrInputStream(input);
        final AbstractEncodedMessage parsedM = EncodedMessageParser.instance().read(otrInput);
        assertEquals(m, parsedM);
    }

    @Test
    public void testConstructAndParsePartialDHKeyMessage() throws IOException {
        final KeyPair keypair = OtrCryptoEngine.generateDHKeyPair(RANDOM);
        // Prepare output message to parse.
        final DHKeyMessage m = new DHKeyMessage(Session.OTRv.THREE, (DHPublicKey) keypair.getPublic(), 12345, 9876543);
        final ByteArrayOutputStream output = new ByteArrayOutputStream();
        final OtrOutputStream otrOutput = new OtrOutputStream(output);
        m.write(otrOutput);
        final byte[] message = output.toByteArray();
        final EncodedMessageParser parser = EncodedMessageParser.instance();
        for (int i = 0; i < message.length; i++) {
            final byte[] partial = copyOf(message, i);
            try (final OtrInputStream partialStream = new OtrInputStream(new ByteArrayInputStream(partial))) {
                parser.read(partialStream);
                fail("Expected exception due to parsing an incomplete message.");
            } catch (final ProtocolException | OtrCryptoException expected) {
                // Expected behavior for partial messages being parsed.
            }
        }
    }
}