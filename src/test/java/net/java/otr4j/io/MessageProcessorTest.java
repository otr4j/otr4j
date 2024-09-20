/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.io;

import net.java.otr4j.api.Version;
import org.junit.Test;

import java.net.ProtocolException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashSet;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Arrays.copyOfRange;
import static java.util.Collections.emptySet;
import static java.util.Objects.requireNonNull;
import static net.java.otr4j.io.MessageProcessor.encodeVersionString;
import static net.java.otr4j.io.MessageProcessor.parseMessage;
import static net.java.otr4j.io.MessageProcessor.parseVersionString;
import static net.java.otr4j.io.MessageProcessor.writeMessage;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

@SuppressWarnings("ConstantConditions")
public final class MessageProcessorTest {

    @Test
    public void testNoFailureOnPlainMessage() throws ProtocolException {
        final Message msg = parseMessage("Hello world");
        assertTrue(msg instanceof PlainTextMessage);
        final PlainTextMessage plainMsg = (PlainTextMessage) msg;
        assertTrue(plainMsg.getVersions().isEmpty());
        assertEquals("Hello world", plainMsg.getCleanText());
    }

    @Test
    public void testCorrectIdentificationOfWhitespaceTagV1() throws ProtocolException {
        PlainTextMessage msg = (PlainTextMessage) parseMessage(" \t  \t\t\t\t \t \t \t   \t \t  \t ");
        assertTrue(msg.getVersions().isEmpty());
        assertEquals("", msg.getCleanText());
    }

    @Test
    public void testCorrectIdentificationOfWhitespaceTagV2() throws ProtocolException {
        PlainTextMessage msg = (PlainTextMessage) parseMessage(" \t  \t\t\t\t \t \t \t    \t\t  \t ");
        assertEquals(1, msg.getVersions().size());
        assertTrue(msg.getVersions().contains(Version.TWO));
        assertEquals("", msg.getCleanText());
    }

    @Test
    public void testCorrectIdentificationOfWhitespaceTagV3() throws ProtocolException {
        PlainTextMessage msg = (PlainTextMessage) parseMessage(" \t  \t\t\t\t \t \t \t    \t\t  \t\t");
        assertEquals(1, msg.getVersions().size());
        assertTrue(msg.getVersions().contains(Version.THREE));
        assertEquals("", msg.getCleanText());
    }

    @Test
    public void testCorrectIdentificationOfWhitespaceTagV4() throws ProtocolException {
        PlainTextMessage msg = (PlainTextMessage) parseMessage(" \t  \t\t\t\t \t \t \t    \t\t \t  ");
        assertEquals(1, msg.getVersions().size());
        assertTrue(msg.getVersions().contains(Version.FOUR));
        assertEquals("", msg.getCleanText());
    }

    @Test
    public void testCorrectIdentificationOfWhitespaceTagV2V3V4() throws ProtocolException {
        PlainTextMessage msg = (PlainTextMessage) parseMessage(" \t  \t\t\t\t \t \t \t    \t\t  \t   \t\t  \t\t  \t\t \t  ");
        assertEquals(3, msg.getVersions().size());
        assertTrue(msg.getVersions().contains(Version.TWO));
        assertTrue(msg.getVersions().contains(Version.THREE));
        assertTrue(msg.getVersions().contains(Version.FOUR));
        assertEquals("", msg.getCleanText());
    }

    @Test
    public void testCorrectIdentificationOfWhitespaceTagV2AndV3() throws ProtocolException {
        PlainTextMessage msg = (PlainTextMessage) parseMessage(" \t  \t\t\t\t \t \t \t    \t\t  \t   \t\t  \t\t");
        assertEquals(2, msg.getVersions().size());
        assertTrue(msg.getVersions().contains(Version.TWO));
        assertTrue(msg.getVersions().contains(Version.THREE));
        assertEquals("", msg.getCleanText());
    }

    @Test
    public void testCorrectIdentificationOfWhitespaceTagV1V2V4() throws ProtocolException {
        PlainTextMessage msg = (PlainTextMessage) parseMessage(" \t  \t\t\t\t \t \t \t   \t \t  \t   \t\t  \t   \t\t \t  ");
        assertEquals(2, msg.getVersions().size());
        assertTrue(msg.getVersions().contains(Version.TWO));
        assertTrue(msg.getVersions().contains(Version.FOUR));
        assertEquals("", msg.getCleanText());
    }

    @Test
    public void testCorrectIdentificationOfWhitespaceTagV1AndV2() throws ProtocolException {
        PlainTextMessage msg = (PlainTextMessage) parseMessage(" \t  \t\t\t\t \t \t \t   \t \t  \t   \t\t  \t ");
        assertEquals(1, msg.getVersions().size());
        assertTrue(msg.getVersions().contains(Version.TWO));
        assertEquals("", msg.getCleanText());
    }

    @Test
    public void testCorrectIdentificationOfWhitespaceTagV1V3V4() throws ProtocolException {
        PlainTextMessage msg = (PlainTextMessage) parseMessage(" \t  \t\t\t\t \t \t \t   \t \t  \t   \t\t  \t\t  \t\t \t  ");
        assertEquals(2, msg.getVersions().size());
        assertTrue(msg.getVersions().contains(Version.THREE));
        assertTrue(msg.getVersions().contains(Version.FOUR));
        assertEquals("", msg.getCleanText());
    }

    @Test
    public void testCorrectIdentificationOfWhitespaceTagV1AndV3() throws ProtocolException {
        PlainTextMessage msg = (PlainTextMessage) parseMessage(" \t  \t\t\t\t \t \t \t   \t \t  \t   \t\t  \t\t");
        assertEquals(1, msg.getVersions().size());
        assertTrue(msg.getVersions().contains(Version.THREE));
        assertEquals("", msg.getCleanText());
    }

    @Test
    public void testCorrectIdentificationOfWhitespaceTagV1V2V3V4() throws ProtocolException {
        PlainTextMessage msg = (PlainTextMessage) parseMessage(" \t  \t\t\t\t \t \t \t   \t \t  \t   \t\t  \t   \t\t  \t\t  \t\t \t  ");
        assertEquals(3, msg.getVersions().size());
        assertTrue(msg.getVersions().contains(Version.TWO));
        assertTrue(msg.getVersions().contains(Version.THREE));
        assertTrue(msg.getVersions().contains(Version.FOUR));
        assertEquals("", msg.getCleanText());
    }

    @Test
    public void testCorrectIdentificationOfWhitespaceTagV1V4V3V2() throws ProtocolException {
        PlainTextMessage msg = (PlainTextMessage) parseMessage(" \t  \t\t\t\t \t \t \t   \t \t  \t   \t\t \t    \t\t  \t\t  \t\t  \t ");
        assertEquals(3, msg.getVersions().size());
        assertTrue(msg.getVersions().contains(Version.TWO));
        assertTrue(msg.getVersions().contains(Version.THREE));
        assertTrue(msg.getVersions().contains(Version.FOUR));
        assertEquals("", msg.getCleanText());
    }

    @Test
    public void testCorrectWhitespaceErasure() throws ProtocolException {
        PlainTextMessage msg = (PlainTextMessage) parseMessage("Hello \t  \t\t\t\t \t \t \t   \t \t  \t   \t\t  \t\t world!");
        assertEquals(1, msg.getVersions().size());
        assertTrue(msg.getVersions().contains(Version.THREE));
        assertEquals("Hello world!", msg.getCleanText());
    }

    @Test
    public void testCorrectDeduplicationOfVersionsWhileParsingQueryMessage() throws ProtocolException {
        final QueryMessage msg = (QueryMessage) parseMessage("?OTRv2222222?");
        assertEquals(1, msg.getVersions().size());
        assertTrue(msg.getVersions().contains(Version.TWO));
    }

    @Test
    public void testEnsureEmptyVersionStringIsCorrectlyParsed() throws ProtocolException {
        final QueryMessage msg = (QueryMessage) parseMessage("?OTRv?");
        assertTrue(msg.getVersions().isEmpty());
    }

    @Test
    public void testEnsureIllegalVersionStringIsCorrectlyParsed() throws ProtocolException {
        final QueryMessage msg = (QueryMessage) parseMessage("?OTRv?4?");
        assertTrue(msg.getVersions().isEmpty());
    }

    @Test
    public void testParseOTRError() throws ProtocolException {
        final ErrorMessage msg = (ErrorMessage) parseMessage("?OTR Error:Hello world of errors!");
        assertEquals("", msg.identifier);
        assertEquals("Hello world of errors!", msg.error);
    }

    @Test
    public void testParseOTRFakeError() throws ProtocolException {
        final PlainTextMessage msg = (PlainTextMessage) parseMessage("My message with injected ?OTR Error: Hello world of errors!");
        assertEquals("My message with injected ?OTR Error: Hello world of errors!", msg.getCleanText());
    }

    @Test
    public void testParseOTR4Error() throws ProtocolException {
        final ErrorMessage msg = (ErrorMessage) parseMessage("?OTR Error: ERROR_1: Hello world of errors!");
        assertEquals("ERROR_1", msg.identifier);
        assertEquals("Hello world of errors!", msg.error);
    }

    @Test
    public void testParseOTR4FakeError() throws ProtocolException {
        final PlainTextMessage msg = (PlainTextMessage) parseMessage("My message with injected ?OTR Error: ERROR_1: Hello world of errors!");
        assertEquals("My message with injected ?OTR Error: ERROR_1: Hello world of errors!", msg.getCleanText());
    }

    @Test
    public void testEnsureOTRv1VersionStringIncomplete() throws ProtocolException {
        final PlainTextMessage msg = (PlainTextMessage) parseMessage("?OTR");
        assertEquals("?OTR", msg.getCleanText());
    }

    @Test
    public void testEnsureOTRv1VersionStringIsIgnored() throws ProtocolException {
        final QueryMessage msg = (QueryMessage) parseMessage("?OTR?");
        assertTrue(msg.getVersions().isEmpty());
    }

    @Test
    public void testEnsureFakeOTRHeadersCorrectlyIgnored1() throws ProtocolException {
        final PlainTextMessage msg = (PlainTextMessage) parseMessage("?");
        assertTrue(msg.getVersions().isEmpty());
    }

    @Test
    public void testEnsureFakeOTRHeadersCorrectlyIgnored2() throws ProtocolException {
        final PlainTextMessage msg = (PlainTextMessage) parseMessage("?O");
        assertTrue(msg.getVersions().isEmpty());
    }

    @Test
    public void testEnsureFakeOTRHeadersCorrectlyIgnored3() throws ProtocolException {
        final PlainTextMessage msg = (PlainTextMessage) parseMessage("?OTRa");
        assertTrue(msg.getVersions().isEmpty());
        assertEquals("?OTRa", msg.getCleanText());
    }

    @Test
    public void testEnsureFakeOTRHeadersCorrectlyIgnored4() throws ProtocolException {
        final PlainTextMessage msg = (PlainTextMessage) parseMessage("?OTR ");
        assertTrue(msg.getVersions().isEmpty());
        assertEquals("?OTR ", msg.getCleanText());
    }

    @Test
    public void testIncompleteOTRv1Header() throws ProtocolException {
        final QueryMessage msg = (QueryMessage) parseMessage("?OTR?v34 abcde");
        assertTrue(msg.getVersions().isEmpty());
    }

    @Test
    public void testIncompleteOTRv3Header() throws ProtocolException {
        final QueryMessage msg = (QueryMessage) parseMessage("?OTRv34 abcde");
        assertTrue(msg.getVersions().isEmpty());
    }

    @Test
    public void testIncompleteMessageMissingEnding() throws ProtocolException {
        final String message = "?OTR:BADBASE64CODEMISSINGDOT";
        final PlainTextMessage msg = (PlainTextMessage) parseMessage(message);
        assertTrue(msg.getVersions().isEmpty());
        assertEquals(message, msg.getCleanText());
    }

    @Test
    public void testOTRQueryMessageV1NotOTREncoded() throws ProtocolException {
        assertTrue(parseMessage("?OTR? some other content ...") instanceof QueryMessage);
    }

    @Test
    public void testCorrectOTREncodingDetection() throws ProtocolException {
        assertTrue(parseMessage("?OTR:AAMDJ+MVmSfjFZcAAAAAAQAAAAIAAADA1g5IjD1ZGLDVQEyCgCyn9hbrL3KAbGDdzE2ZkMyTKl7XfkSxh8YJnudstiB74i4BzT0W2haClg6dMary/jo9sMudwmUdlnKpIGEKXWdvJKT+hQ26h9nzMgEditLB8vjPEWAJ6gBXvZrY6ZQrx3gb4v0UaSMOMiR5sB7Eaulb2Yc6RmRnnlxgUUC2alosg4WIeFN951PLjScajVba6dqlDi+q1H5tPvI5SWMN7PCBWIJ41+WvF+5IAZzQZYgNaVLbAAAAAAAAAAEAAAAHwNiIi5Ms+4PsY/L2ipkTtquknfx6HodLvk3RAAAAAA==.") instanceof EncodedMessage);
    }

    @Test
    public void testOTRv2FragmentNotOTREncoded() throws ProtocolException {
        assertTrue(parseMessage("?OTR,1,3,?OTR:AAMDJ+MVmSfjFZcAAAAAAQAAAAIAAADA1g5IjD1ZGLDVQEyCgCyn9hbrL3KAbGDdzE2ZkMyTKl7XfkSxh8YJnudstiB74i4BzT0W2haClg6dMary/jo9sMudwmUdlnKpIGEKXWdvJKT+hQ26h9nzMgEditLB8v,") instanceof Fragment);
    }

    @Test
    public void testOTRv3FragmentNotOTREncoded() throws ProtocolException {
        assertTrue(parseMessage("?OTR|5a73a599|27e31597,00001,00003,?OTR:AAMDJ+MVmSfjFZcAAAAAAQAAAAIAAADA1g5IjD1ZGLDVQEyCgCyn9hbrL3KAbGDdzE2ZkMyTKl7XfkSxh8YJnudstiB74i4BzT0W2haClg6dMary/jo9sMudwmUdlnKpIGEKXWdvJKT+hQ26h9nzMgEditLB8v,") instanceof Fragment);
    }

    @Test(expected = ProtocolException.class)
    public void testToMessageWrongProtocolVersion() throws Exception {
        parseMessage("?OTR:AAUDdAYBciqzcLcAAAAAAQAAAAIAAADAh7NAcXJNpXa8qw89tvx4eoxhR3iaTx4omdj34HRpgMXDGIR7Kp4trQ+L5k8INcse58RJWHQPYW+dgKMkwrpCNJIgaqjzaiJC5+QPylSchrAB78MNZiCLXW7YU3dSic1Pm0dpa57wwiFp7sfSm00GEcE7M1bRe7Pr1zgb8KP/5PJUeI7IVmYTDj5ONWUsyoocD40RQ+Bu+I7GLgb7WICGZ6mpof3UGEFFmJLB5lDfunhCqb0d3MRP0G6k/8YJzjIlAAAAAAAAAAEAAAAF8VtymMJceqLiPIYPjRTLmlr5gQPirDY87QAAAAA=.");
    }

    @Test(expected = NullPointerException.class)
    public void testEncodeVersionsStringNull() {
        encodeVersionString(null);
    }

    @Test
    public void testEncodeVersionsStringEmptyVersionsSet() {
        assertEquals("", encodeVersionString(Collections.emptySet()));
    }

    @Test
    public void testEncodeVersionsStringSingletonSet() {
        assertEquals("4", encodeVersionString(Collections.singleton(Version.FOUR.value)));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testEncodeVersionsStringDoubleDigitVersion() {
        encodeVersionString(Collections.singleton(Version.NONE.value));
    }

    @Test
    public void testEncodeVersionsStringMultipleVersions() {
        assertEquals("342", encodeVersionString(Arrays.asList(Version.THREE.value, Version.FOUR.value,
                Version.TWO.value)));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testEncodeVersionsStringMultipleVersionsSomeIllegal() {
        encodeVersionString(Arrays.asList(Version.THREE.value, Version.FOUR.value, Version.NONE.value,
                Version.TWO.value));
    }

    @Test(expected = NullPointerException.class)
    public void testParseVersionsStringNull() {
        parseVersionString(null);
    }

    @Test
    public void testParseVersionsStringZero() {
        assertEquals(emptySet(), parseVersionString("0"));
    }

    @Test
    public void testParseVersionsStringSingleton() {
        assertEquals(Collections.singleton(Version.ONE), parseVersionString("1"));
    }

    @Test
    public void testParseVersionsStringMultiple() {
        final EnumSet<Version> expected = EnumSet.of(Version.ONE, Version.THREE, Version.FOUR);
        assertEquals(expected, parseVersionString("134"));
    }

    @Test
    public void testParseVersionsStringDuplicates() {
        final EnumSet<Version> expected = EnumSet.of(Version.THREE, Version.ONE);
        assertEquals(expected, parseVersionString("131113"));
    }

    @Test(expected = ProtocolException.class)
    public void testParseMessageWithUnsupportedVersion() throws ProtocolException {
        parseMessage("?OTR:" + Base64.getEncoder().encodeToString(new byte[]{0x00, 0x01}) + ".");
    }

    @Test(expected = ProtocolException.class)
    public void testParseMessageEmpty() throws ProtocolException {
        parseMessage("?OTR:.");
    }

    @Test
    public void testParsePartialHeaders() throws ProtocolException {
        final byte[] header = new byte[] {0x00, 0x04, (byte) 0xff, 0x1, 0x2, 0x3, 0x4, 0x4, 0x3, 0x2, 0x1};
        for (int i = 0; i < header.length - 1; i++) {
            try {
                parseMessage("?OTR:" + Base64.getEncoder().encodeToString(copyOfRange(header, 0, i)) + ".");
                fail("Expected parsing to fail with ProtocolException but this did not happen.");
            } catch (final ProtocolException expected) {
                // expected failure, no need to respond
            }
        }
        assertNotNull(parseMessage("?OTR:" + Base64.getEncoder().encodeToString(header) + "."));
    }

    @Test
    public void testParseCorrectOTRv4Header() throws ProtocolException {
        final EncodedMessage encoded = (EncodedMessage) parseMessage("?OTR:" + Base64.getEncoder().encodeToString(
                new byte[] {0x00, 0x04, (byte) 0xff, 0x1, 0x2, 0x3, 0x4, 0x4, 0x3, 0x2, 0x1}) + ".");
        assertEquals(Version.FOUR, encoded.version);
        assertEquals((byte) 0xff, encoded.type);
        assertEquals(0x01020304, encoded.senderTag.getValue());
        assertEquals(0x04030201, encoded.receiverTag.getValue());
    }

    @Test
    public void testParseCorrectOTRv3Header() throws ProtocolException {
        final EncodedMessage encoded = (EncodedMessage) parseMessage("?OTR:" + Base64.getEncoder().encodeToString(
                new byte[] {0x00, 0x03, (byte) 0xff, 0x1, 0x2, 0x3, 0x4, 0x4, 0x3, 0x2, 0x1}) + ".");
        assertEquals(Version.THREE, encoded.version);
        assertEquals((byte) 0xff, encoded.type);
        assertEquals(0x01020304, encoded.senderTag.getValue());
        assertEquals(0x04030201, encoded.receiverTag.getValue());
    }

    @Test
    public void testParseCorrectOTRv2Header() throws ProtocolException {
        final EncodedMessage encoded = (EncodedMessage) parseMessage("?OTR:" + Base64.getEncoder().encodeToString(
                new byte[] {0x00, 0x02, (byte) 0xff, 0x1, 0x2, 0x3, 0x4, 0x4, 0x3, 0x2, 0x1}) + ".");
        assertEquals(Version.TWO, encoded.version);
        assertEquals((byte) 0xff, encoded.type);
        assertEquals(0, encoded.senderTag.getValue());
        assertEquals(0, encoded.receiverTag.getValue());
        // Ensure that what would be the instance tags in OTRv3+ are considered part of the content payload in OTRv2.
        assertEquals(0x01020304, encoded.payload.readInt());
        assertEquals(0x04030201, encoded.payload.readInt());
    }

    @Test
    public void testPlaintextMessageNoNullMangling() {
        final String data = "This is a test with \0 null \0 values.";
        final PlainTextMessage m = new PlainTextMessage(new HashSet<>(Arrays.asList(Version.TWO, Version.THREE)), data);
        assertTrue(writeMessage(m).startsWith("This is a test with \0 null \0 values."));
    }

    @Test
    public void testQueryHeaderEmpty() {
        // Verify that we do not send the "bizarre claim" (as documented by otr spec) of willingness to speak otr but we accept not a single version.
        final QueryMessage msg = new QueryMessage(Collections.emptySet());
        assertEquals("", writeMessage(msg));
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testCorrectQueryHeaderV1() {
        final QueryMessage msg = new QueryMessage(Collections.singleton(Version.ONE));
        assertEquals("", writeMessage(msg));
    }

    @Test
    public void testCorrectQueryHeaderV2() {
        final QueryMessage msg = new QueryMessage(Collections.singleton(Version.TWO));
        assertEquals("?OTRv2?", writeMessage(msg));
    }

    @Test
    public void testCorrectQueryHeaderV3() {
        final QueryMessage msg = new QueryMessage(Collections.singleton(Version.THREE));
        assertEquals("?OTRv3?", writeMessage(msg));
    }

    @Test
    public void testCorrectQueryHeaderV2AndV3() {
        final QueryMessage msg = new QueryMessage(new HashSet<>(Arrays.asList(Version.TWO, Version.THREE)));
        assertEquals("?OTRv23?", writeMessage(msg));
    }

    @Test
    public void testWhitespaceTagsNoVersions() {
        final PlainTextMessage m = new PlainTextMessage(Collections.emptySet(), "Hello");
        assertEquals("Hello", writeMessage(m));
    }

    @Test
    public void testWhitespaceTagsAllVersions() {
        final EnumSet<Version> versions = EnumSet.of(Version.TWO, Version.THREE, Version.FOUR);
        final PlainTextMessage m = new PlainTextMessage(versions, "Hello");
        assertEquals("Hello \t  \t\t\t\t \t \t \t    \t\t  \t   \t\t  \t\t  \t\t \t  ", writeMessage(m));
    }

    @Test
    public void testWhitespaceTagsVersion2Only() {
        final PlainTextMessage m = new PlainTextMessage(Collections.singleton(Version.TWO), "Hello");
        assertEquals("Hello \t  \t\t\t\t \t \t \t    \t\t  \t ", writeMessage(m));
    }

    @Test
    public void testWhitespaceTagsVersion3Only() {
        final PlainTextMessage m = new PlainTextMessage(Collections.singleton(Version.THREE), "Hello");
        assertEquals("Hello \t  \t\t\t\t \t \t \t    \t\t  \t\t", writeMessage(m));
    }

    @Test
    public void testWhitespaceTagsVersion4Only() {
        final PlainTextMessage m = new PlainTextMessage(Collections.singleton(Version.FOUR), "Hello");
        assertEquals("Hello \t  \t\t\t\t \t \t \t    \t\t \t  ", writeMessage(m));
    }

    @Test
    public void testMultipleWhitespaceTagsRespectFirstOccurrenceOnly() throws ProtocolException {
        final PlainTextMessage m = (PlainTextMessage) parseMessage("Hello \t  \t\t\t\t \t \t \t    \t\t \t  world \t  \t\t\t\t \t \t \t    \t\t  \t\t!");
        assertEquals(1, m.getVersions().size());
        assertTrue(m.getVersions().contains(Version.FOUR));
    }

    @Test
    public void testWriteErrorMessage() {
        final ErrorMessage errorMessage = new ErrorMessage("", "Hello, you did something wrong, but I'm not gonna tell you what.");
        assertEquals("?OTR Error:Hello, you did something wrong, but I'm not gonna tell you what.",
                writeMessage(errorMessage));
    }

    @Test
    public void testWriteOTRv4ErrorMessage() {
        final ErrorMessage errorMessage = new ErrorMessage("ERROR_2", "Hello, you did something wrong, but I'm not gonna tell you what.");
        assertEquals("?OTR Error: ERROR_2: Hello, you did something wrong, but I'm not gonna tell you what.",
                writeMessage(errorMessage));
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testErrorOnWritingArbitraryMessage() {
        writeMessage(new Message() {
        });
    }

    @Test
    public void testWriteOtrEncodable() {
        final String message = writeMessage(new OtrEncodableTestMessage("Hello world!"));
        assertEquals("?OTR:" + Base64.getEncoder().encodeToString("Hello world!".getBytes(UTF_8)) + ".", message);
    }

    private static final class OtrEncodableTestMessage implements Message, OtrEncodable {

        private final String message;

        private OtrEncodableTestMessage(final String message) {
            this.message = requireNonNull(message);
        }

        @Override
        public void writeTo(final OtrOutputStream out) {
            out.writeMessage(this.message);
        }
    }
}
