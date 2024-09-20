/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.io;

import com.google.errorprone.annotations.CheckReturnValue;
import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.api.Version;

import javax.annotation.Nonnull;
import java.io.StringWriter;
import java.net.ProtocolException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static java.util.Collections.sort;
import static net.java.otr4j.io.Fragment.parseFragment;

/**
 * Message processor.
 * <p>
 * The processor for the general OTR message structure. The parser processes the text representation of an OTR message
 * and returns a message instance. The writer processes object representations to generate text representations.
 */
public final class MessageProcessor {

    private static final Logger LOGGER = Logger.getLogger(MessageProcessor.class.getName());

    private static final String HEAD = "?OTR";
    private static final char HEAD_ENCODED = ':';
    private static final char HEAD_FRAGMENTED_V2 = ',';
    private static final char HEAD_FRAGMENTED_V3 = '|';
    private static final char HEAD_QUERY_Q = '?';
    private static final char HEAD_QUERY_V = 'v';
    private static final char TAIL_FRAGMENTED = ',';
    private static final String ERROR_PREFIX = " Error:";

    /**
     * Index of numbers such that we can easily translate from number character
     * to integer value. We use this index as we can use this also as an index
     * of valid number characters. This avoids having to do code-table-dependent
     * checks such as c &gt;= '0' and c &lt;= '9'.
     */
    private static final String NUMBERINDEX = "0123456789";

    /**
     * PATTERN_WHITESPACE recognizes OTR v1, v2, v3 and v4 whitespace tags. We will continue to recognize OTR v1
     * whitespace tag for compatibility purposes and to avoid bad interpretation.
     * <p>
     * Group 1: OTRv1 whitespace tag. (OTRv1 tag, if present, must always be first for legacy reasons.)
     * Group 2: OTRv2/OTRv3/OTRv4 (0 or more) whitespace tags.
     */
    @SuppressWarnings("RegExpRepeatedSpace")
    private static final Pattern PATTERN_WHITESPACE = Pattern
            .compile(" \\t  \\t\\t\\t\\t \\t \\t \\t  ( \\t \\t  \\t )?((?:  \\t\\t  \\t |  \\t\\t  \\t\\t|  \\t\\t \\t  )*)");

    private static final Pattern PATTERN_ERROR_FORMAT = Pattern.compile("(:?ERROR_\\d+):\\s(.*)");

    private MessageProcessor() {
        // No need to instantiate.
    }

    /**
     * parseOTREncoded parses an OTR-encoded message.
     *
     * @param encoded the encoded message content (including expected OTR prefix and suffix).
     * @return Returns an Encoded Message instance.
     * @throws ProtocolException In case of violations of OTR encoding.
     */
    @Nonnull
    public static EncodedMessage parseOTREncoded(final String encoded) throws ProtocolException {
        if (!otrEncoded(encoded)) {
            throw new ProtocolException("OTR-encoded messages does not have expected prefix and/or suffix.");
        }
        final OtrInputStream input = new OtrInputStream(Base64.getDecoder().decode(encoded.substring(5, encoded.length() - 1)));
        final Version protocolVersion = Version.match(input.readShort());
        if (protocolVersion == null || !Version.SUPPORTED.contains(protocolVersion)) {
            throw new ProtocolException("Unsupported protocol version " + protocolVersion);
        }
        final byte messageType = input.readByte();
        final InstanceTag senderInstanceTag;
        final InstanceTag receiverInstanceTag;
        if (protocolVersion == Version.THREE || protocolVersion == Version.FOUR) {
            senderInstanceTag = input.readInstanceTag();
            receiverInstanceTag = input.readInstanceTag();
        } else {
            senderInstanceTag = InstanceTag.ZERO_TAG;
            receiverInstanceTag = InstanceTag.ZERO_TAG;
        }
        return new EncodedMessage(protocolVersion, messageType, senderInstanceTag, receiverInstanceTag, input);
    }

    /**
     * Parse provided text in order to extract the Message instance that is represented.
     *
     * @param text the content represented as plain text
     * @return Returns the message instance of the message that the text represented.
     * @throws ProtocolException          In case of protocol violations.
     */
    // TODO consider reducing complexity.
    @SuppressWarnings({"PMD.CognitiveComplexity"})
    @Nonnull
    public static Message parseMessage(final String text) throws ProtocolException {

        if (otrError(text)) {
            // Error tag found.
            final String message = text.substring(HEAD.length() + ERROR_PREFIX.length()).trim();
            final Matcher result = PATTERN_ERROR_FORMAT.matcher(message);
            if (result.matches()) {
                return new ErrorMessage(result.group(1), result.group(2));
            }
            return new ErrorMessage("", message);
        }

        final int idxHead = text.indexOf(HEAD);
        if (idxHead >= 0 && text.length() - idxHead > HEAD.length()) {
            // Message contains the string "?OTR". Check to see if it is a query message or a data message.
            final char contentType = text.charAt(idxHead + HEAD.length());
            if (contentType == HEAD_QUERY_V || contentType == HEAD_QUERY_Q) {
                final int idxHeaderBody = idxHead + HEAD.length() + 1;
                final String content = text.substring(idxHeaderBody);
                // Query tag found.
                if (contentType == HEAD_QUERY_Q && (content.isEmpty() || content.charAt(0) != 'v')) {
                    // OTR v1 ONLY query tags will be caught in this else clause and is unsupported.
                    return new QueryMessage(Collections.emptySet());
                }
                final String versionString;
                if (contentType == HEAD_QUERY_Q && content.charAt(0) == 'v' && content.indexOf('?') > -1) {
                    // OTR v1 + ... query tag format. However, we do not actively support OTRv1 anymore. Therefore the
                    // logic only supports skipping over the OTRv1 tags in order to reach OTR v2 and v3 version tags.
                    versionString = content.substring(1, content.indexOf('?'));
                } else if (contentType == HEAD_QUERY_V && content.indexOf('?') > -1) {
                    // OTR v2+ query tag format.
                    versionString = content.substring(0, content.indexOf('?'));
                } else {
                    // Illegal OTR query string. Return as plaintext message instead and do not do further processing.
                    return new PlainTextMessage(Collections.emptySet(), content);
                }
                final Set<Version> versions = parseVersionString(versionString);
                return new QueryMessage(versions);
            } else if (otrFragmented(text)) {
                return parseFragment(text);
            } else if (otrEncoded(text)) {
                return parseOTREncoded(text);
            }
        }

        // Try to detect whitespace tag.
        final Matcher matcher = PATTERN_WHITESPACE.matcher(text);
        final EnumSet<Version> versions = EnumSet.noneOf(Version.class);
        if (matcher.find()) {
            // Ignore group 1 (OTRv1 tag) as version 1 is not supported anymore.
            String tags = matcher.group(2);
            while (!tags.isEmpty() && tags.length() % 8 == 0) {
                if (tags.startsWith("  \t\t  \t ")) {
                    versions.add(Version.TWO);
                } else if (tags.startsWith("  \t\t  \t\t")) {
                    versions.add(Version.THREE);
                } else if (tags.startsWith("  \t\t \t  ")) {
                    versions.add(Version.FOUR);
                } else {
                    LOGGER.info("Skipping unrecognized whitespace version tag: " + tags.substring(0, 8));
                }
                tags = tags.substring(8);
            }
        }

        final String cleanText = matcher.replaceAll("");
        return new PlainTextMessage(versions, cleanText);
    }

    /**
     * Serialize a Message into a string-representation.
     *
     * @param m the message
     * @return Returns the string-representation of the provided message.
     */
    @Nonnull
    public static String writeMessage(final Message m) {
        final StringWriter writer = new StringWriter();
        if (m instanceof ErrorMessage) {
            writer.write(HEAD);
            writer.write(ERROR_PREFIX);
            final ErrorMessage errorMessage = (ErrorMessage) m;
            if (!errorMessage.identifier.isEmpty()) {
                writer.write(' ');
                writer.write(errorMessage.identifier);
                writer.write(": ");
            }
            writer.write(errorMessage.error);
        } else if (m instanceof PlainTextMessage) {
            final PlainTextMessage plaintxt = (PlainTextMessage) m;
            writer.write(plaintxt.getCleanText());
            writer.write(generateWhitespaceTag(plaintxt.getVersions()));
        } else if (m instanceof QueryMessage) {
            final QueryMessage query = (QueryMessage) m;
            if (query.getVersions().size() == 1 && query.getVersions().contains(Version.ONE)) {
                throw new UnsupportedOperationException("OTR v1 is no longer supported. Support in the library has been removed, so the query message should not contain a version 1 entry.");
            }
            final ArrayList<Version> versions = new ArrayList<>(query.getVersions());
            sort(versions);
            writer.write(generateQueryTag(versions));
        } else if (m instanceof OtrEncodable) {
            writer.write(HEAD);
            writer.write(HEAD_ENCODED);
            writer.write(Base64.getEncoder().encodeToString(new OtrOutputStream().write((OtrEncodable) m).toByteArray()));
            writer.write(".");
        } else {
            throw new UnsupportedOperationException("Unsupported message type encountered: " + m.getClass().getName());
        }
        return writer.toString();
    }

    @Nonnull
    private static String generateWhitespaceTag(final Iterable<Version> versions) {
        final StringBuilder builder = new StringBuilder(40);
        for (final Version version : versions) {
            if (version == Version.TWO) {
                builder.append("  \t\t  \t ");
            }
            if (version == Version.THREE) {
                builder.append("  \t\t  \t\t");
            }
            if (version == Version.FOUR) {
                builder.append("  \t\t \t  ");
            }
        }
        return builder.length() == 0 ? "" : " \t  \t\t\t\t \t \t \t  " + builder;
    }

    @Nonnull
    private static String generateQueryTag(final Iterable<Version> versions) {
        final ArrayList<Integer> values = new ArrayList<>();
        for (final Version v : versions) {
            values.add(v.value);
        }
        final String versionsString = encodeVersionString(values);
        return versionsString.length() == 0 ? "" : HEAD + HEAD_QUERY_V + versionsString + HEAD_QUERY_Q;
    }

    /**
     * Encode an iterable containing integer version values into a ASCII-based string representation of the version numbers.
     *
     * @param versions The container containing the versions.
     * @return Returns ASCII string representation.
     */
    @Nonnull
    public static String encodeVersionString(final Iterable<Integer> versions) {
        final StringBuilder versionsString = new StringBuilder();
        for (final int version : versions) {
            if (version == 0) {
                throw new IllegalArgumentException("Illegal version");
            }
            versionsString.append(version);
        }
        return versionsString.toString();
    }

    /**
     * Parse a string containing ASCII-encoded digits (plaintext version numbers) into a set containing integer version numbers.
     *
     * @param versionString The string representation of a sequence of numbers.
     * @return Returns set containing version ints.
     */
    @Nonnull
    public static Set<Version> parseVersionString(final String versionString) {
        final EnumSet<Version> versions = EnumSet.noneOf(Version.class);
        for (int i = 0; i < versionString.length(); i++) {
            final int idx = NUMBERINDEX.indexOf(versionString.charAt(i));
            if (idx == 0) {
                continue;
            }
            final Version v = Version.match(idx);
            if (v == null) {
                continue;
            }
            versions.add(v);
        }
        return versions;
    }

    /**
     * Check whether the provided content is OTR encoded.
     *
     * @param content the content to investigate
     * @return Returns true if content is OTR encoded, or false otherwise.
     */
    @CheckReturnValue
    public static boolean otrEncoded(final String content) {
        return content.startsWith(HEAD + HEAD_ENCODED) && content.endsWith(".");
    }

    /**
     * Check whether the provided content is OTR-fragment encoded.
     *
     * @param content the content to investigate
     * @return Returns true if content is OTR fragment, or false otherwise.
     */
    @CheckReturnValue
    public static boolean otrFragmented(final String content) {
        return (content.startsWith(HEAD + HEAD_FRAGMENTED_V2) || content.startsWith(HEAD + HEAD_FRAGMENTED_V3))
            && content.endsWith(String.valueOf(TAIL_FRAGMENTED));
    }

    /**
     * Check if the message satisfies the requirements for an OTR Error message.
     *
     * @param content the message
     * @return Returns true iff correctly formatted.
     */
    @CheckReturnValue
    public static boolean otrError(final String content) {
        return content.startsWith(HEAD + ERROR_PREFIX);
    }
}
