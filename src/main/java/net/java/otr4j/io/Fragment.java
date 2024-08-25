/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.io;

import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.api.Version;

import javax.annotation.Nonnull;
import java.net.ProtocolException;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static java.lang.Integer.parseInt;
import static java.util.Objects.requireNonNull;
import static net.java.otr4j.api.InstanceTag.ZERO_VALUE;
import static net.java.otr4j.api.InstanceTag.isValidInstanceTag;
import static net.java.otr4j.util.Integers.parseUnsignedInt;

/**
 * An OTR message that represents a fragment of an OTR-encoded message.
 */
public final class Fragment implements Message {

    private static final Logger LOGGER = Logger.getLogger(Fragment.class.getName());

    /**
     * Maximum supported number of fragments.
     */
    private static final int MAX_FRAGMENTS = 65535;
    
    private static final int MAX_FRAGMENT_SIZE = 250 * 1024;

    private static final int DECIMAL_SYSTEM = 10;
    private static final int HEXADECIMAL_SYSTEM = 16;

    /**
     * OTRv2 fragment pattern.
     * <p>
     * Group 1: current message part index.
     * Group 2: total number of message parts.
     * Group 3: fragment content.
     */
    private static final Pattern PATTERN_V2 = Pattern.compile("^\\?OTR,(\\d{1,5}),(\\d{1,5}),([a-zA-Z0-9+/=?:.]*),$");

    /**
     * OTRv3 fragment pattern.
     * <p>
     * Group 1: sender tag.
     * Group 2: receiver tag.
     * Group 3: current message part index.
     * Group 4: total number of message parts.
     * Group 5: fragment content.
     */
    private static final Pattern PATTERN_V3 = Pattern.compile("^\\?OTR\\|([0-9abcdefABCDEF]{1,8})\\|([0-9abcdefABCDEF]{1,8}),(\\d{1,5}),(\\d{1,5}),([a-zA-Z0-9+/=?:.]*),$");

    /**
     * OTRv4 fragment pattern.
     * <p>
     * Group 1: message identifier.
     * Group 2: sender tag.
     * Group 3: receiver tag.
     * Group 4: current message part index.
     * Group 5: total number of message parts.
     * Group 6: fragment content.
     */
    // TODO consider enforcing 8-byte hex value for the 4-byte identifier of OTRv4 fragments (spec is explicit about there being 4 bytes)
    private static final Pattern PATTERN_V4 = Pattern.compile("^\\?OTR\\|([0-9abcdefABCDEF]{1,8})\\|([0-9abcdefABCDEF]{1,8})\\|([0-9abcdefABCDEF]{1,8}),(\\d{1,5}),(\\d{1,5}),([a-zA-Z0-9+/=?:.]*),$");

    private static final int ZERO_IDENTIFIER = 0;

    @Nonnull
    private final Version version;
    private final int identifier;
    @Nonnull
    private final InstanceTag senderTag;
    @Nonnull
    private final InstanceTag receiverTag;
    private final int index;
    private final int total;
    // FIXME I very strongly suspect that using data-type `String` for fragment content is inefficient. Check whether byte-buffer or something similar is a better option.
    @Nonnull
    private final String content;

    private Fragment(final Version version, final int identifier, final InstanceTag senderTag, final InstanceTag receiverTag,
            final int index, final int total, final String content) {
        this.version = requireNonNull(version);
        this.identifier = identifier;
        this.senderTag = requireNonNull(senderTag);
        this.receiverTag = requireNonNull(receiverTag);
        this.index = index;
        this.total = total;
        this.content = requireNonNull(content);
    }

    /**
     * Parse message that is a fragment and verify its contents.
     *
     * @param message the raw message
     * @return Returns a fragment.
     * @throws ProtocolException In case of invalid fragment format, or in case of bad data in the fragment.
     */
    @SuppressWarnings({"PMD.AssignmentInOperand", "PMD.AvoidLiteralsInIfCondition"})
    @Nonnull
    public static Fragment parseFragment(final String message) throws ProtocolException {
        final Version version;
        final int identifier;
        final int sendertagValue;
        final int receivertagValue;
        final int index;
        final int total;
        final String content;
        // Acquire data from fragment message.
        Matcher matcher;
        if ((matcher = PATTERN_V4.matcher(message)).matches()) {
            version = Version.FOUR;
            if (matcher.group(1).length() < 8) {
                LOGGER.log(Level.WARNING, "Other party sent identifier of less than 8 hex-characters. OTRv4 spec is explicit about the 4-byte identifier.");
            }
            identifier = parseUnsignedInt(matcher.group(1), HEXADECIMAL_SYSTEM);
            sendertagValue = parseUnsignedInt(matcher.group(2), HEXADECIMAL_SYSTEM);
            receivertagValue = parseUnsignedInt(matcher.group(3), HEXADECIMAL_SYSTEM);
            index = parseInt(matcher.group(4), DECIMAL_SYSTEM);
            total = parseInt(matcher.group(5), DECIMAL_SYSTEM);
            content = matcher.group(6);
        } else if ((matcher = PATTERN_V3.matcher(message)).matches()) {
            version = Version.THREE;
            identifier = ZERO_IDENTIFIER;
            sendertagValue = parseUnsignedInt(matcher.group(1), HEXADECIMAL_SYSTEM);
            receivertagValue = parseUnsignedInt(matcher.group(2), HEXADECIMAL_SYSTEM);
            index = parseInt(matcher.group(3), DECIMAL_SYSTEM);
            total = parseInt(matcher.group(4), DECIMAL_SYSTEM);
            content = matcher.group(5);
        } else if ((matcher = PATTERN_V2.matcher(message)).matches()) {
            version = Version.TWO;
            identifier = ZERO_IDENTIFIER;
            sendertagValue = ZERO_VALUE;
            receivertagValue = ZERO_VALUE;
            index = parseInt(matcher.group(1), DECIMAL_SYSTEM);
            total = parseInt(matcher.group(2), DECIMAL_SYSTEM);
            content = matcher.group(3);
        } else {
            throw new ProtocolException("Illegal fragment format.");
        }
        // Verify data from fragment message.
        if (!isValidInstanceTag(sendertagValue)) {
            throw new ProtocolException("Illegal sender instance tag: " + sendertagValue);
        }
        if (!isValidInstanceTag(receivertagValue)) {
            throw new ProtocolException("Illegal receiver instance tag: " + receivertagValue);
        }
        if (index <= 0 || index > MAX_FRAGMENTS) {
            throw new ProtocolException("Illegal fragment index: " + index);
        }
        if (total < index || total > MAX_FRAGMENTS) {
            throw new ProtocolException("Illegal fragment total: " + total);
        }
        if (content.length() > MAX_FRAGMENT_SIZE) {
            throw new ProtocolException("Fragment content exceeds allowed maximum single fragment size.");
        }
        return new Fragment(version, identifier, new InstanceTag(sendertagValue), new InstanceTag(receivertagValue),
            index, total, content);
    }

    /**
     * Get the protocol version.
     *
     * @return Returns the version.
     */
    @Nonnull
    public Version getVersion() {
        return this.version;
    }

    /**
     * Get the fragment identifier.
     * <p>
     * The identifier is common amongst all fragments of the same message.
     *
     * @return Returns the identifier.
     */
    public int getIdentifier() {
        return this.identifier;
    }

    /**
     * Get the sender instance tag.
     *
     * @return Returns the instance tag.
     */
    @Nonnull
    public InstanceTag getSenderTag() {
        return this.senderTag;
    }

    /**
     * Get the receiver instance tag.
     *
     * @return Returns the instance tag.
     */
    @Nonnull
    public InstanceTag getReceiverTag() {
        return this.receiverTag;
    }

    /**
     * Get the message fragment index.
     *
     * @return Returns the index value.
     */
    public int getIndex() {
        return this.index;
    }

    /**
     * Get the message total number of fragments.
     *
     * @return Returns the total.
     */
    public int getTotal() {
        return this.total;
    }

    /**
     * Get the fragment content.
     *
     * @return Returns the content.
     */
    @Nonnull
    public String getContent() {
        return this.content;
    }
}
