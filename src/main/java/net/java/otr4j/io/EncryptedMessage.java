/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.io;

import net.java.otr4j.api.TLV;

import javax.annotation.Nonnull;
import java.net.ProtocolException;
import java.util.ArrayList;
import java.util.List;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Objects.requireNonNull;

/**
 * Utility class that defines the message structure for a data message after it has been decrypted.
 */
public final class EncryptedMessage {

    /**
     * Null-byte indicating end of normal message payload and start of (optional) TLV records.
     */
    private static final int TLV_DATA_START_BYTE = 0x00;

    private EncryptedMessage() {
        // No need to instantiate utility class.
    }

    /**
     * Extract message contents from decrypted message bytes.
     *
     * @param messageBytes Bytes of the message (decrypted)
     * @return Returns Content instances containing both the message content
     * and any TLVs that are extracted.
     * @throws ProtocolException In case of incomplete or bad message bytes.
     */
    @Nonnull
    public static Content extractContents(final byte[] messageBytes) throws ProtocolException {

        // find the null TLV separator in the package, or just use the end value
        int tlvIndex = messageBytes.length;
        for (int i = 0; i < messageBytes.length; i++) {
            if (messageBytes[i] == TLV_DATA_START_BYTE) {
                tlvIndex = i;
                break;
            }
        }

        // get message body without trailing 0x00, expect UTF-8 bytes
        final String message = new String(messageBytes, 0, tlvIndex, UTF_8);

        // if the null TLV separator is somewhere in the middle, there are TLVs
        final ArrayList<TLV> tlvs = new ArrayList<>();
        tlvIndex++; // to ignore the null value that separates message from TLVs
        if (tlvIndex < messageBytes.length) {
            final OtrInputStream in = new OtrInputStream(messageBytes, tlvIndex, messageBytes.length - tlvIndex);
            while (in.available() > 0) {
                tlvs.add(in.readTLV());
            }
        }

        return new Content(message, tlvs);
    }

    /**
     * Content is an inner class that is used to return both message body and accompanying TLVs.
     */
    public static final class Content {
        /**
         * The plaintext (user) message content.
         */
        public final String message;
        /**
         * The TLVs embedded in the Data message.
         */
        public final List<TLV> tlvs;

        private Content(final String message, final List<TLV> tlvs) {
            this.message = requireNonNull(message);
            this.tlvs = requireNonNull(tlvs);
        }
    }
}
