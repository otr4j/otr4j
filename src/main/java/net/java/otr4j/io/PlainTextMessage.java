/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.io;

import javax.annotation.Nonnull;
import java.util.Set;

import static java.util.Objects.requireNonNull;

/**
 * The plain text message.
 *
 * @author George Politis
 * @author Danny van Heumen
 */
public final class PlainTextMessage extends QueryMessage {

    @Nonnull
    private final String cleanText;

    /**
     * Constructor for plaintext message.
     *
     * @param versions  the protocol versions
     * @param cleanText the plain text message content
     */
    public PlainTextMessage(final Set<Integer> versions, final String cleanText) {
        super(versions);
        this.cleanText = requireNonNull(cleanText);
    }

    /**
     * The clean text, i.e. the plain text without possible embedded whitespace tag.
     *
     * @return Returns text.
     */
    @Nonnull
    public String getCleanText() {
        return this.cleanText;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + this.cleanText.hashCode();
        return result;
    }

    @Override
    public boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }
        if (!super.equals(obj)) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final PlainTextMessage other = (PlainTextMessage) obj;
        return this.cleanText.equals(other.cleanText);
    }
}
