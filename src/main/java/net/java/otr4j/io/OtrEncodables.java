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

/**
 * Utilities for {@link OtrEncodable}.
 */
public final class OtrEncodables {

    private OtrEncodables() {
        // No need to instantiate utility class.
    }

    /**
     * Encode provided {@link OtrEncodable} into OTR-encoded format.
     *
     * @param encodable the encodable
     * @return Returns byte-array representing OTR-encoded encodable.
     */
    @Nonnull
    public static byte[] encode(final OtrEncodable encodable) {
        return new OtrOutputStream().write(encodable).toByteArray();
    }
}
