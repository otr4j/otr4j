/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.util;

import com.google.errorprone.annotations.CanIgnoreReturnValue;

import javax.annotation.Nonnull;
import java.security.SecureRandom;

/**
 * Utility class for SecureRandom.
 */
public final class SecureRandoms {

    private SecureRandoms() {
        // No need to instantiate utility class.
    }

    /**
     * Fill provided byte-array with random data from provided {@link SecureRandom} instance. This is a convenience
     * function that can be used in-line for field or variable instantiation.
     *
     * @param random a SecureRandom instance
     * @param dest   The destination byte-array to be fully filled with random
     *               data.
     * @return Returns 'dest' filled with random data.
     */
    @CanIgnoreReturnValue
    @Nonnull
    public static byte[] randomBytes(final SecureRandom random, final byte[] dest) {
        random.nextBytes(dest);
        return dest;
    }
}
