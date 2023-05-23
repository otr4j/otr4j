/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.api;

import com.google.errorprone.annotations.CheckReturnValue;
import com.google.errorprone.annotations.Immutable;

import java.security.SecureRandom;
import javax.annotation.Nonnull;

/**
 * Instance tag used in message fragments.
 */
@Immutable
public final class InstanceTag {

    /**
     * Zero-value.
     */
    public static final int ZERO_VALUE = 0;

    /**
     * The smallest possible valid tag value.
     */
    static final int SMALLEST_VALUE = 0x00000100;

    /**
     * The largest possible tag value.
     * Note that this is -1 in the decimal representation.
     */
    static final int HIGHEST_VALUE = 0xffffffff;

    /**
     * Zero-value instance tag.
     */
    public static final InstanceTag ZERO_TAG = new InstanceTag(ZERO_VALUE);

    /**
     * Smallest valid instance tag.
     */
    public static final InstanceTag SMALLEST_TAG = new InstanceTag(SMALLEST_VALUE);

    /**
     * Largest valid instance tag.
     */
    public static final InstanceTag HIGHEST_TAG = new InstanceTag(HIGHEST_VALUE);

    /**
     * Range for valid instance tag values.
     * Corrected for existence of smallest value boundary.
     */
    private static final long RANGE = 0xfffffeffL;

    /**
     * Value of the instance tag instance.
     */
    private final int value;

    /**
     * Test for validity of instance tag value.
     *
     * @param tagValue the tag value
     * @return Returns true iff instance tag is valid.
     */
    @CheckReturnValue
    public static boolean isValidInstanceTag(final int tagValue) {
        // Note that the decimal representation of Java's int is always signed, that means that any value over
        // 0x7fffffff will be interpreted as a negative value. So, instead we verify that the tag value is not in the
        // "forbidden range". Other than the forbidden range, every possible value of the 32 bits of memory is
        // acceptable.
        return !(0 < tagValue && tagValue < SMALLEST_VALUE);
    }

    /**
     * Create a new randomly generated instance tag.
     *
     * @param random Secure random instance to use for generating.
     * @return Returns new randomly generated Instance tag instance.
     */
    @Nonnull
    public static InstanceTag random(final SecureRandom random) {
        return new InstanceTag(random.nextDouble());
    }

    /**
     * Instance Tag constructor.
     * <p>
     * This version of the constructor is provided in order to provide an
     * "pre-generated" random double from which a valid random tag value is
     * derived.
     *
     * @param ratio The provided (random) double ratio that is used to
     * derive a tag value from the full range of valid tag values. The ratio
     * should be a value between 0 (inclusive) and 1 (exclusive).
     */
    public InstanceTag(final double ratio) {
        if (ratio < 0 || ratio >= 1) {
            throw new IllegalArgumentException("ratio should be a value between 0 and 1");
        }
        final long val = (long) (ratio * RANGE) + SMALLEST_VALUE;
        // Because 0xffffffff is the maximum value for both the tag and the 32 bit integer range, we are able to cast to
        // int without loss. The (decimal) interpretation changes, though, because Java's int interprets the last bit as
        // the sign bit. This does not matter, however, since we do not need to do value comparisons / ordering. We only
        // care about equal/not equal.
        this.value = (int) val;
    }

    /**
     * Construct instance tag based on concrete value.
     *
     * @param value The instance tag value
     */
    public InstanceTag(final int value) {
        if (!isValidInstanceTag(value)) {
            throw new IllegalArgumentException("Invalid tag value.");
        }
        this.value = value;
    }

    /**
     * Get tag value.
     *
     * @return Returns the tag value.
     */
    public int getValue() {
        return this.value;
    }

    @Override
    public boolean equals(final Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof InstanceTag)) {
            return false;
        }
        final InstanceTag otherInstanceTag = (InstanceTag) other;
        return this.value == otherInstanceTag.value;
    }

    @Override
    public int hashCode() {
        return this.value;
    }

    @Override
    public String toString() {
        return "InstanceTag{value=" + this.value + '}';
    }
}
