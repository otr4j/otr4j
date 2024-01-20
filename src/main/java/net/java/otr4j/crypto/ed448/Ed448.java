/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.crypto.ed448;

import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.errorprone.annotations.CheckReturnValue;
import nl.dannyvanheumen.joldilocks.Points;

import javax.annotation.Nonnull;
import java.math.BigInteger;

import static java.math.BigInteger.ZERO;
import static net.java.otr4j.util.ByteArrays.constantTimeEquals;

/**
 * Class that provides access to Ed448 constants.
 */
public final class Ed448 {

    /**
     * Identity (or neutral element) of the curve.
     */
    private static final byte[] IDENTITY = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    /**
     * Prime p of the Ed448-Goldilocks curve. (Used as modulus.)
     */
    private static final BigInteger MODULUS = new BigInteger("fffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16);

    /**
     * Base Point of the curve.
     */
    private static final byte[] G = {20, -6, 48, -14, 91, 121, 8, -104, -83, -56, -41, 78, 44, 19, -67, -3, -60, 57, 124, -26, 28, -1, -45, 58, -41, -62, -96, 5, 30, -100, 120, -121, 64, -104, -93, 108, 115, 115, -22, 75, 98, -57, -55, 86, 55, 32, 118, -120, 36, -68, -74, 110, 113, 70, 63, 105, 0};

    /**
     * Prime order.
     */
    private static final byte[] Q = {-13, 68, 88, -85, -110, -62, 120, 35, 85, -113, -59, -115, 114, -62, 108, 33, -112, 54, -42, -82, 73, -37, 78, -60, -23, 35, -54, 124, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 63, 0};

    private Ed448() {
        // No need to instantiate utility class.
    }

    /**
     * Access base point of Ed448-Goldilocks curve.
     *
     * @return Returns base point.
     */
    @Nonnull
    public static Point basePoint() {
        return new Point(G.clone());
    }

    /**
     * Access (prime) order of Ed448-Goldilocks curve.
     *
     * @return Returns prime order.
     */
    @Nonnull
    public static Scalar order() {
        return new Scalar(Q.clone());
    }

    /**
     * Access identity point of Ed448-Goldilocks curve.
     *
     * @return Identity
     */
    @Nonnull
    public static Point identity() {
        return new Point(IDENTITY.clone());
    }

    /**
     * Perform scalar multiplication by Ed448 base point.
     *
     * @param scalar the scalar value
     * @return Returns the point resulting from the multiplication.
     */
    @Nonnull
    public static Point multiplyByBase(final Scalar scalar) {
        return new Point(nl.dannyvanheumen.joldilocks.Ed448.multiplyByBase(scalar.toBigInteger()).encode());
    }

    /**
     * Require point to be valid.
     *
     * @param point the point to validate
     * @return Returns the same point iff it is valid.
     */
    @CanIgnoreReturnValue
    @Nonnull
    public static Point requireValidPoint(final Point point) {
        if (!containsPoint(point)) {
            throw new IllegalArgumentException("Point is illegal.");
        }
        return point;
    }

    /**
     * Verify that given point is contained in the curve.
     *
     * @param point The point to verify.
     * @return Returns true if it is contained in the curve.
     */
    @CheckReturnValue
    public static boolean containsPoint(final Point point) {
        if (checkIdentity(point)) {
            // TODO is this appropriate to handle as special case? (just curious, stumbled upon this question via some unit tests)
            return false;
        }
        try {
            final nl.dannyvanheumen.joldilocks.Point p = Points.decode(point.getEncoded());
            if (p.x().compareTo(ZERO) < 0 || p.x().compareTo(MODULUS) >= 0) {
                return false;
            }
            if (p.y().compareTo(ZERO) < 0 || p.y().compareTo(MODULUS) >= 0) {
                return false;
            }
        } catch (final Points.InvalidDataException e) {
            return false;
        }
        return checkIdentity(point.multiply(order()));
    }

    /**
     * checkIdentity tests if a point is the identity.
     *
     * @param point point
     * @return Returns true if p is identity, or false otherwise.
     */
    @CheckReturnValue
    public static boolean checkIdentity(final Point point) {
        return constantTimeEquals(IDENTITY, point.getEncoded());
    }
}
