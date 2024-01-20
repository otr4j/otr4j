/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.session.smpv4;

import net.java.otr4j.crypto.ed448.Point;
import net.java.otr4j.crypto.ed448.Scalar;
import net.java.otr4j.session.api.SMPStatus;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.SMP_VALUE_0X01;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.SMP_VALUE_0X02;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.SMP_VALUE_0X03;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.SMP_VALUE_0X04;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.SMP_VALUE_0X05;
import static net.java.otr4j.crypto.OtrCryptoEngine4.generateRandomValueInZq;
import static net.java.otr4j.crypto.OtrCryptoEngine4.hashToScalar;
import static net.java.otr4j.crypto.ed448.Ed448.containsPoint;
import static net.java.otr4j.crypto.ed448.Ed448.multiplyByBase;
import static net.java.otr4j.crypto.ed448.Ed448.order;
import static net.java.otr4j.crypto.ed448.Ed448.requireValidPoint;

/**
 * StateExpect1 is the initial state for SMP.
 * <p>
 * StateExpect1 exists of 2 variants, in order of occurrence:
 * <ol>
 * <li>StateExpect1 without message: initial state, we receive the initiation message and given that we have not yet
 * acquired the secret from the local user, we can only request the secret and wait.</li>
 * <li>StateExpect1 with message: we are remembering the message up to the moment where the user provides us with
 * the secret. As soon as the secret answer is provided, we continue processing the remembered initiation message.
 * </li>
 * </ol>
 */
final class StateExpect1 implements SMPState {

    private static final Logger LOGGER = Logger.getLogger(StateExpect1.class.getName());

    /**
     * The SecureRandom instance.
     */
    private final SecureRandom random;

    /**
     * The current SMP status.
     */
    private final SMPStatus status;

    /**
     * The previously received SMPMessage1. This field exists to remember the initiation message in the time we are
     * requesting the local user to provide his answer to the posed question.
     */
    @Nullable
    private final SMPMessage1 message;

    StateExpect1(final SecureRandom random, final SMPStatus status) {
        this.random = requireNonNull(random);
        this.status = requireNonNull(status);
        this.message = null;
    }

    private StateExpect1(final SecureRandom random, final SMPStatus status, final SMPMessage1 message) {
        this.random = requireNonNull(random);
        this.status = requireNonNull(status);
        this.message = requireNonNull(message);
    }

    @Nonnull
    @Override
    public SMPStatus getStatus() {
        return this.status;
    }

    @Nonnull
    @Override
    public SMPMessage1 initiate(final SMPContext context, final String question, final Scalar secret) {
        requireNonNull(context);
        final Scalar a2 = generateRandomValueInZq(this.random);
        final Scalar a3 = generateRandomValueInZq(this.random);
        final Scalar r2 = generateRandomValueInZq(this.random);
        final Scalar r3 = generateRandomValueInZq(this.random);
        final Point g2a = requireValidPoint(multiplyByBase(a2));
        final Point g3a = requireValidPoint(multiplyByBase(a3));
        final Scalar q = order();
        final Scalar c2 = hashToScalar(SMP_VALUE_0X01, multiplyByBase(r2).encode());
        final Scalar d2 = r2.subtract(a2.multiply(c2)).mod(q);
        final Scalar c3 = hashToScalar(SMP_VALUE_0X02, multiplyByBase(r3).encode());
        final Scalar d3 = r3.subtract(a3.multiply(c3)).mod(q);
        context.setState(new StateExpect2(this.random, secret, a2, a3));
        return new SMPMessage1(question, g2a, c2, d2, g3a, c3, d3);
    }

    @Nullable
    @Override
    public SMPMessage2 respondWithSecret(final SMPContext context, final String question, final Scalar secret) {
        requireNonNull(context);
        if (this.message == null) {
            LOGGER.log(Level.WARNING, "The answer to an SMP question is provided, but no SMP init message is waiting to be answered. Ignoring answer.");
            return null;
        }
        if (!question.equals(this.message.question)) {
            LOGGER.log(Level.INFO, "The question does not match the question in the waiting message. The request-for-secret is probably outdated. Ignoring answer.");
            return null;
        }
        final Scalar b2 = generateRandomValueInZq(this.random);
        final Scalar b3 = generateRandomValueInZq(this.random);
        final Scalar r2 = generateRandomValueInZq(this.random);
        final Scalar r3 = generateRandomValueInZq(this.random);
        final Scalar r4 = generateRandomValueInZq(this.random);
        final Scalar r5 = generateRandomValueInZq(this.random);
        final Scalar r6 = generateRandomValueInZq(this.random);
        final Point g2b = requireValidPoint(multiplyByBase(b2));
        final Point g3b = requireValidPoint(multiplyByBase(b3));
        final Scalar q = order();
        final Scalar c2 = hashToScalar(SMP_VALUE_0X03, multiplyByBase(r2).encode());
        final Scalar d2 = r2.subtract(b2.multiply(c2)).mod(q);
        final Scalar c3 = hashToScalar(SMP_VALUE_0X04, multiplyByBase(r3).encode());
        final Scalar d3 = r3.subtract(b3.multiply(c3)).mod(q);
        final Point g2 = requireValidPoint(this.message.g2a.multiply(b2));
        final Point g3 = requireValidPoint(this.message.g3a.multiply(b3));
        final Point pb = requireValidPoint(g3.multiply(r4));
        final Point qb = requireValidPoint(multiplyByBase(r4).add(g2.multiply(secret.mod(q))));
        final Scalar cp = hashToScalar(SMP_VALUE_0X05, g3.multiply(r5).encode(),
                multiplyByBase(r5).add(g2.multiply(r6)).encode());
        final Scalar d5 = r5.subtract(r4.multiply(cp)).mod(q);
        final Scalar d6 = r6.subtract(secret.mod(q).multiply(cp)).mod(q);
        context.setState(new StateExpect3(this.random, pb, qb, b3, this.message.g3a, g2, g3));
        return new SMPMessage2(g2b, c2, d2, g3b, c3, d3, pb, qb, cp, d5, d6);
    }

    @Nullable
    @Override
    public SMPMessage process(final SMPContext context, final SMPMessage message) throws SMPAbortException {
        requireNonNull(context);
        requireNonNull(message);
        if (!(message instanceof SMPMessage1)) {
            throw new SMPAbortException("Received unexpected SMP message in StateExpect1.");
        }
        final SMPMessage1 smp1 = (SMPMessage1) message;
        if (!containsPoint(smp1.g2a) || !containsPoint(smp1.g3a)) {
            throw new SMPAbortException("g2a or g3a failed verification.");
        }
        if (!Scalar.constantTimeEquals(smp1.c2, hashToScalar(SMP_VALUE_0X01,
                multiplyByBase(smp1.d2).add(smp1.g2a.multiply(smp1.c2)).encode()))) {
            throw new SMPAbortException("c2 failed verification.");
        }
        if (!Scalar.constantTimeEquals(smp1.c3, hashToScalar(SMP_VALUE_0X02,
                multiplyByBase(smp1.d3).add(smp1.g3a.multiply(smp1.c3)).encode()))) {
            throw new SMPAbortException("c3 failed verification.");
        }
        context.requestSecret(smp1.question);
        context.setState(new StateExpect1(this.random, this.status, smp1));
        return null;
    }
}
