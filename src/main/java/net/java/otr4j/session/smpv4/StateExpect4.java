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
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.SMP_VALUE_0X08;
import static net.java.otr4j.crypto.OtrCryptoEngine4.hashToScalar;
import static net.java.otr4j.crypto.ed448.Ed448.containsPoint;
import static net.java.otr4j.crypto.ed448.Ed448.multiplyByBase;
import static net.java.otr4j.session.api.SMPStatus.FAILED;
import static net.java.otr4j.session.api.SMPStatus.INPROGRESS;
import static net.java.otr4j.session.api.SMPStatus.SUCCEEDED;
import static net.java.otr4j.session.api.SMPStatus.UNDECIDED;

final class StateExpect4 implements SMPState {

    private static final Logger LOGGER = Logger.getLogger(StateExpect4.class.getName());

    private final SecureRandom random;

    private final Scalar a3;
    private final Point g3b;
    private final Point pa;
    private final Point pb;
    private final Point qa;
    private final Point qb;

    StateExpect4(final SecureRandom random, final Scalar a3, final Point g3b, final Point pa, final Point pb,
            final Point qa, final Point qb) {
        this.random = requireNonNull(random);
        this.a3 = requireNonNull(a3);
        this.g3b = requireNonNull(g3b);
        this.pa = requireNonNull(pa);
        this.pb = requireNonNull(pb);
        this.qa = requireNonNull(qa);
        this.qb = requireNonNull(qb);
    }

    @Nonnull
    @Override
    public SMPStatus getStatus() {
        return INPROGRESS;
    }

    @Nonnull
    @Override
    public SMPMessage1 initiate(final SMPContext context, final String question, final Scalar secret)
            throws SMPAbortException {
        context.setState(new StateExpect1(this.random, UNDECIDED));
        throw new SMPAbortException("Not in initial state. Aborting running SMP negotiation.");
    }

    @Nullable
    @Override
    public SMPMessage2 respondWithSecret(final SMPContext context, final String question, final Scalar secret) {
        // Given that this is an action by the local user, we don't see this as a violation of the protocol. Therefore,
        // we don't abort.
        LOGGER.log(Level.WARNING, "Requested to respond with secret answer, but no request is pending. Ignoring request.");
        return null;
    }

    @Nullable
    @Override
    public SMPMessage process(final SMPContext context, final SMPMessage message) throws SMPAbortException {
        requireNonNull(context);
        requireNonNull(message);
        if (!(message instanceof SMPMessage4)) {
            throw new SMPAbortException("Received SMP message 1 in StateExpect4.");
        }
        final SMPMessage4 smp4 = (SMPMessage4) message;
        if (!containsPoint(smp4.rb)) {
            throw new SMPAbortException("Message validation failed.");
        }
        if (!Scalar.constantTimeEquals(smp4.cr, hashToScalar(SMP_VALUE_0X08,
                multiplyByBase(smp4.d7).add(this.g3b.multiply(smp4.cr)).encode(),
                this.qa.add(this.qb.negate()).multiply(smp4.d7).add(smp4.rb.multiply(smp4.cr)).encode()))) {
            throw new SMPAbortException("Message validation failed.");
        }
        // Verify if the zero-knowledge proof succeeds on our end.
        final Point rab = smp4.rb.multiply(this.a3);
        if (Point.constantTimeEquals(rab, this.pa.add(this.pb.negate()))) {
            LOGGER.log(Level.FINE, "Successful SMP verification.");
            context.setState(new StateExpect1(this.random, SUCCEEDED));
        } else {
            LOGGER.log(Level.FINE, "Failed SMP verification.");
            context.setState(new StateExpect1(this.random, FAILED));
        }
        return null;
    }
}
