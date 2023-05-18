/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.session.smp;

import net.java.otr4j.crypto.DHKeyPairOTR3;
import net.java.otr4j.session.api.SMPStatus;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * SMP state in expectation of SMP message 1. (Or when initiating SMP
 * negotiation.)
 *
 * In this state we accept messages 1 (TLV type 2), and 1Q (TLV type 7).
 *
 * This is the initial and default state. SMP is reset to this state whenever an
 * error occurs or SMP is aborted.
 */
final class StateExpect1 extends AbstractSMPState {

    private final SMPStatus status;

    @Nullable
    private final BigInteger x2;
    @Nullable
    final BigInteger x3;

    @Nullable
    final BigInteger g2;
    @Nullable
    final BigInteger g3;

    @Nullable
    final BigInteger g3o;

    StateExpect1(final SecureRandom sr) {
        this(sr, SMPStatus.UNDECIDED, null, null, null, null, null);
    }

    StateExpect1(final SecureRandom sr, final SMPStatus status) {
        this(sr, status, null, null, null, null, null);
    }

    private StateExpect1(final SecureRandom sr, final SMPStatus status, @Nullable final BigInteger x2,
            @Nullable final BigInteger x3, @Nullable final BigInteger g2, @Nullable final BigInteger g3,
            @Nullable final BigInteger g3o) {
        super(sr);
        this.status = status;
        this.x2 = x2;
        this.x3 = x3;
        this.g2 = g2;
        this.g3 = g3;
        this.g3o = g3o;
    }

    @Override
    public void close() {
        // Nothing to clean up for current implementation.
    }

    @Override
    @Nonnull
    SMPStatus status() {
        return this.status;
    }

    @Override
    @Nonnull
    byte[] startSMP(final SM astate, final byte[] secretBytes) {
        /* Initialize the sm state or update the secret */
        final BigInteger secret = new BigInteger(1, secretBytes);

        final BigInteger x2 = randomExponent();
        final BigInteger x3 = randomExponent();

        final BigInteger[] msg1 = new BigInteger[6];
        msg1[0] = G1.modPow(x2, DHKeyPairOTR3.MODULUS);
        BigInteger[] res = proofKnowLog(x2, 1);
        msg1[1] = res[0];
        msg1[2] = res[1];

        msg1[3] = G1.modPow(x3, DHKeyPairOTR3.MODULUS);
        res = proofKnowLog(x3, 2);
        msg1[4] = res[0];
        msg1[5] = res[1];

        final byte[] ret = SM.serialize(msg1);

        astate.setState(new StateExpect2(this.secureRandom(), secret, x2, x3));
        return ret;
    }

    @Override
    void smpMessage1a(final SM bstate, final byte[] input) throws SMException {
        /* Initialize the sm state if needed */

        /* Read from input to find the mpis */
        final BigInteger[] msg1 = SM.deserialize(input);

        /* Verify parameters and let checks throw exceptions in case of failure.*/
        checkGroupElem(msg1[0]);
        checkExpon(msg1[2]);
        checkGroupElem(msg1[3]);
        checkExpon(msg1[5]);

        /* Store Alice's g3a value for later in the protocol */
        final BigInteger g3o = msg1[3];

        /* Verify Alice's proofs */
        checkKnowLog(msg1[1], msg1[2], msg1[0], 1);
        checkKnowLog(msg1[4], msg1[5], msg1[3], 2);

        /* Create Bob's half of the generators g2 and g3 */
        final BigInteger x2 = randomExponent();
        final BigInteger x3 = randomExponent();

        /* Combine the two halves from Bob and Alice and determine g2 and g3 */
        final BigInteger g2 = msg1[0].modPow(x2, DHKeyPairOTR3.MODULUS);
        final BigInteger g3 = msg1[3].modPow(x3, DHKeyPairOTR3.MODULUS);

        bstate.setState(new StateExpect1(this.secureRandom(), SMPStatus.INPROGRESS, x2, x3, g2, g3, g3o));
    }

    @Override
    @Nonnull
    byte[] smpMessage1b(final SM bstate, final byte[] secretBytes) throws SMException {
        if (status() != SMPStatus.INPROGRESS) {
            // In case a question gets answered before the question is received,
            // this is considered bad order of messages. Abort protocol and
            // reset to default.
            bstate.setState(new StateExpect1(this.secureRandom()));
            throw new SMAbortedException(false,
                    "An SMP exchange initial request was not yet received. There is no question posed that can be answered with a shared secret.");
        }
        if (this.x2 == null || this.x3 == null || this.g2 == null || this.g3 == null) {
            // this case indicates that either state management is bad, or we try to respond with an answer before we
            // have received a question. The "missing question" case should already be discovered with the status check.
            // So if we arrive here, in any case it is considered a bug.
            throw new IllegalStateException("BUG: null field detected. Expected all necessary fields to be present at this time.");
        }

        /* Convert the given secret to the proper form and store it */
        final BigInteger secret = new BigInteger(1, secretBytes);

        final BigInteger[] msg2 = new BigInteger[11];
        msg2[0] = G1.modPow(this.x2, DHKeyPairOTR3.MODULUS);
        BigInteger[] res = proofKnowLog(this.x2, 3);
        msg2[1] = res[0];
        msg2[2] = res[1];

        msg2[3] = G1.modPow(this.x3, DHKeyPairOTR3.MODULUS);
        res = proofKnowLog(this.x3, 4);
        msg2[4] = res[0];
        msg2[5] = res[1];

        /* Calculate P and Q values for Bob */
        final BigInteger r = randomExponent();
        final BigInteger p = this.g3.modPow(r, DHKeyPairOTR3.MODULUS);
        msg2[6] = p;
        final BigInteger qb1 = G1.modPow(r, DHKeyPairOTR3.MODULUS);
        final BigInteger qb2 = this.g2.modPow(secret, DHKeyPairOTR3.MODULUS);
        final BigInteger q = qb1.multiply(qb2).mod(DHKeyPairOTR3.MODULUS);
        msg2[7] = q;

        res = proofEqualCoords(this.g2, this.g3, secret, r, 5);
        msg2[8] = res[0];
        msg2[9] = res[1];
        msg2[10] = res[2];

        bstate.setState(new StateExpect3(this, p, q));

        /* Convert to serialized form */
        return SM.serialize(msg2);
    }
}
