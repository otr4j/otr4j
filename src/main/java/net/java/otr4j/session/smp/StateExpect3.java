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
import java.math.BigInteger;

import static java.util.Objects.requireNonNull;

/**
 * SMP state in expectation of SMP message 3: Alice's final message in SMP
 * exchange.
 *
 * In this state we accept message 3 (TLV type 4).
 */
final class StateExpect3 extends AbstractSMPState {

    private final BigInteger x3;
    private final BigInteger g2;
    private final BigInteger g3;
    private final BigInteger g3o;
    private final BigInteger p;
    private final BigInteger q;

    StateExpect3(final StateExpect1 previous, final BigInteger p, final BigInteger q) {
        super(previous.secureRandom());
        this.x3 = requireNonNull(previous.x3);
        this.g2 = requireNonNull(previous.g2);
        this.g3 = requireNonNull(previous.g3);
        this.g3o = requireNonNull(previous.g3o);
        this.p = p;
        this.q = q;
    }

    @Override
    public void close() {
        // Nothing to clean up for current implementation.
    }

    @Override
    @Nonnull
    SMPStatus status() {
        return SMPStatus.INPROGRESS;
    }

    @Override
    @Nonnull
    byte[] smpMessage3(final SM bstate, final byte[] input) throws SMException {
        /* Read from input to find the MPIs */
        final BigInteger[] msg3 = SM.deserialize(input);

        final BigInteger[] msg4 = new BigInteger[3];

        /* Verify parameters and let checks throw exceptions in case of failure.*/
        checkGroupElem(msg3[0]);
        checkGroupElem(msg3[1]);
        checkGroupElem(msg3[5]);
        checkExpon(msg3[3]);
        checkExpon(msg3[4]);
        checkExpon(msg3[7]);

        /* Verify Alice's coordinate equality proof */
        checkEqualCoords(msg3[2], msg3[3], msg3[4], msg3[0], msg3[1], this.g2, this.g3, 6);

        /* Find Pa/Pb and Qa/Qb */
        BigInteger inv = this.p.modInverse(DHKeyPairOTR3.MODULUS);
        final BigInteger pab = msg3[0].multiply(inv).mod(DHKeyPairOTR3.MODULUS);
        inv = this.q.modInverse(DHKeyPairOTR3.MODULUS);
        final BigInteger qab = msg3[1].multiply(inv).mod(DHKeyPairOTR3.MODULUS);


        /* Verify Alice's log equality proof */
        checkEqualLogs(msg3[6], msg3[7], msg3[5], this.g3o, qab, 7);

        /* Calculate Rb and proof */
        msg4[0] = qab.modPow(this.x3, DHKeyPairOTR3.MODULUS);
        final BigInteger[] res = proofEqualLogs(qab, this.x3, 8);
        msg4[1] = res[0];
        msg4[2] = res[1];

        final byte[] output = SM.serialize(msg4);

        /* Calculate Rab and verify that secrets match */

        final BigInteger rab = msg3[5].modPow(this.x3, DHKeyPairOTR3.MODULUS);
        final int comp = rab.compareTo(pab);

        final SMPStatus status = (comp == 0) ? SMPStatus.SUCCEEDED : SMPStatus.FAILED;
        bstate.setState(new StateExpect1(this.secureRandom(), status));

        return output;
    }
}
