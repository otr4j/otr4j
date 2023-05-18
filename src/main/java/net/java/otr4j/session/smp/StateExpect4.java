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

/**
 * SMP state in expectation of SMP message 4: Bob's final message in SMP
 * exchange.
 *
 * In this state we accept message 4 (TLV type 5).
 */
final class StateExpect4 extends AbstractSMPState {

    private final BigInteger x3;
    private final BigInteger g3o;
    private final BigInteger pab;
    private final BigInteger qab;

    StateExpect4(final StateExpect2 previous, final BigInteger g3o, final BigInteger pab, final BigInteger qab) {
        super(previous.secureRandom());
        this.x3 = previous.x3;
        this.g3o = g3o;
        this.pab = pab;
        this.qab = qab;
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
    void smpMessage4(final SM astate, final byte[] input) throws SMException {
        /* Read from input to find the mpis */
        final BigInteger[] msg4 = SM.deserialize(input);

        /* Verify parameters and let checks throw exceptions in case of failure.*/
        checkGroupElem(msg4[0]);
        checkExpon(msg4[2]);

        /* Verify Bob's log equality proof */
        checkEqualLogs(msg4[1], msg4[2], msg4[0], this.g3o, this.qab, 8);

        /* Calculate Rab and verify that secrets match */

        final BigInteger rab = msg4[0].modPow(this.x3, DHKeyPairOTR3.MODULUS);
        final int comp = rab.compareTo(this.pab);

        final SMPStatus status = (comp == 0) ? SMPStatus.SUCCEEDED : SMPStatus.FAILED;
        astate.setState(new StateExpect1(this.secureRandom(), status));
    }
}
