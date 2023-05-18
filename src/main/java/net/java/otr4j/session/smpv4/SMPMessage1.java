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
import net.java.otr4j.io.OtrOutputStream;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Objects.requireNonNull;

final class SMPMessage1 implements SMPMessage {

    final String question;

    final Point g2a;

    final Scalar c2;

    final Scalar d2;

    final Point g3a;

    final Scalar c3;

    final Scalar d3;

    SMPMessage1(final String question, final Point g2a, final Scalar c2, final Scalar d2, final Point g3a,
            final Scalar c3, final Scalar d3) {
        this.question = requireNonNull(question);
        this.g2a = requireNonNull(g2a);
        this.c2 = requireNonNull(c2);
        this.d2 = requireNonNull(d2);
        this.g3a = requireNonNull(g3a);
        this.c3 = requireNonNull(c3);
        this.d3 = requireNonNull(d3);
    }

    @Override
    public void writeTo(final OtrOutputStream out) {
        out.writeData(this.question.getBytes(UTF_8)).writePoint(this.g2a).writeScalar(this.c2).writeScalar(this.d2)
                .writePoint(this.g3a).writeScalar(this.c3).writeScalar(this.d3);
    }
}
