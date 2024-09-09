/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */
/*
 *  Java OTR library
 *  Copyright (C) 2008-2009  Ian Goldberg, Muhaimeen Ashraf, Andrew Chung,
 *                           Can Tang
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of version 2.1 of the GNU Lesser General
 *  Public License as published by the Free Software Foundation.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
/* Ported to otr4j by devrandom */

package net.java.otr4j.session.smp;

import net.java.otr4j.io.OtrInputStream;
import net.java.otr4j.io.OtrOutputStream;
import net.java.otr4j.session.api.SMPStatus;

import javax.annotation.Nonnull;
import java.math.BigInteger;
import java.net.ProtocolException;
import java.security.SecureRandom;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

import static net.java.otr4j.crypto.OtrCryptoEngine.sha256Hash;

/**
 * Socialist Millionaire protocol implementation.
 */
@SuppressWarnings({"PMD.AvoidRethrowingException", "PMD.AvoidCatchingGenericException"})
final class SM implements AutoCloseable {

    private static final Logger LOGGER = Logger.getLogger(SM.class.getName());

    /**
     * Constant indicating the maximum accepted MPI array size. This array size
     * can in principle be as large as JVM's max array size, however such a
     * size will not be needed for typical SMP TLV types 2-5 messages. To reduce
     * risk of misuse, go with far smaller value.
     */
    private static final int MAX_MPI_ARRAY_SIZE = 100;

    /**
     * The current state of the Socialist Millionaire's Protocol.
     */
    private AbstractSMPState state;

    /**
     * Constructor.
     *
     * @param sr secure random instance
     */
    SM(final SecureRandom sr) {
        this.state = new StateExpect1(sr);
    }

    void setState(final AbstractSMPState state) {
        LOGGER.log(Level.FINER, "Updating SMP state to: {0}", state);
        this.state = Objects.requireNonNull(state);
    }

    @Nonnull
    static BigInteger hash(final int version, final BigInteger a) {
        final byte[] digest = sha256Hash(new byte[] {(byte) version},
                new OtrOutputStream().writeBigInt(a).toByteArray());
        return new BigInteger(1, digest);
    }

    @Nonnull
    static BigInteger hash(final int version, final BigInteger a, final BigInteger b) {
        final byte[] digest = sha256Hash(new byte[] {(byte) version},
                new OtrOutputStream().writeBigInt(a).writeBigInt(b).toByteArray());
        return new BigInteger(1, digest);
    }

    @Nonnull
    static byte[] serialize(final BigInteger[] ints) {
        final OtrOutputStream serialization = new OtrOutputStream().writeInt(ints.length);
        for (final BigInteger i : ints) {
            serialization.writeBigInt(i);
        }
        return serialization.toByteArray();
    }

    @Nonnull
    static BigInteger[] deserialize(final byte[] bytes) throws SMException {
        try {
            final OtrInputStream in = new OtrInputStream(bytes);
            final int len = in.readInt();
            if (len < 0) {
                // Length is read into (signed) int. Bit shifting is used to
                // compose the final int value, but bit shifting does not
                // prevent Java from interpreting the value as a signed int,
                // thus negative for values where sign bit is set.
                throw new SMException("Invalid number of ints: " + len);
            }
            if (len > MAX_MPI_ARRAY_SIZE) {
                // The maximum supported length by otr4j. Because of the reason
                // described above, the maximum supported value is only 2**31
                // big (minus some overhead).
                // To avoid risk of misuse, we typically use a smaller upper
                // bound for the MPI array. The MPI array may in principle be as
                // large as MAX_ARRAY_SIZE.
                // (http://hg.openjdk.java.net/jdk7/jdk7/jdk/file/tip/src/share/classes/java/util/ArrayList.java#l190)
                throw new SMException("Too many ints");
            }
            final BigInteger[] ints = new BigInteger[len];
            for (int i = 0; i < ints.length; i++) {
                ints[i] = in.readBigInt();
            }
            return ints;
        } catch (final ProtocolException ex) {
            throw new SMException("cannot deserialize bigints", ex);
        }
    }

    /**
     * The current status of the SM state machine.
     *
     * @return Returns the current status.
     */
    @Nonnull
    SMPStatus status() {
        final SMPStatus status = this.state.status();
        LOGGER.log(Level.FINE, "Retrieving status for SMP exchange: {0}", status.name());
        return status;
    }

    /**
     * Abort the current SM exchange. This resets the state machine to the
     * default/initial state.
     * <p>
     * In case the abort is initiated by the local user, it may be necessary to
     * send a type 6 TLV to the counterparty as to inform them of the decision.
     * This is outside the scope of responsibility of the state machine.
     *
     * @return Returns true if SMP exchange was originally in progress. It will
     * return false in initial state and final states.
     */
    boolean abort() {
        LOGGER.fine("Aborting SMP exchange.");
        return this.state.smpAbort(this);
    }

    /**
     * Create first message in SMP exchange. Input is Alice's secret value which
     * this protocol aims to compare to Bob's. The return value is a serialized
     * BigInteger array whose elements correspond to the following: [0] = g2a,
     * Alice's half of DH exchange to determine g2 [1] = c2, [2] = d2, Alice's
     * ZK proof of knowledge of g2a exponent [3] = g3a, Alice's half of DH
     * exchange to determine g3 [4] = c3, [5] = d3, Alice's ZK proof of
     * knowledge of g3a exponent
     *
     * @param secret The SMP secret to be verified.
     * @return Returns first SMP message to be sent to other party as a way to
     * start SMP negotiation.
     * @throws SMAbortedException SMP state machine was
     * not in SMP_EXPECT1 state. Abort has been initiated and state machine
     * reset to initial state. Send a type 6 TLV to indicate SMP exchange abort
     * and then you can immediately make a subsequent call to initiate a new SMP
     * exchange.
     */
    @Nonnull
    byte[] step1(final byte[] secret) throws SMException {
        LOGGER.fine("Initiating SMP exchange.");
        // startSMP is solely controlled by the local user. In case an exception
        // occurs here, it is related to a programming error.
        return this.state.startSMP(this, secret);
    }

    /**
     * Receive the first message in SMP exchange, which was generated by step1.
     * Input is saved until the user inputs their secret information. No output.
     *
     * @param input The input to step 2a: SMP message 1a.
     * @throws SMAbortedException Thrown in case of exchange abort. This
     * happens in case an unexpected message is recieved or on request.
     * @throws SMException Thrown in case of abort or failure to process SMP
     * message.
     */
    void step2a(final byte[] input) throws SMException {
        LOGGER.fine("Received SMP exchange initiation request.");
        try {
            this.state.smpMessage1a(this, input);
        } catch (final SMAbortedException e) {
            // Let SMAbortedException pass. This exception may at times occur
            // and is a valid interruption that is not considered cheating.
            throw e;
        } catch (final SMException e) {
            this.state = new StateExpect1(this.state.secureRandom(), SMPStatus.CHEATED);
            throw e;
        } catch (final RuntimeException | AssertionError e) {
            this.state = new StateExpect1(this.state.secureRandom(), SMPStatus.CHEATED);
            throw new SMException(e);
        }
    }

    /**
     * Create second message in SMP exchange. Input is Bob's secret value.
     * Information from earlier steps in the exchange is taken from Bob's state.
     * Output is a serialized mpi array whose elements correspond to the
     * following: [0] = g2b, Bob's half of DH exchange to determine g2 [1] = c2,
     * [2] = d2, Bob's ZK proof of knowledge of g2b exponent [3] = g3b, Bob's
     * half of DH exchange to determine g3 [4] = c3, [5] = d3, Bob's ZK proof of
     * knowledge of g3b exponent [6] = pb, [7] = qb, Bob's halves of the (Pa/Pb)
     * and (Qa/Qb) values [8] = cp, [9] = d5, [10] = d6, Bob's ZK proof that pb,
     * qb formed correctly
     *
     * @param secret The secret to be verified using SMP.
     * @return Returns message to send to other party as way to respond to SMP
     * request.
     * @throws SMException Thrown in case of failure to process SMP message or
     * on abort.
     */
    @Nonnull
    byte[] step2b(final byte[] secret) throws SMException {
        LOGGER.fine("Continuing SMP exchange initiation reply after receiving data from OtrEngineHost.");
        try {
            return this.state.smpMessage1b(this, secret);
        } catch (final SMAbortedException e) {
            // Let SMAbortedException pass. This exception may at times occur
            // and is a valid interruption that is not considered cheating.
            throw e;
        } catch (final SMException e) {
            this.state = new StateExpect1(this.state.secureRandom(), SMPStatus.CHEATED);
            throw e;
        } catch (final RuntimeException | AssertionError e) {
            this.state = new StateExpect1(this.state.secureRandom(), SMPStatus.CHEATED);
            throw new SMException(e);
        }
    }

    /**
     * Create third message in SMP exchange. Input is a message generated by
     * otrl_sm_step2b. Output is a serialized mpi array whose elements
     * correspond to the following: [0] = pa, [1] = qa, Alice's halves of the
     * (Pa/Pb) and (Qa/Qb) values [2] = cp, [3] = d5, [4] = d6, Alice's ZK proof
     * that pa, qa formed correctly [5] = ra, calculated as (Qa/Qb)^x3 where x3
     * is the exponent used in g3a [6] = cr, [7] = d7, Alice's ZK proof that ra
     * is formed correctly
     *
     * @param input The input to SMP step 3 (SMP message 2)
     * @return Returns response to SMP message 2 as defined in SMP step 3.
     * @throws SMException Thrown in case of failure to process SMP message, or
     * in case of abort.
     */
    @Nonnull
    byte[] step3(final byte[] input) throws SMException {
        LOGGER.fine("Received reply to SMP exchange initiation request. Sending final message in SMP exchange.");
        try {
            return this.state.smpMessage2(this, input);
        } catch (final SMAbortedException e) {
            // Let SMAbortedException pass. This exception may at times occur
            // and is a valid interruption that is not considered cheating.
            throw e;
        } catch (final SMException e) {
            this.state = new StateExpect1(this.state.secureRandom(), SMPStatus.CHEATED);
            throw e;
        } catch (final RuntimeException | AssertionError e) {
            this.state = new StateExpect1(this.state.secureRandom(), SMPStatus.CHEATED);
            throw new SMException(e);
        }
    }

    /**
     * Create final message in SMP exchange. Input is a message generated by
     * otrl_sm_step3. Output is a serialized mpi array whose elements correspond
     * to the following: [0] = rb, calculated as (Qa/Qb)^x3 where x3 is the
     * exponent used in g3b [1] = cr, [2] = d7, Bob's ZK proof that rb is formed
     * correctly This method also checks if Alice and Bob's secrets were the
     * same. If so, it returns NO_ERROR. If the secrets differ, an INV_VALUE
     * error is returned instead.
     *
     * @param input The input to SMP step 4. (SMP message 3)
     * @return Returns final response to SMP negotiation.
     * @throws SMException Thrown in case of failure to process SMP message or
     * in case of abort.
     */
    @Nonnull
    byte[] step4(final byte[] input) throws SMException {
        LOGGER.fine("Received final SMP response. Concluding SMP exchange and sending final response.");
        try {
            return this.state.smpMessage3(this, input);
        } catch (final SMAbortedException e) {
            // Let SMAbortedException pass. This exception may at times occur
            // and is a valid interruption that is not considered cheating.
            throw e;
        } catch (final SMException e) {
            this.state = new StateExpect1(this.state.secureRandom(), SMPStatus.CHEATED);
            throw e;
        } catch (final RuntimeException | AssertionError e) {
            this.state = new StateExpect1(this.state.secureRandom(), SMPStatus.CHEATED);
            throw new SMException(e);
        } finally {
            LOGGER.log(Level.FINE, "Final SMP exchange state: {0}", this.state.status().name());
        }
    }

    /**
     * Receives the final SMP message, which was generated in otrl_sm_step. This
     * method checks if Alice and Bob's secrets were the same. If so, it returns
     * NO_ERROR. If the secrets differ, an INV_VALUE error is returned instead.
     *
     * @param input The final SMP message to be received.
     * @throws SMException Thrown in case of failure to process SMP message or in case of abort.
     */
    void step5(final byte[] input) throws SMException {
        LOGGER.fine("Received final SMP response. Concluding SMP exchange.");
        try {
            this.state.smpMessage4(this, input);
        } catch (final SMAbortedException e) {
            // Let SMAbortedException pass. This exception may at times occur
            // and is a valid interruption that is not considered cheating.
            throw e;
        } catch (final SMException e) {
            this.state = new StateExpect1(this.state.secureRandom(), SMPStatus.CHEATED);
            throw e;
        } catch (final RuntimeException | AssertionError e) {
            this.state = new StateExpect1(this.state.secureRandom(), SMPStatus.CHEATED);
            throw new SMException(e);
        } finally {
            LOGGER.log(Level.FINE, "Final SMP exchange state: {0}", this.state.status().name());
        }
    }

    @Override
    public void close() {
        this.state.close();
    }
}
