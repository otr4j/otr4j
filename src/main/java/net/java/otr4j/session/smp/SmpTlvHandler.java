/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.session.smp;

import com.google.errorprone.annotations.CheckReturnValue;
import net.java.otr4j.api.Event;
import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.api.OtrEngineHost;
import net.java.otr4j.api.OtrException;
import net.java.otr4j.api.SessionID;
import net.java.otr4j.api.TLV;
import net.java.otr4j.crypto.SharedSecret;
import net.java.otr4j.session.api.SMPHandler;
import net.java.otr4j.session.api.SMPStatus;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.security.SecureRandom;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Objects.requireNonNull;
import static net.java.otr4j.api.OtrEngineHosts.handleEvent;
import static net.java.otr4j.crypto.OtrCryptoEngine.sha256Hash;
import static net.java.otr4j.session.api.SMPStatus.INPROGRESS;
import static net.java.otr4j.session.api.SMPStatus.SUCCEEDED;

/**
 * SMP TLV Handler handles any interaction w.r.t. mutual authentication using
 * SMP (Socialist Millionaires Protocol).
 *
 * @author Danny van Heumen
 */
public final class SmpTlvHandler implements SMPHandler, AutoCloseable {

    private static final byte[] VERSION_BYTE = {1};

    /**
     * The message contains a step in the Socialist Millionaires' Protocol.
     */
    private static final int SMP1 = 0x0002;
    /**
     * The message contains a step in the Socialist Millionaires' Protocol.
     */
    private static final int SMP2 = 0x0003;
    /**
     * The message contains a step in the Socialist Millionaires' Protocol.
     */
    private static final int SMP3 = 0x0004;
    /**
     * The message contains a step in the Socialist Millionaires' Protocol.
     */
    private static final int SMP4 = 0x0005;
    /**
     * The message indicates any in-progress SMP session must be aborted.
     */
    private static final int SMP_ABORT = 0x0006;
    /**
     * Like SMP1, but there's a question for the buddy at the beginning.
     */
    private static final int SMP1Q = 0x0007;

    private final OtrEngineHost host;
    private final SessionID sessionID;
    private final byte[] localFingerprint;
    private final byte[] remoteFingerprint;
    private final SharedSecret s;
    private final SM sm;
    private final InstanceTag receiverTag;

    /**
     * Construct an OTR Socialist Millionaire handler object.
     *
     * @param random SecureRandom instance
     * @param sessionID session ID
     * @param localFingerprint the fingerprint of the local public key
     * @param remoteFingerprint the fingerprint of the remote public key
     * @param receiverTag the receiver instance tag for this SMP session
     * @param host the OTR engine host
     * @param s the session's shared secret
     */
    public SmpTlvHandler(final SecureRandom random, final SessionID sessionID, final byte[] localFingerprint,
            final byte[] remoteFingerprint, final InstanceTag receiverTag, final OtrEngineHost host,
            final SharedSecret s) {
        this.sessionID = requireNonNull(sessionID);
        this.localFingerprint = requireNonNull(localFingerprint);
        this.remoteFingerprint = requireNonNull(remoteFingerprint);
        this.s = requireNonNull(s);
        this.host = requireNonNull(host);
        this.sm = new SM(random);
        this.receiverTag = requireNonNull(receiverTag);
    }

    /**
     * Check if TLV is an SMP TLV payload.
     *
     * @param tlv TLV
     * @return Returns true iff TLV contains SMP payload.
     */
    @CheckReturnValue
    public static boolean smpPayload(final TLV tlv) {
        return tlv.type == SMP1 || tlv.type == SMP1Q || tlv.type == SMP2 || tlv.type == SMP3 || tlv.type == SMP4
                || tlv.type == SMP_ABORT;
    }

    @Nonnull
    @Override
    public TLV initiate(final String question, final byte[] answer) throws OtrException {
        final byte[] secret = generateSecret(answer, this.localFingerprint, this.remoteFingerprint);
        try {
            final byte[] smpmsg = this.sm.step1(secret);
            if (question.isEmpty()) {
                return new TLV(SMP1, smpmsg);
            }
            // A question needs to be attached to the SMP message.
            final byte[] questionBytes = question.getBytes(UTF_8);
            final byte[] questionSmpmsg = new byte[questionBytes.length + 1 + smpmsg.length];
            System.arraycopy(questionBytes, 0, questionSmpmsg, 0, questionBytes.length);
            System.arraycopy(smpmsg, 0, questionSmpmsg, questionBytes.length + 1, smpmsg.length);
            return new TLV(SMP1Q, questionSmpmsg);
        } catch (final SMAbortedException e) {
            // As prescribed by OTR, we must always be allowed to initiate a new SMP exchange. In case another SMP
            // exchange is in progress, an abort is signaled. We honor the abort exception and send the abort signal
            // to the counter party. Then we immediately initiate a new SMP exchange as requested.
            handleEvent(this.host, this.sessionID, this.receiverTag, Event.SMP_ABORTED, Event.AbortReason.INTERRUPTION);
            return new TLV(SMP_ABORT, TLV.EMPTY_BODY);
        } catch (final SMException e) {
            throw new OtrException("Failed to initiate SMP negotiation.", e);
        }
    }

    @Nonnull
    @Override
    public TLV respond(final String question, final byte[] answer) throws OtrException {
        if (this.sm.status() != INPROGRESS) {
            throw new OtrException("There is no question to be answered.");
        }
        final byte[] secret = generateSecret(answer, this.remoteFingerprint, this.localFingerprint);
        try {
            return new TLV(SMP2, this.sm.step2b(secret));
        } catch (final SMAbortedException e) {
            // As prescribed by OTR, we must always be allowed to initiate a new SMP exchange. In case another SMP
            // exchange is in progress, an abort is signaled. We honor the abort exception and send the abort signal
            // to the counter party. Then we immediately initiate a new SMP exchange as requested.
            handleEvent(this.host, this.sessionID, this.receiverTag, Event.SMP_ABORTED, Event.AbortReason.INTERRUPTION);
            return new TLV(SMP_ABORT, TLV.EMPTY_BODY);
        } catch (final SMException e) {
            throw new OtrException("Failed to respond to SMP with answer to the question.", e);
        }
    }

    /**
     * Construct the combined secret as a SHA-256 hash of:
     * <ol>
     * <li>Version byte (0x01)</li>
     * <li>Initiator fingerprint</li>
     * <li>Responder fingerprint</li>
     * <li>Secure session id a.k.a. SSID</li>
     * <li>secret answer</li>
     * </ol>
     *
     * @param answer the answer of the local user
     * @return Returns the generated secret MPI to be used in SMP.
     */
    private byte[] generateSecret(final byte[] answer, final byte[] initiatorFingerprint,
            final byte[] responderFingerprint) {
        return sha256Hash(VERSION_BYTE, initiatorFingerprint, responderFingerprint, this.s.ssid(), answer);
    }

    @Nonnull
    @Override
    public TLV abort() {
        if (this.sm.abort()) {
            handleEvent(this.host, this.sessionID, this.receiverTag, Event.SMP_ABORTED, Event.AbortReason.USER);
        }
        return new TLV(SMP_ABORT, TLV.EMPTY_BODY);
    }

    @Override
    public boolean smpAbortedTLV(final TLV tlv) {
        return tlv.type == SMP_ABORT;
    }

    @Nonnull
    @Override
    public SMPStatus getStatus() {
        return this.sm.status();
    }

    /**
     * Process TLV payload intended for SMP.
     *
     * @param tlv the payload
     * @return Returns response to provided payload.
     * @throws SMException In case of failure to process TLV.
     */
    @Nullable
    public TLV process(final TLV tlv) throws SMException {
        try {
            switch (tlv.type) {
            case SMP_ABORT:
                abort();
                return null;
            case SMP1:
                return processTlvSMP1(tlv);
            case SMP1Q:
                return processTlvSMP1Q(tlv);
            case SMP2:
                return processTlvSMP2(tlv);
            case SMP3:
                return processTlvSMP3(tlv);
            case SMP4:
                return processTlvSMP4(tlv);
            default:
                throw new IllegalStateException("Unknown SMP TLV type: " + tlv.type + ". Cannot process this TLV.");
            }
        } catch (final SMAbortedException e) {
            handleEvent(this.host, this.sessionID, this.receiverTag, Event.SMP_ABORTED, Event.AbortReason.INTERRUPTION);
            return new TLV(SMP_ABORT, TLV.EMPTY_BODY);
        } catch (final SMException e) {
            handleEvent(this.host, this.sessionID, this.receiverTag, Event.SMP_ABORTED, Event.AbortReason.VIOLATION);
            throw e;
        }
    }

    @Nullable
    private TLV processTlvSMP1Q(final TLV tlv) throws SMException {
        // We can only do the verification half now.
        // We must wait for the secret to be entered
        // to continue.
        final byte[] question = tlv.value;
        int qlen = 0;
        while (qlen != question.length && question[qlen] != 0) {
            qlen++;
        }
        if (qlen == question.length) {
            qlen = 0;
        } else {
            qlen++;
        }
        final byte[] input = new byte[question.length - qlen];
        System.arraycopy(question, qlen, input, 0, question.length - qlen);
        this.sm.step2a(input);
        if (qlen != 0) {
            qlen--;
        }
        final byte[] plainq = new byte[qlen];
        System.arraycopy(question, 0, plainq, 0, qlen);
        handleEvent(this.host, this.sessionID, this.receiverTag, Event.SMP_REQUEST_SECRET, new String(plainq, UTF_8));
        return null;
    }

    @Nullable
    private TLV processTlvSMP1(final TLV tlv) throws SMException {
        // We can only do the verification half now. We must wait for the secret to be entered to continue.
        this.sm.step2a(tlv.value);
        handleEvent(this.host, this.sessionID, this.receiverTag, Event.SMP_REQUEST_SECRET, "");
        return null;
    }

    @Nonnull
    private TLV processTlvSMP2(final TLV tlv) throws SMException {
        final byte[] nextmsg = this.sm.step3(tlv.value);
        return new TLV(SMP3, nextmsg);
    }

    @Nonnull
    private TLV processTlvSMP3(final TLV tlv) throws SMException {
        final byte[] nextmsg = this.sm.step4(tlv.value);
        // Set trust level based on result.
        final Event.SMPResult result = new Event.SMPResult(this.sm.status() == SUCCEEDED, this.remoteFingerprint);
        handleEvent(this.host, this.sessionID, this.receiverTag, Event.SMP_COMPLETED, result);
        return new TLV(SMP4, nextmsg);
    }

    @Nullable
    private TLV processTlvSMP4(final TLV tlv) throws SMException {
        this.sm.step5(tlv.value);
        final Event.SMPResult result = new Event.SMPResult(this.sm.status() == SUCCEEDED, this.remoteFingerprint);
        handleEvent(this.host, this.sessionID, this.receiverTag, Event.SMP_COMPLETED, result);
        return null;
    }

    @Override
    public void close() {
        this.s.close();
        this.sm.close();
    }
}
