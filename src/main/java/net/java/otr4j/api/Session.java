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

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.concurrent.ThreadSafe;
import java.util.List;
import java.util.Set;

import static net.java.otr4j.util.Objects.requireNonNull;

/**
 * Interface that defines the OTR session.
 * <p>
 * This the primary interface for clients (users of otr4j) to interact with. It provides access to all the (available)
 * OTR functionality. In addition, it manages the session and any (unexpected) state transitions.
 * <p>
 * {@link Session} must be thread-safe.
 */
@ThreadSafe
@SuppressWarnings("PMD.ConstantsInInterface")
public interface Session {

    /**
     * Constants for OTR versions.
     */
    interface Version {

        /**
         * OTR protocol version 1. (Not supported anymore.)
         */
        int ONE = 1;
        /**
         * OTR protocol version 2.
         */
        int TWO = 2;
        /**
         * OTR protocol version 3.
         */
        int THREE = 3;
        /**
         * OTR protocol version 4.
         */
        int FOUR = 4;

        /**
         * Set of all supported OTR protocol versions.
         */
        Set<Integer> SUPPORTED = Set.of(TWO, THREE, FOUR);
    }

    /* Methods that provide session information. */

    /**
     * Get the session ID for the session.
     *
     * @return Returns the session ID.
     */
    @Nonnull
    SessionID getSessionID();

    /**
     * Get current outgoing session's status.
     *
     * @return Returns session status.
     */
    @Nonnull
    SessionStatus getSessionStatus();

    /**
     * Get current session status for a particular receiver instance.
     *
     * @param tag the receiver instance tag
     * @return Returns session status.
     */
    @Nonnull
    SessionStatus getSessionStatus(InstanceTag tag);

    /**
     * Get session policy.
     *
     * @return session policy
     */
    @Nonnull
    OtrPolicy getSessionPolicy();

    /**
     * Get status of offering OTR through whitespace tags.
     *
     * @return Returns status of whitespace offer.
     */
    @SuppressWarnings("unused")
    @Nonnull
    OfferStatus getOfferStatus();

    /**
     * Get protocol version for active session.
     *
     * @return Returns protocol version or 0 in case of no session active.
     */
    int getProtocolVersion();

    /**
     * Get sender instance tag.
     *
     * @return Returns sender instance tag.
     */
    @Nonnull
    InstanceTag getSenderInstanceTag();

    /**
     * Get receiver instance tag.
     *
     * @return Returns receiver instance tag or 0 in case of OTRv2 session /
     * OTRv3 master session instance.
     */
    @Nonnull
    InstanceTag getReceiverInstanceTag();

    /**
     * Get remote's long-term public key.
     *
     * @return Returns long-term public key.
     * @throws OtrException Thrown in case message state is not ENCRYPTED, hence
     * no long-term public key is known.
     */
    @Nonnull
    RemoteInfo getRemoteInfo() throws OtrException;

    /**
     * Get remote's long-term public key.
     *
     * @param tag receiver instance tag
     * @return Returns long-term public key.
     * @throws OtrException Thrown in case message state is not ENCRYPTED, hence no long-term public key is
     * known.
     */
    @Nonnull
    RemoteInfo getRemoteInfo(InstanceTag tag) throws OtrException;

    /**
     * Get list of session instances.
     * <p>
     * Index {@code 0} is guaranteed to contain the master session. Any {@code index > 0} will contain slave instances.
     *
     * @return Returns list of session instances.
     */
    @Nonnull
    List<? extends Session> getInstances();

    /**
     * Get Extra Symmetric Key that is provided by OTRv3 based on the current Session Keys.
     *
     * @return Returns 256-bit (shared) secret that can be used to start an out-of-band confidential communication channel
     * @throws OtrException In case message status is not ENCRYPTED.
     */
    @Nonnull
    byte[] getExtraSymmetricKey() throws OtrException;

    // Methods related to session use and control.

    /**
     * Start a new OTR session.
     *
     * @throws OtrException Throws exception in case failure to inject Query
     * message.
     */
    void startSession() throws OtrException;

    /**
     * Get outgoing session.
     *
     * @return Returns session instance.
     */
    @Nonnull
    Session getOutgoingSession();

    /**
     * Set outgoing session to instance corresponding to specified receiver
     * instance tag.
     *
     * @param tag receiver instance tag
     * @throws java.util.NoSuchElementException In case instance tag cannot be found.
     */
    void setOutgoingSession(InstanceTag tag);

    /**
     * Transform message text to prepare for sending which includes possible
     * OTR facilities. This method assumes no TLVs need to be sent.
     *
     * @param msgText plain message content
     * @return Returns OTR-processed (possibly ENCRYPTED) message content in
     * suitable fragments according to host information on the transport
     * fragmentation.
     * @throws OtrException Thrown in case of problems during transformation.
     */
    @Nonnull
    String[] transformSending(String msgText) throws OtrException;

    /**
     * Transform message text to prepare for sending which includes possible
     * OTR facilities.
     *
     * @param msgText plain message content
     * @param tlvs any TLV records to be packed with the other message contents.
     * @return Returns OTR-processed (possibly ENCRYPTED) message content in
     * suitable fragments according to host information on the transport
     * fragmentation.
     * @throws OtrException Thrown in case of problems during transformation.
     */
    @Nonnull
    String[] transformSending(String msgText, Iterable<TLV> tlvs) throws OtrException;

    /**
     * Transform (OTR encoded) message to plain text message.
     *
     * @param msgText the (possibly encrypted) raw message content
     * @return Returns the plaintext message content.
     * @throws OtrException Thrown in case of problems during transformation.
     */
    @Nonnull
    Msg transformReceiving(String msgText) throws OtrException;

    /**
     * Msg struct to compose aspects of the final message output.
     */
    // TODO consider if this is the ideal way to provide message+instancetag+status, making concrete type Msg part of interface.
    final class Msg {
        /**
         * The status of the session under which the output was produced. This status may be different from the current
         * status of the session, if the message initiated a state change.
         */
        @Nonnull
        public final SessionStatus status;
        /**
         * The instance tag for the instance that processed the message.
         */
        @Nonnull
        public final InstanceTag tag;
        /**
         * The (original/decrypted) message content.
         */
        @Nullable
        public final String content;

        /**
         * Constructor for Msg.
         *
         * @param status the session status of the session that processed the message.
         * @param tag the instance tag of the session that processed the message.
         * @param content String content(-body). This is the message, whether the full original content because it was
         * plaintext or the decrypted content.
         */
        public Msg(@Nonnull final SessionStatus status, @Nonnull final InstanceTag tag, @Nullable final String content) {
            this.status = requireNonNull(status);
            this.tag = requireNonNull(tag);
            this.content = content;
        }
    }

    /**
     * Refresh an existing OTR session, i.e. perform new AKE. If sufficient
     * information is available about the protocol capabilities of the other
     * party, then we will immediately send an D-H Commit message with the
     * receiver instance tag set to speed up the process and to avoid other
     * instances from being triggered to start AKE.
     *
     * @throws OtrException In case of failed refresh.
     */
    void refreshSession() throws OtrException;

    /**
     * End ENCRYPTED session.
     *
     * @throws OtrException in case of failure to inject OTR message to inform
     * counter party. (The transition to PLAINTEXT will
     * happen regardless.)
     */
    void endSession() throws OtrException;

    // Methods related to zero-knowledge-based authentication.

    /**
     * Initiate a new SMP negotiation by providing an optional question and a secret.
     *
     * @param question The optional question, may be null.
     * @param secret The secret that we should verify the other side knows about.
     * @throws OtrException In case of failure during initiation.
     */
    void initSmp(@Nullable String question, String secret) throws OtrException;

    /**
     * Respond to an SMP request for a specific receiver instance tag.
     *
     * @param receiverTag receiver instance tag
     * @param question The question
     * @param secret The secret
     * @throws OtrException In case of failure during response.
     */
    @SuppressWarnings("unused")
    void respondSmp(InstanceTag receiverTag, @Nullable String question, String secret) throws OtrException;

    /**
     * Respond to an SMP request for a specific receiver instance tag.
     *
     * @param question The question
     * @param secret The secret
     * @throws OtrException In case of failure during response.
     */
    void respondSmp(@Nullable String question, String secret) throws OtrException;

    /**
     * Abort a running SMP negotiation.
     *
     * @throws OtrException In case session is not in ENCRYPTED message state.
     */
    void abortSmp() throws OtrException;

    /**
     * Query if SMP is in progress.
     *
     * @return Returns true if in progress, or false otherwise.
     */
    @CheckReturnValue
    boolean isSmpInProgress();

    // Methods related to registering OTR engine listeners.

    /**
     * Register OTR engine listener.
     *
     * @param l OTR engine listener instance.
     */
    void addOtrEngineListener(OtrEngineListener l);

    /**
     * Unregister OTR engine listener.
     *
     * @param l OTR engine listener instance.
     */
    @SuppressWarnings("unused")
    void removeOtrEngineListener(OtrEngineListener l);
}
