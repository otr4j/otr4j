/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.api;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.concurrent.ThreadSafe;
import java.util.List;

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
@SuppressWarnings({"PMD.ConstantsInInterface", "unused"})
public interface Session {

    /* Methods that provide session information. */

    /**
     * Get the session ID for the session.
     *
     * @return Returns the session ID.
     */
    @Nonnull
    SessionID getSessionID();

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
    @Nonnull
    OfferStatus getOfferStatus();

    /**
     * Get protocol version for active session.
     *
     * @return Returns protocol version or 0 in case of no session active.
     */
    @Nonnull
    Version getProtocolVersion();

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
     * Get a specific session instance as specified by the provided tag.
     *
     * @param receiverTag the receiver instance tag
     * @return Returns the outgoing session for the specified tag.
     */
    @Nullable
    Instance getInstance(InstanceTag receiverTag);

    /**
     * Get list of session instances.
     * <p>
     * Index {@code 0} is guaranteed to contain the master session. Any {@code index > 0} will contain slave instances.
     *
     * @return Returns list of session instances.
     */
    @Nonnull
    List<? extends Instance> getInstances();

    // Methods related to session use and control.

    /**
     * Start a new OTR session.
     *
     * @throws OtrException Throws exception in case failure to inject Query
     * message.
     */
    // TODO right now we allow starting a new session even though existing encrypted sessions exist. This was previously not allowed. This isn't a problem per se, because it is possible that starting a new session means that more clients can be upgraded to encrypted sessions, but this isn't the behavior as it was before. Additionally, we should check whether this means that the message interferes with existing encrypted sessions.
    void startSession() throws OtrException;

    /**
     * Transform (OTR encoded) message to plain text message.
     *
     * @param msgText the (possibly encrypted) raw message content
     * @return Returns the plaintext message content.
     * @throws OtrException Thrown in case of problems during transformation.
     */
    @Nonnull
    Result transformReceiving(String msgText) throws OtrException;

    /**
     * Result struct to compose parts of the final (transformation) result.
     */
    final class Result {
        /**
         * The instance tag for the instance that processed the message.
         */
        @Nonnull
        public final InstanceTag tag;
        /**
         * The status of the session state under which the output was produced. This status may be different from the
         * current status of the session, if the message initiated a state transition.
         */
        @Nonnull
        public final SessionStatus status;
        /**
         * Rejected, whether message processing was aborted due to being irrelevant or illegal.
         */
        public final boolean rejected;
        /**
         * Confidential, whether the message was received confidentially or in plaintext.
         */
        public final boolean confidential;
        /**
         * The (original/decrypted) message content. The content is `null` if there was no message, or if the message
         * was an OTR protocol control message processed internally, or if message was a fragment and a complete message
         * could not yet be reconstructed, or if the message was rejected for reasons good (e.g. message intended for
         * other instance) or bad (message is illegal, violates protocol).
         */
        @Nullable
        public final String content;

        /**
         * Constructor for Result.
         *
         * @param tag the instance tag of the session that processed the message.
         * @param status the session status of the session state that processed the message.
         * @param rejected whether the result is due to the message being rejected by the protocol.
         * @param confidential whether the content was received confidentially or in plaintext.
         * @param content String content(-body). This is the message, whether the full original content because it was
         * plaintext or the decrypted content.
         */
        public Result(final InstanceTag tag, final SessionStatus status, final boolean rejected,
                final boolean confidential, @Nullable final String content) {
            this.tag = requireNonNull(tag);
            this.status = requireNonNull(status);
            this.rejected = rejected;
            this.confidential = confidential;
            this.content = content;
        }
    }
    
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
    void removeOtrEngineListener(OtrEngineListener l);
}
