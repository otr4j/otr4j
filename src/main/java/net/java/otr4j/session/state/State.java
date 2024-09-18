/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.session.state;

import net.java.otr4j.api.Event;
import net.java.otr4j.api.OtrException;
import net.java.otr4j.api.RemoteInfo;
import net.java.otr4j.api.SessionStatus;
import net.java.otr4j.api.TLV;
import net.java.otr4j.api.Version;
import net.java.otr4j.io.Message;
import net.java.otr4j.io.PlainTextMessage;
import net.java.otr4j.messages.AbstractEncodedMessage;
import net.java.otr4j.session.ake.AuthState;
import net.java.otr4j.session.api.SMPHandler;
import net.java.otr4j.session.dake.DAKEState;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.net.ProtocolException;

import static net.java.otr4j.api.OtrEngineHosts.handleEvent;
import static net.java.otr4j.util.Objects.requireNonNull;

/**
 * Interface to the (Session) Messaging-state.
 */
public interface State {

    /**
     * Constant to indicate that no flag bit is set.
     */
    byte FLAG_NONE = 0x00;

    /**
     * Constant for the flag IGNORE_UNREADABLE, which is used to indicate that if such a flagged message cannot be read,
     * we do not need to respond with an error message.
     */
    byte FLAG_IGNORE_UNREADABLE = 0x01;

    /**
     * Get active protocol version.
     *
     * @return Returns protocol version that is active in this session state.
     * (0 for plaintext/finished, OTR version for ENCRYPTED message state.)
     */
    @Nonnull
    Version getVersion();

    /**
     * Get session status for currently active session.
     *
     * @return Returns session status.
     */
    @Nonnull
    SessionStatus getStatus();

    /**
     * getRemoteInfo provides a RemoteInfo object that contains information about the established OTR session about the
     * other party.
     *
     * @return Returns RemoteInfo with information on the other party. (on the remote end)
     * @throws IncorrectStateException thrown in case no OTR session has been established (yet).
     */
    @Nonnull
    RemoteInfo getRemoteInfo() throws IncorrectStateException;

    /**
     * Acquire the extra symmetric key for this session.
     *
     * @return Returns the extra symmetric key that is derived from the
     * session's shared secret.
     * @throws IncorrectStateException Throws exception in case of incorrect
     * state, i.e. a different state than ENCRYPTED.
     */
    @Nonnull
    byte[] getExtraSymmetricKey() throws IncorrectStateException;

    /**
     * Transforms a message ready to be sent given the current session state of
     * OTR.
     *
     * @param context The message state context.
     * @param msgText The message ready to be sent.
     * @param tlvs TLVs.
     * @param flags (Encoded) message flags, see constants in {@link State}, such as {@link #FLAG_IGNORE_UNREADABLE}.
     * @return Returns message to be sent over IM transport.
     * @throws OtrException In case an exception occurs.
     */
    @Nullable
    default Message transformSending(final Context context, final String msgText, final Iterable<TLV> tlvs,
            final byte flags) throws OtrException {
        handleEvent(context.getHost(), context.getSessionID(), context.getReceiverInstanceTag(),
                Event.ENCRYPTED_MESSAGES_REQUIRED, msgText);
        return null;
    }

    /**
     * Handle the received plaintext message.
     *
     * @param context The message state context.
     * @param plainTextMessage The received plaintext message.
     * @return Returns the cleaned plaintext message. (The message excluding
     * possible whitespace tags or other OTR artifacts.)
     */
    @Nonnull
    Result handlePlainTextMessage(Context context, PlainTextMessage plainTextMessage);

    /**
     * Handle the received encoded message.
     * <p>
     * Note: avoid implementing this in any abstract state. Leave this entry-point to the concrete implementations, such
     * that they have full control over which messages are allowed processing and which are dropped. For example, drop
     * OTRv3 (AKE) messages in {@link StateEncrypted4}.
     *
     * @param context The message state context.
     * @param message the encoded message
     * @return Returns decoded, decrypted plaintext message payload, if exists, or {@code null} otherwise.
     * @throws OtrException In case of failure to process encoded message.
     * @throws ProtocolException In case of bad input data resulting in an unsound message.
     */
    @Nonnull
    Result handleEncodedMessage(Context context, AbstractEncodedMessage message) throws ProtocolException, OtrException;

    /**
     * Result contains the multi-field result of message processing in the state instance.
     */
    final class Result {
        /**
         * Status indicates the status of the state in which processing happened.
         */
        @Nonnull
        public final SessionStatus status;
        /**
         * Rejected indicates whether processing was aborted due to the message being irrelevant or illegal.
         */
        public final boolean rejected;
        /**
         * Whether the message was received confidentially or in plaintext.
         */
        public final boolean confidential;
        /**
         * Content is the message content. (Optional)
         */
        @Nullable
        public final String content;

        /**
         * Constructor for the session result.
         *
         * @param status the status of the processing state
         * @param content the content
         */
        Result(final SessionStatus status, final boolean rejected, final boolean confidential,
                @Nullable final String content) {
            this.status = requireNonNull(status);
            this.rejected = rejected;
            this.confidential = confidential;
            this.content = content;
        }
    }

    /**
     * Get current authentication state from the AKE state machine.
     *
     * @return current authentication state
     */
    @Nonnull
    AuthState getAuthState();

    /**
     * Set authentication state for the AKE state machine.
     *
     * @param state the new authentication state
     */
    void setAuthState(AuthState state);

    /**
     * Get the current interactive DAKE state.
     *
     * @return the DAKE state instance
     */
    @Nonnull
    DAKEState getDAKEState();

    /**
     * Set the new interactive DAKE state.
     *
     * @param state the new DAKE state
     */
    void setDAKEState(DAKEState state);

    /**
     * Initiate AKE.
     *
     * @param context The message state context.
     * @param version the protocol version
     * @throws OtrException In case of failure to inject message into network.
     */
    void initiateAKE(Context context, Version version) throws OtrException;

    /**
     * Call to end encrypted session, if any.
     * <p>
     * In case an encrypted session is established, this is the moment where the final MAC codes are revealed as part of
     * the TLV DISCONNECT message.
     *
     * @param context The message state context.
     * @throws OtrException In case an exception occurs.
     */
    void end(Context context) throws OtrException;

    /**
     * Expire the current state.
     * <p>
     * This assumes that there is such a concept of 'expiration' for this state. If there is, perform the necessary
     * steps to expire the state. If there is not, throw {@link IncorrectStateException} to indicate as such.
     *
     * @param context the session state context
     * @throws OtrException Thrown in case of failure during expiration of the state. (Or in the most benign case,
     * {@link IncorrectStateException} is thrown to indicate expiration is not applicable to this
     * state.
     */
    default void expire(final Context context) throws OtrException {
        throw new IncorrectStateException("State " + this.getClass().getName() + " does not expire.");
    }

    /**
     * Get SMP TLV handler for use in SMP negotiations.
     * <p>
     * The handler is only available in Encrypted states. In case another state
     * is active at time of calling, {@link IncorrectStateException} is thrown.
     *
     * @return Returns SMP TLV handler instance for this encrypted session.
     * @throws IncorrectStateException Throws IncorrectStateException for any
     * non-encrypted states.
     */
    @Nonnull
    SMPHandler getSmpHandler() throws IncorrectStateException;

    /**
     * Securely clear the content of the state after {@link Context#transition(State, State)}-ing away from it.
     */
    void destroy();

    /**
     * Get the last moment of activity in this session. (The 'last activity' timestamp is used by the session expiration
     * timer.)
     * <p>
     * This returns a monotonic timestamp (according to {@link System#nanoTime()} that can be used to determine how
     * much time has elapsed between events.
     * <p>
     * The exact semantics of "last activity" is determined by the implementing state and may vary per state and
     * protocol version. Each state may choose their timestamps such that it most accurately represents relevant
     * activities. (For example, in OTRv4 the rotation of ephemeral secrets are the determining factor. - 2019-02-11)
     *
     * @return Returns monotonic timestamp of last activity. ({@linkplain System#nanoTime()})
     * @throws IncorrectStateException Thrown in case the current state does not have a notion of relevant activity.
     */
    default long getLastActivityTimestamp() throws IncorrectStateException {
        throw new IncorrectStateException("State " + this.getClass().getName() + " does not expire.");
    }

    /**
     * Get the timestamp of the most recently sent data message of this state. (The 'last message sent timestamp' is
     * used by the Heartbeat timer.)
     * <p>
     * This returns a monotonic timestamp (according to {@link System#nanoTime()} that can be used to determine how much
     * time has elapsed between events.
     *
     * @return Returns the monotonic timestamp of most recently sent message. ({@link System#nanoTime()})
     * @throws IncorrectStateException Thrown in case the current state does not do private messaging.
     */
    default long getLastMessageSentTimestamp() throws IncorrectStateException {
        throw new IncorrectStateException("State " + this.getClass().getName() + " is not an encrypted state.");
    }
}
