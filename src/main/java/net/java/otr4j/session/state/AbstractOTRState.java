/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.session.state;

import com.google.errorprone.annotations.ForOverride;
import net.java.otr4j.api.OtrException;
import net.java.otr4j.api.OtrPolicy;
import net.java.otr4j.api.SessionID;
import net.java.otr4j.api.Version;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.messages.AbstractEncodedMessage;
import net.java.otr4j.messages.DHCommitMessage;
import net.java.otr4j.messages.DHKeyMessage;
import net.java.otr4j.messages.DataMessage;
import net.java.otr4j.messages.DataMessage4;
import net.java.otr4j.messages.IdentityMessage;
import net.java.otr4j.messages.RevealSignatureMessage;
import net.java.otr4j.messages.SignatureMessage;
import net.java.otr4j.session.ake.AuthState;
import net.java.otr4j.session.dake.DAKEState;
import net.java.otr4j.session.dake.SecurityParameters4;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.net.ProtocolException;
import java.util.logging.Level;
import java.util.logging.Logger;

import static java.util.Objects.requireNonNull;
import static java.util.logging.Level.FINEST;
import static java.util.logging.Level.INFO;
import static net.java.otr4j.api.InstanceTag.ZERO_TAG;
import static net.java.otr4j.api.SessionStatus.ENCRYPTED;
import static net.java.otr4j.session.state.Contexts.signalUnreadableMessage;
import static net.java.otr4j.util.Objects.requireEquals;

/**
 * Abstract base implementation for session state implementations.
 * <p>
 * This abstract base implementation focuses on providing a general mechanism for handling authentication (AKE) message
 * and state handling. Anything that is not AKE-related will be deferred to the state implementation subclass.
 *
 * @author Danny van Heumen
 */
abstract class AbstractOTRState implements State {

    private static final Logger LOGGER = Logger.getLogger(AbstractOTRState.class.getName());

    /**
     * State-management for the AKE negotiation.
     */
    @Nonnull
    private AuthState authState;

    /**
     * State-management for the DAKE negotiation.
     */
    @Nonnull
    private DAKEState dakeState;

    AbstractOTRState(final AuthState authState, final DAKEState dakeState) {
        this.authState = requireNonNull(authState);
        this.dakeState = requireNonNull(dakeState);
    }

    @Nonnull
    @Override
    public AuthState getAuthState() {
        return this.authState;
    }

    @Override
    public void setAuthState(final AuthState state) {
        LOGGER.log(Level.FINE, "Transitioning authentication state to {0}", state);
        this.authState = requireNonNull(state);
    }

    @Nonnull
    @Override
    public DAKEState getDAKEState() {
        return this.dakeState;
    }

    @Override
    public void setDAKEState(final DAKEState state) {
        LOGGER.log(Level.FINE, "Transitioning DAKE state to {0}", state);
        this.dakeState = requireNonNull(state);
    }

    /**
     * Handle the received data message in OTRv2/OTRv3 format.
     *
     * @param message The received data message.
     * @return Returns the decrypted message text.
     * @throws ProtocolException In case of I/O reading fails.
     * @throws OtrException      In case an exception occurs.
     */
    @ForOverride
    @Nonnull
    abstract Result handleDataMessage(Context context, DataMessage message) throws ProtocolException, OtrException;

    /**
     * Handle the received data message in OTRv4 format.
     *
     * @param message The received data message.
     * @return Returns the decrypted message text.
     * @throws ProtocolException In case of I/O reading failures.
     * @throws OtrException      In case of failures regarding the OTR protocol (implementation).
     */
    @ForOverride
    @Nonnull
    abstract Result handleDataMessage(Context context, DataMessage4 message) throws ProtocolException, OtrException;

    @Nullable
    private AbstractEncodedMessage handleAKEMessage(final Context context, final AbstractEncodedMessage message) {
        if (!(message instanceof DHCommitMessage || message instanceof DHKeyMessage
                || message instanceof SignatureMessage || message instanceof RevealSignatureMessage)) {
            throw new UnsupportedOperationException("Only OTRv2/OTRv3 AKE messages are supported.");
        }
        final SessionID sessionID = context.getSessionID();
        LOGGER.log(FINEST, "{0} received an AKE message from {1} through {2}.",
                new Object[]{sessionID.getAccountID(), sessionID.getUserID(), sessionID.getProtocolName()});
        // Verify that we received an AKE message using the previously agreed upon protocol version. Exception to this
        // rule for DH Commit message, as this message initiates a new AKE negotiation and thus proposes a new protocol
        // version corresponding to the message's intention.
        if (!(message instanceof DHCommitMessage) && !(message instanceof DHKeyMessage)
                && message.protocolVersion != this.authState.getVersion()) {
            LOGGER.log(INFO, "AKE message containing unexpected protocol version encountered. ({0} instead of {1}.) Ignoring.",
                    new Object[]{message.protocolVersion, this.authState.getVersion()});
            return null;
        }
        LOGGER.log(FINEST, "Handling AKE message in state {0}", this.authState.getClass().getName());
        try {
            final AuthState.Result result = this.authState.handle(context, message);
            if (result.params != null) {
                context.transition(this, new StateEncrypted3(context, this.authState, this.dakeState, result.params));
                if (context.getSessionStatus() != ENCRYPTED) {
                    throw new IllegalStateException("Session failed to transition to ENCRYPTED. (OTRv2/OTRv3)");
                }
                LOGGER.info("Session secured. Message state transitioned to ENCRYPTED. (OTRv2/OTRv3)");
            }
            return result.response;
        } catch (final ProtocolException e) {
            LOGGER.log(FINEST, "Ignoring message. Bad message content / incomplete message received.", e);
            return null;
        } catch (final OtrCryptoException e) {
            LOGGER.log(FINEST, "Ignoring message. Exception while processing message due to cryptographic verification failure.", e);
            return null;
        } catch (final OtrException e) {
            LOGGER.log(FINEST, "Ignoring message. Exception while processing message due to non-cryptographic error.", e);
            return null;
        }
    }

    @Nonnull
    protected final Result handleEncodedMessage3(final Context context, final AbstractEncodedMessage message)
            throws OtrException, ProtocolException {
        if (message.protocolVersion != Version.TWO && message.protocolVersion != Version.THREE) {
            throw new IllegalArgumentException("Illegal version");
        }
        assert !message.receiverTag.equals(ZERO_TAG) || message instanceof DHCommitMessage
                : "BUG: receiver instance should be set for anything other than the first AKE message.";
        final SessionID sessionID = context.getSessionID();
        if (message instanceof DataMessage) {
            LOGGER.log(FINEST, "{0} received a data message (OTRv2/OTRv3) from {1}, handling in state {2}.",
                    new Object[]{sessionID.getAccountID(), sessionID.getUserID(), this.getClass().getName()});
            return handleDataMessage(context, (DataMessage) message);
        }
        // Check if policy allows handling message according to protocol version. (Always allow handling data-message as
        // not to interfere with ongoing sessions.)
        final OtrPolicy policy = context.getSessionPolicy();
        if (message.protocolVersion == Version.TWO && !policy.isAllowV2()) {
            LOGGER.finest("ALLOW_V2 is not set, ignore this message.");
            return new Result(getStatus(), true, false, null);
        }
        if (message.protocolVersion == Version.THREE && !policy.isAllowV3()) {
            LOGGER.finest("ALLOW_V3 is not set, ignore this message.");
            return new Result(getStatus(), true, false, null);
        }
        // Anything that is not a Data message is some type of AKE message.
        final AbstractEncodedMessage reply = handleAKEMessage(context, message);
        if (reply != null) {
            context.injectMessage(reply);
        }
        return new Result(getStatus(), false, false, null);
    }

    @Nonnull
    protected final Result handleEncodedMessage4(final Context context, final AbstractEncodedMessage message) throws ProtocolException, OtrException {
        requireEquals(Version.FOUR, message.protocolVersion, "Encoded message must be part of protocol 4.");
        assert !message.receiverTag.equals(ZERO_TAG) || message instanceof IdentityMessage
                : "BUG: receiver instance should be set for anything other than the first AKE message.";
        final SessionID sessionID = context.getSessionID();
        if (message instanceof DataMessage4) {
            LOGGER.log(FINEST, "{0} received a data message (OTRv4) from {1}, handling in state {2}.",
                    new Object[]{sessionID.getAccountID(), sessionID.getUserID(), this.getClass().getName()});
            return handleDataMessage(context, (DataMessage4) message);
        }
        // Check policy before initiating OTRv4 DAKE. (For now, always handling data-message as a session may be in
        // progress.)
        final OtrPolicy policy = context.getSessionPolicy();
        if (message.protocolVersion == Version.FOUR && !policy.isAllowV4()) {
            LOGGER.finest("ALLOW_V4 is not set, ignore this message.");
            return new Result(getStatus(), true, false, null);
        }
        // OTRv4 messages that are not data messages, should therefore be DAKE messages.
        final DAKEState.Result result = this.dakeState.handle(context, message);
        if (result.params != null) {
            secure(context, result.params);
        }
        if (result.response != null) {
            context.injectMessage(result.response);
        }
        return new Result(getStatus(), false, false, null);
    }

    @Override
    public void initiateAKE(final Context context, final Version version) throws OtrException {
        LOGGER.log(Level.FINE, "Initiating AKE…");
        switch (version) {
        case ONE:
            throw new IllegalArgumentException("BUG: request for OTRv1 AKE");
        case TWO:
        case THREE:
            context.injectMessage(this.authState.initiate(context, version));
            break;
        case FOUR:
            context.injectMessage(this.dakeState.initiate(context, version));
            break;
        default:
            throw new IllegalArgumentException("Unknown/unsupported protocol version");
        }
    }

    /**
     * Secure existing session, i.e. transition to `ENCRYPTED_MESSAGES`. This ensures that, apart from transitioning to
     * the encrypted messages state, that we also set the default outgoing session to this instance, if the current
     * outgoing session is not secured yet.
     *
     * @param context the session context
     * @param params the OTRv4 variation of the necessary security parameters
     */
    private void secure(final Context context, final SecurityParameters4 params) {
        final DoubleRatchet ratchet;
        switch (params.ratchet.nextRotation()) {
        case RECEIVING:
            ratchet = params.ratchet;
            break;
        case SENDING:
            // Note: immediately rotate sender-keys as we need both sides to be able to send messages from the start of
            // the session. This was previously done within the DAKE state-machine, but now moved one step away to the
            // transition to the OTRv4 secure message-state.
            ratchet = params.ratchet.rotateSenderKeys();
            break;
        default:
            throw new IllegalArgumentException("BUG: unsupported purpose specified.");
        }
        context.transition(this, new StateEncrypted4(context, params.ssid, ratchet, params.longTermKey,
                params.forgingKey, params.other, this.authState, this.dakeState));
        if (context.getSessionStatus() != ENCRYPTED) {
            throw new IllegalStateException("Session failed to transition to ENCRYPTED (OTRv4).");
        }
        LOGGER.info("Session secured. Message state transitioned to ENCRYPTED. (OTRv4)");
    }

    /**
     * Handle any OTR2/3 unreadable data-message.
     *
     * @param context the context
     * @param message the unreadable data-message
     * @param error the error message to feed back to the user
     * @throws OtrException in case of failure to signal about the unreadable message
     */
    final void handleUnreadableMessage(final Context context, final DataMessage message, final String error)
            throws OtrException {
        if ((message.flags & FLAG_IGNORE_UNREADABLE) != 0) {
            LOGGER.fine("Unreadable message received with IGNORE_UNREADABLE flag set. Ignoring silently.");
            return;
        }
        signalUnreadableMessage(context, "", error);
    }

    /**
     * Handle any OTRv4 unreadable data-message.
     *
     * @param context the context
     * @param message the unreadable data-message
     * @param identifier the error identifier (introduced in OTRV4)
     * @param error the error message to feed back to the user
     * @throws OtrException in case of failure to signal about the unreadable message
     */
    final void handleUnreadableMessage(final Context context, final DataMessage4 message, final String identifier,
            final String error) throws OtrException {
        if ((message.flags & FLAG_IGNORE_UNREADABLE) != 0) {
            // TODO consider detecting (and logging) whether revealed MAC-keys are non-empty. This concerns the issue with OTRv4 (also v3?) spec which mentions that when the other party receives a DISCONNECT-TLV, they end the session, but this means that they do not reveal present MAC keys to be revealed of our previous messages. Logging this allows us to check that the other party acts properly. That is, if we accept that as part of the spec.
            LOGGER.fine("Unreadable message received with IGNORE_UNREADABLE flag set. Ignoring silently.");
            return;
        }
        signalUnreadableMessage(context, identifier, error);
    }
}
