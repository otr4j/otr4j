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
import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.api.OtrException;
import net.java.otr4j.api.OtrPolicy;
import net.java.otr4j.api.SessionID;
import net.java.otr4j.api.Version;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.io.EncodedMessage;
import net.java.otr4j.messages.AbstractEncodedMessage;
import net.java.otr4j.messages.DHCommitMessage;
import net.java.otr4j.messages.DHKeyMessage;
import net.java.otr4j.messages.DataMessage;
import net.java.otr4j.messages.RevealSignatureMessage;
import net.java.otr4j.messages.SignatureMessage;
import net.java.otr4j.session.ake.AuthState;
import net.java.otr4j.session.ake.SecurityParameters;

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
import static net.java.otr4j.messages.EncodedMessageParser.parseEncodedMessage;

/**
 * Abstract base implementation for session state implementations.
 * <p>
 * This abstract base implementation focuses on providing a general mechanism for handling authentication (AKE) message
 * and state handling. Anything that is not AKE-related will be deferred to the state implementation subclass.
 *
 * @author Danny van Heumen
 */
abstract class AbstractOTR3State implements State {

    private static final Logger LOGGER = Logger.getLogger(AbstractOTR3State.class.getName());

    /**
     * State management for the AKE negotiation.
     */
    @Nonnull
    private AuthState authState;

    AbstractOTR3State(final AuthState authState) {
        this.authState = requireNonNull(authState);
    }

    @Nonnull
    @Override
    public AuthState getAuthState() {
        return this.authState;
    }

    @Override
    public void setAuthState(final AuthState state) {
        LOGGER.fine("Transitioning authentication state to " + state);
        this.authState = requireNonNull(state);
    }

    @Nonnull
    Result handleEncodedMessage3(final Context context, final EncodedMessage message) throws OtrException, ProtocolException {
        if (message.version != Version.TWO && message.version != Version.THREE) {
            throw new IllegalArgumentException("Illegal version");
        }
        final AbstractEncodedMessage encodedM = parseEncodedMessage(message);
        assert !encodedM.receiverTag.equals(ZERO_TAG) || encodedM instanceof DHCommitMessage
                : "BUG: receiver instance should be set for anything other than the first AKE message.";
        // TODO We've started replicating current authState in *all* cases where a new slave session is created. Is this indeed correct? Probably is, but needs focused verification.
        final SessionID sessionID = context.getSessionID();
        if (encodedM instanceof DataMessage) {
            LOGGER.log(FINEST, "{0} received a data message (OTRv2/OTRv3) from {1}, handling in state {2}.",
                    new Object[]{sessionID.getAccountID(), sessionID.getUserID(), this.getClass().getName()});
            return handleDataMessage(context, (DataMessage) encodedM);
        }
        // Anything that is not a Data message is some type of AKE message.
        final AbstractEncodedMessage reply = handleAKEMessage(context, encodedM);
        if (reply != null) {
            context.injectMessage(reply);
        }
        return new Result(getStatus(), false, false, null);
    }

    @Nullable
    private AbstractEncodedMessage handleAKEMessage(final Context context, final AbstractEncodedMessage message) {

        if (!(message instanceof DHCommitMessage || message instanceof DHKeyMessage
                || message instanceof SignatureMessage || message instanceof RevealSignatureMessage)) {
            throw new UnsupportedOperationException("Only OTRv2/OTRv3 AKE messages are supported.");
        }

        final SessionID sessionID = context.getSessionID();
        LOGGER.log(FINEST, "{0} received an AKE message from {1} through {2}.",
                new Object[]{sessionID.getAccountID(), sessionID.getUserID(), sessionID.getProtocolName()});

        // Verify that policy allows handling message according to protocol version.
        final OtrPolicy policy = context.getSessionPolicy();
        if (message.protocolVersion == Version.TWO && !policy.isAllowV2()) {
            LOGGER.finest("ALLOW_V2 is not set, ignore this message.");
            return null;
        }
        if (message.protocolVersion == Version.THREE && !policy.isAllowV3()) {
            LOGGER.finest("ALLOW_V3 is not set, ignore this message.");
            return null;
        }

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
                secure(context, result.params);
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

    private void secure(final Context context, final SecurityParameters params) throws OtrCryptoException {
        context.transition(this, new StateEncrypted3(context, this.authState, params));
        if (context.getSessionStatus() != ENCRYPTED) {
            throw new IllegalStateException("Session failed to transition to ENCRYPTED. (OTRv2/OTRv3)");
        }
        LOGGER.info("Session secured. Message state transitioned to ENCRYPTED. (OTRv2/OTRv3)");
    }

    @Override
    public void initiateAKE(final Context context, final Version version, final InstanceTag receiverTag) throws OtrException {
        LOGGER.log(Level.FINE, "Initiating AKE…");
        context.injectMessage(this.authState.initiate(context, version, receiverTag));
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
}
