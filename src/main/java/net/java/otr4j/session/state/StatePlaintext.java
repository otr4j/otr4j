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
import net.java.otr4j.api.OtrPolicy;
import net.java.otr4j.api.RemoteInfo;
import net.java.otr4j.api.SessionStatus;
import net.java.otr4j.api.TLV;
import net.java.otr4j.api.Version;
import net.java.otr4j.io.Message;
import net.java.otr4j.io.PlainTextMessage;
import net.java.otr4j.messages.AbstractEncodedMessage;
import net.java.otr4j.messages.DataMessage;
import net.java.otr4j.messages.DataMessage4;
import net.java.otr4j.session.ake.AuthState;
import net.java.otr4j.session.api.SMPHandler;
import net.java.otr4j.session.dake.DAKEState;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.net.ProtocolException;
import java.util.Collections;
import java.util.Set;
import java.util.logging.Logger;

import static java.util.logging.Level.FINEST;
import static java.util.logging.Level.INFO;
import static net.java.otr4j.api.OfferStatus.REJECTED;
import static net.java.otr4j.api.OtrEngineHosts.handleEvent;
import static net.java.otr4j.api.OtrPolicys.allowedVersions;
import static net.java.otr4j.io.ErrorMessage.ERROR_2_NOT_IN_PRIVATE_STATE_MESSAGE;
import static net.java.otr4j.io.ErrorMessage.ERROR_ID_NOT_IN_PRIVATE_STATE;

/**
 * Message state PLAINTEXT. This is the only message state that is publicly accessible. Message states and transitions
 * are always initiated from the initial state.
 *
 * @author Danny van Heumen
 */
public final class StatePlaintext extends AbstractOTRState {

    private static final Logger LOGGER = Logger.getLogger(StatePlaintext.class.getName());

    private static final SessionStatus STATUS = SessionStatus.PLAINTEXT;

    /**
     * Constructor for the Plaintext message state.
     *
     * @param authState the current authentication (AKE) state instance.
     * @param dakeState the current authentication (DAKE) state instance.
     */
    public StatePlaintext(final AuthState authState, final DAKEState dakeState) {
        super(authState, dakeState);
    }

    @Nonnull
    @Override
    public Version getVersion() {
        return Version.NONE;
    }

    @Override
    @Nonnull
    public SessionStatus getStatus() {
        return STATUS;
    }

    @Nonnull
    @Override
    public RemoteInfo getRemoteInfo() throws IncorrectStateException {
        throw new IncorrectStateException("No OTR session is established yet.");
    }

    @Override
    @Nonnull
    public SMPHandler getSmpHandler() throws IncorrectStateException {
        throw new IncorrectStateException("SMP negotiation is not available in plaintext state.");
    }

    @Override
    @Nonnull
    public byte[] getExtraSymmetricKey() throws IncorrectStateException {
        throw new IncorrectStateException("Extra symmetric key is not available in plaintext state.");
    }

    @Override
    @Nonnull
    Result handleDataMessage(final Context context, final DataMessage message) throws OtrException {
        LOGGER.log(FINEST, "Received OTRv3 data message in PLAINTEXT state. Message cannot be read.");
        handleUnreadableMessage(context, message, ERROR_2_NOT_IN_PRIVATE_STATE_MESSAGE);
        return new Result(STATUS, true, false, null);
    }

    @Nonnull
    @Override
    Result handleDataMessage(final Context context, final DataMessage4 message) throws OtrException {
        LOGGER.log(FINEST, "Received OTRv4 data message in PLAINTEXT state. Message cannot be read.");
        handleUnreadableMessage(context, message, ERROR_ID_NOT_IN_PRIVATE_STATE, ERROR_2_NOT_IN_PRIVATE_STATE_MESSAGE);
        return new Result(STATUS, true, false, null);
    }

    @Nonnull
    @Override
    public Result handleEncodedMessage(final Context context, final AbstractEncodedMessage message) throws ProtocolException, OtrException {
        switch (message.protocolVersion) {
        case ONE:
            LOGGER.log(INFO, "Encountered message for protocol version 1. Ignoring message.");
            return new Result(getStatus(), true, false, null);
        case TWO:
        case THREE:
            return handleEncodedMessage3(context, message);
        case FOUR:
            return handleEncodedMessage4(context, message);
        default:
            throw new UnsupportedOperationException("BUG: Unsupported protocol version: " + message.protocolVersion);
        }
    }

    @Override
    @Nullable
    public Message transformSending(final Context context, final String msgText, final Iterable<TLV> tlvs,
            final byte flags) throws OtrException {
        final OtrPolicy otrPolicy = context.getSessionPolicy();
        if (otrPolicy.isRequireEncryption()) {
            // Prevent original message from being sent. Start AKE.
            if (!otrPolicy.viable()) {
                throw new OtrException("OTR policy disallows all versions of the OTR protocol. We cannot initiate a new OTR session.");
            }
            context.startSession();
            handleEvent(context.getHost(), context.getSessionID(), context.getReceiverInstanceTag(),
                    Event.ENCRYPTED_MESSAGES_REQUIRED, msgText);
            return null;
        }
        if (!otrPolicy.isSendWhitespaceTag() || context.getOfferStatus() == REJECTED) {
            // As we do not want to send a specially crafted whitespace tag
            // message, just return the original message text to be sent.
            return new PlainTextMessage(Collections.emptySet(), msgText);
        }
        // Continue with crafting a special whitespace message tag and embedding it into the original message.
        final Set<Version> versions = allowedVersions(otrPolicy);
        if (versions.isEmpty()) {
            // Catch situation where we do not actually offer any versions.
            // At this point, reaching this state is considered a bug.
            throw new IllegalStateException("The current OTR policy does not allow any supported version of OTR. The software should either enable some protocol version or disable sending whitespace tags.");
        }
        final PlainTextMessage m = new PlainTextMessage(versions, msgText);
        context.setOfferStatusSent();
        return m;
    }

    @Override
    public void end(final Context context) {
        // already in "ended" state
    }

    @Override
    public void destroy() {
        // no sensitive material to destroy
    }
}
