/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.session.state;

import net.java.otr4j.api.OtrException;
import net.java.otr4j.api.OtrPolicy;
import net.java.otr4j.api.RemoteInfo;
import net.java.otr4j.api.SessionStatus;
import net.java.otr4j.api.Session;
import net.java.otr4j.api.TLV;
import net.java.otr4j.io.EncodedMessage;
import net.java.otr4j.io.Message;
import net.java.otr4j.io.PlainTextMessage;
import net.java.otr4j.messages.AbstractEncodedMessage;
import net.java.otr4j.messages.DataMessage;
import net.java.otr4j.messages.DataMessage4;
import net.java.otr4j.messages.IdentityMessage;
import net.java.otr4j.messages.ValidationException;
import net.java.otr4j.session.ake.AuthState;
import net.java.otr4j.session.api.SMPHandler;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.net.ProtocolException;
import java.util.Collections;
import java.util.Set;
import java.util.logging.Logger;

import static java.util.logging.Level.FINE;
import static java.util.logging.Level.FINEST;
import static java.util.logging.Level.INFO;
import static net.java.otr4j.api.OfferStatus.REJECTED;
import static net.java.otr4j.api.OtrEngineHosts.requireEncryptedMessage;
import static net.java.otr4j.api.OtrPolicys.allowedVersions;
import static net.java.otr4j.api.SessionStatus.PLAINTEXT;
import static net.java.otr4j.io.ErrorMessage.ERROR_2_NOT_IN_PRIVATE_STATE_MESSAGE;
import static net.java.otr4j.io.ErrorMessage.ERROR_ID_NOT_IN_PRIVATE_STATE;

/**
 * Message state PLAINTEXT. This is the only message state that is publicly accessible. Message states and transitions
 * are always initiated from the initial state.
 *
 * @author Danny van Heumen
 */
public final class StatePlaintext extends AbstractCommonState {

    private static final Logger LOGGER = Logger.getLogger(StatePlaintext.class.getName());

    /**
     * Constructor for the Plaintext message state.
     *
     * @param authState the initial authentication (AKE) state instance.
     */
    public StatePlaintext(final AuthState authState) {
        super(authState);
    }

    @Override
    public int getVersion() {
        return 0;
    }

    @Override
    @Nonnull
    public SessionStatus getStatus() {
        return PLAINTEXT;
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
    public String handlePlainTextMessage(final Context context, final PlainTextMessage message) {
        return message.getCleanText();
    }

    @Nullable
    @Override
    public String handleEncodedMessage(final Context context, final EncodedMessage message) throws ProtocolException, OtrException {
        // TODO check all `handleEncodedMessage` implementations, check whether `return null` (ignore) or `ProtocolException` is better suitable.
        switch (message.version) {
        case Session.Version.ONE:
            throw new UnsupportedOperationException("Protocol version 1 is unsupported.");
        case Session.Version.TWO:
        case Session.Version.THREE:
            return handleEncodedMessage3(context, message);
        case Session.Version.FOUR:
            return handleEncodedMessage4(context, message);
        default:
            throw new UnsupportedOperationException("BUG: Unsupported protocol version: " + message.version);
        }
    }

    @Override
    void handleAKEMessage(final Context context, final AbstractEncodedMessage message) throws OtrException {
        if (!context.getSessionPolicy().isAllowV4()) {
            LOGGER.finest("ALLOW_V4 is not set, ignore this message.");
            return;
        }
        if (!(message instanceof IdentityMessage)) {
            LOGGER.log(FINE, "Ignoring unexpected DAKE message type: " + message.getType());
            return;
        }
        try {
            handleIdentityMessage(context, (IdentityMessage) message);
        } catch (final ValidationException e) {
            LOGGER.log(INFO, "Failed to process Identity message.", e);
        }
    }

    @Override
    @Nullable
    String handleDataMessage(final Context context, final DataMessage message) throws OtrException {
        LOGGER.log(FINEST, "Received OTRv3 data message in PLAINTEXT state. Message cannot be read.");
        handleUnreadableMessage(context, message, ERROR_ID_NOT_IN_PRIVATE_STATE, ERROR_2_NOT_IN_PRIVATE_STATE_MESSAGE);
        return null;
    }

    @Nullable
    @Override
    String handleDataMessage(final Context context, final DataMessage4 message) throws OtrException {
        LOGGER.log(FINEST, "Received OTRv4 data message in PLAINTEXT state. Message cannot be read.");
        handleUnreadableMessage(context, message, ERROR_ID_NOT_IN_PRIVATE_STATE, ERROR_2_NOT_IN_PRIVATE_STATE_MESSAGE);
        return null;
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
            context.queueMessage(msgText);
            requireEncryptedMessage(context.getHost(), context.getSessionID(), msgText);
            return null;
        }
        if (!otrPolicy.isSendWhitespaceTag() || context.getOfferStatus() == REJECTED) {
            // As we do not want to send a specially crafted whitespace tag
            // message, just return the original message text to be sent.
            return new PlainTextMessage(Collections.emptySet(), msgText);
        }
        // Continue with crafting a special whitespace message tag and embedding it into the original message.
        final Set<Integer> versions = allowedVersions(otrPolicy);
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
