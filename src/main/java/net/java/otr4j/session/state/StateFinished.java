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
import net.java.otr4j.api.SessionStatus;
import net.java.otr4j.api.TLV;
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
import java.security.interfaces.DSAPublicKey;
import java.util.logging.Level;
import java.util.logging.Logger;

import static java.util.logging.Level.INFO;
import static net.java.otr4j.api.OtrEngineHosts.finishedSessionMessage;
import static net.java.otr4j.api.OtrEngineHosts.unencryptedMessageReceived;
import static net.java.otr4j.io.ErrorMessage.ERROR_2_NOT_IN_PRIVATE_STATE_MESSAGE;
import static net.java.otr4j.io.ErrorMessage.ERROR_ID_NOT_IN_PRIVATE_STATE;

/**
 * Message state FINISHED. This message state is initiated through events started from the initial message state
 * PLAINTEXT (and transition through ENCRYPTED).
 *
 * @author Danny van Heumen
 */
// TODO currently `StateFinished` is shared among OTRv2/3/4. In OTRv4 spec, separate `FINISHED` states exist for OTRv3 and OTRv4. Consider separating as well. (Needed to prevent subtle switching from OTR 4 to OTR 3 with intermediate FINISHED.)
final class StateFinished extends AbstractCommonState {

    private static final Logger LOGGER = Logger.getLogger(StateFinished.class.getName());

    StateFinished(final AuthState authState) {
        super(authState);
    }

    @Override
    public int getVersion() {
        return 0;
    }

    @Override
    @Nonnull
    public SessionStatus getStatus() {
        return SessionStatus.FINISHED;
    }

    @Override
    @Nonnull
    public SMPHandler getSmpHandler() throws IncorrectStateException {
        throw new IncorrectStateException("SMP negotiation is not available in finished state.");
    }

    @Override
    @Nonnull
    public DSAPublicKey getRemotePublicKey() throws IncorrectStateException {
        throw new IncorrectStateException("Remote public key is not available in finished state.");
    }

    @Override
    @Nonnull
    public byte[] getExtraSymmetricKey() throws IncorrectStateException {
        throw new IncorrectStateException("Extra symmetric key is not available in finished state.");
    }

    @Override
    @Nonnull
    public String handlePlainTextMessage(final Context context, final PlainTextMessage message) {
        // Display the message to the user, but warn him that the message was received unencrypted.
        unencryptedMessageReceived(context.getHost(), context.getSessionID(), message.getCleanText());
        return message.getCleanText();
    }

    @Override
    void handleAKEMessage(final Context context, final AbstractEncodedMessage message) throws OtrException {
        if (message instanceof IdentityMessage) {
            try {
                handleIdentityMessage(context, (IdentityMessage) message);
            } catch (final ValidationException e) {
                LOGGER.log(INFO, "Failed to process Identity message.", e);
            }
            return;
        }
        LOGGER.log(INFO, "We only expect to receive an Identity message. Ignoring message with messagetype: {0}",
                message.getType());
    }

    @Override
    @Nullable
    String handleDataMessage(final Context context, final DataMessage message) throws OtrException {
        LOGGER.log(Level.FINEST, "Received OTRv2/3 data message in FINISHED state. Message cannot be read.");
        handleUnreadableMessage(context, message, ERROR_ID_NOT_IN_PRIVATE_STATE, ERROR_2_NOT_IN_PRIVATE_STATE_MESSAGE);
        return null;
    }

    @Nullable
    @Override
    String handleDataMessage(final Context context, final DataMessage4 message) throws OtrException {
        LOGGER.log(Level.FINEST, "Received OTRv4 data message in FINISHED state. Message cannot be read.");
        handleUnreadableMessage(context, message, ERROR_ID_NOT_IN_PRIVATE_STATE, ERROR_2_NOT_IN_PRIVATE_STATE_MESSAGE);
        return null;
    }

    @Override
    @Nullable
    public Message transformSending(final Context context, final String msgText, final Iterable<TLV> tlvs,
            final byte flags) {
        context.queueMessage(msgText);
        finishedSessionMessage(context.getHost(), context.getSessionID(), msgText);
        return null;
    }

    @Override
    public void end(final Context context) {
        context.transition(this, new StatePlaintext(getAuthState()));
    }

    @Override
    public void destroy() {
        // no sensitive material to destroy
    }
}
