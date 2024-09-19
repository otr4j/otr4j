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
import net.java.otr4j.messages.AbstractEncodedMessage;
import net.java.otr4j.messages.DataMessage;
import net.java.otr4j.messages.DataMessage4;
import net.java.otr4j.session.ake.AuthState;
import net.java.otr4j.session.api.SMPHandler;
import net.java.otr4j.session.dake.DAKEState;
import net.java.otr4j.util.Unit;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.net.ProtocolException;
import java.util.logging.Level;
import java.util.logging.Logger;

import static java.util.logging.Level.INFO;
import static net.java.otr4j.api.OtrEngineHosts.handleEvent;
import static net.java.otr4j.io.ErrorMessage.ERROR_2_NOT_IN_PRIVATE_STATE_MESSAGE;
import static net.java.otr4j.io.ErrorMessage.ERROR_ID_NOT_IN_PRIVATE_STATE;

/**
 * Message state FINISHED. This message state is initiated through events started from the initial message state
 * PLAINTEXT (and transition through ENCRYPTED).
 *
 * @author Danny van Heumen
 */
final class StateFinished extends AbstractOTRState {

    private static final Logger LOGGER = Logger.getLogger(StateFinished.class.getName());

    private static final SessionStatus STATUS = SessionStatus.FINISHED;

    StateFinished(final AuthState authState, final DAKEState dakeState) {
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
        throw new IncorrectStateException("SMP negotiation is not available in finished state.");
    }

    @Override
    @Nonnull
    public byte[] getExtraSymmetricKey() throws IncorrectStateException {
        throw new IncorrectStateException("Extra symmetric key is not available in finished state.");
    }

    // TODO currently `StateFinished` is shared among OTRv2/3/4. In OTRv4 spec, separate `FINISHED` states exist for OTRv3 and OTRv4. Consider separating as well. (Needed to prevent subtle switching from OTR 4 to OTR 3 with intermediate FINISHED.)
    @Nonnull
    @Override
    public Result handleEncodedMessage(final Context context, final AbstractEncodedMessage message) throws ProtocolException, OtrException {
        switch (message.protocolVersion) {
        case ONE:
            LOGGER.log(INFO, "Encountered message for protocol version 1. Ignoring message.");
            return new Result(STATUS, true, false, null);
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
    @Nonnull
    Result handleDataMessage(final Context context, final DataMessage message) throws OtrException {
        LOGGER.log(Level.FINEST, "Received OTRv2/3 data message in FINISHED state. Message cannot be read.");
        handleUnreadableMessage(context, message, ERROR_2_NOT_IN_PRIVATE_STATE_MESSAGE);
        return new Result(STATUS, true, false, null);
    }

    @Nonnull
    @Override
    Result handleDataMessage(final Context context, final DataMessage4 message) throws OtrException {
        LOGGER.log(Level.FINEST, "Received OTRv4 data message in FINISHED state. Message cannot be read.");
        handleUnreadableMessage(context, message, ERROR_ID_NOT_IN_PRIVATE_STATE, ERROR_2_NOT_IN_PRIVATE_STATE_MESSAGE);
        return new Result(STATUS, true, false, null);
    }

    @Override
    @Nullable
    public Message transformSending(final Context context, final String msgText, final Iterable<TLV> tlvs,
            final byte flags) {
        handleEvent(context.getHost(), context.getSessionID(), context.getReceiverInstanceTag(), Event.SESSION_FINISHED,
                Unit.UNIT);
        return null;
    }

    @Override
    public void end(final Context context) {
        context.transition(this, new StatePlaintext(getAuthState(), getDAKEState()));
    }

    @Override
    public void destroy() {
        // no sensitive material to destroy
    }
}
