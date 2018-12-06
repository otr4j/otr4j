/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.state;

import net.java.otr4j.api.ClientProfile;
import net.java.otr4j.api.OtrException;
import net.java.otr4j.api.SessionID;
import net.java.otr4j.api.SessionStatus;
import net.java.otr4j.api.TLV;
import net.java.otr4j.crypto.DHKeyPair;
import net.java.otr4j.crypto.OtrCryptoEngine4;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.crypto.ed448.ECDHKeyPair;
import net.java.otr4j.crypto.ed448.EdDSAKeyPair;
import net.java.otr4j.crypto.ed448.Point;
import net.java.otr4j.io.Message;
import net.java.otr4j.io.PlainTextMessage;
import net.java.otr4j.messages.AbstractEncodedMessage;
import net.java.otr4j.messages.AuthIMessage;
import net.java.otr4j.messages.AuthRMessage;
import net.java.otr4j.messages.ClientProfilePayload;
import net.java.otr4j.messages.DataMessage;
import net.java.otr4j.messages.DataMessage4;
import net.java.otr4j.messages.IdentityMessage;
import net.java.otr4j.messages.IdentityMessages;
import net.java.otr4j.messages.ValidationException;
import net.java.otr4j.session.ake.AuthState;
import net.java.otr4j.session.api.SMPHandler;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.math.BigInteger;
import java.net.ProtocolException;
import java.security.interfaces.DSAPublicKey;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import static java.util.Objects.requireNonNull;
import static java.util.logging.Level.WARNING;
import static net.java.otr4j.api.OtrEngineHostUtil.unencryptedMessageReceived;
import static net.java.otr4j.api.Session.Version.FOUR;
import static net.java.otr4j.api.SessionStatus.PLAINTEXT;
import static net.java.otr4j.crypto.OtrCryptoEngine4.ringSign;
import static net.java.otr4j.messages.AuthIMessages.validate;
import static net.java.otr4j.messages.MysteriousT4.Purpose.AUTH_R;
import static net.java.otr4j.messages.MysteriousT4.encode;
import static net.java.otr4j.session.state.SecurityParameters4.Component.THEIRS;

/**
 * The state AWAITING_AUTH_I.
 *
 * This is a state in which Alice will be while awaiting Bob's final message.
 */
final class StateAwaitingAuthI extends AbstractState {

    private static final Logger LOGGER = Logger.getLogger(StateAwaitingAuthI.class.getName());

    private final String queryTag;

    /**
     * Our ECDH key pair. (Its public key is also known as X.)
     */
    private final ECDHKeyPair ourECDHKeyPair;

    /**
     * Our DH key pair. (Its public key is also known as A.)
     */
    private final DHKeyPair ourDHKeyPair;

    private final Point y;

    private final BigInteger b;

    private final ClientProfilePayload ourProfile;

    private final ClientProfilePayload profileBob;

    StateAwaitingAuthI(@Nonnull final Context context, @Nonnull final AuthState authState,
                       @Nonnull final String queryTag, @Nonnull final ECDHKeyPair ourECDHKeyPair,
                       @Nonnull final DHKeyPair ourDHKeyPair, @Nonnull final Point y, @Nonnull final BigInteger b,
                       @Nonnull final ClientProfilePayload ourProfile, @Nonnull final ClientProfilePayload profileBob) {
        super(context, authState);
        this.queryTag = requireNonNull(queryTag);
        this.ourECDHKeyPair = requireNonNull(ourECDHKeyPair);
        this.ourDHKeyPair = requireNonNull(ourDHKeyPair);
        this.y = requireNonNull(y);
        this.b = requireNonNull(b);
        this.ourProfile = requireNonNull(ourProfile);
        this.profileBob = requireNonNull(profileBob);
    }

    @Nullable
    @Override
    public Message transformSending(@Nonnull final String msgText, @Nonnull final List<TLV> tlvs, final byte flags) throws OtrException {
        // FIXME implement transformSending
        throw new UnsupportedOperationException("To be implemented");
    }

    @Nonnull
    @Override
    public String handlePlainTextMessage(@Nonnull final PlainTextMessage plainTextMessage) {
        // Simply display the message to the user. If REQUIRE_ENCRYPTION is set,
        // warn him that the message was received unencrypted.
        if (context.getSessionPolicy().isRequireEncryption()) {
            unencryptedMessageReceived(context.getHost(), getSessionID(), plainTextMessage.getCleanText());
        }
        return plainTextMessage.getCleanText();
    }

    @Nullable
    @Override
    AbstractEncodedMessage handleAKEMessage(@Nonnull final AbstractEncodedMessage message) {
        if (message instanceof IdentityMessage) {
            try {
                return handleIdentityMessage((IdentityMessage) message);
            } catch (OtrCryptoException | ValidationException e) {
                // FIXME consider how to handle this case and where.
                LOGGER.log(WARNING, "Failed to process identity message.", e);
                return null;
            }
        }
        if (message instanceof AuthIMessage) {
            try {
                handleAuthIMessage((AuthIMessage) message);
                return null;
            } catch (OtrCryptoException | ValidationException e) {
                // FIXME consider how to handle this case and where.
                LOGGER.log(WARNING, "Failed to process Auth-R message.", e);
                return null;
            }
        }
        // FIXME how to handle unexpected other AKE messages? (Be strict)
        // OTR: "Ignore the message."
        LOGGER.log(Level.INFO, "We only expect to receive an Identity message or an Auth-I message or its protocol version does not match expectations. Ignoring message with messagetype: {0}",
                message.getType());
        return super.handleAKEMessage(message);
    }

    @Nonnull
    @Override
    public SessionStatus getStatus() {
        return PLAINTEXT;
    }

    @Nonnull
    @Override
    public DSAPublicKey getRemotePublicKey() throws IncorrectStateException {
        throw new IncorrectStateException("Remote public key is not available until encrypted session is fully established.");
    }

    @Nonnull
    @Override
    public byte[] getExtraSymmetricKey() throws IncorrectStateException {
        throw new IncorrectStateException("Extra symmetric key is not available until encrypted session is fully established.");
    }

    @Override
    @Nonnull
    public SMPHandler getSmpHandler() throws IncorrectStateException {
        throw new IncorrectStateException("SMP negotiation is not available until encrypted session is fully established.");
    }

    /**
     * Handle Identity message.
     * <p>
     * This implementation deviates from the implementation in StateInitial as we reuse previously generated variables.
     *
     * @param message the identity message
     * @return Returns the Auth-R message to send
     * @throws OtrCryptoException  In case of failure to validate cryptographic components in other party's identity
     *                             message.
     * @throws ValidationException In case of failure to validate other party's identity message or client profile.
     */
    private AuthRMessage handleIdentityMessage(@Nonnull final IdentityMessage message)
            throws OtrCryptoException, ValidationException {
        final ClientProfile theirNewClientProfile = message.getClientProfile().validate();
        IdentityMessages.validate(message, theirNewClientProfile);
        final SessionID sessionID = context.getSessionID();
        // Note: we query the context for a new client profile, because we're responding to a new Identity message.
        // This ensures a "fresh" profile. (May be unnecessary, but seems smart right now ... I may regret it later)
        final ClientProfilePayload profilePayload = context.getClientProfilePayload();
        final EdDSAKeyPair longTermKeyPair = context.getHost().getLongTermKeyPair(sessionID);
        // TODO should we verify that long-term key pair matches with long-term public key from user profile? (This would be an internal sanity check.)
        // Generate t value and calculate sigma based on known facts and generated t value.
        final byte[] t = encode(AUTH_R, profilePayload, message.getClientProfile(), this.ourECDHKeyPair.getPublicKey(),
            message.getY(), this.ourDHKeyPair.getPublicKey(), message.getB(), context.getSenderInstanceTag().getValue(),
            context.getReceiverInstanceTag().getValue(), this.queryTag, sessionID.getUserID(), sessionID.getAccountID());
        final OtrCryptoEngine4.Sigma sigma = ringSign(context.secureRandom(), longTermKeyPair,
                theirNewClientProfile.getForgingKey(), longTermKeyPair.getPublicKey(), message.getY(), t);
        // Generate response message and transition into next state.
        final AuthRMessage authRMessage = new AuthRMessage(FOUR, context.getSenderInstanceTag(),
                context.getReceiverInstanceTag(), profilePayload, this.ourECDHKeyPair.getPublicKey(),
                this.ourDHKeyPair.getPublicKey(), sigma);
        context.transition(this, new StateAwaitingAuthI(this.context, getAuthState(), this.queryTag,
                this.ourECDHKeyPair, this.ourDHKeyPair, message.getY(), message.getB(), ourProfile,
                message.getClientProfile()));
        return authRMessage;
    }

    private void handleAuthIMessage(@Nonnull final AuthIMessage message)
            throws OtrCryptoException, ValidationException {
        final ClientProfile profileBobValidated = this.profileBob.validate();
        final ClientProfile ourProfileValidated = this.ourProfile.validate();
        validate(message, this.queryTag, this.ourProfile, ourProfileValidated, this.profileBob, profileBobValidated,
                this.ourECDHKeyPair.getPublicKey(), this.y, this.ourDHKeyPair.getPublicKey(), this.b,
                context.getSessionID().getUserID(), context.getSessionID().getAccountID());
        secure(new SecurityParameters4(THEIRS, this.ourECDHKeyPair, this.ourDHKeyPair, this.y, this.b,
                ourProfileValidated, profileBobValidated));
        // FIXME clear queryTag?
    }

    @Nullable
    @Override
    String handleDataMessage(@Nonnull final DataMessage message) throws ProtocolException, OtrException {
        // FIXME implement handleDataMessage
        throw new UnsupportedOperationException("To be implemented");
    }

    @Nullable
    @Override
    String handleDataMessage(@Nonnull final DataMessage4 message) throws ProtocolException, OtrException {
        // FIXME implement handleDataMessage
        throw new UnsupportedOperationException("To be implemented");
    }

    @Override
    public void end() throws OtrException {
        // FIXME implement end
        throw new UnsupportedOperationException("To be implemented");
    }

    @Override
    public void destroy() {
        // FIXME implement destroy
        throw new UnsupportedOperationException("To be implemented");
    }

    @Override
    public int getVersion() {
        return FOUR;
    }
}
