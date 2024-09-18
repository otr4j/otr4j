/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.session.dake;

import net.java.otr4j.api.ClientProfile;
import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.api.SessionID;
import net.java.otr4j.api.Version;
import net.java.otr4j.crypto.DHKeyPair;
import net.java.otr4j.crypto.MixedSharedSecret;
import net.java.otr4j.crypto.OtrCryptoEngine4;
import net.java.otr4j.crypto.ed448.ECDHKeyPair;
import net.java.otr4j.crypto.ed448.EdDSAKeyPair;
import net.java.otr4j.messages.AuthRMessage;
import net.java.otr4j.messages.ClientProfilePayload;
import net.java.otr4j.messages.IdentityMessage;
import net.java.otr4j.messages.MysteriousT4;
import net.java.otr4j.messages.ValidationException;

import javax.annotation.Nonnull;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.logging.Level;
import java.util.logging.Logger;

import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.AUTH_R_PHI;
import static net.java.otr4j.crypto.OtrCryptoEngine4.ringSign;
import static net.java.otr4j.messages.IdentityMessages.validate;
import static net.java.otr4j.messages.MysteriousT4.Purpose.AUTH_R;
import static net.java.otr4j.util.Objects.requireEquals;

// TODO consider renaming to `AbstractDAKEState` for identifiability.
abstract class AbstractState implements DAKEState {

    private static final Logger LOGGER = Logger.getLogger(AbstractState.class.getName());

    private final long timestamp = System.nanoTime();

    @Override
    public final long getTimestamp() {
        return this.timestamp;
    }

    @Nonnull
    @Override
    public IdentityMessage initiate(final DAKEContext context, final Version version) {
        switch (version) {
        case TWO:
        case THREE:
            throw new IllegalArgumentException("BUG: DAKE is not supported in protocol version 2 and 3.");
        case FOUR:
            requireEquals(Version.FOUR, version, "Unexpected protocol version");
            LOGGER.log(Level.FINE, "Generating new short-term keypairs for DAKE…");
            final SecureRandom secureRandom = context.secureRandom();
            final ECDHKeyPair y = ECDHKeyPair.generate(secureRandom);
            final DHKeyPair b  = DHKeyPair.generate(secureRandom);
            final ClientProfilePayload profilePayload = context.getClientProfilePayload();
            final ECDHKeyPair ourFirstECDHKeyPair = ECDHKeyPair.generate(secureRandom);
            final DHKeyPair ourFirstDHKeyPair = DHKeyPair.generate(secureRandom);
            final InstanceTag receiverTag = context.getReceiverInstanceTag();
            final IdentityMessage message = new IdentityMessage(context.getSenderInstanceTag(), receiverTag,
                    profilePayload, y.publicKey(), b.publicKey(),  ourFirstECDHKeyPair.publicKey(),
                    ourFirstDHKeyPair.publicKey());
            context.setDAKEState(new DAKEAwaitingAuthR(y, b, ourFirstECDHKeyPair, ourFirstDHKeyPair, profilePayload,
                    message));
            return message;
        default:
            throw new UnsupportedOperationException("BUG: unsupported protocol version.");
        }
    }

    /**
     * Common implementation for handling OTRv4 Identity message that is shared among states.
     *
     * @param context the session context
     * @param message the Identity message to be processed
     * @return the result after processing the Identity-message
     * @throws ValidationException In case of failure to validate received Identity message.
     */
    @Nonnull
    protected Result handleIdentityMessage(final DAKEContext context, final IdentityMessage message) throws ValidationException {
        final ClientProfile theirClientProfile = message.clientProfile.validate(Instant.now());
        validate(message, theirClientProfile);
        final SecureRandom secureRandom = context.secureRandom();
        final ECDHKeyPair x = ECDHKeyPair.generate(secureRandom);
        final DHKeyPair a = DHKeyPair.generate(secureRandom);
        final ECDHKeyPair ourFirstECDHKeyPair = ECDHKeyPair.generate(secureRandom);
        final DHKeyPair ourFirstDHKeyPair = DHKeyPair.generate(secureRandom);
        final byte[] k;
        final byte[] ssid;
        try (MixedSharedSecret sharedSecret = new MixedSharedSecret(secureRandom, x, a, message.y, message.b)) {
            k = sharedSecret.getK();
            ssid = sharedSecret.generateSSID();
        }
        x.close();
        a.close();
        // Generate t value and calculate sigma based on known facts and generated t value.
        final ClientProfilePayload profile = context.getClientProfilePayload();
        final EdDSAKeyPair longTermKeyPair = context.getLongTermKeyPair();
        final SessionID sessionID = context.getSessionID();
        final byte[] phi = MysteriousT4.generatePhi(AUTH_R_PHI, context.getSenderInstanceTag(),
                context.getReceiverInstanceTag(), ourFirstECDHKeyPair.publicKey(), ourFirstDHKeyPair.publicKey(),
                message.firstECDHPublicKey, message.firstDHPublicKey, sessionID.getAccountID(), sessionID.getUserID());
        final byte[] t = MysteriousT4.encode(AUTH_R, message.clientProfile, profile, message.y, x.publicKey(),
                message.b, a.publicKey(), phi);
        final OtrCryptoEngine4.Sigma sigma = ringSign(secureRandom, longTermKeyPair, theirClientProfile.getForgingKey(),
                longTermKeyPair.getPublicKey(), message.y, t);
        // Generate response message and transition into next state.
        final AuthRMessage response = new AuthRMessage(context.getSenderInstanceTag(), context.getReceiverInstanceTag(),
                profile, x.publicKey(), a.publicKey(), sigma,
                ourFirstECDHKeyPair.publicKey(), ourFirstDHKeyPair.publicKey());
        context.setDAKEState(new DAKEAwaitingAuthI(k, ssid, x, a, ourFirstECDHKeyPair, ourFirstDHKeyPair, message.y,
                message.b, message.firstECDHPublicKey, message.firstDHPublicKey, profile, message.clientProfile));
        return new Result(response, null);
    }
}
