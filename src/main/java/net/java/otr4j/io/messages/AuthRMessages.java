package net.java.otr4j.io.messages;

import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.api.Session;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.profile.UserProfile;
import net.java.otr4j.profile.UserProfiles;
import nl.dannyvanheumen.joldilocks.Point;

import javax.annotation.Nonnull;
import java.math.BigInteger;

import static net.java.otr4j.crypto.DHKeyPairs.verifyPublicKey;
import static net.java.otr4j.crypto.ECDHKeyPairs.verifyECDHPublicKey;
import static net.java.otr4j.crypto.OtrCryptoEngine4.ringVerify;
import static net.java.otr4j.profile.UserProfiles.validate;

/**
 * Utility class for AuthRMessage. (AUTH_R messages)
 */
public final class AuthRMessages {

    private AuthRMessages() {
        // No need to instantiate utility class.
    }

    /**
     * Verify an AuthRMessage, using additional parameters to supply additional required data.
     *
     * @param message               the AUTH_R message
     * @param ourUserProfile        our UserProfile instance
     * @param senderTag             the sender's instance tag
     * @param receiverTag           the receiver's instance tag
     * @param senderAccountID       the sender's account ID
     * @param receiverAccountID     the Receiver's account ID
     * @param receiverECDHPublicKey the receiver's ECDH public key
     * @param receiverDHPublicKey   the receiver's DH public key
     * @param queryTag              the query tag
     * @throws UserProfiles.InvalidUserProfileException In case user profile validation has failed.
     * @throws OtrCryptoException                       In case any cryptographic verification failed, such as ephemeral
     *                                                  public keys or the ring signature.
     */
    public static void verify(@Nonnull final AuthRMessage message, @Nonnull final UserProfile ourUserProfile,
                              @Nonnull final InstanceTag senderTag, @Nonnull final InstanceTag receiverTag,
                              @Nonnull final String senderAccountID, @Nonnull final String receiverAccountID,
                              @Nonnull final Point receiverECDHPublicKey, @Nonnull final BigInteger receiverDHPublicKey,
                              @Nonnull final String queryTag) throws UserProfiles.InvalidUserProfileException, OtrCryptoException {
        if (message.getType() != AuthRMessage.MESSAGE_AUTH_R) {
            throw new IllegalStateException("AUTH_R message should not have any other type than 0x91.");
        }
        if (message.protocolVersion != Session.OTRv.FOUR) {
            throw new IllegalStateException("Identity message should not have any other protocol version than 4.");
        }
        // FIXME Check that the receiver's instance tag matches your sender's instance tag.
        validate(message.getUserProfile());
        // TODO maybe these public key verifications are redundant, but checking just-in-case, until I know for certain. (They're not documented in the spec.)
        verifyECDHPublicKey(message.getX());
        verifyPublicKey(message.getA());
        final byte[] t = MysteriousT4.encode(message.getUserProfile(), ourUserProfile, message.getX(),
            receiverECDHPublicKey, message.getA(), receiverDHPublicKey, senderTag, receiverTag, queryTag,
            senderAccountID, receiverAccountID);
        // "Verify the sigma with Ring Signature Authentication, that is sigma == RVrf({H_b, H_a, Y}, t)."
        ringVerify(ourUserProfile.getLongTermPublicKey(), message.getUserProfile().getLongTermPublicKey(),
            receiverECDHPublicKey, message.getSigma(), t);
    }
}