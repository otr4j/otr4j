/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.session.ake;

import net.java.otr4j.api.Version;
import net.java.otr4j.crypto.DHKeyPairOTR3;
import net.java.otr4j.messages.AbstractEncodedMessage;
import net.java.otr4j.messages.DHCommitMessage;
import net.java.otr4j.messages.DHKeyMessage;

import javax.annotation.Nonnull;
import java.util.logging.Level;
import java.util.logging.Logger;

import static net.java.otr4j.crypto.DHKeyPairOTR3.generateDHKeyPair;

/**
 * Initial AKE state, a.k.a. NONE.
 * <p>
 * StateInitial can be initialized with a query tag in case such a tag was sent.
 *
 * @author Danny van Heumen
 */
public final class StateInitial extends AbstractAuthState {

    private static final Logger LOGGER = Logger.getLogger(StateInitial.class.getName());

    /**
     * Instance with empty-string query tag, provided for convenience as any new AKE would start in this state.
     */
    private static final StateInitial INSTANCE = new StateInitial();

    /**
     * Acquire the original instance of StateInitial.
     *
     * @return Returns the singleton instance.
     */
    @Nonnull
    public static StateInitial instance() {
        return INSTANCE;
    }

    @Nonnull
    @Override
    public Result handle(final AuthContext context, final AbstractEncodedMessage message) {
        if (message.protocolVersion != Version.TWO && message.protocolVersion != Version.THREE) {
            throw new IllegalArgumentException("unsupported protocol version");
        }
        if (message instanceof DHCommitMessage) {
            // OTR: "Reply with a D-H Key Message, and transition authstate to AUTHSTATE_AWAITING_REVEALSIG."
            // OTR: "Choose a random value y (at least 320 bits), and calculate gy."
            final DHKeyPairOTR3 keypair = generateDHKeyPair(context.secureRandom());
            LOGGER.finest("Generated local D-H key pair.");
            context.setAuthState(new StateAwaitingRevealSig(message.protocolVersion, keypair,
                    ((DHCommitMessage) message).dhPublicKeyHash, ((DHCommitMessage) message).dhPublicKeyEncrypted));
            LOGGER.finest("Sending D-H key message.");
            // OTR: "Sends Bob gy"
            return new Result(new DHKeyMessage(message.protocolVersion, keypair.getPublic(),
                    context.getSenderInstanceTag(), context.getReceiverInstanceTag()), null);
        }
        // OTR: "Ignore the message."
        LOGGER.log(Level.INFO, "We only expect to receive a DH Commit message or its protocol version does not match expectations. Ignoring message with messagetype: {0}",
                message.getType());
        return new Result();
    }

    @Override
    public Version getVersion() {
        return Version.NONE;
    }
}
