/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.session.ake;

import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.api.Version;
import net.java.otr4j.crypto.DHKeyPairOTR3;
import net.java.otr4j.crypto.OtrCryptoEngine;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.io.OtrOutputStream;
import net.java.otr4j.messages.AbstractEncodedMessage;
import net.java.otr4j.messages.DHCommitMessage;

import javax.annotation.Nonnull;
import javax.crypto.interfaces.DHPublicKey;
import java.util.logging.Logger;

import static net.java.otr4j.crypto.DHKeyPairOTR3.generateDHKeyPair;
import static net.java.otr4j.crypto.DHKeyPairOTR3.verifyDHPublicKey;
import static net.java.otr4j.crypto.OtrCryptoEngine.CTR_LENGTH_BYTES;
import static net.java.otr4j.crypto.OtrCryptoEngine.aesEncrypt;
import static net.java.otr4j.crypto.OtrCryptoEngine.sha256Hash;
import static net.java.otr4j.util.SecureRandoms.randomBytes;

/**
 * Abstract AuthState implementation that provides authentication initiation
 * as this is supported in any state and is always processed in the same manner.
 *
 * @author Danny van Heumen
 */
abstract class AbstractAuthState implements AuthState {

    private static final Logger LOGGER = Logger.getLogger(AbstractAuthState.class.getName());

    private final long timestamp = System.nanoTime();

    @Override
    public final long getTimestamp() {
        return this.timestamp;
    }

    @Nonnull
    @Override
    public AbstractEncodedMessage initiate(final AuthContext context, final Version version) {
        if (version == Version.TWO || version == Version.THREE) {
            final InstanceTag receiverTag = context.getReceiverInstanceTag();
            if (version == Version.TWO && !receiverTag.equals(InstanceTag.ZERO_TAG)) {
                throw new IllegalStateException("BUG: a version 2 session should never be initiated from an instance (other than master session instance 0)");
            }
            return initiateVersion3(context, version, receiverTag);
        }
        if (version == Version.FOUR) {
            throw new IllegalArgumentException("Protocol version 4 is handled outside of AKE package, as part of message state machine.");
        }
        throw new UnsupportedOperationException("Unsupported protocol version.");
    }

    @Nonnull
    private static DHCommitMessage initiateVersion3(final AuthContext context, final Version version, final InstanceTag receiverTag) {
        // OTR: "Choose a random value x (at least 320 bits)"
        final DHKeyPairOTR3 keypair = generateDHKeyPair(context.secureRandom());
        LOGGER.finest("Generated local D-H key pair.");
        final DHPublicKey localDHPublicKey = keypair.getPublic();
        try {
            verifyDHPublicKey(localDHPublicKey);
        } catch (final OtrCryptoException ex) {
            // Caught and handled here as all components are constructed here
            // and failure should thus be considered a programming error.
            throw new IllegalStateException("Failed to generate valid local DH keypair.", ex);
        }
        // OTR: "Serialize gx as an MPI, gxmpi. [gxmpi will probably be 196 bytes long, starting with "\x00\x00\x00\xc0".]"
        final byte[] publicKeyBytes = new OtrOutputStream().writeBigInt(localDHPublicKey.getY()).toByteArray();
        // OTR: "Choose a random value r (128 bits)"
        final byte[] r = randomBytes(context.secureRandom(), new byte[OtrCryptoEngine.AES_KEY_LENGTH_BYTES]);
        // OTR: "Encrypt gxmpi using AES128-CTR, with key r and initial counter value 0. The result will be the same length as gxmpi."
        // use initial counter of all zero-bytes.
        final byte[] publicKeyEncrypted = aesEncrypt(r, new byte[CTR_LENGTH_BYTES], publicKeyBytes);
        // OTR: "This is the SHA256 hash of gxmpi."
        final byte[] publicKeyHash = sha256Hash(publicKeyBytes);
        // OTR: "Sends Alice AESr(gx), HASH(gx)"
        final DHCommitMessage dhcommit = new DHCommitMessage(version, publicKeyHash, publicKeyEncrypted,
                context.getSenderInstanceTag(), receiverTag);
        LOGGER.finest("Sending DH commit message.");
        context.setAuthState(new StateAwaitingDHKey(version, keypair, r));
        return dhcommit;
    }
}
