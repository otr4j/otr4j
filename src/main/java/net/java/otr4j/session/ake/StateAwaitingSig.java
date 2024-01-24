/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.session.ake;

import net.java.otr4j.api.OtrException;
import net.java.otr4j.api.Version;
import net.java.otr4j.crypto.DHKeyPairOTR3;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.crypto.SharedSecret;
import net.java.otr4j.io.OtrOutputStream;
import net.java.otr4j.messages.AbstractEncodedMessage;
import net.java.otr4j.messages.DHCommitMessage;
import net.java.otr4j.messages.DHKeyMessage;
import net.java.otr4j.messages.RevealSignatureMessage;
import net.java.otr4j.messages.SignatureM;
import net.java.otr4j.messages.SignatureMessage;
import net.java.otr4j.messages.SignatureX;

import javax.annotation.Nonnull;
import javax.crypto.interfaces.DHPublicKey;
import java.net.ProtocolException;
import java.util.logging.Level;
import java.util.logging.Logger;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.crypto.DHKeyPairOTR3.generateDHKeyPair;
import static net.java.otr4j.crypto.DHKeyPairOTR3.verifyDHPublicKey;
import static net.java.otr4j.crypto.OtrCryptoEngine.CTR_LENGTH_BYTES;
import static net.java.otr4j.crypto.OtrCryptoEngine.aesDecrypt;
import static net.java.otr4j.crypto.OtrCryptoEngine.checkEquals;
import static net.java.otr4j.crypto.OtrCryptoEngine.sha256Hmac;
import static net.java.otr4j.crypto.OtrCryptoEngine.sha256Hmac160;
import static net.java.otr4j.io.OtrEncodables.encode;
import static net.java.otr4j.messages.SignatureXs.readSignatureX;

/**
 * AKE state Awaiting Signature message, a.k.a. AUTHSTATE_AWAITING_SIG.
 *
 * @author Danny van Heumen
 */
final class StateAwaitingSig extends AbstractAuthState {

    private static final Logger LOGGER = Logger.getLogger(StateAwaitingSig.class.getName());

    private final Version version;
    private final DHKeyPairOTR3 localDHKeyPair;
    private final DHPublicKey remoteDHPublicKey;
    private final SharedSecret s;

    /**
     * Saved copy of the Reveal Signature message for retransmission in case we receive a DH-Key message with the exact
     * same DH public key.
     */
    private final RevealSignatureMessage previousRevealSigMessage;

    StateAwaitingSig(final Version version, final DHKeyPairOTR3 localDHKeyPair, final DHPublicKey remoteDHPublicKey,
            final SharedSecret s, final RevealSignatureMessage previousRevealSigMessage) {
        super();
        if (version != Version.TWO && version != Version.THREE) {
            throw new IllegalArgumentException("unsupported version specified");
        }
        this.version = version;
        this.localDHKeyPair = requireNonNull(localDHKeyPair);
        try {
            this.remoteDHPublicKey = verifyDHPublicKey(remoteDHPublicKey);
        } catch (final OtrCryptoException ex) {
            throw new IllegalArgumentException("Illegal D-H Public Key provided.", ex);
        }
        this.s = requireNonNull(s);
        this.previousRevealSigMessage = requireNonNull(previousRevealSigMessage);
    }

    @Nonnull
    @Override
    public Result handle(final AuthContext context, final AbstractEncodedMessage message) throws OtrException,
            ProtocolException {
        if (message instanceof DHCommitMessage) {
            return handleDHCommitMessage(context, (DHCommitMessage) message);
        }
        if (message.protocolVersion != this.version) {
            throw new IllegalArgumentException("unexpected version");
        }
        if (message instanceof DHKeyMessage) {
            return handleDHKeyMessage((DHKeyMessage) message);
        }
        if (message instanceof SignatureMessage) {
            return handleSignatureMessage(context, (SignatureMessage) message);
        }
        LOGGER.log(Level.FINEST, "Only expected message types are DHKeyMessage and SignatureMessage. Ignoring message with type: {0}", message.getType());
        return new Result(null, null);
    }

    @Nonnull
    @Override
    public Version getVersion() {
        return this.version;
    }

    @Nonnull
    private static Result handleDHCommitMessage(final AuthContext context, final DHCommitMessage message) {
        // OTR: "Reply with a new D-H Key message, and transition authstate to AUTHSTATE_AWAITING_REVEALSIG."
        LOGGER.finest("Generating local D-H key pair.");
        // OTR: "Choose a random value y (at least 320 bits), and calculate gy."
        final DHKeyPairOTR3 newKeypair = generateDHKeyPair(context.secureRandom());
        LOGGER.finest("Ignoring AWAITING_SIG state and sending a new DH key message.");
        context.setAuthState(new StateAwaitingRevealSig(message.protocolVersion, newKeypair, message.dhPublicKeyHash,
                message.dhPublicKeyEncrypted));
        return new Result(
                new DHKeyMessage(message.protocolVersion, newKeypair.getPublic(), context.getSenderInstanceTag(),
                context.getReceiverInstanceTag()), null);
    }

    @Nonnull
    private Result handleDHKeyMessage(final DHKeyMessage message) {
        // OTR: "If this D-H Key message is the same the one you received earlier (when you entered AUTHSTATE_AWAITING_SIG):
        // Retransmit your Reveal Signature Message. Otherwise: Ignore the message."
        if (!this.localDHKeyPair.getPublic().getY().equals(message.dhPublicKey.getY())) {
            // DH keypair is not the same as local pair, this message is either
            // fake or not intended for this session.
            LOGGER.info("DHKeyMessage contains different DH public key. Ignoring message.");
            return new Result(null, null);
        }
        // DH keypair is the same, so other side apparently didn't receive our
        // first reveal signature message, let's send the message again.
        return new Result(this.previousRevealSigMessage, null);
    }

    @Nonnull
    private Result handleSignatureMessage(final AuthContext context, final SignatureMessage message)
            throws OtrCryptoException, ProtocolException {
        // OTR: "Decrypt the encrypted signature, and verify the signature and the MACs."
        try {
            // OTR: "Uses m2' to verify MACm2'(AESc'(XA))"
            final OtrOutputStream out = new OtrOutputStream().writeData(message.xEncrypted);
            final byte[] xEncryptedMAC = sha256Hmac160(out.toByteArray(), this.s.m2p());
            checkEquals(xEncryptedMAC, message.xEncryptedMAC, "xEncryptedMAC failed verification.");
            // OTR: "Uses c' to decrypt AESc'(XA) to obtain XA = pubA, keyidA, sigA(MA)"
            final byte[] remoteXBytes = aesDecrypt(this.s.cp(), new byte[CTR_LENGTH_BYTES], message.xEncrypted);
            final SignatureX remoteX = readSignatureX(remoteXBytes);
            // OTR: "Computes MA = MACm1'(gy, gx, pubA, keyidA)"
            final SignatureM remoteM = new SignatureM(this.remoteDHPublicKey, this.localDHKeyPair.getPublic(),
                    remoteX.getLongTermPublicKey(), remoteX.getDhKeyID());
            final byte[] expectedSignature = sha256Hmac(encode(remoteM), this.s.m1p());
            // OTR: "Uses pubA to verify sigA(MA)"
            remoteX.verify(expectedSignature);
            // Transition to ENCRYPTED session state.
            // OTR: "Transition msgstate to MSGSTATE_ENCRYPTED."
            final SecurityParameters params = new SecurityParameters(this.version, this.localDHKeyPair,
                    remoteX.getLongTermPublicKey(), this.remoteDHPublicKey, this.s);
            return new Result(null, params);
        } finally {
            // Ensure transition to AUTHSTATE_NONE.
            // OTR: "Transition authstate to AUTHSTATE_NONE."
            // OTR: "Regardless of whether the signature verifications succeed, the authstate variable is transitioned to AUTHSTATE_NONE."
            // NOTE: we explicitly construct an instance of StateInitial as to indicate that a transition happened
            // towards StateInitial at a later time, such that there will be no confusion in case of a need to copy
            // master session AuthState to slave session.
            context.setAuthState(new StateInitial());
        }
    }
}
