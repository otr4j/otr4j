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
import net.java.otr4j.api.SessionID;
import net.java.otr4j.api.SessionStatus;
import net.java.otr4j.api.TLV;
import net.java.otr4j.api.Version;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.io.EncryptedMessage.Content;
import net.java.otr4j.io.ErrorMessage;
import net.java.otr4j.io.OtrOutputStream;
import net.java.otr4j.messages.AbstractEncodedMessage;
import net.java.otr4j.messages.DataMessage;
import net.java.otr4j.messages.DataMessage4;
import net.java.otr4j.messages.MysteriousT;
import net.java.otr4j.session.ake.AuthState;
import net.java.otr4j.session.ake.SecurityParameters;
import net.java.otr4j.session.dake.DAKEState;
import net.java.otr4j.session.smp.SMException;
import net.java.otr4j.session.smp.SmpTlvHandler;
import net.java.otr4j.session.state.SessionKeyManager.SessionKeyUnavailableException;
import net.java.otr4j.util.ByteArrays;

import javax.annotation.Nonnull;
import javax.crypto.interfaces.DHPublicKey;
import java.net.ProtocolException;
import java.security.interfaces.DSAPublicKey;
import java.util.logging.Level;
import java.util.logging.Logger;

import static java.util.Collections.singletonList;
import static java.util.logging.Level.FINE;
import static java.util.logging.Level.FINEST;
import static java.util.logging.Level.INFO;
import static java.util.logging.Level.WARNING;
import static net.java.otr4j.api.OtrEngineHosts.handleEvent;
import static net.java.otr4j.crypto.OtrCryptoEngine.aesDecrypt;
import static net.java.otr4j.crypto.OtrCryptoEngine.aesEncrypt;
import static net.java.otr4j.crypto.OtrCryptoEngine.sha1Hmac;
import static net.java.otr4j.crypto.OtrCryptoEngine4.EXTRA_SYMMETRIC_KEY_CONTEXT_LENGTH_BYTES;
import static net.java.otr4j.io.EncryptedMessage.extractContents;
import static net.java.otr4j.io.ErrorMessage.ERROR_1_MESSAGE_UNREADABLE_MESSAGE;
import static net.java.otr4j.io.OtrEncodables.encode;
import static net.java.otr4j.session.smp.DSAPublicKeys.fingerprint;
import static net.java.otr4j.session.smp.SmpTlvHandler.smpPayload;
import static net.java.otr4j.util.ByteArrays.constantTimeEquals;

/**
 * Message state in case an encrypted session is established.
 * <p>
 * This message state is package-private as we only allow transitioning to this
 * state through the initial PLAINTEXT state.
 *
 * @author Danny van Heumen
 */
// TODO write additional unit tests for StateEncrypted3
final class StateEncrypted3 extends AbstractOTRState implements StateEncrypted {

    private static final SessionStatus STATUS = SessionStatus.ENCRYPTED;

    /**
     * TLV 8 notifies the recipient to use the extra symmetric key to set up an
     * out-of-band encrypted connection.
     * <p>
     * Payload:
     *  - 4-byte indication of what to use it for, e.g. file transfer, voice
     *    encryption, ...
     *  - undefined, free for use. Subsequent data might be the file name of
     *    your confidential file transfer.
     * <p>
     * WARNING! You should NEVER send the extra symmetric key as payload inside
     * the TLV record. The recipient can already generate the extra symmetric
     * key.
     */
    private static final int USE_EXTRA_SYMMETRIC_KEY = 0x0008;

    /**
     * Active version of the protocol in use in this encrypted session.
     */
    @Nonnull
    private final Version protocolVersion;

    @SuppressWarnings("PMD.LoggerIsNotStaticFinal")
    private final Logger logger;

    /**
     * The Socialist Millionaire Protocol handler.
     */
    @Nonnull
    private final SmpTlvHandler smpTlvHandler;

    /**
     * Long-term remote public key.
     */
    @Nonnull
    private final DSAPublicKey remotePublicKey;

    /**
     * Manager for session keys that are used during encrypted message state.
     */
    private final SessionKeyManager sessionKeyManager;

    private long lastMessageSentTimestamp = System.nanoTime();

    StateEncrypted3(final Context context, final AuthState authState, final DAKEState dakeState,
            final SecurityParameters params) throws OtrCryptoException {
        super(authState, dakeState);
        final SessionID sessionID = context.getSessionID();
        this.logger = Logger.getLogger(sessionID.getAccountID() + "-->" + sessionID.getUserID());
        this.protocolVersion = params.getVersion();
        this.smpTlvHandler = new SmpTlvHandler(context.secureRandom(), sessionID,
                fingerprint(context.getLocalKeyPair().getPublic()), fingerprint(params.getRemoteLongTermPublicKey()),
                context.getReceiverInstanceTag(), context.getHost(), params.getS());
        this.remotePublicKey = params.getRemoteLongTermPublicKey();
        this.sessionKeyManager = new SessionKeyManager(context.secureRandom(), params.getLocalDHKeyPair(),
                params.getRemoteDHPublicKey());
    }

    @Nonnull
    @Override
    public Version getVersion() {
        return this.protocolVersion;
    }

    @Override
    @Nonnull
    public SessionStatus getStatus() {
        return STATUS;
    }

    @Nonnull
    @Override
    public RemoteInfo getRemoteInfo() {
        return new RemoteInfo(Version.THREE, this.remotePublicKey, null);
    }

    @Override
    @Nonnull
    public SmpTlvHandler getSmpHandler() {
        return this.smpTlvHandler;
    }

    @Override
    @Nonnull
    public byte[] getExtraSymmetricKey() {
        if (this.protocolVersion == Version.TWO) {
            throw new UnsupportedOperationException("An OTR version 2 session was negotiated. The Extra Symmetric Key is not available in this version of the protocol.");
        }
        return this.sessionKeyManager.extraSymmetricKey();
    }

    @Nonnull
    @Override
    public Result handleEncodedMessage(final Context context, final AbstractEncodedMessage message)
            throws ProtocolException, OtrException {
        switch (message.protocolVersion) {
        case ONE:
            this.logger.log(INFO, "Encountered message for protocol version 1. Ignoring message.");
            return new Result(STATUS, true, false, null);
        case TWO:
        case THREE:
            return handleEncodedMessage3(context, message);
        case FOUR:
            // TODO consider if it is best to allow for OTRv4 DAKE messages to process, or strictly stick with OTRv3 messages only, when in `StateEncrypted3` (OTRv3 encrypted-messaging state)
            this.logger.log(INFO, "Encountered message for protocol version 4. Handling, in case this involves DAKE initiation.");
            return handleEncodedMessage4(context, message);
        default:
            throw new UnsupportedOperationException("BUG: Unsupported protocol version: " + message.protocolVersion);
        }
    }

    @Override
    @Nonnull
    @SuppressWarnings("PMD.CognitiveComplexity")
    Result handleDataMessage(final Context context, final DataMessage message) throws OtrException, ProtocolException {
        this.logger.finest("Message state is ENCRYPTED. Trying to decrypt message.");
        // Find matching session keys.
        final SessionKey matchingKeys;
        try {
            matchingKeys = this.sessionKeyManager.get(message.recipientKeyID, message.senderKeyID);
        } catch (final SessionKeyUnavailableException ex) {
            this.logger.finest("No matching keys found.");
            handleUnreadableMessage(context, message, ERROR_1_MESSAGE_UNREADABLE_MESSAGE);
            return new Result(STATUS, true, false, null);
        }

        // Verify received MAC with a locally calculated MAC.
        this.logger.finest("Transforming T to byte[] to calculate it's HmacSHA1.");

        final byte[] computedMAC = sha1Hmac(encode(message.getT()), matchingKeys.receivingMAC());
        if (!constantTimeEquals(computedMAC, message.mac)) {
            this.logger.finest("MAC verification failed, ignoring message.");
            handleUnreadableMessage(context, message, ERROR_1_MESSAGE_UNREADABLE_MESSAGE);
            return new Result(STATUS, true, false, null);
        }

        this.logger.finest("Computed HmacSHA1 value matches sent one.");

        // Mark this MAC key as old to be revealed.
        matchingKeys.markUsed();
        final byte[] dmc;
        try {
            final byte[] lengthenedReceivingCtr = matchingKeys.verifyReceivingCtr(message.ctr);
            dmc = aesDecrypt(matchingKeys.receivingAESKey(), lengthenedReceivingCtr, message.encryptedMessage);
        } catch (final SessionKey.ReceivingCounterValidationFailed ex) {
            this.logger.log(Level.WARNING, "Receiving ctr value failed validation, ignoring message: {0}", ex.getMessage());
            // TODO injecting error message because message MAC is already verified. This is a protocol error on the sender-side.
            context.injectMessage(new ErrorMessage("", "Message's counter value failed validation."));
            return new Result(STATUS, true, false, null);
        }

        // Rotate keys if necessary.
        final SessionKey mostRecent = this.sessionKeyManager.getMostRecentSessionKeys();
        if (mostRecent.getLocalKeyID() == message.recipientKeyID) {
            this.sessionKeyManager.rotateLocalKeys();
        }
        if (mostRecent.getRemoteKeyID() == message.senderKeyID) {
            this.sessionKeyManager.rotateRemoteKeys(message.nextDH);
        }

        // Extract and process TLVs.
        final Content content = extractContents(dmc);
        for (final TLV tlv : content.tlvs) {
            this.logger.log(FINE, "Received TLV type {0}", tlv.type);
            if (smpPayload(tlv)) {
                try {
                    final TLV response = this.smpTlvHandler.process(tlv);
                    if (response != null) {
                        context.injectMessage(transformSending(context, "", singletonList(response), FLAG_IGNORE_UNREADABLE));
                    }
                } catch (final SMException e) {
                    this.logger.log(Level.WARNING, "Illegal, bad or corrupt SMP TLV encountered. Stopped processing. This may indicate a bad implementation of OTR at the other party.",
                            e);
                }
                continue;
            }
            switch (tlv.type) {
            case TLV.PADDING: // TLV0
                // nothing to do here, just ignore the padding
                break;
            case TLV.DISCONNECTED: // TLV1
                if (!content.message.isEmpty()) {
                    this.logger.warning("Expected other party to send TLV type 1 with empty human-readable message.");
                }
                context.transition(this, new StateFinished(getAuthState(), getDAKEState()));
                break;
            case USE_EXTRA_SYMMETRIC_KEY:
                if (tlv.value.length < EXTRA_SYMMETRIC_KEY_CONTEXT_LENGTH_BYTES) {
                    throw new ProtocolException("OTR protocol specification requires at least 4 bytes, indicating the purpose for the extra symmetric key.");
                }
                final byte[] key = matchingKeys.extraSymmetricKey();
                if (constantTimeEquals(key, tlv.value)) {
                    this.logger.log(WARNING, "Other party sent Extra Symmetric Key in the TLV payload. This is incorrect use of the Extra Symmetric Key and exposes a secret value unnecessarily.");
                }
                final byte[] eskContext = ByteArrays.cloneRange(tlv.value, 0, 4);
                final byte[] eskValue = ByteArrays.cloneRange(tlv.value, 4, tlv.value.length - 4);
                handleEvent(context.getHost(), context.getSessionID(), context.getReceiverInstanceTag(),
                        Event.EXTRA_SYMMETRIC_KEY_DISCOVERED, new Event.ExtraSymmetricKey(key, eskContext, eskValue));
                break;
            default:
                this.logger.log(INFO, "Unsupported TLV #{0} received. Ignoring.", tlv.type);
                break;
            }
        }
        return new Result(STATUS, false, true, content.message.isEmpty() ? null : content.message);
    }

    @Nonnull
    @Override
    Result handleDataMessage(final Context context, final DataMessage4 message) {
        this.logger.log(FINE, "Received an OTRv4 data-message in OTRv3 session. This message cannot be decrypted. Ignoring.");
        return new Result(STATUS, true, false, null);
    }

    @Override
    @Nonnull
    public DataMessage transformSending(final Context context, final String msgText, final Iterable<TLV> tlvs,
            final byte flags) {
        final SessionID sessionID = context.getSessionID();
        this.logger.log(FINEST, "{0} sends an encrypted message to {1} through {2}.",
                new Object[]{sessionID.getAccountID(), sessionID.getUserID(), sessionID.getProtocolName()});

        final byte[] data = new OtrOutputStream().writeMessage(msgText).writeByte(0).writeTLV(tlvs).toByteArray();

        // Get encryption keys.
        final SessionKey encryptionKeys = this.sessionKeyManager.getEncryptionSessionKeys();
        final int senderKeyID = encryptionKeys.getLocalKeyID();
        final int recipientKeyID = encryptionKeys.getRemoteKeyID();

        // Increment CTR.
        final byte[] ctr = encryptionKeys.acquireSendingCtr();

        // Encrypt message.
        this.logger.log(FINEST, "Encrypting message with keyids (localKeyID, remoteKeyID) = ({0}, {1})",
                new Object[]{senderKeyID, recipientKeyID});
        final byte[] encryptedMsg = aesEncrypt(encryptionKeys.sendingAESKey(), ctr, data);

        // Get most recent keys to get the next D-H public key.
        final SessionKey mostRecentKeys = this.sessionKeyManager.getMostRecentSessionKeys();
        final DHPublicKey nextDH = mostRecentKeys.getLocalKeyPair().getPublic();

        // Calculate T.
        final MysteriousT t = new MysteriousT(this.protocolVersion, context.getSenderInstanceTag(),
                context.getReceiverInstanceTag(), flags, senderKeyID, recipientKeyID, nextDH, ctr, encryptedMsg);

        // Calculate T hash.
        final byte[] sendingMACKey = encryptionKeys.sendingMAC();

        this.logger.finest("Transforming T to byte[] to calculate it's HmacSHA1.");
        final byte[] mac = sha1Hmac(encode(t), sendingMACKey);

        // Get old MAC keys to be revealed.
        final byte[] oldKeys = this.sessionKeyManager.collectOldMacKeys();
        final DataMessage message = new DataMessage(t, mac, oldKeys, context.getSenderInstanceTag(),
                context.getReceiverInstanceTag());
        this.lastMessageSentTimestamp = System.nanoTime();
        return message;
    }

    @Override
    public void end(final Context context) throws OtrException {
        // The message carrying TLV 1 (Disconnect) is supposed to contain remaining MAC keys. However, as part of
        // sending the data message, we already include remaining MAC keys as part of sending the Data message.
        final TLV disconnectTlv = new TLV(TLV.DISCONNECTED, TLV.EMPTY_BODY);
        final AbstractEncodedMessage m = transformSending(context, "", singletonList(disconnectTlv),
                FLAG_IGNORE_UNREADABLE);
        try {
            context.injectMessage(m);
        } finally {
            // Transitioning to PLAINTEXT state should not depend on host. Ensure we transition to PLAINTEXT even if we
            // have problems injecting the message into the transport.
            context.transition(this, new StatePlaintext(getAuthState(), getDAKEState()));
        }
    }

    @Override
    public void destroy() {
        this.smpTlvHandler.close();
        this.sessionKeyManager.close();
    }

    @Override
    public long getLastMessageSentTimestamp() {
        return this.lastMessageSentTimestamp;
    }
}
