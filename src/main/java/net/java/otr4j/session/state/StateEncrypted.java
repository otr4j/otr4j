/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.state;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.crypto.interfaces.DHPublicKey;
import net.java.otr4j.OtrEngineHost;
import net.java.otr4j.OtrEngineHostUtil;
import net.java.otr4j.OtrException;
import net.java.otr4j.OtrPolicy;
import net.java.otr4j.OtrPolicyUtil;
import net.java.otr4j.crypto.OtrCryptoEngine;
import net.java.otr4j.io.OtrInputStream;
import net.java.otr4j.io.OtrOutputStream;
import net.java.otr4j.io.SerializationConstants;
import net.java.otr4j.io.SerializationUtils;
import net.java.otr4j.io.messages.AbstractMessage;
import net.java.otr4j.io.messages.DataMessage;
import net.java.otr4j.io.messages.ErrorMessage;
import net.java.otr4j.io.messages.MysteriousT;
import net.java.otr4j.io.messages.PlainTextMessage;
import net.java.otr4j.io.messages.QueryMessage;
import net.java.otr4j.session.SessionID;
import net.java.otr4j.session.SessionStatus;
import net.java.otr4j.session.TLV;
import net.java.otr4j.session.ake.SecurityParameters;

/**
 * Message state in case an encrypted session is established.
 *
 * This message state is package-private as we only allow transitioning to this
 * state through the initial PLAINTEXT state.
 *
 * @author Danny van Heumen
 */
final class StateEncrypted extends AbstractState {

    @SuppressWarnings("NonConstantLogger")
    private final Logger logger;

    /**
     * Session ID.
     */
    private final SessionID sessionId;

    /**
     * Active version of the protocol in use in this encrypted session.
     */
    private final int protocolVersion;

    /**
     * The Socialist Millionaire Protocol handler.
     */
    private final SmpTlvHandler smpTlvHandler;

    /**
     * Long-term remote public key.
     */
    private final PublicKey remotePublicKey;

    /**
     * Manager for session keys that are used during encrypted message state.
     */
    private final SessionKeyManager sessionKeyManager;

    StateEncrypted(@Nonnull final Context context, @Nonnull final SecurityParameters params) throws OtrException {
        this.sessionId = context.getSessionID();
        this.logger = Logger.getLogger(sessionId.getAccountID() + "-->" + sessionId.getUserID());
        if (params.getVersion() > 3) {
            throw new UnsupportedOperationException("Unsupported protocol version specified.");
        }
        this.protocolVersion = params.getVersion();
        this.smpTlvHandler = new SmpTlvHandler(this, context, params.getS());
        this.remotePublicKey = params.getRemoteLongTermPublicKey();
        this.sessionKeyManager = new SessionKeyManager(context.secureRandom(),
                params.getLocalDHKeyPair(), params.getRemoteDHPublicKey());
    }

    @Override
    public int getVersion() {
        return this.protocolVersion;
    }

    @Override
    @Nonnull
    public SessionID getSessionID() {
        return this.sessionId;
    }

    @Override
    @Nonnull
    public SessionStatus getStatus() {
        return SessionStatus.ENCRYPTED;
    }

    @Override
    @Nonnull
    public SmpTlvHandler getSmpTlvHandler() {
        return this.smpTlvHandler;
    }

    @Override
    @Nonnull
    public PublicKey getRemotePublicKey() {
        return remotePublicKey;
    }

    @Override
    public byte[] getExtraSymmetricKey() {
        return this.sessionKeyManager.extraSymmetricKey();
    }

    @Nonnull
    @Override
    public String handlePlainTextMessage(@Nonnull final Context context, @Nonnull final PlainTextMessage plainTextMessage) throws OtrException {
        // Display the message to the user, but warn him that the message was
        // received unencrypted.
        OtrEngineHostUtil.unencryptedMessageReceived(context.getHost(),
                sessionId, plainTextMessage.cleanText);
        return plainTextMessage.cleanText;
    }
    
    // TODO should we assume that ctr value is always incremented and should we check our expectations against actual ctr value being sent? What if counter party always picks ctr == 0?
    @Override
    @Nullable
    public String handleDataMessage(@Nonnull final Context context, @Nonnull final DataMessage data) throws OtrException {
        logger.finest("Message state is ENCRYPTED. Trying to decrypt message.");
        final OtrEngineHost host = context.getHost();
        // Find matching session keys.
        final SessionKey matchingKeys;
        try {
            matchingKeys = sessionKeyManager.get(data.recipientKeyID,
                    data.senderKeyID);
        } catch(final SessionKeyManager.SessionKeyUnavailableException ex) {
            logger.finest("No matching keys found.");
            OtrEngineHostUtil.unreadableMessageReceived(host, sessionId);
            final String replymsg = OtrEngineHostUtil.getReplyForUnreadableMessage(host, sessionId, DEFAULT_REPLY_UNREADABLE_MESSAGE);
            context.injectMessage(new ErrorMessage(AbstractMessage.MESSAGE_ERROR, replymsg));
            return null;
        }

        // Verify received MAC with a locally calculated MAC.
        logger.finest("Transforming T to byte[] to calculate it's HmacSHA1.");

        final byte[] serializedT = SerializationUtils.toByteArray(data.getT());
        final byte[] computedMAC = OtrCryptoEngine.sha1Hmac(serializedT,
                matchingKeys.receivingMAC(), SerializationConstants.TYPE_LEN_MAC);
        if (!Arrays.equals(computedMAC, data.mac)) {
            // TODO consider replacing this with OtrCryptoEngine.checkEquals such that signaling error happens automatically. Do we want this?
            logger.finest("MAC verification failed, ignoring message");
            OtrEngineHostUtil.unreadableMessageReceived(host, sessionId);
            final String replymsg = OtrEngineHostUtil.getReplyForUnreadableMessage(host, sessionId, DEFAULT_REPLY_UNREADABLE_MESSAGE);
            context.injectMessage(new ErrorMessage(AbstractMessage.MESSAGE_ERROR, replymsg));
            return null;
        }

        logger.finest("Computed HmacSHA1 value matches sent one.");

        // Mark this MAC key as old to be revealed.
        matchingKeys.markUsed();
        final byte[] dmc;
        try {
            final byte[] lengthenedReceivingCtr = matchingKeys.verifyReceivingCtr(data.ctr);
            dmc = OtrCryptoEngine.aesDecrypt(matchingKeys.receivingAESKey(),
                    lengthenedReceivingCtr, data.encryptedMessage);
        } catch (final SessionKey.ReceivingCounterValidationFailed ex) {
            // TODO consider if this is the right way of handling failed receiving counter validation
            logger.finest("Receiving ctr validation failed, ignoring message");
            OtrEngineHostUtil.unreadableMessageReceived(host, sessionId);
            final String replymsg = OtrEngineHostUtil.getReplyForUnreadableMessage(host, sessionId, DEFAULT_REPLY_UNREADABLE_MESSAGE);
            context.injectMessage(new ErrorMessage(AbstractMessage.MESSAGE_ERROR, replymsg));
            return null;
        }

        // Rotate keys if necessary.
        final SessionKey mostRecent = this.sessionKeyManager.getMostRecentSessionKeys();
        if (mostRecent.getLocalKeyID() == data.recipientKeyID) {
            this.sessionKeyManager.rotateLocalKeys();
        }
        if (mostRecent.getRemoteKeyID() == data.senderKeyID) {
            this.sessionKeyManager.rotateRemoteKeys(data.nextDH);
        }

        // find the null TLV separator in the package, or just use the end value
        int tlvIndex = dmc.length;
        for (int i = 0; i < dmc.length; i++) {
            if (dmc[i] == 0x00) {
                tlvIndex = i;
                break;
            }
        }

        // get message body without trailing 0x00, expect UTF-8 bytes
        final String decryptedMsgContent = new String(dmc, 0, tlvIndex, SerializationUtils.UTF8);

        // if the null TLV separator is somewhere in the middle, there are TLVs
        final LinkedList<TLV> tlvs = new LinkedList<>();
        tlvIndex++;  // to ignore the null
        if (tlvIndex < dmc.length) {
            byte[] tlvsb = new byte[dmc.length - tlvIndex];
            System.arraycopy(dmc, tlvIndex, tlvsb, 0, tlvsb.length);

            final ByteArrayInputStream tin = new ByteArrayInputStream(tlvsb);
            final OtrInputStream eois = new OtrInputStream(tin);
            try {
                while (tin.available() > 0) {
                    final int type = eois.readShort();
                    final byte[] tdata = eois.readTlvData();
                    tlvs.add(new TLV(type, tdata));
                }
            } catch (IOException e) {
                throw new OtrException(e);
            } finally {
                try {
                    eois.close();
                } catch (IOException e) {
                    throw new OtrException(e);
                }
            }
        }
        if (!tlvs.isEmpty()) {
            for (final TLV tlv : tlvs) {
                logger.log(Level.FINE, "Received TLV type {0}", tlv.getType());
                switch (tlv.getType()) {
                    case TLV.PADDING: // TLV0
                        // nothing to do here, just ignore the padding
                        break;
                    case TLV.DISCONNECTED: // TLV1
                        context.setState(new StateFinished(this.sessionId));
                        break;
                    case TLV.SMP1Q: //TLV7
                        this.smpTlvHandler.processTlvSMP1Q(tlv);
                        break;
                    case TLV.SMP1: // TLV2
                        this.smpTlvHandler.processTlvSMP1(tlv);
                        break;
                    case TLV.SMP2: // TLV3
                        this.smpTlvHandler.processTlvSMP2(tlv);
                        break;
                    case TLV.SMP3: // TLV4
                        this.smpTlvHandler.processTlvSMP3(tlv);
                        break;
                    case TLV.SMP4: // TLV5
                        this.smpTlvHandler.processTlvSMP4(tlv);
                        break;
                    case TLV.SMP_ABORT: //TLV6
                        this.smpTlvHandler.processTlvSMP_ABORT(tlv);
                        break;
                    default:
                        logger.log(Level.WARNING, "Unsupported TLV #{0} received!", tlv.getType());
                        break;
                }
            }
        }
        return decryptedMsgContent;
    }

    @Override
    public void handleErrorMessage(@Nonnull final Context context, @Nonnull final ErrorMessage errorMessage) throws OtrException {
        super.handleErrorMessage(context, errorMessage);
        final OtrPolicy policy = context.getSessionPolicy();
        if (!policy.getErrorStartAKE()) {
            return;
        }
        // Re-negotiate if we got an error and we are in ENCRYPTED message state
        logger.finest("Error message starts AKE.");
        final Set<Integer> versions = OtrPolicyUtil.allowedVersions(policy);
        logger.finest("Sending Query");
        context.injectMessage(new QueryMessage(versions));
    }

    @Override
    @Nonnull
    public DataMessage transformSending(@Nonnull final Context context, @Nonnull final String msgText, @Nonnull final List<TLV> tlvs) throws OtrException {
        logger.log(Level.FINEST, "{0} sends an encrypted message to {1} through {2}.",
                new Object[]{sessionId.getAccountID(), sessionId.getUserID(), sessionId.getProtocolName()});

        // Get encryption keys.
        final SessionKey encryptionKeys = this.sessionKeyManager.getEncryptionSessionKeys();
        final int senderKeyID = encryptionKeys.getLocalKeyID();
        final int receipientKeyID = encryptionKeys.getRemoteKeyID();

        // Increment CTR.
        final byte[] ctr = encryptionKeys.acquireSendingCtr();

        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        if (msgText.length() > 0) {
            try {
                out.write(SerializationUtils.convertTextToBytes(msgText));
            } catch (IOException e) {
                throw new OtrException(e);
            }
        }

        // Append tlvs
        if (!tlvs.isEmpty()) {
            out.write((byte) 0x00);

            final OtrOutputStream eoos = new OtrOutputStream(out);
            try {
                for (TLV tlv : tlvs) {
                    eoos.writeShort(tlv.getType());
                    eoos.writeTlvData(tlv.getValue());
                }
            } catch (final IOException ex) {
                throw new OtrException(ex);
            } finally {
                try {
                    eoos.close();
                } catch (IOException e) {
                    throw new OtrException(e);
                }
            }
        }

        final byte[] data = out.toByteArray();
        // Encrypt message.
        logger.log(Level.FINEST, "Encrypting message with keyids (localKeyID, remoteKeyID) = ({0}, {1})",
                new Object[]{senderKeyID, receipientKeyID});
        final byte[] encryptedMsg = OtrCryptoEngine.aesEncrypt(encryptionKeys
                .sendingAESKey(), ctr, data);

        // Get most recent keys to get the next D-H public key.
        final SessionKey mostRecentKeys = this.sessionKeyManager.getMostRecentSessionKeys();
        final DHPublicKey nextDH = (DHPublicKey) mostRecentKeys.getLocalKeyPair().getPublic();

        // Calculate T.
        final MysteriousT t
                = new MysteriousT(this.protocolVersion,
                        context.getSenderInstanceTag().getValue(),
                        context.getReceiverInstanceTag().getValue(),
                        0, senderKeyID, receipientKeyID, nextDH, ctr,
                        encryptedMsg);

        // Calculate T hash.
        final byte[] sendingMACKey = encryptionKeys.sendingMAC();

        logger.finest("Transforming T to byte[] to calculate it's HmacSHA1.");
        final byte[] serializedT = SerializationUtils.toByteArray(t);
        final byte[] mac = OtrCryptoEngine.sha1Hmac(serializedT, sendingMACKey,
                SerializationConstants.TYPE_LEN_MAC);

        // Get old MAC keys to be revealed.
        final byte[] oldKeys = this.sessionKeyManager.collectOldMacKeys();
        final DataMessage m = new DataMessage(t, mac, oldKeys);
        m.senderInstanceTag = context.getSenderInstanceTag().getValue();
        m.receiverInstanceTag = context.getReceiverInstanceTag().getValue();
        return m;
    }

    @Override
    public void secure(@Nonnull final Context context, @Nonnull final SecurityParameters params) throws OtrException {
        context.setState(new StateEncrypted(context, params));
    }

    @Override
    public void end(@Nonnull final Context context) throws OtrException {
        final TLV disconnectTlv = new TLV(TLV.DISCONNECTED, new byte[0]);
        final DataMessage m = transformSending(context, "", Collections.singletonList(disconnectTlv));
        // TODO consider wrapping in try-finally to ensure state transition to plaintext
        context.injectMessage(m);
        context.setState(new StatePlaintext(this.sessionId));
    }
}
