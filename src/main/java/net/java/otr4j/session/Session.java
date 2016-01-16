/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.ProtocolException;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.Vector;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.interfaces.DHPublicKey;

import net.java.otr4j.OtrEngineHost;
import net.java.otr4j.OtrEngineHostUtil;
import net.java.otr4j.OtrEngineListener;
import net.java.otr4j.OtrEngineListenerUtil;
import net.java.otr4j.OtrException;
import net.java.otr4j.OtrPolicy;
import net.java.otr4j.crypto.OtrCryptoEngine;
import net.java.otr4j.io.OtrInputStream;
import net.java.otr4j.io.OtrOutputStream;
import net.java.otr4j.io.SerializationConstants;
import net.java.otr4j.io.SerializationUtils;
import net.java.otr4j.io.messages.AbstractEncodedMessage;
import net.java.otr4j.io.messages.AbstractMessage;
import net.java.otr4j.io.messages.DHCommitMessage;
import net.java.otr4j.io.messages.DataMessage;
import net.java.otr4j.io.messages.ErrorMessage;
import net.java.otr4j.io.messages.MysteriousT;
import net.java.otr4j.io.messages.PlainTextMessage;
import net.java.otr4j.io.messages.QueryMessage;

/**
 * @author George Politis
 * @author Danny van Heumen
 */
public class Session {

    public static interface OTRv {
        public static final int ONE = 1;
        public static final int TWO = 2;
        public static final int THREE = 3;
        public static final Set<Integer> ALL = new HashSet<Integer>(
                Arrays.asList(ONE, TWO, THREE));
    }

    private HashMap<InstanceTag, Session> slaveSessions;

    private volatile Session outgoingSession;

    private final boolean isMasterSession;

    private SessionID sessionID;
    private OtrEngineHost host;
    private SessionStatus sessionStatus;
    private AuthContext authContext;
    private SessionKeys[][] sessionKeys;
    private Vector<byte[]> oldMacKeys;
    private Logger logger;
    private SmpTlvHandler smpTlvHandler;
    private BigInteger ess;
    private OfferStatus offerStatus;
    private final InstanceTag senderTag;
    private InstanceTag receiverTag;
    private int protocolVersion;
    private OtrAssembler assembler;
    private final OtrFragmenter fragmenter;

    /**
     * Secure random instance to be used for this Session. This single
     * SecureRandom instance is there to be shared among classes the classes in
     * this package in order to support this specific Session instance.
     * 
     * The SecureRandom instance should not be shared between sessions.
     *
     * Note: Please ensure that an instance always exists, as it is also used by
     * other classes in the package.
     */
    private final SecureRandom secureRandom;

    public Session(final SessionID sessionID, final OtrEngineHost listener) {
        this.secureRandom = new SecureRandom();

        this.setSessionID(sessionID);
        this.setHost(listener);

        // client application calls OtrSessionManager.getSessionStatus()
        // -> create new session if it does not exist, end up here
        // -> setSessionStatus() fires statusChangedEvent
        // -> client application calls OtrSessionManager.getSessionStatus()
        this.sessionStatus = SessionStatus.PLAINTEXT;
        this.offerStatus = OfferStatus.idle;

        this.senderTag = new InstanceTag(this.secureRandom.nextDouble());
        this.receiverTag = InstanceTag.ZERO_TAG;

        slaveSessions = new HashMap<InstanceTag, Session>();
        outgoingSession = this;
        isMasterSession = true;

        assembler = new OtrAssembler(this.senderTag);
        fragmenter = new OtrFragmenter(outgoingSession, listener);
    }

    // A private constructor for instantiating 'slave' sessions.
    private Session(final SessionID sessionID,
            final OtrEngineHost listener,
            final InstanceTag senderTag,
            final InstanceTag receiverTag,
            final SecureRandom secureRandom) {
        if (secureRandom == null) {
            throw new NullPointerException("secureRandom");
        }
        this.secureRandom = secureRandom;

        this.setSessionID(sessionID);
        this.setHost(listener);

        this.sessionStatus = SessionStatus.PLAINTEXT;
        this.offerStatus = OfferStatus.idle;

        this.senderTag = senderTag;
        this.receiverTag = receiverTag;

        outgoingSession = this;
        isMasterSession = false;
        protocolVersion = OTRv.THREE;

        assembler = new OtrAssembler(this.senderTag);
        fragmenter = new OtrFragmenter(outgoingSession, listener);
    }

    /**
     * Expose secure random instance to other classes in the package.
     * Don't expose to public, though.
     *
     * @return Returns the Session's secure random instance.
     */
    SecureRandom secureRandom() {
        return this.secureRandom;
    }

    public BigInteger getS() {
        return ess;
    }

    private SessionKeys getEncryptionSessionKeys() {
        logger.finest("Getting encryption keys");
        return getSessionKeysByIndex(SessionKeys.PREVIOUS, SessionKeys.CURRENT);
    }

    private SessionKeys getMostRecentSessionKeys() {
        logger.finest("Getting most recent keys.");
        return getSessionKeysByIndex(SessionKeys.CURRENT, SessionKeys.CURRENT);
    }

    private SessionKeys getSessionKeysByID(final int localKeyID, final int remoteKeyID) {
        logger.finest("Searching for session keys with (localKeyID, remoteKeyID) = ("
                + localKeyID + "," + remoteKeyID + ")");

        // TODO consider introducing local sessionKeys variable instead of repeated getSessionKeys() calls
        for (int i = 0; i < getSessionKeys().length; i++) {
            for (int j = 0; j < getSessionKeys()[i].length; j++) {
                final SessionKeys current = getSessionKeysByIndex(i, j);
                if (current.getLocalKeyID() == localKeyID
                        && current.getRemoteKeyID() == remoteKeyID) {
                    logger.finest("Matching keys found.");
                    return current;
                }
            }
        }

        return null;
    }

    private SessionKeys getSessionKeysByIndex(final int localKeyIndex,
            final int remoteKeyIndex) {
        if (getSessionKeys()[localKeyIndex][remoteKeyIndex] == null) {
            getSessionKeys()[localKeyIndex][remoteKeyIndex] = new SessionKeys(
                    localKeyIndex, remoteKeyIndex);
        }

        return getSessionKeys()[localKeyIndex][remoteKeyIndex];
    }

    private void rotateRemoteSessionKeys(final DHPublicKey pubKey)
            throws OtrException {

        logger.finest("Rotating remote keys.");
        final SessionKeys sess1 = getSessionKeysByIndex(SessionKeys.CURRENT,
                SessionKeys.PREVIOUS);
        if (sess1.getIsUsedReceivingMACKey()) {
            logger
                    .finest("Detected used Receiving MAC key. Adding to old MAC keys to reveal it.");
            getOldMacKeys().add(sess1.getReceivingMACKey());
        }

        final SessionKeys sess2 = getSessionKeysByIndex(SessionKeys.PREVIOUS,
                SessionKeys.PREVIOUS);
        if (sess2.getIsUsedReceivingMACKey()) {
            logger
                    .finest("Detected used Receiving MAC key. Adding to old MAC keys to reveal it.");
            getOldMacKeys().add(sess2.getReceivingMACKey());
        }

        final SessionKeys sess3 = getSessionKeysByIndex(SessionKeys.CURRENT,
                SessionKeys.CURRENT);
        sess1.setRemoteDHPublicKey(sess3.getRemoteKey(), sess3.getRemoteKeyID());

        final SessionKeys sess4 = getSessionKeysByIndex(SessionKeys.PREVIOUS,
                SessionKeys.CURRENT);
        sess2.setRemoteDHPublicKey(sess4.getRemoteKey(), sess4.getRemoteKeyID());

        sess3.setRemoteDHPublicKey(pubKey, sess3.getRemoteKeyID() + 1);
        sess4.setRemoteDHPublicKey(pubKey, sess4.getRemoteKeyID() + 1);
    }

    private void rotateLocalSessionKeys() throws OtrException {

        logger.finest("Rotating local keys.");
        final SessionKeys sess1 = getSessionKeysByIndex(SessionKeys.PREVIOUS,
                SessionKeys.CURRENT);
        if (sess1.getIsUsedReceivingMACKey()) {
            logger.finest("Detected used Receiving MAC key. Adding to old MAC keys to reveal it.");
            getOldMacKeys().add(sess1.getReceivingMACKey());
        }

        final SessionKeys sess2 = getSessionKeysByIndex(SessionKeys.PREVIOUS,
                SessionKeys.PREVIOUS);
        if (sess2.getIsUsedReceivingMACKey()) {
            logger.finest("Detected used Receiving MAC key. Adding to old MAC keys to reveal it.");
            getOldMacKeys().add(sess2.getReceivingMACKey());
        }

        final SessionKeys sess3 = getSessionKeysByIndex(SessionKeys.CURRENT,
                SessionKeys.CURRENT);
        sess1.setLocalPair(sess3.getLocalPair(), sess3.getLocalKeyID());
        final SessionKeys sess4 = getSessionKeysByIndex(SessionKeys.CURRENT,
                SessionKeys.PREVIOUS);
        sess2.setLocalPair(sess4.getLocalPair(), sess4.getLocalKeyID());

        final KeyPair newPair = OtrCryptoEngine.generateDHKeyPair(this.secureRandom);
        sess3.setLocalPair(newPair, sess3.getLocalKeyID() + 1);
        sess4.setLocalPair(newPair, sess4.getLocalKeyID() + 1);
    }

    private byte[] collectOldMacKeys() {
        logger.finest("Collecting old MAC keys to be revealed.");
        int len = 0;
        for (int i = 0; i < getOldMacKeys().size(); i++) {
            len += getOldMacKeys().get(i).length;
        }

        final ByteBuffer buff = ByteBuffer.allocate(len);
        for (int i = 0; i < getOldMacKeys().size(); i++) {
            buff.put(getOldMacKeys().get(i));
        }

        getOldMacKeys().clear();
        return buff.array();
    }

    private void setSessionStatus(final SessionStatus sessionStatus)
            throws OtrException {

        switch (sessionStatus) {
            case ENCRYPTED:
                final AuthContext auth = this.getAuthContext();
                ess = auth.getS();
                logger.finest("Setting most recent session keys from auth.");
                for (int i = 0; i < this.getSessionKeys()[0].length; i++) {
                    final SessionKeys current = getSessionKeysByIndex(0, i);
                    current.setLocalPair(auth.getLocalDHKeyPair(), 1);
                    current.setRemoteDHPublicKey(auth.getRemoteDHPublicKey(), 1);
                    current.setS(auth.getS());
                }

                final KeyPair nextDH = OtrCryptoEngine.generateDHKeyPair(this.secureRandom);
                for (int i = 0; i < this.getSessionKeys()[1].length; i++) {
                    final SessionKeys current = getSessionKeysByIndex(1, i);
                    current.setRemoteDHPublicKey(auth.getRemoteDHPublicKey(), 1);
                    current.setLocalPair(nextDH, 2);
                }

                this.setRemotePublicKey(auth.getRemoteLongTermPublicKey());

                auth.reset();
                getSmpTlvHandler().reset();
                break;
            case FINISHED:
            case PLAINTEXT:
                break;
        }

        if (sessionStatus == this.sessionStatus) {
            return;
        }

        this.sessionStatus = sessionStatus;

        OtrEngineListenerUtil.sessionStatusChanged(this.listeners, getSessionID());
    }

    public SessionStatus getSessionStatus() {
        if (this != outgoingSession && getProtocolVersion() == OTRv.THREE) {
            return outgoingSession.getSessionStatus();
        }
        return sessionStatus;
    }

    private void setSessionID(final SessionID sessionID) {
        logger = Logger.getLogger(sessionID.getAccountID() + "-->" + sessionID.getUserID());
        this.sessionID = sessionID;
    }

    public SessionID getSessionID() {
        return sessionID;
    }

    private void setHost(final OtrEngineHost host) {
        this.host = host;
    }

    OtrEngineHost getHost() {
        return host;
    }

    private SmpTlvHandler getSmpTlvHandler() {
        if (smpTlvHandler == null) {
            smpTlvHandler = new SmpTlvHandler(this);
        }
        return smpTlvHandler;
    }

    private SessionKeys[][] getSessionKeys() {
        if (sessionKeys == null) {
            sessionKeys = new SessionKeys[2][2];
        }
        return sessionKeys;
    }

    AuthContext getAuthContext() {
        if (authContext == null) {
            authContext = new AuthContext(this);
        }
        return authContext;
    }

    private Vector<byte[]> getOldMacKeys() {
        if (oldMacKeys == null) {
            oldMacKeys = new Vector<byte[]>();
        }
        return oldMacKeys;
    }

    public String transformReceiving(String msgText) throws OtrException {

        final OtrPolicy policy = getSessionPolicy();
        if (!policy.getAllowV1() && !policy.getAllowV2() && !policy.getAllowV3()) {
            logger
                    .finest("Policy does not allow neither V1 nor V2 & V3, ignoring message.");
            return msgText;
        }

        try {
            msgText = assembler.accumulate(msgText);
        } catch (UnknownInstanceException e) {
            // The fragment is not intended for us
            logger.finest(e.getMessage());
            OtrEngineHostUtil.messageFromAnotherInstanceReceived(getHost(), getSessionID());
            return null;
        } catch (ProtocolException e) {
            logger.warning("An invalid message fragment was discarded.");
            return null;
        }

        if (msgText == null) {
            return null; // Not a complete message (yet).
        }

        final AbstractMessage m;
        try {
            m = SerializationUtils.toMessage(msgText);
        } catch (IOException e) {
            throw new OtrException(e);
        }
        if (m == null) {
            return msgText; // Propably null or empty.
        }

        if (m.messageType != AbstractMessage.MESSAGE_PLAINTEXT) {
            offerStatus = OfferStatus.accepted;
        } else if (offerStatus == OfferStatus.sent) {
            offerStatus = OfferStatus.rejected;
        }

        if (m instanceof AbstractEncodedMessage && isMasterSession) {

            final AbstractEncodedMessage encodedM = (AbstractEncodedMessage) m;

            if (encodedM.protocolVersion == OTRv.THREE) {

                if (encodedM.receiverInstanceTag != this.getSenderInstanceTag().getValue()) {
                    if (!(encodedM.messageType == AbstractEncodedMessage.MESSAGE_DH_COMMIT
                    && encodedM.receiverInstanceTag == 0)) {

                        // The message is not intended for us. Discarding...
                        logger.finest("Received an encoded message with receiver instance tag" +
                                " that is different from ours, ignore this message");
                        OtrEngineHostUtil.messageFromAnotherInstanceReceived(getHost(), getSessionID());
                        return null;
                    }
                }

                if (encodedM.senderInstanceTag != this.getReceiverInstanceTag().getValue()
                        && this.getReceiverInstanceTag().getValue() != 0) {

                    /*
                     * Message is intended for us but is coming from a different
                     * instance. We relay this message to the appropriate
                     * session for transforming.
                     */

                    logger.finest("Received an encoded message from a different instance. Our buddy"
                            +
                            "may be logged from multiple locations.");

                    final InstanceTag newReceiverTag = new InstanceTag(encodedM.senderInstanceTag);
                    // TODO consider making slaveSessions final in order to avoid slaveSessions locking fails (synchronization on non-final fields)
                    synchronized (slaveSessions) {

                        if (!slaveSessions.containsKey(newReceiverTag)) {

                            final Session session =
                                    new Session(sessionID,
                                            getHost(),
                                            getSenderInstanceTag(),
                                            newReceiverTag,
                                            this.secureRandom);

                            if (encodedM.messageType == AbstractEncodedMessage.MESSAGE_DHKEY) {

                                session.getAuthContext().r =
                                        this.getAuthContext().r;
                                session.getAuthContext().localDHKeyPair =
                                        this.getAuthContext().localDHKeyPair;
                                session.getAuthContext().localDHPublicKeyBytes =
                                        this.getAuthContext().localDHPublicKeyBytes;
                                session.getAuthContext().localDHPublicKeyEncrypted =
                                        this.getAuthContext().localDHPublicKeyEncrypted;
                                session.getAuthContext().localDHPublicKeyHash =
                                        this.getAuthContext().localDHPublicKeyHash;
                            }
                            session.addOtrEngineListener(new OtrEngineListener() {

                                @Override
                                public void sessionStatusChanged(final SessionID sessionID) {
                                    OtrEngineListenerUtil.sessionStatusChanged(listeners, sessionID);
                                }

                                @Override
                                public void multipleInstancesDetected(final SessionID sessionID) {
                                }

                                @Override
                                public void outgoingSessionChanged(final SessionID sessionID) {
                                }
                            });

                            slaveSessions.put(newReceiverTag, session);

                            OtrEngineHostUtil.multipleInstancesDetected(getHost(), sessionID);
                            OtrEngineListenerUtil.multipleInstancesDetected(this.listeners, sessionID);
                        }
                    }
                    return slaveSessions.get(newReceiverTag).transformReceiving(msgText);
                }
            }
        }

        switch (m.messageType) {
            case AbstractEncodedMessage.MESSAGE_DATA:
                return handleDataMessage((DataMessage) m);
            case AbstractMessage.MESSAGE_ERROR:
                handleErrorMessage((ErrorMessage) m);
                return null;
            case AbstractMessage.MESSAGE_PLAINTEXT:
                return handlePlainTextMessage((PlainTextMessage) m);
            case AbstractMessage.MESSAGE_QUERY:
                handleQueryMessage((QueryMessage) m);
                return null;
            case AbstractEncodedMessage.MESSAGE_DH_COMMIT:
            case AbstractEncodedMessage.MESSAGE_DHKEY:
            case AbstractEncodedMessage.MESSAGE_REVEALSIG:
            case AbstractEncodedMessage.MESSAGE_SIGNATURE:
                final AuthContext auth = this.getAuthContext();
                auth.handleReceivingMessage(m);

                if (auth.getIsSecure()) {
                    this.setSessionStatus(SessionStatus.ENCRYPTED);
                    logger.finest("Gone Secure.");
                }
                return null;
            default:
                throw new UnsupportedOperationException(
                        "Received an unknown message type.");
        }
    }

    private void handleQueryMessage(final QueryMessage queryMessage)
            throws OtrException {
        logger.finest(getSessionID().getAccountID()
                + " received a query message from "
                + getSessionID().getUserID() + " through "
                + getSessionID().getProtocolName() + ".");

        final OtrPolicy policy = getSessionPolicy();
        if (queryMessage.versions.contains(OTRv.THREE) && policy.getAllowV3()) {
            logger.finest("Query message with V3 support found.");
            final DHCommitMessage dhCommit = getAuthContext().respondAuth(OTRv.THREE);
            if (isMasterSession) {
                for (final Session session : slaveSessions.values()) {
                    session.getAuthContext().reset();
                    session.getAuthContext().r =
                            this.getAuthContext().r;
                    session.getAuthContext().localDHKeyPair =
                            this.getAuthContext().localDHKeyPair;
                    session.getAuthContext().localDHPublicKeyBytes =
                            this.getAuthContext().localDHPublicKeyBytes;
                    session.getAuthContext().localDHPublicKeyEncrypted =
                            this.getAuthContext().localDHPublicKeyEncrypted;
                    session.getAuthContext().localDHPublicKeyHash =
                            this.getAuthContext().localDHPublicKeyHash;
                }
            }
            injectMessage(dhCommit);
        }
        else if (queryMessage.versions.contains(OTRv.TWO) && policy.getAllowV2()) {
            logger.finest("Query message with V2 support found.");
            final DHCommitMessage dhCommit = getAuthContext().respondAuth(OTRv.TWO);
            logger.finest("Sending D-H Commit Message");
            injectMessage(dhCommit);
        } else if (queryMessage.versions.contains(OTRv.ONE) && policy.getAllowV1()) {
            logger.finest("Query message with V1 support found - ignoring.");
        }
    }

    private void handleErrorMessage(final ErrorMessage errorMessage)
            throws OtrException {
        logger.finest(getSessionID().getAccountID()
                + " received an error message from "
                + getSessionID().getUserID() + " through "
                + getSessionID().getUserID() + ".");

        getHost().showError(this.getSessionID(), errorMessage.error);

        final OtrPolicy policy = getSessionPolicy();
        // Re-negotiate if we got an error and we are encrypted
        if (policy.getErrorStartAKE() && getSessionStatus() == SessionStatus.ENCRYPTED) {
            logger.finest("Error message starts AKE.");
            final Vector<Integer> versions = new Vector<Integer>();
            if (policy.getAllowV1()) {
                versions.add(OTRv.ONE);
            }

            if (policy.getAllowV2()) {
                versions.add(OTRv.TWO);
            }

            if (policy.getAllowV3()) {
                versions.add(OTRv.THREE);
            }

            logger.finest("Sending Query");
            injectMessage(new QueryMessage(versions));
        }
    }

    private String handleDataMessage(final DataMessage data) throws OtrException {
        logger.finest(getSessionID().getAccountID()
                + " received a data message from " + getSessionID().getUserID()
                + ".");

        switch (this.getSessionStatus()) {
            case ENCRYPTED:
                logger.finest("Message state is ENCRYPTED. Trying to decrypt message.");
                // Find matching session keys.
                final int senderKeyID = data.senderKeyID;
                final int receipientKeyID = data.recipientKeyID;
                final SessionKeys matchingKeys = this.getSessionKeysByID(receipientKeyID,
                        senderKeyID);

                if (matchingKeys == null) {
                    logger.finest("No matching keys found.");
                    OtrEngineHostUtil.unreadableMessageReceived(getHost(),
                            this.getSessionID());
                    injectMessage(new ErrorMessage(AbstractMessage.MESSAGE_ERROR,
                            getHost().getReplyForUnreadableMessage(getSessionID())));
                    return null;
                }

                // Verify received MAC with a locally calculated MAC.
                logger
                        .finest("Transforming T to byte[] to calculate it's HmacSHA1.");

                final byte[] serializedT;
                try {
                    serializedT = SerializationUtils.toByteArray(data.getT());
                } catch (IOException e) {
                    throw new OtrException(e);
                }

                final byte[] computedMAC = OtrCryptoEngine.sha1Hmac(serializedT,
                        matchingKeys.getReceivingMACKey(),
                        SerializationConstants.TYPE_LEN_MAC);
                if (!Arrays.equals(computedMAC, data.mac)) {
                    logger.finest("MAC verification failed, ignoring message");
                    OtrEngineHostUtil.unreadableMessageReceived(getHost(),
                            this.getSessionID());
                    injectMessage(new ErrorMessage(AbstractMessage.MESSAGE_ERROR,
                            getHost().getReplyForUnreadableMessage(getSessionID())));
                    return null;
                }

                logger.finest("Computed HmacSHA1 value matches sent one.");

                // Mark this MAC key as old to be revealed.
                matchingKeys.setIsUsedReceivingMACKey(true);

                matchingKeys.setReceivingCtr(data.ctr);

                final byte[] dmc = OtrCryptoEngine.aesDecrypt(matchingKeys
                        .getReceivingAESKey(), matchingKeys.getReceivingCtr(),
                        data.encryptedMessage);

                // Rotate keys if necessary.
                final SessionKeys mostRecent = this.getMostRecentSessionKeys();
                if (mostRecent.getLocalKeyID() == receipientKeyID) {
                    this.rotateLocalSessionKeys();
                }

                if (mostRecent.getRemoteKeyID() == senderKeyID) {
                    this.rotateRemoteSessionKeys(data.nextDH);
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
                List<TLV> tlvs = null;
                tlvIndex++;  // to ignore the null
                if (tlvIndex < dmc.length) {
                    byte[] tlvsb = new byte[dmc.length - tlvIndex];
                    System.arraycopy(dmc, tlvIndex, tlvsb, 0, tlvsb.length);

                    tlvs = new Vector<TLV>();
                    final ByteArrayInputStream tin = new ByteArrayInputStream(tlvsb);
                    while (tin.available() > 0) {
                        final int type;
                        final byte[] tdata;
                        final OtrInputStream eois = new OtrInputStream(tin);
                        try {
                            type = eois.readShort();
                            tdata = eois.readTlvData();
                            // TODO consider doing eois.close() inside finally
                            eois.close();
                        } catch (IOException e) {
                            throw new OtrException(e);
                        }

                        tlvs.add(new TLV(type, tdata));
                    }
                }
                if (tlvs != null && tlvs.size() > 0) {
                    for (TLV tlv : tlvs) {
                        switch (tlv.getType()) {
                            case TLV.PADDING: // TLV0
                                // nothing to do here, just ignore the padding
                                break;
                            case TLV.DISCONNECTED: // TLV1
                                this.setSessionStatus(SessionStatus.FINISHED);
                                break;
                            case TLV.SMP1Q: //TLV7
                                getSmpTlvHandler().processTlvSMP1Q(tlv);
                                break;
                            case TLV.SMP1: // TLV2
                                getSmpTlvHandler().processTlvSMP1(tlv);
                                break;
                            case TLV.SMP2: // TLV3
                                getSmpTlvHandler().processTlvSMP2(tlv);
                                break;
                            case TLV.SMP3: // TLV4
                                getSmpTlvHandler().processTlvSMP3(tlv);
                                break;
                            case TLV.SMP4: // TLV5
                                getSmpTlvHandler().processTlvSMP4(tlv);
                                break;
                            case TLV.SMP_ABORT: //TLV6
                                getSmpTlvHandler().processTlvSMP_ABORT(tlv);
                                break;
                            default:
                                logger.warning("Unsupported TLV #" + tlv.getType() + " received!");
                                break;
                        }
                    }
                }
                return decryptedMsgContent;

            case FINISHED:
            case PLAINTEXT:
                OtrEngineHostUtil.unreadableMessageReceived(getHost(),
                        this.getSessionID());
                injectMessage(new ErrorMessage(AbstractMessage.MESSAGE_ERROR,
                        getHost().getReplyForUnreadableMessage(getSessionID())));
                break;
        }

        return null;
    }

    public void injectMessage(final AbstractMessage m) throws OtrException {
        String msg;
        try {
            msg = SerializationUtils.toString(m);
        } catch (IOException e) {
            throw new OtrException(e);
        }
        if (m instanceof QueryMessage) {
            String fallback = OtrEngineHostUtil.getFallbackMessage(getHost(),
                    getSessionID());
            if (fallback == null || fallback.equals("")) {
                fallback = SerializationConstants.DEFAULT_FALLBACK_MESSAGE;
            }
            msg += fallback;
        }

        if (SerializationUtils.otrEncoded(msg)) {
            // Content is OTR encoded, so we are allowed to partition.
            final String[] fragments;
            try {
                fragments = this.fragmenter.fragment(msg);
                for (final String fragment : fragments) {
                    getHost().injectMessage(getSessionID(), fragment);
                }
            } catch (IOException e) {
                logger.warning("Failed to fragment message according to provided instructions.");
                throw new OtrException(e);
            }
        } else {
            getHost().injectMessage(getSessionID(), msg);
        }
    }

    private String handlePlainTextMessage(final PlainTextMessage plainTextMessage)
            throws OtrException {
        logger.finest(getSessionID().getAccountID()
                + " received a plaintext message from "
                + getSessionID().getUserID() + " through "
                + getSessionID().getProtocolName() + ".");

        final OtrPolicy policy = getSessionPolicy();
        final List<Integer> versions = plainTextMessage.versions;
        if (versions == null || versions.size() < 1) {
            logger
                    .finest("Received plaintext message without the whitespace tag.");
            switch (this.getSessionStatus()) {
                case ENCRYPTED:
                case FINISHED:
                    /*
                     * Display the message to the user, but warn him that the
                     * message was received unencrypted.
                     */
                    OtrEngineHostUtil.unencryptedMessageReceived(getHost(),
                            sessionID, plainTextMessage.cleanText);
                    return plainTextMessage.cleanText;
                case PLAINTEXT:
                    /*
                     * Simply display the message to the user. If
                     * REQUIRE_ENCRYPTION is set, warn him that the message was
                     * received unencrypted.
                     */
                    if (policy.getRequireEncryption()) {
                        OtrEngineHostUtil.unencryptedMessageReceived(getHost(),
                                sessionID, plainTextMessage.cleanText);
                    }
                    return plainTextMessage.cleanText;
            }
        } else {
            logger
                    .finest("Received plaintext message with the whitespace tag.");
            switch (this.getSessionStatus()) {
                case ENCRYPTED:
                case FINISHED:
                    /*
                     * Remove the whitespace tag and display the message to the
                     * user, but warn him that the message was received
                     * unencrypted.
                     */
                    OtrEngineHostUtil.unencryptedMessageReceived(getHost(),
                            sessionID, plainTextMessage.cleanText);
                case PLAINTEXT:
                    /*
                     * Remove the whitespace tag and display the message to the
                     * user. If REQUIRE_ENCRYPTION is set, warn him that the
                     * message was received unencrypted.
                     */
                    if (policy.getRequireEncryption()) {
                        OtrEngineHostUtil.unencryptedMessageReceived(getHost(),
                                sessionID, plainTextMessage.cleanText);
                    }
            }

            if (policy.getWhitespaceStartAKE()) {
                logger.finest("WHITESPACE_START_AKE is set");

                if (plainTextMessage.versions.contains(OTRv.THREE)
                        && policy.getAllowV3()) {
                    logger.finest("V3 tag found.");
                    try {
                        final DHCommitMessage dhCommit = getAuthContext().respondAuth(OTRv.THREE);
                        if (isMasterSession) {
                            for (final Session session : slaveSessions.values()) {
                                session.getAuthContext().reset();
                                session.getAuthContext().r =
                                        this.getAuthContext().r;
                                session.getAuthContext().localDHKeyPair =
                                        this.getAuthContext().localDHKeyPair;
                                session.getAuthContext().localDHPublicKeyBytes =
                                        this.getAuthContext().localDHPublicKeyBytes;
                                session.getAuthContext().localDHPublicKeyEncrypted =
                                        this.getAuthContext().localDHPublicKeyEncrypted;
                                session.getAuthContext().localDHPublicKeyHash =
                                        this.getAuthContext().localDHPublicKeyHash;
                            }
                        }
                        logger.finest("Sending D-H Commit Message");
                        injectMessage(dhCommit);
                    } catch (OtrException e) {
                        // TODO either add comment for explicit silencing or do any logging or throwing. But don't empty-catch.
                    }
                } else if (plainTextMessage.versions.contains(OTRv.TWO)
                        && policy.getAllowV2()) {
                    logger.finest("V2 tag found.");
                    try {
                        final DHCommitMessage dhCommit = getAuthContext().respondAuth(OTRv.TWO);
                        logger.finest("Sending D-H Commit Message");
                        injectMessage(dhCommit);
                    } catch (OtrException e) {
                        // TODO either add comment for explicit silencing or do any logging or throwing. But don't empty-catch.
                    }
                } else if (plainTextMessage.versions.contains(1)
                        && policy.getAllowV1()) {
                    throw new UnsupportedOperationException();
                }
            }
        }

        return plainTextMessage.cleanText;
    }

    public String[] transformSending(final String msgText)
            throws OtrException {
        return this.transformSending(msgText, null);
    }

    public String[] transformSending(final String msgText, final List<TLV> tlvs)
            throws OtrException {

        if (isMasterSession && outgoingSession != this && getProtocolVersion() == OTRv.THREE) {
            return outgoingSession.transformSending(msgText, tlvs);
        }

        switch (this.getSessionStatus()) {
            case PLAINTEXT:
                final OtrPolicy otrPolicy = getSessionPolicy();
                if (otrPolicy.getRequireEncryption()) {
                    this.startSession();
                    getHost().requireEncryptedMessage(sessionID, msgText);
                    return null;
                } else {
                    if (otrPolicy.getSendWhitespaceTag()
                            && offerStatus != OfferStatus.rejected) {
                        offerStatus = OfferStatus.sent;
                        List<Integer> versions = new Vector<Integer>();
                        if (otrPolicy.getAllowV1()) {
                            versions.add(OTRv.ONE);
                        }
                        if (otrPolicy.getAllowV2()) {
                            versions.add(OTRv.TWO);
                        }
                        if (otrPolicy.getAllowV3()) {
                            versions.add(OTRv.THREE);
                        }
                        if (versions.isEmpty()) {
                            versions = null;
                        }
                        final AbstractMessage abstractMessage = new PlainTextMessage(
                                versions, msgText);
                        try {
                            return new String[] {
                                    SerializationUtils.toString(abstractMessage)
                            };
                        } catch (IOException e) {
                            throw new OtrException(e);
                        }
                    } else {
                        return new String[] {
                                msgText
                        };
                    }
                }
            case ENCRYPTED:
                logger.finest(getSessionID().getAccountID()
                        + " sends an encrypted message to "
                        + getSessionID().getUserID() + " through "
                        + getSessionID().getProtocolName() + ".");

                // Get encryption keys.
                final SessionKeys encryptionKeys = this.getEncryptionSessionKeys();
                final int senderKeyID = encryptionKeys.getLocalKeyID();
                final int receipientKeyID = encryptionKeys.getRemoteKeyID();

                // Increment CTR.
                encryptionKeys.incrementSendingCtr();
                final byte[] ctr = encryptionKeys.getSendingCtr();

                final ByteArrayOutputStream out = new ByteArrayOutputStream();
                if (msgText != null && msgText.length() > 0) {
                    try {
                        out.write(SerializationUtils.convertTextToBytes(msgText));
                    } catch (IOException e) {
                        throw new OtrException(e);
                    }
                }

                // Append tlvs
                if (tlvs != null && tlvs.size() > 0) {
                    out.write((byte) 0x00);

                    final OtrOutputStream eoos = new OtrOutputStream(out);
                    for (TLV tlv : tlvs) {
                        try {
                            eoos.writeShort(tlv.type);
                            eoos.writeTlvData(tlv.value);
                            // TODO consider closing eoos in finally-block
                            eoos.close();
                        } catch (IOException e) {
                            throw new OtrException(e);
                        }
                    }
                }

                final byte[] data = out.toByteArray();
                // Encrypt message.
                logger.finest("Encrypting message with keyids (localKeyID, remoteKeyID) = ("
                        + senderKeyID + ", " + receipientKeyID + ")");
                final byte[] encryptedMsg = OtrCryptoEngine.aesEncrypt(encryptionKeys
                        .getSendingAESKey(), ctr, data);

                // Get most recent keys to get the next D-H public key.
                final SessionKeys mostRecentKeys = this.getMostRecentSessionKeys();
                final DHPublicKey nextDH = (DHPublicKey) mostRecentKeys.getLocalPair()
                        .getPublic();

                // Calculate T.
                final MysteriousT t =
                        new MysteriousT(this.protocolVersion, getSenderInstanceTag().getValue(),
                                getReceiverInstanceTag().getValue(),
                                0, senderKeyID, receipientKeyID, nextDH, ctr, encryptedMsg);

                // Calculate T hash.
                final byte[] sendingMACKey = encryptionKeys.getSendingMACKey();

                logger.finest("Transforming T to byte[] to calculate it's HmacSHA1.");
                final byte[] serializedT;
                try {
                    serializedT = SerializationUtils.toByteArray(t);
                } catch (IOException e) {
                    throw new OtrException(e);
                }

                final byte[] mac = OtrCryptoEngine.sha1Hmac(serializedT, sendingMACKey,
                        SerializationConstants.TYPE_LEN_MAC);

                // Get old MAC keys to be revealed.
                final byte[] oldKeys = this.collectOldMacKeys();
                final DataMessage m = new DataMessage(t, mac, oldKeys);
                m.senderInstanceTag = getSenderInstanceTag().getValue();
                m.receiverInstanceTag = getReceiverInstanceTag().getValue();

                try {
                    final String completeMessage = SerializationUtils.toString(m);
                    return this.fragmenter.fragment(completeMessage);
                } catch (IOException e) {
                    throw new OtrException(e);
                }
            case FINISHED:
                getHost().finishedSessionMessage(sessionID, msgText);
                return null;
            default:
                throw new OtrException("Unknown message state, not processing");
        }
    }

    public void startSession() throws OtrException {
        if (this != outgoingSession && getProtocolVersion() == OTRv.THREE) {
            outgoingSession.startSession();
            return;
        }
        if (this.getSessionStatus() == SessionStatus.ENCRYPTED) {
            return;
        }

        if (!getSessionPolicy().getAllowV2() || !getSessionPolicy().getAllowV3()) {
            throw new UnsupportedOperationException();
        }

        this.getAuthContext().startAuth();
    }

    public void endSession() throws OtrException {
        if (this != outgoingSession && getProtocolVersion() == OTRv.THREE) {
            outgoingSession.endSession();
            return;
        }
        final SessionStatus status = this.getSessionStatus();
        switch (status) {
            case ENCRYPTED:
                final Vector<TLV> tlvs = new Vector<TLV>();
                tlvs.add(new TLV(TLV.DISCONNECTED, null));

                final String[] msg = this.transformSending(null, tlvs);
                for (final String part : msg) {
                    getHost().injectMessage(getSessionID(), part);
                }
                this.setSessionStatus(SessionStatus.PLAINTEXT);
                break;
            case FINISHED:
                this.setSessionStatus(SessionStatus.PLAINTEXT);
                break;
            case PLAINTEXT:
                return;
        }

    }

    public void refreshSession() throws OtrException {
        this.endSession();
        this.startSession();
    }

    private PublicKey remotePublicKey;

    private void setRemotePublicKey(final PublicKey pubKey) {
        this.remotePublicKey = pubKey;
    }

    public PublicKey getRemotePublicKey() {
        if (this != outgoingSession && getProtocolVersion() == OTRv.THREE) {
            return outgoingSession.getRemotePublicKey();
        }
        return remotePublicKey;
    }

    private final List<OtrEngineListener> listeners = new Vector<OtrEngineListener>();

    public void addOtrEngineListener(OtrEngineListener l) {
        synchronized (listeners) {
            if (!listeners.contains(l)) {
                listeners.add(l);
            }
        }
    }

    public void removeOtrEngineListener(OtrEngineListener l) {
        synchronized (listeners) {
            listeners.remove(l);
        }
    }

    public OtrPolicy getSessionPolicy() {
        return getHost().getSessionPolicy(getSessionID());
    }

    public KeyPair getLocalKeyPair() throws OtrException {
        return getHost().getLocalKeyPair(this.getSessionID());
    }

    public void initSmp(final String question, final String secret) throws OtrException {
        if (this != outgoingSession && getProtocolVersion() == OTRv.THREE) {
            outgoingSession.initSmp(question, secret);
            return;
        }
        if (this.getSessionStatus() != SessionStatus.ENCRYPTED) {
            return;
        }
        final List<TLV> tlvs = getSmpTlvHandler().initRespondSmp(question, secret, true);
        final String[] msg = transformSending("", tlvs);
        for (final String part : msg) {
            getHost().injectMessage(getSessionID(), part);
        }
    }

    public void respondSmp(final String question, final String secret) throws OtrException {
        if (this != outgoingSession && getProtocolVersion() == OTRv.THREE) {
            outgoingSession.respondSmp(question, secret);
            return;
        }
        if (this.getSessionStatus() != SessionStatus.ENCRYPTED) {
            return;
        }
        final List<TLV> tlvs = getSmpTlvHandler().initRespondSmp(question, secret, false);
        final String[] msg = transformSending("", tlvs);
        for (final String part : msg) {
            getHost().injectMessage(getSessionID(), part);
        }
    }

    public void abortSmp() throws OtrException {
        if (this != outgoingSession && getProtocolVersion() == OTRv.THREE) {
            outgoingSession.abortSmp();
            return;
        }
        if (this.getSessionStatus() != SessionStatus.ENCRYPTED) {
            return;
        }
        final List<TLV> tlvs = getSmpTlvHandler().abortSmp();
        final String[] msg = transformSending("", tlvs);
        for (final String part : msg) {
            getHost().injectMessage(getSessionID(), part);
        }
    }

    public boolean isSmpInProgress() {
        if (this != outgoingSession && getProtocolVersion() == OTRv.THREE) {
            return outgoingSession.isSmpInProgress();
        }
        return getSmpTlvHandler().isSmpInProgress();
    }

    public InstanceTag getSenderInstanceTag() {
        return senderTag;
    }

    public InstanceTag getReceiverInstanceTag() {
        return receiverTag;
    }

    public void setReceiverInstanceTag(final InstanceTag receiverTag) {
        // ReceiverInstanceTag of a slave session is not supposed to change
        if (!isMasterSession) {
            return;
        }
        this.receiverTag = receiverTag;
    }

    public void setProtocolVersion(final int protocolVersion) {
        // Protocol version of a slave session is not supposed to change
        if (!isMasterSession) {
            return;
        }
        this.protocolVersion = protocolVersion;
    }

    public int getProtocolVersion() {
        return isMasterSession ? this.protocolVersion : 3;
    }

    public List<Session> getInstances() {
        final List<Session> result = new ArrayList<Session>();
        result.add(this);
        result.addAll(slaveSessions.values());
        return result;
    }

    public boolean setOutgoingInstance(final InstanceTag tag) {
        // Only master session can set the outgoing session.
        if (!isMasterSession) {
            return false;
        }
        if (tag.equals(getReceiverInstanceTag())) {
            outgoingSession = this;
            OtrEngineListenerUtil.outgoingSessionChanged(this.listeners, sessionID);
            return true;
        }

        final Session newActiveSession = slaveSessions.get(tag);
        if (newActiveSession != null) {
            outgoingSession = newActiveSession;
            OtrEngineListenerUtil.outgoingSessionChanged(this.listeners, sessionID);
            return true;
        } else {
            outgoingSession = this;
            return false;
        }
    }

    public void respondSmp(final InstanceTag receiverTag, final String question, final String secret)
            throws OtrException
    {
        if (receiverTag.equals(getReceiverInstanceTag()))
        {
            respondSmp(question, secret);
            return;
        }
        else
        {
            final Session slave = slaveSessions.get(receiverTag);
            if (slave != null) {
                slave.respondSmp(question, secret);
            } else {
                respondSmp(question, secret);
            }
        }
    }

    public SessionStatus getSessionStatus(final InstanceTag tag) {
        if (tag.equals(getReceiverInstanceTag())) {
            return sessionStatus;
        } else {
            final Session slave = slaveSessions.get(tag);
            return slave != null ? slave.getSessionStatus() : sessionStatus;
        }
    }

    public PublicKey getRemotePublicKey(final InstanceTag tag) {
        if (tag.equals(getReceiverInstanceTag())) {
            return remotePublicKey;
        } else {
            final Session slave = slaveSessions.get(tag);
            return slave != null ? slave.getRemotePublicKey() : remotePublicKey;
        }
    }

    public Session getOutgoingInstance() {
        return outgoingSession;
    }
}
