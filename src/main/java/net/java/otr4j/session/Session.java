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
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.ProtocolException;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Vector;
import java.util.logging.Logger;

import javax.crypto.interfaces.DHPublicKey;

import net.java.otr4j.OtrEngineHost;
import net.java.otr4j.OtrEngineListener;
import net.java.otr4j.OtrException;
import net.java.otr4j.OtrPolicy;
import net.java.otr4j.crypto.OtrCryptoEngine;
import net.java.otr4j.crypto.OtrCryptoEngineImpl;
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
                Arrays.asList(new Integer[] {
                        ONE, TWO, THREE
                }));
    }

    private Map<InstanceTag, Session> slaveSessions;

    private volatile Session outgoingSession;

    private final boolean isMasterSession;

    private SessionID sessionID;
    private OtrEngineHost host;
    private SessionStatus sessionStatus;
    private AuthContext authContext;
    private SessionKeys[][] sessionKeys;
    private Vector<byte[]> oldMacKeys;
    private Logger logger;
    private final OtrSm otrSm;
    private BigInteger ess;
    private OfferStatus offerStatus;
    private final InstanceTag senderTag;
    private InstanceTag receiverTag;
    private int protocolVersion;
    private OtrAssembler assembler;
    private final OtrFragmenter fragmenter;

    public Session(SessionID sessionID, OtrEngineHost listener) {

        this.setSessionID(sessionID);
        this.setHost(listener);

        // client application calls OtrSessionManager.getSessionStatus()
        // -> create new session if it does not exist, end up here
        // -> setSessionStatus() fires statusChangedEvent
        // -> client application calls OtrSessionManager.getSessionStatus()
        this.sessionStatus = SessionStatus.PLAINTEXT;
        this.offerStatus = OfferStatus.idle;

        otrSm = new OtrSm(this, listener);
        this.senderTag = new InstanceTag();
        this.receiverTag = InstanceTag.ZERO_TAG;

        slaveSessions = new HashMap<InstanceTag, Session>();
        outgoingSession = this;
        isMasterSession = true;

        assembler = new OtrAssembler(getSenderInstanceTag());
        fragmenter = new OtrFragmenter(outgoingSession, listener);
    }

    // A private constructor for instantiating 'slave' sessions.
    private Session(SessionID sessionID,
            OtrEngineHost listener,
            InstanceTag senderTag,
            InstanceTag receiverTag) {

        this.setSessionID(sessionID);
        this.setHost(listener);

        this.sessionStatus = SessionStatus.PLAINTEXT;
        this.offerStatus = OfferStatus.idle;

        otrSm = new OtrSm(this, listener);
        this.senderTag = senderTag;
        this.receiverTag = receiverTag;

        outgoingSession = this;
        isMasterSession = false;
        protocolVersion = OTRv.THREE;

        assembler = new OtrAssembler(getSenderInstanceTag());
        fragmenter = new OtrFragmenter(outgoingSession, listener);
    }

    public BigInteger getS() {
        return ess;
    }

    private SessionKeys getEncryptionSessionKeys() {
        logger.finest("Getting encryption keys");
        return getSessionKeysByIndex(SessionKeys.Previous, SessionKeys.Current);
    }

    private SessionKeys getMostRecentSessionKeys() {
        logger.finest("Getting most recent keys.");
        return getSessionKeysByIndex(SessionKeys.Current, SessionKeys.Current);
    }

    private SessionKeys getSessionKeysByID(int localKeyID, int remoteKeyID) {
        logger.finest("Searching for session keys with (localKeyID, remoteKeyID) = ("
                + localKeyID + "," + remoteKeyID + ")");

        for (int i = 0; i < getSessionKeys().length; i++) {
            for (int j = 0; j < getSessionKeys()[i].length; j++) {
                SessionKeys current = getSessionKeysByIndex(i, j);
                if (current.getLocalKeyID() == localKeyID
                        && current.getRemoteKeyID() == remoteKeyID) {
                    logger.finest("Matching keys found.");
                    return current;
                }
            }
        }

        return null;
    }

    private SessionKeys getSessionKeysByIndex(int localKeyIndex,
            int remoteKeyIndex) {
        if (getSessionKeys()[localKeyIndex][remoteKeyIndex] == null)
            getSessionKeys()[localKeyIndex][remoteKeyIndex] = new SessionKeysImpl(
                    localKeyIndex, remoteKeyIndex);

        return getSessionKeys()[localKeyIndex][remoteKeyIndex];
    }

    private void rotateRemoteSessionKeys(DHPublicKey pubKey)
            throws OtrException {

        logger.finest("Rotating remote keys.");
        SessionKeys sess1 = getSessionKeysByIndex(SessionKeys.Current,
                SessionKeys.Previous);
        if (sess1.getIsUsedReceivingMACKey()) {
            logger
                    .finest("Detected used Receiving MAC key. Adding to old MAC keys to reveal it.");
            getOldMacKeys().add(sess1.getReceivingMACKey());
        }

        SessionKeys sess2 = getSessionKeysByIndex(SessionKeys.Previous,
                SessionKeys.Previous);
        if (sess2.getIsUsedReceivingMACKey()) {
            logger
                    .finest("Detected used Receiving MAC key. Adding to old MAC keys to reveal it.");
            getOldMacKeys().add(sess2.getReceivingMACKey());
        }

        SessionKeys sess3 = getSessionKeysByIndex(SessionKeys.Current,
                SessionKeys.Current);
        sess1.setRemoteDHPublicKey(sess3.getRemoteKey(), sess3.getRemoteKeyID());

        SessionKeys sess4 = getSessionKeysByIndex(SessionKeys.Previous,
                SessionKeys.Current);
        sess2.setRemoteDHPublicKey(sess4.getRemoteKey(), sess4.getRemoteKeyID());

        sess3.setRemoteDHPublicKey(pubKey, sess3.getRemoteKeyID() + 1);
        sess4.setRemoteDHPublicKey(pubKey, sess4.getRemoteKeyID() + 1);
    }

    private void rotateLocalSessionKeys() throws OtrException {

        logger.finest("Rotating local keys.");
        SessionKeys sess1 = getSessionKeysByIndex(SessionKeys.Previous,
                SessionKeys.Current);
        if (sess1.getIsUsedReceivingMACKey()) {
            logger.finest("Detected used Receiving MAC key. Adding to old MAC keys to reveal it.");
            getOldMacKeys().add(sess1.getReceivingMACKey());
        }

        SessionKeys sess2 = getSessionKeysByIndex(SessionKeys.Previous,
                SessionKeys.Previous);
        if (sess2.getIsUsedReceivingMACKey()) {
            logger.finest("Detected used Receiving MAC key. Adding to old MAC keys to reveal it.");
            getOldMacKeys().add(sess2.getReceivingMACKey());
        }

        SessionKeys sess3 = getSessionKeysByIndex(SessionKeys.Current,
                SessionKeys.Current);
        sess1.setLocalPair(sess3.getLocalPair(), sess3.getLocalKeyID());
        SessionKeys sess4 = getSessionKeysByIndex(SessionKeys.Current,
                SessionKeys.Previous);
        sess2.setLocalPair(sess4.getLocalPair(), sess4.getLocalKeyID());

        KeyPair newPair = new OtrCryptoEngineImpl().generateDHKeyPair();
        sess3.setLocalPair(newPair, sess3.getLocalKeyID() + 1);
        sess4.setLocalPair(newPair, sess4.getLocalKeyID() + 1);
    }

    private byte[] collectOldMacKeys() {
        logger.finest("Collecting old MAC keys to be revealed.");
        int len = 0;
        for (int i = 0; i < getOldMacKeys().size(); i++)
            len += getOldMacKeys().get(i).length;

        ByteBuffer buff = ByteBuffer.allocate(len);
        for (int i = 0; i < getOldMacKeys().size(); i++)
            buff.put(getOldMacKeys().get(i));

        getOldMacKeys().clear();
        return buff.array();
    }

    private void setSessionStatus(SessionStatus sessionStatus)
            throws OtrException {

        switch (sessionStatus) {
            case ENCRYPTED:
                AuthContext auth = this.getAuthContext();
                ess = auth.getS();
                logger.finest("Setting most recent session keys from auth.");
                for (int i = 0; i < this.getSessionKeys()[0].length; i++) {
                    SessionKeys current = getSessionKeysByIndex(0, i);
                    current.setLocalPair(auth.getLocalDHKeyPair(), 1);
                    current.setRemoteDHPublicKey(auth.getRemoteDHPublicKey(), 1);
                    current.setS(auth.getS());
                }

                KeyPair nextDH = new OtrCryptoEngineImpl().generateDHKeyPair();
                for (int i = 0; i < this.getSessionKeys()[1].length; i++) {
                    SessionKeys current = getSessionKeysByIndex(1, i);
                    current.setRemoteDHPublicKey(auth.getRemoteDHPublicKey(), 1);
                    current.setLocalPair(nextDH, 2);
                }

                this.setRemotePublicKey(auth.getRemoteLongTermPublicKey());

                auth.reset();
                otrSm.reset();
                break;
            case FINISHED:
            case PLAINTEXT:
                break;
        }

        if (sessionStatus == this.sessionStatus)
            return;

        this.sessionStatus = sessionStatus;

        for (OtrEngineListener l : this.listeners)
            l.sessionStatusChanged(getSessionID());
    }

    public SessionStatus getSessionStatus() {
        if (this != outgoingSession && getProtocolVersion() == OTRv.THREE)
            return outgoingSession.getSessionStatus();
        return sessionStatus;
    }

    private void setSessionID(SessionID sessionID) {
        logger = Logger.getLogger(sessionID.getAccountID() + "-->" + sessionID.getUserID());
        this.sessionID = sessionID;
    }

    public SessionID getSessionID() {
        return sessionID;
    }

    private void setHost(OtrEngineHost host) {
        this.host = host;
    }

    private OtrEngineHost getHost() {
        return host;
    }

    private SessionKeys[][] getSessionKeys() {
        if (sessionKeys == null)
            sessionKeys = new SessionKeys[2][2];
        return sessionKeys;
    }

    AuthContext getAuthContext() {
        if (authContext == null)
            authContext = new AuthContext(this);
        return authContext;
    }

    private Vector<byte[]> getOldMacKeys() {
        if (oldMacKeys == null)
            oldMacKeys = new Vector<byte[]>();
        return oldMacKeys;
    }

    public String transformReceiving(String msgText) throws OtrException {

        OtrPolicy policy = getSessionPolicy();
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
            getHost().messageFromAnotherInstanceReceived(getSessionID());
            return null;
        } catch (ProtocolException e) {
            logger.warning("An invalid message fragment was discarded.");
            return null;
        }

        if (msgText == null)
            return null; // Not a complete message (yet).

        AbstractMessage m;
        try {
            m = SerializationUtils.toMessage(msgText);
        } catch (IOException e) {
            throw new OtrException(e);
        }
        if (m == null)
            return msgText; // Propably null or empty.

        if (m.messageType != AbstractMessage.MESSAGE_PLAINTEXT)
            offerStatus = OfferStatus.accepted;
        else if (offerStatus == OfferStatus.sent)
            offerStatus = OfferStatus.rejected;

        if (m instanceof AbstractEncodedMessage && isMasterSession) {

            AbstractEncodedMessage encodedM = (AbstractEncodedMessage) m;

            if (encodedM.protocolVersion == OTRv.THREE) {

                if (encodedM.receiverInstanceTag != this.getSenderInstanceTag().getValue()) {
                    if (!(encodedM.messageType == AbstractEncodedMessage.MESSAGE_DH_COMMIT
                    && encodedM.receiverInstanceTag == 0)) {

                        // The message is not intended for us. Discarding...
                        logger.finest("Received an encoded message with receiver instance tag" +
                                " that is different from ours, ignore this message");
                        getHost().messageFromAnotherInstanceReceived(getSessionID());
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

                    InstanceTag newReceiverTag = new InstanceTag(encodedM.senderInstanceTag);
                    synchronized (slaveSessions) {

                        if (!slaveSessions.containsKey(newReceiverTag)) {

                            final Session session =
                                    new Session(sessionID,
                                            getHost(),
                                            getSenderInstanceTag(),
                                            newReceiverTag);

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

                                public void sessionStatusChanged(SessionID sessionID) {
                                    for (OtrEngineListener l : listeners)
                                        l.sessionStatusChanged(sessionID);
                                }

                                public void multipleInstancesDetected(SessionID sessionID) {
                                }

                                public void outgoingSessionChanged(SessionID sessionID) {
                                }
                            });

                            slaveSessions.put(newReceiverTag, session);

                            getHost().multipleInstancesDetected(sessionID);
                            for (OtrEngineListener l : listeners)
                                l.multipleInstancesDetected(sessionID);
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
                AuthContext auth = this.getAuthContext();
                auth.handleReceivingMessage(m);

                if (auth.getIsSecure()) {
                    this.setSessionStatus(SessionStatus.ENCRYPTED);
                    logger.finest("Gone Secure.");
                }
                return null;
            default:
                throw new UnsupportedOperationException(
                        "Received an uknown message type.");
        }
    }

    private void handleQueryMessage(QueryMessage queryMessage)
            throws OtrException {
        logger.finest(getSessionID().getAccountID()
                + " received a query message from "
                + getSessionID().getUserID() + " through "
                + getSessionID().getProtocolName() + ".");

        OtrPolicy policy = getSessionPolicy();
        if (queryMessage.versions.contains(OTRv.THREE) && policy.getAllowV3()) {
            logger.finest("Query message with V3 support found.");
            DHCommitMessage dhCommit = getAuthContext().respondAuth(OTRv.THREE);
            if (isMasterSession) {
                for (Session session : slaveSessions.values()) {
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
            DHCommitMessage dhCommit = getAuthContext().respondAuth(OTRv.TWO);
            logger.finest("Sending D-H Commit Message");
            injectMessage(dhCommit);
        } else if (queryMessage.versions.contains(OTRv.ONE) && policy.getAllowV1()) {
            logger.finest("Query message with V1 support found - ignoring.");
        }
    }

    private void handleErrorMessage(ErrorMessage errorMessage)
            throws OtrException {
        logger.finest(getSessionID().getAccountID()
                + " received an error message from "
                + getSessionID().getUserID() + " through "
                + getSessionID().getUserID() + ".");

        getHost().showError(this.getSessionID(), errorMessage.error);

        OtrPolicy policy = getSessionPolicy();
        if (policy.getErrorStartAKE()) {
            logger.finest("Error message starts AKE.");
            Vector<Integer> versions = new Vector<Integer>();
            if (policy.getAllowV1())
                versions.add(OTRv.ONE);

            if (policy.getAllowV2())
                versions.add(OTRv.TWO);

            if (policy.getAllowV3())
                versions.add(OTRv.THREE);

            logger.finest("Sending Query");
            injectMessage(new QueryMessage(versions));
        }
    }

    private String handleDataMessage(DataMessage data) throws OtrException {
        logger.finest(getSessionID().getAccountID()
                + " received a data message from " + getSessionID().getUserID()
                + ".");

        switch (this.getSessionStatus()) {
            case ENCRYPTED:
                logger
                        .finest("Message state is ENCRYPTED. Trying to decrypt message.");
                // Find matching session keys.
                int senderKeyID = data.senderKeyID;
                int receipientKeyID = data.recipientKeyID;
                SessionKeys matchingKeys = this.getSessionKeysByID(receipientKeyID,
                        senderKeyID);

                if (matchingKeys == null) {
                    logger.finest("No matching keys found.");
                    getHost().unreadableMessageReceived(this.getSessionID());
                    injectMessage(new ErrorMessage(AbstractMessage.MESSAGE_ERROR,
                            getHost().getReplyForUnreadableMessage(getSessionID())));
                    return null;
                }

                // Verify received MAC with a locally calculated MAC.
                logger
                        .finest("Transforming T to byte[] to calculate it's HmacSHA1.");

                byte[] serializedT;
                try {
                    serializedT = SerializationUtils.toByteArray(data.getT());
                } catch (IOException e) {
                    throw new OtrException(e);
                }

                OtrCryptoEngine otrCryptoEngine = new OtrCryptoEngineImpl();

                byte[] computedMAC = otrCryptoEngine.sha1Hmac(serializedT,
                        matchingKeys.getReceivingMACKey(),
                        SerializationConstants.TYPE_LEN_MAC);
                if (!Arrays.equals(computedMAC, data.mac)) {
                    logger.finest("MAC verification failed, ignoring message");
                    getHost().unreadableMessageReceived(this.getSessionID());
                    injectMessage(new ErrorMessage(AbstractMessage.MESSAGE_ERROR,
                            getHost().getReplyForUnreadableMessage(getSessionID())));
                    return null;
                }

                logger.finest("Computed HmacSHA1 value matches sent one.");

                // Mark this MAC key as old to be revealed.
                matchingKeys.setIsUsedReceivingMACKey(true);

                matchingKeys.setReceivingCtr(data.ctr);

                byte[] dmc = otrCryptoEngine.aesDecrypt(matchingKeys
                        .getReceivingAESKey(), matchingKeys.getReceivingCtr(),
                        data.encryptedMessage);
                String decryptedMsgContent;
                try {
                    // Expect bytes to be text encoded in UTF-8.
                    decryptedMsgContent = new String(dmc, "UTF-8");
                } catch (UnsupportedEncodingException e) {
                    throw new OtrException(e);
                }

                logger.finest("Decrypted message: \"" + decryptedMsgContent + "\"");

                // Rotate keys if necessary.
                SessionKeys mostRecent = this.getMostRecentSessionKeys();
                if (mostRecent.getLocalKeyID() == receipientKeyID)
                    this.rotateLocalSessionKeys();

                if (mostRecent.getRemoteKeyID() == senderKeyID)
                    this.rotateRemoteSessionKeys(data.nextDH);

                // Handle TLVs
                List<TLV> tlvs = null;
                int tlvIndex = decryptedMsgContent.indexOf((char) 0x0);
                if (tlvIndex > -1) {
                    decryptedMsgContent = decryptedMsgContent
                            .substring(0, tlvIndex);
                    tlvIndex++;
                    byte[] tlvsb = new byte[dmc.length - tlvIndex];
                    System.arraycopy(dmc, tlvIndex, tlvsb, 0, tlvsb.length);

                    tlvs = new Vector<TLV>();
                    ByteArrayInputStream tin = new ByteArrayInputStream(tlvsb);
                    while (tin.available() > 0) {
                        int type;
                        byte[] tdata;
                        OtrInputStream eois = new OtrInputStream(tin);
                        try {
                            type = eois.readShort();
                            tdata = eois.readTlvData();
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
                            case TLV.DISCONNECTED:
                                this.setSessionStatus(SessionStatus.FINISHED);
                                return null;
                            default:
                                if (otrSm.doProcessTlv(tlv))
                                    return null;
                        }
                    }
                }
                return decryptedMsgContent;

            case FINISHED:
            case PLAINTEXT:
                getHost().unreadableMessageReceived(this.getSessionID());
                injectMessage(new ErrorMessage(AbstractMessage.MESSAGE_ERROR,
                        getHost().getReplyForUnreadableMessage(getSessionID())));
                break;
        }

        return null;
    }

    public void injectMessage(AbstractMessage m) throws OtrException {
        String msg;
        try {
            msg = SerializationUtils.toString(m);
        } catch (IOException e) {
            throw new OtrException(e);
        }
        if (m instanceof QueryMessage)
            msg += getHost().getFallbackMessage(getSessionID());

        if (SerializationUtils.otrEncoded(msg)) {
            // Content is OTR encoded, so we are allowed to partition.
            String[] fragments;
            try {
                fragments = this.fragmenter.fragment(msg);
                for (String fragment : fragments) {
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

    private String handlePlainTextMessage(PlainTextMessage plainTextMessage)
            throws OtrException {
        logger.finest(getSessionID().getAccountID()
                + " received a plaintext message from "
                + getSessionID().getUserID() + " through "
                + getSessionID().getProtocolName() + ".");

        OtrPolicy policy = getSessionPolicy();
        List<Integer> versions = plainTextMessage.versions;
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
                    getHost().unencryptedMessageReceived(sessionID,
                            plainTextMessage.cleanText);
                    return plainTextMessage.cleanText;
                case PLAINTEXT:
                    /*
                     * Simply display the message to the user. If
                     * REQUIRE_ENCRYPTION is set, warn him that the message was
                     * received unencrypted.
                     */
                    if (policy.getRequireEncryption()) {
                        getHost().unencryptedMessageReceived(sessionID,
                                plainTextMessage.cleanText);
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
                    getHost().unencryptedMessageReceived(sessionID,
                            plainTextMessage.cleanText);
                case PLAINTEXT:
                    /*
                     * Remove the whitespace tag and display the message to the
                     * user. If REQUIRE_ENCRYPTION is set, warn him that the
                     * message was received unencrypted.
                     */
                    if (policy.getRequireEncryption())
                        getHost().unencryptedMessageReceived(sessionID,
                                plainTextMessage.cleanText);
            }

            if (policy.getWhitespaceStartAKE()) {
                logger.finest("WHITESPACE_START_AKE is set");

                if (plainTextMessage.versions.contains(OTRv.THREE)
                        && policy.getAllowV3()) {
                    logger.finest("V3 tag found.");
                    try {
                        DHCommitMessage dhCommit = getAuthContext().respondAuth(OTRv.THREE);
                        if (isMasterSession) {
                            for (Session session : slaveSessions.values()) {
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
                    }
                } else if (plainTextMessage.versions.contains(OTRv.TWO)
                        && policy.getAllowV2()) {
                    logger.finest("V2 tag found.");
                    try {
                        DHCommitMessage dhCommit = getAuthContext().respondAuth(OTRv.TWO);
                        logger.finest("Sending D-H Commit Message");
                        injectMessage(dhCommit);
                    } catch (OtrException e) {
                    }
                } else if (plainTextMessage.versions.contains(1)
                        && policy.getAllowV1()) {
                    throw new UnsupportedOperationException();
                }
            }
        }

        return plainTextMessage.cleanText;
    }

    public String[] transformSending(String msgText)
            throws OtrException {
        return this.transformSending(msgText, null);
    }

    public String[] transformSending(String msgText, List<TLV> tlvs)
            throws OtrException {

        if (isMasterSession && outgoingSession != this && getProtocolVersion() == OTRv.THREE) {
            return outgoingSession.transformSending(msgText, tlvs);
        }

        switch (this.getSessionStatus()) {
            case PLAINTEXT:
                OtrPolicy otrPolicy = getSessionPolicy();
                if (otrPolicy.getRequireEncryption()) {
                    this.startSession();
                    getHost().requireEncryptedMessage(sessionID, msgText);
                    return null;
                } else {
                    if (otrPolicy.getSendWhitespaceTag()
                            && offerStatus != OfferStatus.rejected) {
                        offerStatus = OfferStatus.sent;
                        List<Integer> versions = new Vector<Integer>();
                        if (otrPolicy.getAllowV1())
                            versions.add(OTRv.ONE);
                        if (otrPolicy.getAllowV2())
                            versions.add(OTRv.TWO);
                        if (otrPolicy.getAllowV3())
                            versions.add(OTRv.THREE);
                        if (versions.isEmpty())
                            versions = null;
                        AbstractMessage abstractMessage = new PlainTextMessage(
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
                SessionKeys encryptionKeys = this.getEncryptionSessionKeys();
                int senderKeyID = encryptionKeys.getLocalKeyID();
                int receipientKeyID = encryptionKeys.getRemoteKeyID();

                // Increment CTR.
                encryptionKeys.incrementSendingCtr();
                byte[] ctr = encryptionKeys.getSendingCtr();

                ByteArrayOutputStream out = new ByteArrayOutputStream();
                if (msgText != null && msgText.length() > 0) {
                    try {
                        out.write(msgText.getBytes(SerializationUtils.UTF8));
                    } catch (IOException e) {
                        throw new OtrException(e);
                    }
                }

                // Append tlvs
                if (tlvs != null && tlvs.size() > 0) {
                    out.write((byte) 0x00);

                    OtrOutputStream eoos = new OtrOutputStream(out);
                    for (TLV tlv : tlvs) {
                        try {
                            eoos.writeShort(tlv.type);
                            eoos.writeTlvData(tlv.value);
                            eoos.close();
                        } catch (IOException e) {
                            throw new OtrException(e);
                        }
                    }
                }

                OtrCryptoEngine otrCryptoEngine = new OtrCryptoEngineImpl();

                byte[] data = out.toByteArray();
                // Encrypt message.
                logger.finest("Encrypting message with keyids (localKeyID, remoteKeyID) = ("
                        + senderKeyID + ", " + receipientKeyID + ")");
                byte[] encryptedMsg = otrCryptoEngine.aesEncrypt(encryptionKeys
                        .getSendingAESKey(), ctr, data);

                // Get most recent keys to get the next D-H public key.
                SessionKeys mostRecentKeys = this.getMostRecentSessionKeys();
                DHPublicKey nextDH = (DHPublicKey) mostRecentKeys.getLocalPair()
                        .getPublic();

                // Calculate T.
                MysteriousT t =
                        new MysteriousT(this.protocolVersion, getSenderInstanceTag().getValue(),
                                getReceiverInstanceTag().getValue(),
                                0, senderKeyID, receipientKeyID, nextDH, ctr, encryptedMsg);

                // Calculate T hash.
                byte[] sendingMACKey = encryptionKeys.getSendingMACKey();

                logger.finest("Transforming T to byte[] to calculate it's HmacSHA1.");
                byte[] serializedT;
                try {
                    serializedT = SerializationUtils.toByteArray(t);
                } catch (IOException e) {
                    throw new OtrException(e);
                }

                byte[] mac = otrCryptoEngine.sha1Hmac(serializedT, sendingMACKey,
                        SerializationConstants.TYPE_LEN_MAC);

                // Get old MAC keys to be revealed.
                byte[] oldKeys = this.collectOldMacKeys();
                DataMessage m = new DataMessage(t, mac, oldKeys);
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
                logger.finest("Uknown message state, not processing.");
                return new String[] {
                        msgText
                };
        }
    }

    public void startSession() throws OtrException {
        if (this != outgoingSession && getProtocolVersion() == OTRv.THREE) {
            outgoingSession.startSession();
            return;
        }
        if (this.getSessionStatus() == SessionStatus.ENCRYPTED)
            return;

        if (!getSessionPolicy().getAllowV2() || !getSessionPolicy().getAllowV3())
            throw new UnsupportedOperationException();

        this.getAuthContext().startAuth();
    }

    public void endSession() throws OtrException {
        if (this != outgoingSession && getProtocolVersion() == OTRv.THREE) {
            outgoingSession.endSession();
            return;
        }
        SessionStatus status = this.getSessionStatus();
        switch (status) {
            case ENCRYPTED:
                Vector<TLV> tlvs = new Vector<TLV>();
                tlvs.add(new TLV(TLV.DISCONNECTED, null));

                String[] msg = this.transformSending(null, tlvs);
                for (String part : msg) {
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

    private void setRemotePublicKey(PublicKey pubKey) {
        this.remotePublicKey = pubKey;
    }

    public PublicKey getRemotePublicKey() {
        if (this != outgoingSession && getProtocolVersion() == OTRv.THREE)
            return outgoingSession.getRemotePublicKey();
        return remotePublicKey;
    }

    private List<OtrEngineListener> listeners = new Vector<OtrEngineListener>();

    public void addOtrEngineListener(OtrEngineListener l) {
        synchronized (listeners) {
            if (!listeners.contains(l))
                listeners.add(l);
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

    public void initSmp(String question, String secret) throws OtrException {
        if (this != outgoingSession && getProtocolVersion() == OTRv.THREE) {
            outgoingSession.initSmp(question, secret);
            return;
        }
        if (this.getSessionStatus() != SessionStatus.ENCRYPTED)
            return;
        List<TLV> tlvs = otrSm.initRespondSmp(question, secret, true);
        String[] msg = transformSending("", tlvs);
        for (String part : msg) {
            getHost().injectMessage(getSessionID(), part);
        }
    }

    public void respondSmp(String question, String secret) throws OtrException {
        if (this != outgoingSession && getProtocolVersion() == OTRv.THREE) {
            outgoingSession.respondSmp(question, secret);
            return;
        }
        if (this.getSessionStatus() != SessionStatus.ENCRYPTED)
            return;
        List<TLV> tlvs = otrSm.initRespondSmp(question, secret, false);
        String[] msg = transformSending("", tlvs);
        for (String part : msg) {
            getHost().injectMessage(getSessionID(), part);
        }
    }

    public void abortSmp() throws OtrException {
        if (this != outgoingSession && getProtocolVersion() == OTRv.THREE) {
            outgoingSession.abortSmp();
            return;
        }
        if (this.getSessionStatus() != SessionStatus.ENCRYPTED)
            return;
        List<TLV> tlvs = otrSm.abortSmp();
        String[] msg = transformSending("", tlvs);
        for (String part : msg) {
            getHost().injectMessage(getSessionID(), part);
        }
    }

    public boolean isSmpInProgress() {
        if (this != outgoingSession && getProtocolVersion() == OTRv.THREE)
            return outgoingSession.isSmpInProgress();
        return otrSm.isSmpInProgress();
    }

    public InstanceTag getSenderInstanceTag() {
        return senderTag;
    }

    public InstanceTag getReceiverInstanceTag() {
        return receiverTag;
    }

    public void setReceiverInstanceTag(InstanceTag receiverTag) {
        // ReceiverInstanceTag of a slave session is not supposed to change
        if (!isMasterSession)
            return;
        this.receiverTag = receiverTag;
    }

    public void setProtocolVersion(int protocolVersion) {
        // Protocol version of a slave session is not supposed to change
        if (!isMasterSession)
            return;
        this.protocolVersion = protocolVersion;
    }

    public int getProtocolVersion() {
        return isMasterSession ? this.protocolVersion : 3;
    }

    public List<Session> getInstances() {
        List<Session> result = new ArrayList<Session>();
        result.add(this);
        result.addAll(slaveSessions.values());
        return result;
    }

    public boolean setOutgoingInstance(InstanceTag tag) {
        // Only master session can set the outgoing session.
        if (!isMasterSession)
            return false;
        if (tag.equals(getReceiverInstanceTag())) {
            outgoingSession = this;
            for (OtrEngineListener l : listeners)
                l.outgoingSessionChanged(sessionID);
            return true;
        }

        Session newActiveSession = slaveSessions.get(tag);
        if (newActiveSession != null) {
            outgoingSession = newActiveSession;
            for (OtrEngineListener l : listeners)
                l.outgoingSessionChanged(sessionID);
            return true;
        } else {
            outgoingSession = this;
            return false;
        }
    }

    public void respondSmp(InstanceTag receiverTag, String question, String secret)
            throws OtrException
    {
        if (receiverTag.equals(getReceiverInstanceTag()))
        {
            respondSmp(question, secret);
            return;
        }
        else
        {
            Session slave = slaveSessions.get(receiverTag);
            if (slave != null)
                slave.respondSmp(question, secret);
            else
                respondSmp(question, secret);
        }
    }

    public SessionStatus getSessionStatus(InstanceTag tag) {
        if (tag.equals(getReceiverInstanceTag()))
            return sessionStatus;
        else
        {
            Session slave = slaveSessions.get(tag);
            return slave != null ? slave.getSessionStatus() : sessionStatus;
        }
    }

    public PublicKey getRemotePublicKey(InstanceTag tag) {
        if (tag.equals(getReceiverInstanceTag()))
            return remotePublicKey;
        else
        {
            Session slave = slaveSessions.get(tag);
            return slave != null ? slave.getRemotePublicKey() : remotePublicKey;
        }
    }

    public Session getOutgoingInstance() {
        return outgoingSession;
    }
}
