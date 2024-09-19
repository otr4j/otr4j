/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.session.state;

import net.java.otr4j.api.ClientProfile;
import net.java.otr4j.api.Event;
import net.java.otr4j.api.OtrException;
import net.java.otr4j.api.RemoteInfo;
import net.java.otr4j.api.SessionID;
import net.java.otr4j.api.SessionStatus;
import net.java.otr4j.api.TLV;
import net.java.otr4j.api.Version;
import net.java.otr4j.crypto.OtrCryptoEngine4;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.crypto.ed448.Point;
import net.java.otr4j.io.EncryptedMessage.Content;
import net.java.otr4j.io.OtrOutputStream;
import net.java.otr4j.messages.AbstractEncodedMessage;
import net.java.otr4j.messages.DataMessage;
import net.java.otr4j.messages.DataMessage4;
import net.java.otr4j.session.ake.AuthState;
import net.java.otr4j.session.dake.DAKEState;
import net.java.otr4j.session.smpv4.SMP;
import net.java.otr4j.session.state.DoubleRatchet.RotationLimitationException;
import net.java.otr4j.util.ByteArrays;

import javax.annotation.Nonnull;
import java.math.BigInteger;
import java.net.ProtocolException;
import java.util.logging.Logger;

import static java.util.Collections.singleton;
import static java.util.Collections.singletonList;
import static java.util.Objects.requireNonNull;
import static java.util.logging.Level.FINE;
import static java.util.logging.Level.FINEST;
import static java.util.logging.Level.INFO;
import static java.util.logging.Level.WARNING;
import static net.java.otr4j.api.OtrEngineHosts.handleEvent;
import static net.java.otr4j.api.TLV.DISCONNECTED;
import static net.java.otr4j.api.TLV.PADDING;
import static net.java.otr4j.crypto.OtrCryptoEngine4.EXTRA_SYMMETRIC_KEY_CONTEXT_LENGTH_BYTES;
import static net.java.otr4j.io.EncryptedMessage.extractContents;
import static net.java.otr4j.io.ErrorMessage.ERROR_1_MESSAGE_UNREADABLE_MESSAGE;
import static net.java.otr4j.io.ErrorMessage.ERROR_ID_UNREADABLE_MESSAGE;
import static net.java.otr4j.messages.DataMessage4s.encodeDataMessageSections;
import static net.java.otr4j.messages.DataMessage4s.verify;
import static net.java.otr4j.session.smpv4.SMP.smpPayload;
import static net.java.otr4j.util.ByteArrays.allZeroBytes;
import static net.java.otr4j.util.ByteArrays.clear;
import static net.java.otr4j.util.ByteArrays.concatenate;

/**
 * The OTRv4 ENCRYPTED_MESSAGES state.
 * <p>
 * Note: AbstractOTRState contains quite a bit of scaffolding for handling (D)AKE messages and transitioning states.
 * However, all message arrive through {@link #handleEncodedMessage(Context, AbstractEncodedMessage)}, which is
 * (supposed to be) implemented in each of the concrete states. Consequently, this is the single entry-point at which
 * undesirable messages can be stopped, fully within control of each state. (E.g. stop all OTRv3 messages.) The
 * scaffolding is there for internal (re)use.
 */
// TODO write additional unit tests for StateEncrypted4
// TODO consider showing an notification/error when an AKE is initiated (tried to) such that user is informed, even if this is a suspicious situation. (We can silently drop all OTRv3 messages, given that we already have an established encrypted state. However, we cannot invariably drop all AKE messages, because if counter-party loses their encrypted session, they need some way to (re)initiate an encrypted session.)
final class StateEncrypted4 extends AbstractOTRState implements StateEncrypted {

    private static final SessionStatus STATUS = SessionStatus.ENCRYPTED;

    /**
     * Note that in OTRv4 the TLV type for the extra symmetric key is 0x7.
     */
    private static final int EXTRA_SYMMETRIC_KEY = 0x7;

    @SuppressWarnings({"PMD.LoggerIsNotStaticFinal", "NonConstantLogger"})
    private final Logger logger;

    private volatile DoubleRatchet ratchet;

    private final SMP smp;

    private volatile long lastMessageSentTimestamp = System.nanoTime();

    private final RemoteInfo remoteinfo;

    StateEncrypted4(final Context context, final byte[] ssid, final DoubleRatchet ratchet,
            final Point ourLongTermPublicKey, final Point ourForgingKey, final ClientProfile theirProfile,
             final AuthState authState, final DAKEState dakeState) {
        super(authState, dakeState);
        final SessionID sessionID = context.getSessionID();
        this.logger = Logger.getLogger(sessionID.getAccountID() + "-->" + sessionID.getUserID());
        this.ratchet = requireNonNull(ratchet);
        this.smp = new SMP(context.secureRandom(), context.getHost(), sessionID, ssid, ourLongTermPublicKey,
                ourForgingKey, theirProfile.getLongTermPublicKey(), theirProfile.getForgingKey(),
                context.getReceiverInstanceTag());
        this.remoteinfo = new RemoteInfo(Version.FOUR, theirProfile.getDsaPublicKey(), theirProfile);
    }

    @Nonnull
    @Override
    public Version getVersion() {
        return Version.FOUR;
    }

    @Nonnull
    @Override
    public SessionStatus getStatus() {
        return STATUS;
    }

    @Nonnull
    @Override
    public RemoteInfo getRemoteInfo() {
        return this.remoteinfo;
    }

    /**
     * The extra symmetric key is the "raw" key of the Sender. It does not perform the additional multi-key-derivations
     * that are described in the OTRv4 specification in case of multiple TLV 7 payloads using index and payload context
     * (first 4 bytes).
     * <p>
     * The acquired extra symmetric key is the key that corresponds to the next message that is sent.
     * <p>
     * Note: the user is responsible for cleaning up the extra symmetric key material after use.
     * <p>
     * Note: for receiving keys we currently automatically calculate the derived keys, so the sending user is expected
     * to do the same. You can use {@link net.java.otr4j.crypto.OtrCryptoEngine4#deriveExtraSymmetricKey(int, byte[], byte[])}
     * for this.
     * <p>
     * {@inheritDoc}
     */
    @Nonnull
    @Override
    public byte[] getExtraSymmetricKey() {
        return this.ratchet.extraSymmetricKeySender();
    }

    @Nonnull
    @Override
    public DataMessage4 transformSending(final Context context, final String msgText, final Iterable<TLV> tlvs,
            final byte flags) {
        return transformSending(context, msgText, tlvs, flags, new byte[0]);
    }

    @Nonnull
    private DataMessage4 transformSending(final Context context, final String msgText, final Iterable<TLV> tlvs,
            final byte flags, final byte[] providedMACsToReveal) {
        assert providedMACsToReveal.length == 0 || !allZeroBytes(providedMACsToReveal)
                : "BUG: expected providedMACsToReveal to contains some non-zero values.";
        // Perform ratchet if necessary, possibly collecting MAC codes to reveal.
        final byte[] collectedMACs;
        if (this.ratchet.nextRotation() == DoubleRatchet.Purpose.SENDING) {
            final byte[] revealedMacs;
            try (DoubleRatchet previous = this.ratchet) {
                this.ratchet = this.ratchet.rotateSenderKeys();
                revealedMacs = previous.collectReveals();
            }
            this.logger.log(FINEST, "Sender keys rotated. revealed MACs size: {0}.",
                    new Object[]{revealedMacs.length});
            collectedMACs = concatenate(providedMACsToReveal, revealedMacs);
        } else {
            this.logger.log(FINEST, "Sender keys rotation is not needed.");
            collectedMACs = providedMACsToReveal;
        }
        // Construct data message.
        final byte[] msgBytes = new OtrOutputStream().writeMessage(msgText).writeByte(0).writeTLV(tlvs).toByteArray();
        final byte[] ciphertext = this.ratchet.encrypt(msgBytes);
        // "When sending a data message in the same DH Ratchet: Set `i - 1` as the Data message's ratchet id. (except
        // for when immediately sending data messages after receiving a Auth-I message. In that it case it should be Set
        // `i` as the Data message's ratchet id)."
        final int ratchetId = Math.max(0, this.ratchet.getI() - 1);
        final int messageId = this.ratchet.getJ();
        final BigInteger dhPublicKey = ratchetId % 3 == 0 ? this.ratchet.getDHPublicKey() : null;
        // We intentionally set the authenticator to `new byte[64]` (all zero-bytes), such that we can calculate the
        // corresponding authenticator value. Then we construct a new DataMessage4 and substitute the real authenticator
        // for the dummy.
        final DataMessage4 unauthenticated = new DataMessage4(context.getSenderInstanceTag(),
                context.getReceiverInstanceTag(), flags, this.ratchet.getPn(), ratchetId, messageId,
                this.ratchet.getECDHPublicKey(), dhPublicKey, ciphertext, new byte[64], collectedMACs);
        final byte[] authenticator = this.ratchet.authenticate(encodeDataMessageSections(unauthenticated));
        // TODO we rotate away, so we need to acquire the extra symmetric key for this message ID now or never.
        this.ratchet.rotateSendingChainKey();
        final DataMessage4 message = new DataMessage4(unauthenticated, authenticator);
        this.lastMessageSentTimestamp = System.nanoTime();
        return message;
    }

    @Nonnull
    @Override
    public Result handleEncodedMessage(final Context context, final AbstractEncodedMessage message) throws ProtocolException, OtrException {
        switch (message.protocolVersion) {
        case ONE:
            this.logger.log(INFO, "Encountered message for protocol version 1. Ignoring message.");
            return new Result(STATUS, true, false, null);
        case TWO:
        case THREE:
            this.logger.log(INFO, "Encountered message for lower protocol version: {0}. Ignoring message.",
                    new Object[]{message.protocolVersion});
            return new Result(STATUS, true, false, null);
        case FOUR:
            return handleEncodedMessage4(context, message);
        default:
            throw new UnsupportedOperationException("BUG: Unsupported protocol version: " + message.protocolVersion);
        }
    }

    @Nonnull
    @Override
    Result handleDataMessage(final Context context, final DataMessage message) {
        throw new IllegalStateException("BUG: OTRv4 encrypted message state does not allow OTRv2/OTRv3 data messages.");
    }

    @Nonnull
    @Override
    @SuppressWarnings("PMD.CognitiveComplexity")
    Result handleDataMessage(final Context context, final DataMessage4 message) throws OtrException, ProtocolException {
        verify(message);
        if (message.i > this.ratchet.getI()) {
            this.logger.log(WARNING, "Received message is for a future ratchet ID: message must be malicious. (Current ratchet: {0}, message ratchet: {1})",
                    new Object[]{this.ratchet.getI(), message.i});
            throw new ProtocolException("Received message is for a future ratchet; must be malicious.");
        }
        final DoubleRatchet provisional;
        if (message.i == this.ratchet.getI()) {
            // If any message in a new ratchet is received, a new ratchet key has been received, any message keys
            // corresponding to skipped messages from the previous receiving ratchet are stored. A new DH ratchet is
            // performed.
            if (this.ratchet.nextRotation() != DoubleRatchet.Purpose.RECEIVING) {
                throw new ProtocolException("Message in next ratchet received before sending keys were rotated. Message violates protocol; probably malicious.");
            }
            // NOTE: with each message in a new ratchet, we receive new public keys. To acquire the authentication and
            // decryption keys, we need to incorporate these public keys in the ratchet. However, this means we must
            // work with unauthenticated data. Therefore, the ratchet constructs a new instance upon each rotation. We
            // work with the new ratchet instance provisionally, until we have authenticated and decrypted the message.
            // Only after successfully processing the message, do we transition to the new ratchet instance.
            provisional = this.ratchet.rotateReceiverKeys(message.ecdhPublicKey, message.dhPublicKey, message.pn);
        } else {
            provisional = this.ratchet;
        }
        // If the encrypted message corresponds to an stored message key corresponding to an skipped message, the
        // message is verified and decrypted with that key which is deleted from the storage.
        // If a new message from the current receiving ratchet is received, any message keys corresponding to skipped
        // messages from the same ratchet are stored, and a symmetric-key ratchet is performed to derive the current
        // message key and the next receiving chain key. The message is then verified and decrypted.
        final byte[] decrypted;
        final byte[] extraSymmetricKey;
        try {
            decrypted = provisional.decrypt(message.i, message.j, encodeDataMessageSections(message),
                    message.authenticator, message.ciphertext);
            extraSymmetricKey = provisional.extraSymmetricKeyReceiver(message.i, message.j);
        } catch (final RotationLimitationException e) {
            this.logger.log(INFO, "Cannot obtain public keys for that ratchet. The message cannot be decrypted.");
            handleUnreadableMessage(context, message, ERROR_ID_UNREADABLE_MESSAGE, ERROR_1_MESSAGE_UNREADABLE_MESSAGE);
            return new Result(STATUS, true, false, null);
        } catch (final OtrCryptoException e) {
            this.logger.log(INFO, "Received message fails verification. Rejecting the message.");
            return new Result(STATUS, true, false, null);
        }
        // Now that we successfully passed authentication and decryption, we know that the message was authentic.
        // Therefore, any new key material we might have received is authentic, and the message keys we used were used
        // and subsequently discarded correctly. At this point, malicious messages should not be able to have a lasting
        // impact, while authentic messages correctly progress the Double Ratchet.
        if (provisional != this.ratchet) {
            this.ratchet.transferReveals(provisional);
            this.ratchet.close();
            this.ratchet = provisional;
        }
        this.ratchet.confirmReceivingChainKey(message.i, message.j);
        this.ratchet.evictExcessKeys();
        // Process decrypted message contents. Extract and process TLVs. Possibly reply, e.g. SMP, disconnect.
        final byte[] currentESK = extraSymmetricKey.clone();
        final Content content = extractContents(decrypted);
        for (int i = 0; i < content.tlvs.size(); i++) {
            final TLV tlv = content.tlvs.get(i);
            this.logger.log(FINE, "Received TLV type {0}", tlv.type);
            if (smpPayload(tlv)) {
                if ((message.flags & FLAG_IGNORE_UNREADABLE) != FLAG_IGNORE_UNREADABLE) {
                    // Detect improvements for protocol implementation of remote party.
                    this.logger.log(WARNING, "Other party is using a faulty OTR client: all SMP messages are expected to have the IGNORE_UNREADABLE flag set.");
                }
                try {
                    final TLV response = this.smp.process(tlv);
                    if (response != null) {
                        context.injectMessage(transformSending(context, "", singletonList(response),
                                FLAG_IGNORE_UNREADABLE));
                    }
                } catch (final ProtocolException | OtrCryptoException e) {
                    this.logger.log(WARNING, "Illegal, bad or corrupt SMP TLV encountered. Stopped processing. This may indicate a bad implementation of OTR at the other party.", e);
                }
                continue;
            }
            switch (tlv.type) {
            case PADDING:
                // nothing to do here, just ignore the padding
                break;
            case DISCONNECTED:
                if ((message.flags & FLAG_IGNORE_UNREADABLE) != FLAG_IGNORE_UNREADABLE) {
                    this.logger.log(WARNING, "Other party is using a faulty OTR client: DISCONNECT messages are expected to have the IGNORE_UNREADABLE flag set.");
                }
                if (!content.message.isEmpty()) {
                    this.logger.warning("Expected other party to send TLV type 1 with empty human-readable message.");
                }
                final byte[] unused = this.ratchet.collectReveals();
                // TODO we need to reveal any remaining MK_MACs in the reveals list. (This use case is not covered in the specification. Basically, the other party reveals in the same message as TLV 1, but the receiving party doesn't. They could do this in a "dummy" data message with IGNORE_UNREADABLE flag set, because revealed MK_MACs are exposed anyways.
                clear(unused);
                context.transition(this, new StateFinished(getAuthState(), getDAKEState()));
                break;
            case EXTRA_SYMMETRIC_KEY:
                // TODO consider how to limit/warn that only 10 extra symmetric keys should be derived to preserve security properties.
                // REMARK we currently only call back to host with derived extra symmetric keys, i.e. derivation for each TLV. The "extra symmetric key" base-key is never reported back. Consider if this is the intended behavior, because spec is not clear on this.
                final byte[] eskContext = new byte[4];
                final byte[] eskValue;
                if (tlv.value.length < EXTRA_SYMMETRIC_KEY_CONTEXT_LENGTH_BYTES) {
                    System.arraycopy(tlv.value, 0, eskContext, 0, tlv.value.length);
                    eskValue = new byte[0];
                } else {
                    System.arraycopy(tlv.value, 0, eskContext, 0, 4);
                    eskValue = ByteArrays.cloneRange(tlv.value, 4, tlv.value.length - 4);
                }
                OtrCryptoEngine4.deriveExtraSymmetricKey(currentESK, (byte) i, eskContext, currentESK);
                handleEvent(context.getHost(), context.getSessionID(), context.getReceiverInstanceTag(),
                        Event.EXTRA_SYMMETRIC_KEY_DISCOVERED,
                        new Event.ExtraSymmetricKey(currentESK.clone(), eskContext, eskValue));
                break;
            default:
                this.logger.log(INFO, "Unsupported TLV #{0} received. Ignoring.", tlv.type);
                break;
            }
        }
        clear(extraSymmetricKey);
        return new Result(STATUS, false, true, content.message.length() > 0 ? content.message : null);
    }

    @Nonnull
    @Override
    public SMP getSmpHandler() {
        return this.smp;
    }

    @Override
    public void end(final Context context) throws OtrException {
        // Note: although we send a TLV 1 (DISCONNECT) here, we should not reveal remaining MACs.
        final TLV disconnectTlv = new TLV(DISCONNECTED, TLV.EMPTY_BODY);
        final AbstractEncodedMessage m = transformSending(context, "", singletonList(disconnectTlv), FLAG_IGNORE_UNREADABLE);
        try {
            context.injectMessage(m);
        } finally {
            // Transitioning to PLAINTEXT state should not depend on host. Ensure we transition to PLAINTEXT even if we
            // have problems injecting the message into the transport.
            context.transition(this, new StatePlaintext(getAuthState(), getDAKEState()));
        }
    }

    @Override
    public void expire(final Context context) throws OtrException {
        final TLV disconnectTlv = new TLV(DISCONNECTED, TLV.EMPTY_BODY);
        final DataMessage4 m = transformSending(context, "", singleton(disconnectTlv), FLAG_IGNORE_UNREADABLE,
                this.ratchet.collectReveals());
        try {
            context.injectMessage(m);
        } finally {
            context.transition(this, new StateFinished(getAuthState(), getDAKEState()));
        }
    }

    @Override
    public void destroy() {
        // TODO consider distinguishing between "normal" close(), also used for provisionally rotated DoubleRatchet-instances, and a (hypothetical) "destroy()" which is called upon exiting StateEncrypted4 to eradicate any remaining message-keys.
        this.ratchet.close();
        this.smp.close();
    }

    @Override
    public long getLastActivityTimestamp() {
        return this.ratchet.getLastRotation();
    }

    @Override
    public long getLastMessageSentTimestamp() {
        return this.lastMessageSentTimestamp;
    }
}
