/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.session.state;

import com.google.errorprone.annotations.CheckReturnValue;
import com.google.errorprone.annotations.MustBeClosed;
import net.java.otr4j.crypto.MixedSharedSecret;
import net.java.otr4j.crypto.OtrCryptoEngine4;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.crypto.ed448.Point;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.net.ProtocolException;
import java.util.logging.Logger;

import static java.lang.Integer.MIN_VALUE;
import static java.util.Objects.requireNonNull;
import static java.util.logging.Level.FINE;
import static java.util.logging.Level.FINER;
import static java.util.logging.Level.FINEST;
import static java.util.logging.Level.WARNING;
import static net.java.otr4j.crypto.OtrCryptoEngine4.AUTHENTICATOR_LENGTH_BYTES;
import static net.java.otr4j.crypto.OtrCryptoEngine4.EXTRA_SYMMETRIC_KEY_LENGTH_BYTES;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.AUTHENTICATOR;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.CHAIN_KEY;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.EXTRA_SYMMETRIC_KEY;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.MAC_KEY;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.MESSAGE_KEY;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.NEXT_CHAIN_KEY;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.ROOT_KEY;
import static net.java.otr4j.crypto.OtrCryptoEngine4.MK_ENC_LENGTH_BYTES;
import static net.java.otr4j.crypto.OtrCryptoEngine4.MK_MAC_LENGTH_BYTES;
import static net.java.otr4j.crypto.OtrCryptoEngine4.ROOT_KEY_LENGTH_BYTES;
import static net.java.otr4j.crypto.OtrCryptoEngine4.hcmac;
import static net.java.otr4j.crypto.OtrCryptoEngine4.kdf;
import static net.java.otr4j.util.ByteArrays.allZeroBytes;
import static net.java.otr4j.util.ByteArrays.constantTimeEquals;
import static net.java.otr4j.util.ByteArrays.requireLengthExactly;
import static org.bouncycastle.util.Arrays.clear;
import static org.bouncycastle.util.Arrays.concatenate;

/**
 * The Double Ratchet. (OTRv4)
 * <p>
 * The logistics of the Double Ratchet-algorithm. The mechanism according to which the key rotations are performed. The
 * cryptographic secrets updates are performed in {@link MixedSharedSecret}.
 * <p>
 * Key rotations consist of 2 cases:
 * <ol>
 * <li>Every third ratchet, starting at the first ratchet: rotate the DH key and derive key material from the new DH key
 * pair.</li>
 * <li>Other two ratchets: rotate key material based on symmetric key (brace key) only.</li>
 * </ol>
 * <p>
 * DoubleRatchet is NOT thread-safe.
 */
// TODO DoubleRatchet currently does not keep history. Therefore it is not possible to decode out-of-order messages from previous ratchets. (Also needed to keep MessageKeys instances for messages failing verification.)
final class DoubleRatchet implements AutoCloseable {

    private static final Logger LOGGER = Logger.getLogger(DoubleRatchet.class.getName());

    private final ByteArrayOutputStream macsToReveal = new ByteArrayOutputStream();

    /**
     * Sender ratchet (a.k.a. `j`) represents the ratchet process on the part of the message sender.
     * <p>
     * The sender ratchet contains message ID 'j'.
     */
    private final Ratchet senderRatchet = new Ratchet();

    /**
     * Receiver ratchet (a.k.a. `k`) represents the ratchet process on part of the message receiver.
     * <p>
     * The receiver ratchet contains message ID 'k'.
     */
    private final Ratchet receiverRatchet = new Ratchet();

    private final MixedSharedSecret sharedSecret;

    /**
     * The 'root key' in the Double Ratchet. The root key is shared between sender and receiver ratchets.
     */
    private final byte[] rootKey;

    /**
     * The next ratchet ID.
     * <p>
     * NOTE: 'i' is incremented as soon as a rotation has finished. For typical use outside of this class, one would use
     * need value 'i - 1', instead of 'i'.
     */
    private int i = 0;

    /**
     * The number of messages in the previous ratchet, i.e. sender ratchet message number.
     */
    private int pn = 0;

    /**
     * Monotonic timestamp of the last rotation activity. ({@link System#nanoTime()})
     */
    private long lastRotation = System.nanoTime();

    DoubleRatchet(final MixedSharedSecret sharedSecret, final byte[] initialRootKey, final Role role) {
        this.sharedSecret = requireNonNull(sharedSecret);
        this.rootKey = requireLengthExactly(ROOT_KEY_LENGTH_BYTES, initialRootKey);
        assert !allZeroBytes(this.rootKey) : "Expected random data, instead of all zero-bytes. There might be something severely wrong.";
        switch (role) {
        case BOB:
            generateRatchetKeys(Purpose.RECEIVING);
            this.senderRatchet.needsRotation = true;
            // As we set the `needsRotation` flag on the sender ratchet, next time a message is sent new ratchet keys
            // will be generated. According to the Double Ratchet initialization in OTRv4 spec, we should do this
            // immediately. However, the steps are exactly the same and generating them here means we need to find a way
            // to put the public keys into the next data message. This makes things a lot more complicated and in the
            // end achieves the exact same effect.
            break;
        case ALICE:
            generateRatchetKeys(Purpose.SENDING);
            break;
        default:
            throw new UnsupportedOperationException("Unsupported purpose.");
        }
    }

    @Override
    public void close() {
        clear(this.rootKey);
        this.i = MIN_VALUE;
        this.pn = 0;
        this.sharedSecret.close();
        if (this.macsToReveal.size() > 0) {
            throw new IllegalStateException("BUG: Remaining MACs have not been revealed.");
        }
        this.senderRatchet.close();
        this.receiverRatchet.close();
    }

    /**
     * Indicates whether or not Sender key rotation is required before encrypting/authenticating the next message to be
     * sent.
     *
     * @return Returns true iff sender key rotation is required.
     */
    @CheckReturnValue
    boolean isNeedSenderKeyRotation() {
        return this.senderRatchet.needsRotation;
    }

    /**
     * The ratchet ID ('i')
     *
     * @return Returns current ratchet ID.
     */
    int getI() {
        return this.i;
    }

    /**
     * The sender message ID ('j')
     *
     * @return Returns message ID.
     */
    int getJ() {
        return this.senderRatchet.messageID;
    }

    /**
     * The receiver message ID ('k')
     *
     * @return Returns message ID.
     */
    int getK() {
        return this.receiverRatchet.messageID;
    }

    /**
     * Number of (sender) messages in previous ratchet.
     *
     * @return Returns number of messages.
     */
    int getPn() {
        return this.pn;
    }

    /**
     * Get the monotonic timestamp for the last sender keys rotation.
     *
     * @return Returns the monotonic timestamp for the last sender keys rotation. ({@link System#nanoTime()})
     */
    long getLastRotation() {
        return this.lastRotation;
    }

    @Nonnull
    Point getECDHPublicKey() {
        return this.sharedSecret.getECDHPublicKey();
    }
    
    @Nonnull
    BigInteger getDHPublicKey() {
        return this.sharedSecret.getDHPublicKey();
    }
    
    @CheckReturnValue
    @Nonnull
    byte[] rotateSenderKeys() {
        requireNotClosed();
        if (!this.senderRatchet.needsRotation) {
            throw new IllegalStateException("Rotation is only allowed after new public key material was received from the other party.");
        }
        // Perform sender key rotation.
        LOGGER.log(FINE, "Rotating root key and sending chain key for ratchet " + this.i);
        final boolean performDHRatchet = this.i % 3 == 0;
        this.sharedSecret.rotateOurKeys(performDHRatchet);
        generateRatchetKeys(Purpose.SENDING);
        this.i += 1;
        // Update last-rotation time such that we can keep track of when the last rotation took place.
        this.lastRotation = System.nanoTime();
        // Extract MACs to reveal.
        final byte[] revealedMacs = this.macsToReveal.toByteArray();
        this.macsToReveal.reset();
        return revealedMacs;
    }

    /**
     * Encrypt provided data with the current sending message keys. In the process, generate a nonce required for
     * encryption.
     *
     * @param data the data
     * @return Returns a composite result consisting of the generated nonce and the ciphertext.
     */
    @Nonnull
    byte[] encrypt(final byte[] data) {
        LOGGER.log(FINER, "Generating message keys for encryption of ratchet {0}, message {1}.",
                new Object[]{this.i - 1, this.senderRatchet.messageID});
        try (MessageKeys keys = this.generateSendingKeys()) {
            return keys.encrypt(data);
        }
    }

    /**
     * Generate an authenticator value for later content verification.
     *
     * @param dataMessageSectionsContent the hash of the data message sections
     * @return Returns authenticator value.
     */
    @Nonnull
    byte[] authenticate(final byte[] dataMessageSectionsContent) {
        LOGGER.log(FINER, "Generating message keys for authentication of ratchet {0}, message {1}.",
                new Object[]{this.i - 1, this.senderRatchet.messageID});
        try (MessageKeys keys = this.generateSendingKeys()) {
            return keys.authenticate(dataMessageSectionsContent);
        }
    }

    @MustBeClosed
    @Nonnull
    private MessageKeys generateSendingKeys() {
        final byte[] chainKey = this.senderRatchet.getChainKey();
        try {
            return generateMessageKeys(chainKey);
        } finally {
            clear(chainKey);
        }
    }

    /**
     * Verify then decrypt a received OTRv4 data message.
     *
     * @param ratchetId                  ID for the receiving ratchet.
     * @param messageId                  ID for the receiving ratchet message ID.
     * @param encodedDataMessageSections Data message sections that need to be authenticated, encoded as byte-array.
     * @param ciphertext                 The encrypted message ciphertext.
     * @return Returns the decrypted ciphertext.
     * @throws VerificationException       If data message fails verification, i.e. the authenticators do not match.
     * @throws RotationLimitationException In case of failure to acquire the corresponding message keys. This exception
     *                                     occurs when the first message of a new message is missing and therefore we
     *                                     cannot generate the necessary keys.
     */
    byte[] decrypt(final int ratchetId, final int messageId, final byte[] encodedDataMessageSections,
            final byte[] authenticator, final byte[] ciphertext) throws VerificationException,
            RotationLimitationException {
        LOGGER.log(FINER, "Generating message keys for verification and decryption of ratchet {0}, message {1}.",
                new Object[]{this.i - 1, this.receiverRatchet.messageID});
        try (MessageKeys keys = generateReceivingKeys(ratchetId, messageId)) {
            keys.verify(encodedDataMessageSections, authenticator);
            this.macsToReveal.write(authenticator, 0, authenticator.length);
            return keys.decrypt(ciphertext);
        }
    }

    /**
     * Acquire the extra symmetric key that corresponds to the next message to be sent.
     * <p>
     * Note that this is the "raw" extra symmetric key. OTRv4 specifies how one can derive additional keys from this
     * "raw" input data. These derivation steps are not performed.
     *
     * @return The "raw" extra symmetric key. (User needs to clean up the byte-array after use.)
     */
    @Nonnull
    byte[] extraSymmetricKeySender() {
        requireNotClosed();
        LOGGER.log(FINEST, "Generating extra symmetric keys for encryption of ratchet {0}, message {1}.",
                new Object[] {Math.max(this.i, 0), this.senderRatchet.messageID});
        try (MessageKeys keys = generateSendingKeys()) {
            // TODO encapsulate extra symmetric key in AutoCloseable to control exposure/clearing of bytes?
            return keys.getExtraSymmetricKey();
        }
    }

    /**
     * Acquire the extra symmetric key that corresponds to received messages.
     *
     * @return The "raw" extra symmetric key. (User needs to clean up the byte-array after use.)
     */
    @Nonnull
    byte[] extraSymmetricKeyReceiver(final int ratchetId, final int messageId) throws RotationLimitationException {
        requireNotClosed();
        LOGGER.log(FINEST, "Generating extra symmetric keys for encryption of ratchet {0}, message {1}.",
                new Object[]{ratchetId, messageId});
        try (MessageKeys keys = generateReceivingKeys(ratchetId, messageId)) {
            return keys.getExtraSymmetricKey();
        }
    }

    /**
     * Generate receiving Message Keys.
     *
     * @param ratchetId The ratchet ID as indicated in the Data message.
     * @param messageId The message ID as indicated in the Data message.
     * @return Returns corresponding MessageKeys instance.
     * @throws RotationLimitationException Indicates that we cross a ratchet boundary and therefore we cannot fast-forward
     *                               rotations to a point where the right message keys can be generated. This is a
     *                               limitation of the Double Ratchet. Matching message keys cannot be generated.
     */
    // TODO preserve message keys before rotating past ratchetId, messageId combination.
    @MustBeClosed
    private MessageKeys generateReceivingKeys(final int ratchetId, final int messageId) throws RotationLimitationException {
        requireNotClosed();
        if (Math.max(0, this.i - 1) > ratchetId || this.receiverRatchet.messageID > messageId) {
            throw new UnsupportedOperationException("Retrieval of previous Message Keys has not been implemented yet. Only current Message Keys can be generated.");
        }
        if (Math.max(0, this.i - 1) < ratchetId) {
            // The first message in the new ratchet provides us with the information we need to generate missing message
            // keys in previous ratchet, as well as necessary key material to decrypt and authenticate the message.
            // There is no way to process this message given that this information is missing.
            throw new RotationLimitationException("Cannot fast-forward rotate receiving keys over new ratchet ID. We have not encountered.");
        }
        // TODO verify that number of messages needing to fast-forward is acceptable. (max_skip in OTRv4 spec)
        while (this.receiverRatchet.messageID < messageId) {
            LOGGER.log(FINEST, "Fast-forward rotating receiving chain key to catch up with message ID: " + messageId);
            this.receiverRatchet.rotateChainKey();
            // TODO store intermediate message keys for previous messages as the message may arrive out-of-order
        }
        final byte[] chainKey = this.receiverRatchet.getChainKey();
        try {
            return generateMessageKeys(chainKey);
        } finally {
            clear(chainKey);
        }
    }

    /**
     * Rotate the sending chain key.
     */
    void rotateSendingChainKey() {
        this.senderRatchet.rotateChainKey();
    }

    /**
     * Rotate the receiving chain key.
     */
    void rotateReceivingChainKey() {
        this.receiverRatchet.rotateChainKey();
    }

    /**
     * Rotate the receiver key.
     * <p>
     * For convenience, it is allowed to pass in null for each of the keys. Depending on the input, a key rotation will
     * be performed, or it will be skipped.
     *
     * @param nextECDH The other party's ECDH public key.
     * @param nextDH   The other party's DH public key.
     */
    // TODO preserve message keys in previous ratchet before rotating away.
    // FIXME need to verify that public keys (ECDH and DH) were not encountered previously.
    void rotateReceiverKeys(final Point nextECDH, @Nullable final BigInteger nextDH) throws OtrCryptoException, ProtocolException {
        requireNotClosed();
        LOGGER.log(FINE, "Rotating root key and receiving chain key for ratchet {0} (nextDH = {1})",
                new Object[]{this.i, nextDH != null});
        if (nextECDH.constantTimeEquals(this.sharedSecret.getTheirECDHPublicKey())) {
            LOGGER.log(FINE, "Skipping rotating receiver keys as ECDH public key is already known.");
            return;
        }
        // FIXME check in spec: is this conditional expressed exactly as described in the spec? Seems counter-intuitive.
//        if (nextDH != null && nextDH.equals(this.sharedSecret.getTheirDHPublicKey())) {
//            LOGGER.log(FINE, "Skipping rotating receiver keys as DH public key is already known.");
//            return;
//        }
        final boolean performDHRatchet = this.i % 3 == 0;
        if (performDHRatchet && nextDH == null) {
            LOGGER.log(WARNING, "Performing receiver keys rotation for message in new ratchet. DH-ratchet is expected, but DH public key is missing.");
            throw new ProtocolException("DH public key missing for rotation with DH ratchet. (Buggy implementation of OTR of the other party?)");
        }
        if (!performDHRatchet && nextDH != null) {
            LOGGER.log(WARNING, "Performing receiver keys rotation for message in new ratchet. DH public key is provided but not expected.");
            throw new ProtocolException("DH public key provided for rotation while not expected. (Buggy implementation of OTR of the other party?)");
        }
        final BigInteger maybeNextDH = performDHRatchet ? nextDH : null;
        this.sharedSecret.rotateTheirKeys(performDHRatchet, nextECDH, maybeNextDH);
        this.pn = this.senderRatchet.messageID;
        generateRatchetKeys(Purpose.RECEIVING);
        this.senderRatchet.needsRotation = true;
        this.i += 1;
    }

    private void generateRatchetKeys(final Purpose purpose) {
        final byte[] previousRootKey = this.rootKey.clone();
        final byte[] newK = this.sharedSecret.getK();
        final byte[] concatPreviousRootKeyNewK = concatenate(previousRootKey, newK);
        kdf(this.rootKey, 0, ROOT_KEY_LENGTH_BYTES, ROOT_KEY, concatPreviousRootKeyNewK);
        switch (purpose) {
        case SENDING:
            this.senderRatchet.rotateKeys(concatPreviousRootKeyNewK);
            break;
        case RECEIVING:
            this.receiverRatchet.rotateKeys(concatPreviousRootKeyNewK);
            break;
        default:
            throw new UnsupportedOperationException("Unsupported parameter: " + purpose);
        }
        clear(newK);
        clear(previousRootKey);
        clear(concatPreviousRootKeyNewK);
    }

    /**
     * Get the remaining MAC-keys-to-be-revealed. (And remove them from the internal list to be revealed.)
     * <p>
     * NOTE: this method should only used to acquire the last remaining MAC keys prior to a session end. The general
     * revelation case is facilitated through key rotation, i.e. {@link #rotateSenderKeys()}.
     *
     * @return Returns the remaining MAC keys to reveal.
     */
    byte[] collectRemainingMACsToReveal() {
        requireNotClosed();
        final byte[] revealed = this.macsToReveal.toByteArray();
        this.macsToReveal.reset();
        return revealed;
    }

    /**
     * Forget the remaining MAC-keys-to-be-revealed. (This is called whenever remaining MAC keys need not be revealed
     * before actually closing.)
     */
    void forgetRemainingMACsToReveal() {
        requireNotClosed();
        this.macsToReveal.reset();
    }

    @MustBeClosed
    private MessageKeys generateMessageKeys(final byte[] chainkey) {
        assert !allZeroBytes(chainkey) : "Expected chainkey of random data instead of all zero-bytes.";
        final byte[] encrypt = kdf(MK_ENC_LENGTH_BYTES, MESSAGE_KEY, chainkey);
        final byte[] extraSymmetricKey = kdf(EXTRA_SYMMETRIC_KEY_LENGTH_BYTES, EXTRA_SYMMETRIC_KEY,
                new byte[] {(byte) 0xff}, chainkey);
        return new MessageKeys(encrypt, extraSymmetricKey);
    }

    private void requireNotClosed() {
        if (this.i < 0) {
            throw new IllegalStateException("Instance was previously closed and cannot be used anymore.");
        }
    }

    /**
     * Ratchet, the individual ratchet used for either sending or receiving.
     */
    private final static class Ratchet implements AutoCloseable {

        private static final int CHAIN_KEY_LENGTH_BYTES = 64;

        /**
         * The chain key.
         * <p>
         * The key relies on a first key rotation to become initialized.
         */
        private final byte[] chainKey = new byte[CHAIN_KEY_LENGTH_BYTES];

        /**
         * Message ID.
         */
        private int messageID = 0;

        /**
         * The boolean indicates that we need key rotation before we have sensible data to work with. (Initially, the
         * chain key is all-zero.)
         */
        private boolean needsRotation = false;

        @Override
        public void close() {
            this.messageID = MIN_VALUE;
            clear(this.chainKey);
        }

        /**
         * Acquire ratchet's chain key.
         * <p>
         * NOTE: caller needs to clear the return key after use.
         *
         * @return Returns chain key.
         */
        byte[] getChainKey() {
            requireNotClosed();
            requireRotationNotNeeded();
            return this.chainKey.clone();
        }

        /**
         * Rotate the chain key.
         * <p>
         * Generate a new chain key based on the old chain key and increment the message ID.
         */
        void rotateChainKey() {
            requireNotClosed();
            requireRotationNotNeeded();
            this.messageID += 1;
            kdf(this.chainKey, 0, CHAIN_KEY_LENGTH_BYTES, NEXT_CHAIN_KEY, this.chainKey);
        }

        /**
         * Rotate the ratchet key.
         */
        void rotateKeys(final byte[] concatPreviousRootKeyNewK) {
            requireNotClosed();
            this.messageID = 0;
            kdf(this.chainKey, 0, CHAIN_KEY_LENGTH_BYTES, CHAIN_KEY, concatPreviousRootKeyNewK);
            this.needsRotation = false;
        }

        private void requireRotationNotNeeded() {
            if (this.needsRotation) {
                throw new IllegalStateException("Key rotation needs to be performed before new keys can be generated.");
            }
        }

        private void requireNotClosed() {
            if (this.messageID < 0) {
                throw new IllegalStateException("Ratchet instance is already closed.");
            }
        }
    }

    /**
     * Encrypt/decrypt and authenticate/verify using the secret key material in the MessageKeys.
     * <p>
     * NOTE: Please ensure that message keys are appropriately cleared by calling {@link #close()} after use.
     */
    private static final class MessageKeys implements AutoCloseable {

        /**
         * Flag to indicate when MessageKeys instanced has been cleaned up.
         */
        private boolean closed = false;

        /**
         * Encryption/Decryption key. (MUST be cleared after use.)
         */
        private final byte[] encrypt;

        /**
         * Extra Symmetric Key. (MUST be cleared after use.)
         */
        private final byte[] extraSymmetricKey;

        /**
         * Construct Keys instance.
         *
         * @param encrypt           message key for encryption
         * @param extraSymmetricKey extra symmetric key
         */
        @MustBeClosed
        private MessageKeys(final byte[] encrypt, final byte[] extraSymmetricKey) {
            assert !allZeroBytes(encrypt) : "Expected encryption key of \"random\" data, instead of all zero-bytes.";
            this.encrypt = requireLengthExactly(MK_ENC_LENGTH_BYTES, encrypt);
            assert !allZeroBytes(extraSymmetricKey) : "Expected extra symmetric key of \"random\" data, instead of all zero-bytes.";
            this.extraSymmetricKey = requireLengthExactly(EXTRA_SYMMETRIC_KEY_LENGTH_BYTES, extraSymmetricKey);
        }

        /**
         * Clear sensitive material.
         */
        @Override
        public void close() {
            clear(this.encrypt);
            clear(this.extraSymmetricKey);
            this.closed = true;
        }

        /**
         * Encrypt a message using a random nonce.
         *
         * @param message The plaintext message.
         * @return Returns a result containing the ciphertext and nonce used.
         */
        @Nonnull
        byte[] encrypt(final byte[] message) {
            requireNotClosed();
            return OtrCryptoEngine4.encrypt(this.encrypt, message);
        }

        /**
         * Decrypt a ciphertext.
         *
         * @param ciphertext The ciphertext.
         * @return Returns the plaintext message.
         */
        @Nonnull
        byte[] decrypt(final byte[] ciphertext) {
            requireNotClosed();
            return OtrCryptoEngine4.decrypt(this.encrypt, ciphertext);
        }

        /**
         * Get the authenticator (MAC).
         * <p>
         * This method only performs the final hash calculation that includes the MAC key. The internal hash calculation
         * defined by OTRv4 is expected to be performed prior to calling this method:
         * <pre>
         *       Authenticator = KDF_1(usageAuthenticator || MKmac || data_message_sections, 64)
         * </pre>
         *
         * @param dataMessageSections The data message sections (excluding Authenticator and Revealed MACs).
         * @return Returns the MAC. (Must be cleared separately.)
         */
        @Nonnull
        byte[] authenticate(final byte[] dataMessageSections) {
            requireNotClosed();
            final byte[] mac = kdf(MK_MAC_LENGTH_BYTES, MAC_KEY, this.encrypt);
            final byte[] authenticator = hcmac(AUTHENTICATOR, AUTHENTICATOR_LENGTH_BYTES, mac, dataMessageSections);
            clear(mac);
            assert !allZeroBytes(authenticator) : "Expected non-zero bytes in authenticator";
            return authenticator;
        }

        /**
         * Verify a given authenticator against the expected authentication hash.
         *
         * @param dataMessageSection The data message section content to be authenticated.
         * @param authenticator      The authenticator value.
         * @throws VerificationException In case of failure to verify the authenticator against the data message section
         *                               content.
         */
        void verify(final byte[] dataMessageSection, final byte[] authenticator)
                throws VerificationException {
            assert !allZeroBytes(authenticator) : "Expected non-zero bytes in authenticator";
            requireNotClosed();
            final byte[] expectedAuthenticator = authenticate(dataMessageSection);
            try {
                if (!constantTimeEquals(expectedAuthenticator, authenticator)) {
                    throw new VerificationException("The authenticator is invalid.");
                }
            } finally {
                clear(expectedAuthenticator);
            }
        }

        /**
         * Get the Extra Symmetric Key.
         *
         * @return Returns the Extra Symmetric Key. (Instance must be cleared by user.)
         */
        @Nonnull
        byte[] getExtraSymmetricKey() {
            requireNotClosed();
            return extraSymmetricKey.clone();
        }

        private void requireNotClosed() {
            if (this.closed) {
                throw new IllegalStateException("BUG: Use of closed MessageKeys instance.");
            }
        }
    }

    /**
     * This is used to indicate that a boundary is reached that the DoubleRatchet cannot handle.
     */
    static final class RotationLimitationException extends Exception {

        private static final long serialVersionUID = -2200918867384812098L;

        private RotationLimitationException(final String message) {
            super(message);
        }
    }

    /**
     * The VerificationException indicates a failure to verify the authenticator.
     */
    static final class VerificationException extends Exception {

        private static final long serialVersionUID = 2169901253478095348L;

        private VerificationException(final String message) {
            super(message);
        }
    }

    /**
     * The role which is fulfilled according to the OTRv4 specification.
     */
    enum Role {
        ALICE, BOB
    }

    private enum Purpose {
        SENDING, RECEIVING
    }
}
