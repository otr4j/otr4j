/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.api;

import com.google.errorprone.annotations.CheckReturnValue;
import net.java.otr4j.util.Unit;

import javax.annotation.Nonnull;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.util.ByteArrays.requireLengthExactly;

/**
 * Event represents each of the possible event variants that may be signaled to the OtrEngineHost.
 *
 * @param <T> the type for the event payload
 */
public final class Event<T> {
    /**
     * An unencrypted message was received. (The message is the payload.)
     * <p>
     * This event is reported whenever a session has at least one instance that is not in plaintext state. Event if
     * plaintext messages cannot be assigned to a specific instance, this at least tells the user that a secure session
     * is possible and (previously) established, but still he received an unencrypted message.
     */
    public static final Event<String> UNENCRYPTED_MESSAGE_RECEIVED = new Event<>(String.class);
    /**
     * T.b.d.
     */
    public static final Event<String> ERROR = new Event<>(String.class);
    /**
     * An unreadable message was received, i.e. due to encryption keys no longer being available. (No payload.)
     */
    public static final Event<Unit> UNREADABLE_MESSAGE_RECEIVED = new Event<>(Unit.class);
    /**
     * Received message was intended for another instance. (No payload.)
     */
    public static final Event<Unit> MESSAGE_FOR_ANOTHER_INSTANCE_RECEIVED = new Event<>(Unit.class);
    /**
     * The received data message contains a TLV for use of the Extra Symmetric Key. (Payload is a composite class with
     * additional data for use of the extra symmetric key.) This event is triggered for each TLV.
     * <p>
     * Field `key` is the extra symmetric key, as locally derived from the session key material.
     * Field `context` represents the 4-byte context value, as described in the specification.
     * Field `value` are the remaining bytes, i.e. `[4,)`.
     */
    public static final Event<ExtraSymmetricKey> EXTRA_SYMMETRIC_KEY_DISCOVERED = new Event<>(ExtraSymmetricKey.class);
    /**
     * Event is triggered if the policy forbids messaging without establishing an encrypted session first. (Payload is
     * the original message.)
     */
    public static final Event<String> ENCRYPTED_MESSAGES_REQUIRED = new Event<>(String.class);
    /**
     * Session is `Finished`, indicating that the user should manually transition back to plaintext to indicate they
     * are aware that messages are no longer sent confidentially. (No payload.)
     */
    // TODO should event type include a copy of the message sent in SessionFinished? (or just show error?)
    public static final Event<Unit> SESSION_FINISHED = new Event<>(Unit.class);
    /**
     * Signal Engine Host to ask user for answer to the question provided by the
     * other party in the SMP authentication session. (Payload is the question (SMP1Q) or empty string if initiated
     * without accompanying question (SMP1).)
     */
    public static final Event<String> SMP_REQUEST_SECRET = new Event<>(String.class);
    /**
     * When a remote user's key is verified via the Socialist Millionaire's Protocol (SMP) shared passphrase or
     * question/answer, this event will be called upon successful completion of that process.
     * (Payload is the fingerprint that is verified.)
     */
    public static final Event<SMPResult> SMP_COMPLETED = new Event<>(SMPResult.class);
    /**
     * Signal OTR Engine Host to inform that SMP is aborted.
     * <p>
     * Payload is a boolean value that indicates whether: `false` abort is called by user request or incoming abort TLV,
     * or `true` abort is motivated by cheating.
     */
    public static final Event<AbortReason> SMP_ABORTED = new Event<>(AbortReason.class);

    private final Class<T> type;

    private Event(final Class<T> type) {
        this.type = requireNonNull(type);
    }

    /**
     * Convert the (presumably untyped) payload to type corresponding to the event.
     *
     * @param payload the (presumably untyped) payload
     * @return Returns the payload cast to the appropriate type.
     */
    @CheckReturnValue
    @Nonnull
    public T convert(final Object payload) {
        return this.type.cast(payload);
    }

    /**
     * SMPResult represents the result of a completed Socialist Millionaire Protocol exchange.
     */
    public static final class SMPResult {

        /**
         * Flag indicating whether SMP completed successfully or resulted in failure.
         */
        public final boolean success;

        /**
         * The fingerprint of the remote's public key.
         */
        public final byte[] fingerprint;

        /**
         * SMPResult constructs an SMP result for the corresponding event.
         *
         * @param success flag indicating success or failure
         * @param fingerprint the fingerprint of the remote public key
         */
        public SMPResult(final boolean success, final byte[] fingerprint) {
            this.success = success;
            this.fingerprint = requireNonNull(fingerprint);
        }
    }

    /**
     * EventAbortReason is the set of reasons for aborting the SMP.
     */
    public enum AbortReason {
        /**
         * User-initiated abort, either by the local user or the remote user (through TLV).
         */
        USER,
        /**
         * SMP process interrupted by unexpected event, e.g. reset for not following protocol. Not necessarily malicious.
         */
        INTERRUPTION,
        /**
         * SMP process reset because of some violation, such as bad input or conclusion 'cheated'.
         */
        VIOLATION
    }

    /**
     * EventExtraSymmetricKey is the event class that carries the data for the corresponding event.
     */
    public static final class ExtraSymmetricKey {

        /**
         * The extra symmetric key, base-key in case of OTRv3, or derived key (according to spec) for OTRv4.
         */
        public final byte[] key;
        /**
         * The context (4-byte) value present in the TLV value.
         */
        public final byte[] context;
        /**
         * The remaining bytes present in the TLV value.
         */
        public final byte[] value;

        /**
         * Constructor for the event.
         *
         * @param key the extra symmetric key
         * @param context the context
         * @param value the (remaining) value
         */
        public ExtraSymmetricKey(final byte[] key, final byte[] context, final byte[] value) {
            this.key = requireNonNull(key);
            this.context = requireLengthExactly(4, context);
            this.value = requireNonNull(value);
        }
    }
}
