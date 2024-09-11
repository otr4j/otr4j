/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.api;

import net.java.otr4j.crypto.DSAKeyPair;
import net.java.otr4j.crypto.ed448.EdDSAKeyPair;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * This interface should be implemented by the host application. It is required
 * for otr4j to work properly. This provides the core interface between the app
 * and otr4j.
 *
 * @author George Politis
 * @author Danny van Heumen
 */
// TODO consider default implementations for methods similar to <https://docs.oracle.com/en/java/javase/17/docs/api/java.net.http/java/net/http/HttpClient.html#newWebSocketBuilder()> to prevent having to implement methods that should execute as expected.
// TODO callback to feed client-profiles back to host for management, but would also require ability to request for comparison on each session.
public interface OtrEngineHost {

    /**
     * Request host to inject a new message into the IM communication stream upon which the OTR session is built.
     * <p>
     * Calls to {@code injectMessage} are expected to always succeed, as there is no way to mitigate not being able to
     * send arbitrary messages in the protocol. On the side of the OtrEngineHost implementation, if it is possible to
     * retry or to implement mitigations, such as queueing to retry sending later, this is acceptable. Such decisions
     * should be made depending on the characteristics and state of the underlying chat protocol.
     *
     * @param sessionID The session ID
     * @param msg       The message to inject
     */
    void injectMessage(SessionID sessionID, String msg);

    /**
     * Request the current session policy for provided session ID.
     *
     * @param sessionID the session ID
     * @return Returns the current policy for specified session.
     */
    @Nonnull
    OtrPolicy getSessionPolicy(SessionID sessionID);

    /**
     * Get instructions for the necessary fragmentation operations.
     * <p>
     * If no fragmentation is necessary, return {@link Integer#MAX_VALUE} to indicate the largest possible fragment
     * size. Return any positive integer to specify a maximum fragment size and enable fragmentation using that boundary
     * condition. If specified max fragment size is too small to fit at least the fragmentation overhead + some part of
     * the message, fragmentation will fail with an IOException when fragmentation is attempted during message
     * encryption.
     *
     * @param sessionID the session ID of the session
     * @return Returns the maximum fragment size allowed. Or return the maximum value possible,
     * {@link Integer#MAX_VALUE}, if fragmentation is not necessary.
     */
    default int getMaxFragmentSize(final SessionID sessionID) {
        return Integer.MAX_VALUE;
    }

    /**
     * Request local key pair from Engine Host. (OTRv2/OTRv3)
     * <p>
     * As OTR version 4 is now the preferred version, the local key pair will typically be used to provide a
     * transitional signature. Only when version 4 is not acceptable/suitable, will this be the primary key pair.
     * <p>
     * The local OTRv3 key pair can be generated using {@link DSAKeyPair#generateDSAKeyPair(java.security.SecureRandom)}.
     * <p>
     * WARNING: the keypair is considered sensitive information and should be stored securely.
     * 
     * @param sessionID the session ID
     * @return Returns the local key pair.
     */
    @Nonnull
    DSAKeyPair getLocalKeyPair(SessionID sessionID);

    /**
     * Request local long-term key pair from Engine Host. (OTRv4)
     * <p>
     * The long-term key pair can be generated using {@link EdDSAKeyPair#generate(java.security.SecureRandom)}.
     * <p>
     * WARNING: the keypair is considered sensitive information and should be stored securely.
     *
     * @param sessionID the session ID
     * @return Returns the local long-term Ed448-goldilocks key pair.
     */
    @Nonnull
    EdDSAKeyPair getLongTermKeyPair(SessionID sessionID);

    /**
     * Request local forging key pair from Engine Host. (OTRv4)
     * <p>
     * The forging key pair can be generated using {@link EdDSAKeyPair#generate(java.security.SecureRandom)}.
     * <p>
     * WARNING: the keypair is considered sensitive information and should be stored securely.
     *
     * @param sessionID the session ID
     * @return Returns the local long-term Ed448-goldilocks key pair.
     */
    @Nonnull
    EdDSAKeyPair getForgingKeyPair(SessionID sessionID);

    /**
     * Publish Client Profile payload.
     * <p>
     * In order to guarantee the deniability property in full, we require that any Client Profile in use is also
     * published, i.e. made available to the public. This way, it is always possible to acquire the Client Profile
     * without having to actually be in contact with the owner of the Client Profile.
     * <p>
     * Once a Client Profile payload is successfully published, otr4j expects to be able to re-acquire this payload
     * on construction. otr4j will call {@link #restoreClientProfilePayload()} to try and acquire the payload.
     *
     * @param payload the encoded Client Profile payload.
     */
    // TODO how to handle the case where multiple Session-instances all want to update the same expired profile, so we create and sign a number of profiles that are subsequently overwritten by the next session that beat the race-condition with the earliest update to be issued? (There is an obvious solution that is providing previous payload, allowing for a atomic compare-and-swap. However, that makes things more complicated again, for a use-case that might never even arise depending on how the client is implemented. Leaving this for now. This can be implemented later, and the adjustment both in otr4j and in the host-application are fairly minor.)
    void updateClientProfilePayload(byte[] payload);

    /**
     * Restore a previously published Client Profile payload.
     * <p>
     * Initially, we restore the previous Client Profile payload. Once the payload expires, or the composition of the
     * Client Profile changes, we will need to refresh the payload and the refreshed payload would need to be published.
     * <p>
     * The client profile "payload" is the encoded (bytes) representation of the Client Profile data-structure. This
     * payload contains public information, so is not considered sensitive information. The host-application should
     * treat the payload as an opaque blob. Either the blob is returned as is, or an empty array to indicate either
     * no payload is present or the host-application purged the payload.
     * <p>
     * The returned payload must correspond with long-term keypair, forging keypair, and optional legacy keypair. In
     * case an expired/purged payload is refreshed by otr4j, these individual components will be queried and a new
     * client-profile payload is generated based on those components. Returning data inconsistently will cause errors.
     * <p>
     * Note: only payloads that are successfully published ({@link #updateClientProfilePayload(byte[])}) should be
     * restored. otr4j assumes that the payload acquired through this method is already made public.
     *
     * @return Returns bytes of Client Profile payload, or zero-length array.
     */
    @Nonnull
    byte[] restoreClientProfilePayload();

    /**
     * When a message is received that is unreadable for some reason, for example the session keys are lost/deleted
     * already, then the Engine Host is asked to provide a suitable reply to send back as an OTR error message.
     * <p>
     * OTRv4 specifies an identifier that can be used to identify distinct types of errors and as such allow localizing
     * error messages based on the identifier. If case is custom / not predefined by OTRv4, an empty string will be
     * provided.
     *
     * @param sessionID the session ID
     * @param identifier the OTRv4 error identifier, or empty-string.
     * @return Returns a message corresponding to the identifier of the error. (<code>null</code> to ignore custom error
     * message.)
     */
    @Nullable
    default String getReplyForUnreadableMessage(final SessionID sessionID, final String identifier) {
        return null;
    }

    /**
     * Return the localized message that explains to the recipient how to get an OTR-enabled client. This is sent as
     * part of the initial OTR Query message that prompts the other side to set up an OTR session. If this returns
     * {@code null} or {@code ""}, then otr4j will use the built-in default message specified in
     * SerializationConstants#DEFAULT_FALLBACK_MESSAGE.
     *
     * @param sessionID the session ID
     * @return String the localized message or {@code null} for use built-in default.
     */
    @Nullable
    default String getFallbackMessage(final SessionID sessionID) {
        return null;
    }

    /**
     * handleEvent is the common method to signal an event to the OTR Engine Host.
     *
     * @param sessionID the session ID
     * @param receiver the receiver (remote participant) instance tag
     * @param event the type of event
     * @param payload the payload corresponding to the event
     * @param <T> the parametric type used to provide type-safety between event and payload.
     */
    <T> void handleEvent(SessionID sessionID, InstanceTag receiver, Event<T> event, T payload);
}
