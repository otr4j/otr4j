/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */
package net.java.otr4j.api;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.logging.Logger;

import static java.util.logging.Level.WARNING;

/**
 * Utils for OtrEngineHost.
 *
 * <p>Methods that do not have a safe-handling counterpart implemented:</p>
 * <ul>
 * <li><i>injectMessage</i>: the OTR protocol depends on messages being injected for the
 * continuation of the process. Silencing any exceptions on this method will
 * silently halt the process which is not desirable.</li>
 *
 * <li><i>getSessionPolicy</i>: the Session policy is required information for further
 * execution. Do not silence such exceptions as they are important for correct
 * operation of the protocol itself.</li>
 *
 * <li><i>getMaxFragmentSize</i>: the fragment size is required for correct
 * functioning of the fragmentation function.</li>
 *
 * <li><i>getLocalKeyPair</i>: acquiring the local key pair is required for
 * continuing execution. There is no use in silencing exceptions that signal
 * problematic error cases.</li>
 *
 * <li><i>getLocalFingerprintRaw</i>: acquiring the local fingerprint is
 * required for continuing execution. There is no use in silencing exceptiosn
 * that signal problematic error cases.</li>
 * </ul>
 *
 * @author Danny van Heumen
 */
@SuppressWarnings({"PMD.AvoidCatchingGenericException", "PMD.AvoidDuplicateLiterals"})
public final class OtrEngineHosts {

    private static final Logger LOGGER = Logger.getLogger(OtrEngineHosts.class.getName());

    private OtrEngineHosts() {
        // static methods only. No need to instantiate this utility class.
    }

    /**
     * Safely call 'getFallbackMessage' in order to retrieve customized fallback
     * message for a chat client that does not support OTR. In case of a runtime
     * exception, null will be returned in order to signal to otr4j to use its
     * default fallback message.
     *
     * @param host the engine host instance
     * @param sessionID the session ID
     * @return Returns the engine host's customized fallback message or null if request failed with a runtime exception.
     */
    @Nullable
    public static String getFallbackMessage(final OtrEngineHost host, final SessionID sessionID) {
        try {
            return host.getFallbackMessage(sessionID);
        } catch (final RuntimeException | AssertionError e) {
            LOGGER.log(WARNING, "Faulty OtrEngineHost! Runtime exception thrown while calling 'getFallbackMessage' on OtrEngineHost '" + host.getClass().getCanonicalName() + "' for session " + sessionID, e);
        }
        return null;
    }

    /**
     * Query Engine Host to create suitable reply to send back as reply to an
     * unreadable message.
     *
     * @param host the Engine Host
     * @param sessionID the session ID
     * @param identifier the error identifier as defined by OTRv4, or empty-string if unknown/custom.
     * @param defaultMessage the default message to use in case call to OtrEngineHost fails
     * @return Returns the reply for unreadable message to send as error to other party.
     */
    @Nonnull
    public static String getReplyForUnreadableMessage(final OtrEngineHost host, final SessionID sessionID,
            final String identifier, final String defaultMessage) {
        try {
            final String reply = host.getReplyForUnreadableMessage(sessionID, identifier);
            return reply == null ? "" : reply;
        } catch (final RuntimeException | AssertionError e) {
            LOGGER.log(WARNING, "Faulty OtrEngineHost! Runtime exception thrown while calling 'getReplyForUnreadableMessage' on OtrEngineHost '" + host.getClass().getCanonicalName() + "' for session " + sessionID, e);
        }
        return defaultMessage;
    }

    /**
     * Request client-profile payload for restoring in session. Upon failure, returns empty payload.
     *
     * @param host the instance
     * @return Returns the OTR-encoded client-profile payload.
     */
    @Nonnull
    public static byte[] restoreClientProfilePayload(final OtrEngineHost host) {
        try {
            return host.restoreClientProfilePayload();
        } catch (final RuntimeException | AssertionError e) {
            LOGGER.log(WARNING, "Faulty OtrEngineHost! Runtime exception thrown while requesting client-profile payload from OtrEngineHost (host-application).", e);
        }
        return new byte[0];
    }

    /**
     * Send updated client-profile payload to OtrEngineHost, i.e. the host-application.
     *
     * @param host the instance
     * @param payload the OTR-encoded client-profile
     */
    public static void updateClientProfilePayload(final OtrEngineHost host, final byte[] payload) {
        try {
            host.updateClientProfilePayload(payload);
        } catch (final RuntimeException | AssertionError e) {
            LOGGER.log(WARNING, "Faulty OtrEngineHost! Runtime exception thrown while sending updated client-profile payload to OtrEngineHost (host-application) for persistence.", e);
        }
    }

    /**
     * Signal an event to the OTR Engine Host with context. This utility offers a safety net in that it mitigates
     * unchecked exceptions that may occur as a result of a bad OTR Engine Host implementation.
     *
     * @param host the OTR engine host
     * @param sessionID the session ID
     * @param receiver the receiver instance tag
     * @param event the event type
     * @param payload the event payload, can be type-cast using the event-type
     * @param <T> the parametric type to enforce type-safety between event-type and payload.
     */
    public static <T> void handleEvent(final OtrEngineHost host, final SessionID sessionID, final InstanceTag receiver,
            final Event<T> event, final T payload) {
        try {
            host.handleEvent(sessionID, receiver, event, payload);
        } catch (final RuntimeException | AssertionError e) {
            LOGGER.log(WARNING, "Faulty OtrEngineHost! Runtime exception thrown while signaling event.", e);
        }
    }
}
