package net.java.otr4j;

import java.util.logging.Level;
import java.util.logging.Logger;
import net.java.otr4j.session.InstanceTag;
import net.java.otr4j.session.SessionID;

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
// TODO consider modifying implementation in fashion of a decorator over OtrEngineHost.
public final class OtrEngineHostUtil {

    private static final Logger LOGGER = Logger.getLogger(OtrEngineHostUtil.class.getCanonicalName());

    private OtrEngineHostUtil() {
        // static methods only. No need to instantiate this utility class.
    }

    /**
     * Safely call 'messageFromAnotherInstanceReceived' event on provided
     * OtrEngineHost. Catch any runtime exception and log occurrence of the
     * exception and consequently the misbehaving of the OtrEngineHost instance.
     *
     * @param host the engine host instance
     * @param sessionID the session ID
     */
    public static void messageFromAnotherInstanceReceived(final OtrEngineHost host, final SessionID sessionID) {
        try {
            host.messageFromAnotherInstanceReceived(sessionID);
        } catch (RuntimeException e) {
            LOGGER.log(Level.WARNING, "Faulty OtrEngineHost! Runtime exception thrown while calling 'messageFromAnotherInstanceReceived' on OtrEngineHost '" + host.getClass().getCanonicalName() + "' for session " + sessionID, e);
        }
    }

    /**
     * Safely call 'multipleInstancesDetected' event on provided OtrEngineHost.
     * Catch any runtime exceptions and log occurrence of the exception and
     * consequently the misbehaving of the OtrEngineHost instance.
     *
     * @param host the engine host instance
     * @param sessionID the session ID
     */
    public static void multipleInstancesDetected(final OtrEngineHost host, final SessionID sessionID) {
        try {
            host.multipleInstancesDetected(sessionID);
        } catch (RuntimeException e) {
            LOGGER.log(Level.WARNING, "Faulty OtrEngineHost! Runtime exception thrown while calling 'multipleInstancesDetected' on OtrEngineHost '" + host.getClass().getCanonicalName() + "' for session " + sessionID, e);
        }
    }

    /**
     * Safely call 'unencryptedMessageReceived' event on provided OtrEngineHost.
     * Catch any runtime exceptions and log occurrence of the exception and
     * consequently the misbehaving of the OtrEngineHost instance.
     *
     * OtrException exceptions are caught, logged and silenced. Calling code
     * cannot handle interruptions by exception and will result in incomplete
     * message processing.
     *
     * @param host the engine host instance
     * @param sessionID the session ID
     * @param message the received message
     */
    public static void unencryptedMessageReceived(final OtrEngineHost host, final SessionID sessionID, final String message) {
        try {
            host.unencryptedMessageReceived(sessionID, message);
        } catch (RuntimeException e) {
            LOGGER.log(Level.WARNING, "Faulty OtrEngineHost! Runtime exception thrown while calling 'unencryptedMessageReceived' on OtrEngineHost '" + host.getClass().getCanonicalName() + "' for session " + sessionID, e);
        } catch (OtrException e) {
            LOGGER.log(Level.WARNING, "OtrException thrown while calling 'unencryptedMessageReceived' on OtrEngineHost '" + host.getClass().getCanonicalName() + "' for session " + sessionID, e);
        }
    }

    /**
     * Safely call 'unreadableMessageReceived' event on provided OtrEngineHost.
     * Catch any runtime exceptions and log occurrence of the exception and
     * consequently the misbehaving of the OtrEngineHost instance.
     *
     * OtrException exceptions are caught, logged and silenced. Calling code
     * cannot handle interruptions by exception and will result in incomplete
     * message processing.
     *
     * @param host the engine host instance
     * @param sessionID the session ID
     */
    public static void unreadableMessageReceived(final OtrEngineHost host, final SessionID sessionID) {
        try {
            host.unreadableMessageReceived(sessionID);
        } catch (RuntimeException e) {
            LOGGER.log(Level.WARNING, "Faulty OtrEngineHost! Runtime exception thrown while calling 'unreadableMessageReceived' on OtrEngineHost '" + host.getClass().getCanonicalName() + "' for session " + sessionID, e);
        } catch (OtrException e) {
            LOGGER.log(Level.WARNING, "OtrException thrown while calling 'unreadableMessageReceived' on OtrEngineHost '" + host.getClass().getCanonicalName() + "' for session " + sessionID, e);
        }
    }

    /**
     * Safely call 'getFallbackMessage' in order to retrieve customized fallback
     * message for a chat client that does not support OTR. In case of a runtime
     * exception, null will be returned in order to signal to otr4j to use its
     * default fallback message.
     *
     * @param host the engine host instance
     * @param sessionID the session ID
     * @return Returns the engine host's customized fallback message or null if
     * request failed with a runtime exception.
     */
    public static String getFallbackMessage(final OtrEngineHost host, final SessionID sessionID) {
        try {
            return host.getFallbackMessage(sessionID);
        } catch (RuntimeException e) {
            LOGGER.log(Level.WARNING, "Faulty OtrEngineHost! Runtime exception thrown while calling 'getFallbackMessage' on OtrEngineHost '" + host.getClass().getCanonicalName() + "' for session " + sessionID, e);
        }
        return null;
    }

    /**
     * Safely call 'verify' on Engine Host. In case of runtime exception an
     * error will be logged and execution will continue. By logging the error
     * and continuing we ensure that the protocol interaction for the current
     * session will continue as expected, even if something went wrong on the
     * Engine Host in registering the successful verification.
     *
     * @param host the Engine Host
     * @param sessionID the session ID
     * @param fingerprint the fingerprint of the verified chat partner
     * @param approved approved
     */
    public static void verify(final OtrEngineHost host, final SessionID sessionID, final String fingerprint, final boolean approved) {
        try {
            host.verify(sessionID, fingerprint, approved);
        } catch (RuntimeException e) {
            LOGGER.log(Level.SEVERE, "Faulty OtrEngineHost! Runtime exception thrown while calling 'verify' on OtrEngineHost '" + host.getClass().getCanonicalName() + "' for session " + sessionID, e);
        }
    }

    /**
     * Safely call 'unverify' on Engine Host. In case of runtime exception an
     * error will be logged and execution will continue. By logging the error
     * and continuing we ensure that the protocol interaction for the current
     * session will continue as expected, even if something went wrong on the
     * Engine Host in registering the unsuccessful verification.
     *
     * @param host the Engine Host
     * @param sessionID the session ID
     * @param fingerprint the fingerprint of the unverified chat partner
     */
    // TODO Consider interrupting or otherwise making the error more explicit. We are signaling for untrustworthy fingerprint after all. Do we want to let bad Engine Host behavior slip???
    public static void unverify(final OtrEngineHost host, final SessionID sessionID, final String fingerprint) {
        try {
            host.unverify(sessionID, fingerprint);
        } catch (RuntimeException e) {
            LOGGER.log(Level.SEVERE, "Faulty OtrEngineHost! Runtime exception thrown while calling 'unverify' on OtrEngineHost '" + host.getClass().getCanonicalName() + "' for session " + sessionID, e);
        }
    }

    /**
     * Safely call 'showError' on Engine Host. In case of runtime exception a
     * warning will be logged and execution will continue. By logging the
     * exception and continuing we ensure that the protocol interaction for the
     * current session will continue as expected, even if something went wrong
     * on the Engine Host in showing the error message.
     *
     * OtrException exceptions are caught, logged and silenced. Calling code
     * cannot handle interruptions by exception and will result in incomplete
     * message processing.
     *
     * @param host the Engine Host
     * @param sessionID the session ID
     * @param error the error message
     */
    public static void showError(final OtrEngineHost host, final SessionID sessionID, final String error) {
        try {
            host.showError(sessionID, error);
        } catch (RuntimeException e) {
            LOGGER.log(Level.WARNING, "Faulty OtrEngineHost! Runtime exception thrown while calling 'showError' on OtrEngineHost '" + host.getClass().getCanonicalName() + "' for session " + sessionID, e);
        } catch (OtrException e) {
            LOGGER.log(Level.WARNING, "OtrException thrown while calling 'showError' on OtrEngineHost '" + host.getClass().getCanonicalName() + "' for session " + sessionID, e);
        }
    }

    /**
     * Safely call 'smpError' on Engine Host. In case of runtime exception a
     * warning will be logged and execution will continue. By logging the
     * exception and continuing we ensure that the SMP error will be handled
     * fully and the session correctly ended, even if something went wrong on
     * the Engine Host.
     *
     * OtrException exceptions are caught, logged and silenced. Calling code
     * cannot handle interruptions by exception and will result in incomplete
     * message processing.
     *
     * @param host the Engine Host
     * @param sessionID the session ID
     * @param tlvType the TLV type
     * @param cheated indicator for nature of SMP error, whether error because
     * of "cheat" status or for other reason.
     */
    public static void smpError(final OtrEngineHost host, final SessionID sessionID, final int tlvType, final boolean cheated) {
        try {
            host.smpError(sessionID, tlvType, cheated);
        } catch (RuntimeException e) {
            LOGGER.log(Level.WARNING, "Faulty OtrEngineHost! Runtime exception thrown while calling 'smpError' on OtrEngineHost '" + host.getClass().getCanonicalName() + "' for session " + sessionID, e);
        } catch (OtrException e) {
            LOGGER.log(Level.WARNING, "OtrException thrown while calling 'smpError' on OtrEngineHost '" + host.getClass().getCanonicalName() + "' for session " + sessionID, e);
        }
    }

    /**
     * Safely call 'smpAborted' on Engine Host. In case of runtime exception a
     * warning will be logged and execution will continue. By logging the
     * exception and continuing we ensure that the SMP abort will be handled
     * fully and the session correctly ended, even if something went wrong on
     * the Engine Host.
     *
     * OtrException exceptions are caught, logged and silenced. Calling code
     * cannot handle interruptions by exception and will result in incomplete
     * message processing.
     *
     * @param host
     * @param sessionID
     */
    public static void smpAborted(final OtrEngineHost host, final SessionID sessionID) {
        try {
            host.smpAborted(sessionID);
        } catch (RuntimeException e) {
            LOGGER.log(Level.WARNING, "Faulty OtrEngineHost! Runtime exception thrown while calling 'smpAborted' on OtrEngineHost '" + host.getClass().getCanonicalName() + "' for session " + sessionID, e);
        } catch (OtrException e) {
            LOGGER.log(Level.WARNING, "OtrException thrown while calling 'smpAborted' on OtrEngineHost '" + host.getClass().getCanonicalName() + "' for session " + sessionID, e);
        }
    }

    /**
     * Signal finished session to Engine Host with provided message. Call Engine
     * Host safely and log any runtime exceptions that are thrown.
     *
     * OtrException exceptions are caught, logged and silenced. Calling code
     * cannot handle interruptions by exception and will result in incomplete
     * message processing.
     *
     * @param host the Engine Host
     * @param sessionID the session ID
     * @param msgText a message text about the finished session
     */
    public static void finishedSessionMessage(final OtrEngineHost host, final SessionID sessionID, final String msgText) {
        try {
            host.finishedSessionMessage(sessionID, msgText);
        } catch (RuntimeException e) {
            LOGGER.log(Level.WARNING, "Faulty OtrEngineHost! Runtime exception thrown while calling 'finishedSessionMessage' on OtrEngineHost '" + host.getClass().getCanonicalName() + "' for session " + sessionID, e);
        } catch (OtrException e) {
            LOGGER.log(Level.WARNING, "OtrException thrown while calling 'finishedSessionMessage' on OtrEngineHost '" + host.getClass().getCanonicalName() + "' for session " + sessionID, e);
        }
    }

    /**
     * Signal require encryption to Engine Host with provided message. Call
     * Engine Host safely and log any runtime exceptions that are thrown.
     *
     * OtrException exceptions are caught, logged and silenced. Calling code
     * cannot handle interruptions by exception and will result in incomplete
     * message processing.
     *
     * @param host the Engine Host
     * @param sessionID the session ID
     * @param msgText the message
     */
    public static void requireEncryptedMessage(final OtrEngineHost host, final SessionID sessionID, final String msgText) {
        try {
            host.requireEncryptedMessage(sessionID, msgText);
        } catch (RuntimeException e) {
            LOGGER.log(Level.WARNING, "Faulty OtrEngineHost! Runtime exception thrown while calling 'requireEncryptedMessage' on OtrEngineHost '" + host.getClass().getCanonicalName() + "' for session " + sessionID, e);
        } catch (OtrException e) {
            LOGGER.log(Level.WARNING, "OtrException thrown while calling 'requireEncryptedMessage' on OtrEngineHost '" + host.getClass().getCanonicalName() + "' for session " + sessionID, e);
        }
    }

    /**
     * Signal Engine Host to ask user for the secret answer for the provided question.
     *
     * @param host the Engine Host
     * @param sessionID the session ID
     * @param sender the sender instance tag
     * @param question The question sent by the other party.
     */
    public static void askForSecret(final OtrEngineHost host, final SessionID sessionID, final InstanceTag sender, final String question) {
        try {
            host.askForSecret(sessionID, sender, question);
        } catch (RuntimeException e) {
            LOGGER.log(Level.WARNING, "Faulty OtrEngineHost! Runtime exception thrown while calling 'askForSecret' on OtrEngineHost '" + host.getClass().getCanonicalName() + "' for session " + sessionID, e);
        }
    }

    /**
     * Query Engine Host to create suitable reply to send back as reply to an
     * unreadable message.
     *
     * @param host the Engine Host
     * @param sessionID the session ID
     * @return Returns the reply for unreadable message to send as error to other party.
     */
    public static String getReplyForUnreadableMessage(final OtrEngineHost host, final SessionID sessionID, final String defaultMessage) {
        try {
            return host.getReplyForUnreadableMessage(sessionID);
        } catch (RuntimeException e) {
            LOGGER.log(Level.WARNING, "Faulty OtrEngineHost! Runtime exception thrown while calling 'getReplyForUnreadableMessage' on OtrEngineHost '" + host.getClass().getCanonicalName() + "' for session " + sessionID, e);
        }
        return defaultMessage;
    }
}