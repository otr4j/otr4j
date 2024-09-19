/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.session;

import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.api.OtrEngineHost;
import net.java.otr4j.api.OtrEngineListener;
import net.java.otr4j.api.OtrEngineListeners;
import net.java.otr4j.api.Session;
import net.java.otr4j.api.SessionID;
import net.java.otr4j.crypto.Init;
import net.java.otr4j.util.Classes;

import javax.annotation.Nonnull;
import javax.annotation.concurrent.ThreadSafe;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Timer;
import java.util.logging.Logger;

import static java.util.Collections.synchronizedMap;
import static java.util.Objects.requireNonNull;
import static net.java.otr4j.api.OtrEngineListeners.duplicate;

/**
 * The OTR session manager.
 * <p>
 * The session manager helps to manage sessions. The {@link SessionID} identifies each session. The session manager
 * observes changes to each session.
 * <p>
 * To merely create a new session, i.e. without actually using the session manager, use
 * {@link #createSession(SessionID, OtrEngineHost)}.
 *
 * @author George Politis
 * @author Danny van Heumen
 */
@ThreadSafe
public final class OtrSessionManager {

    private static final Logger LOGGER = Logger.getLogger(OtrSessionManager.class.getName());

    private static final long EXPIRATION_TIMER_INITIAL_DELAY = 60000L;

    private static final long EXPIRATION_TIMER_PERIOD = 60000L;

    private static final long HEARTBEAT_TIMER_INITIAL_DELAY = 60000L;

    private static final long HEARTBEAT_TIMER_PERIOD = 60000L;

    /**
     * The timer that periodically runs to check for expired OTR sessions.
     */
    private static final Timer EXPIRATION_TIMER = new Timer("otr-session-expiration-timer", true);

    /**
     * The timer that periodically checks to see if we need to send a heartbeat message for instance sessions that are
     * in private messaging state.
     */
    private static final Timer HEARTBEAT_TIMER = new Timer("otr-heartbeat-timer", true);

    static {
        Classes.initialize(Init.class);
        EXPIRATION_TIMER.schedule(SessionExpirationTimerTask.instance(), EXPIRATION_TIMER_INITIAL_DELAY,
                EXPIRATION_TIMER_PERIOD);
        LOGGER.info("OTR session expiration timer started.");
        HEARTBEAT_TIMER.schedule(HeartBeatTimerTask.instance(), HEARTBEAT_TIMER_INITIAL_DELAY, HEARTBEAT_TIMER_PERIOD);
        LOGGER.info("OTR heartbeat timer started.");
    }

    /**
     * The OTR Engine Host instance.
     */
    @Nonnull
    private final OtrEngineHost host;

    /**
     * Map with known sessions.
     * <p>
     * As the session map is needed as soon as we get/create our first session,
     * we might as well construct it immediately.
     */
    // For now, we suppress the UseConcurrentHashMap warning, because the ConcurrentHashMap does not allow us to
    // synchronize on the complete map such that we can be sure that only a single entry is added for a key.
    // ConcurrentHashMap has its own construct for putting conditionally. Currently, it is not worth the benefit as it
    // is a relatively minor issue compared to the introduction of OTRv4 support. For now, we'll leave it as is.
    @SuppressWarnings("PMD.UseConcurrentHashMap")
    private final Map<SessionID, SessionImpl> sessions = synchronizedMap(new HashMap<>());

    /**
     * List for keeping track of listeners.
     */
    private final ArrayList<OtrEngineListener> listeners = new ArrayList<>(0);

    /**
     * Constructor for OTR session manager.
     *
     * @param host OTR engine host that provides callback interface to host
     * logic.
     */
    public OtrSessionManager(final OtrEngineHost host) {
        this.host = requireNonNull(host, "OtrEngineHost is required");
    }

    /**
     * Create an OTR session instance without the management of the OtrSessionManager.
     * <p>
     * Sessions created through this method will not be managed or remembered by any OtrSessionManager.
     *
     * @param sessionID         The session ID
     * @param host              The OTR engine host
     * @return Returns a newly created OTR session instance.
     */
    @Nonnull
    public static Session createSession(final SessionID sessionID, final OtrEngineHost host) {
        final SessionImpl session = new SessionImpl(sessionID, host);
        SessionExpirationTimerTask.instance().register(session);
        return session;
    }

    /**
     * Singleton instance of OtrEngineListener for listeners registered with
     * Session Manager.
     * <p>
     * This listener instance will be registered as an OtrEngineListener with
     * all new sessions.
     */
    // TODO could be an anonymous class.
    @SuppressWarnings("UnnecessaryAnonymousClass")
    private final OtrEngineListener sessionManagerListener = new OtrEngineListener() {
        // Note that this implementation must be context-agnostic as the same instance is now reused in all sessions.

        @Override
        public void sessionStatusChanged(final SessionID sessionID, final InstanceTag receiverTag) {
            OtrEngineListeners.sessionStatusChanged(duplicate(OtrSessionManager.this.listeners), sessionID, receiverTag);
        }
    };

    /**
     * Fetches the existing session with this {@link SessionID} or creates a new
     * {@link Session} if one does not exist.
     *
     * @param sessionID The session's ID.
     * @return Returns Session instance that corresponds to provided sessionID.
     */
    public Session getSession(final SessionID sessionID) {
        synchronized (this.sessions) {
            SessionImpl session = this.sessions.get(sessionID);
            if (session == null) {
                // Don't differentiate between existing but null and non-existing. If we do not get a valid instance,
                // then we create a new instance.
                session = new SessionImpl(sessionID, this.host);
                session.addOtrEngineListener(this.sessionManagerListener);
                SessionExpirationTimerTask.instance().register(session);
                HeartBeatTimerTask.instance().register(session);
                this.sessions.put(sessionID, session);
            }
            return session;
        }
    }

    /**
     * Add a new OtrEngineListener.
     *
     * @param l the listener
     */
    public void addOtrEngineListener(final OtrEngineListener l) {
        requireNonNull(l, "null is not a valid listener");
        synchronized (this.listeners) {
            if (!this.listeners.contains(l)) {
                this.listeners.add(l);
            }
        }
    }

    /**
     * Remove a registered OtrEngineListener.
     *
     * @param l the listener
     */
    public void removeOtrEngineListener(final OtrEngineListener l) {
        requireNonNull(l, "null is not a valid listener");
        synchronized (this.listeners) {
            this.listeners.remove(l);
        }
    }
}
