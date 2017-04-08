/*
 * otr4j, the open source java otr librar
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import javax.annotation.Nonnull;

import net.java.otr4j.api.OtrEngineHost;
import net.java.otr4j.api.OtrEngineListener;
import net.java.otr4j.api.OtrEngineListenerUtil;
import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.api.Session;
import net.java.otr4j.api.SessionID;

/**
 * @author George Politis
 * @author Danny van Heumen
 */
public final class OtrSessionManager {

    /**
     * The OTR Engine Host instance.
     */
    private final OtrEngineHost host;

    /**
     * Map with known sessions.
     *
     * As the session map is needed as soon as we get/create our first session,
     * we might as well construct it immediately.
     */
    private final Map<SessionID, Session> sessions = Collections.synchronizedMap(new HashMap<SessionID, Session>());

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
    public OtrSessionManager(@Nonnull final OtrEngineHost host) {
        this.host = Objects.requireNonNull(host, "OtrEngineHost is required");
    }

    /**
     * Create an OTR session instance without the management of the OtrSessionManager.
     * <p>
     * Sessions created through this method will not be managed or remembered by any OtrSessionManager.
     *
     * @param sessionID The session ID
     * @param host      The OTR engine host
     * @return Returns a newly created OTR session instance.
     */
    @Nonnull
    public static Session createSession(@Nonnull final SessionID sessionID, @Nonnull final OtrEngineHost host) {
        return new SessionImpl(sessionID, host);
    }

    /**
     * Singleton instance of OtrEngineListener for listeners registered with
     * Session Manager.
     *
     * This listener instance will be registered as an OtrEngineListener with
     * all new sessions.
     */
    private final OtrEngineListener sessionManagerListener = new OtrEngineListener() {
        // Note that this implementation must be context-agnostic as the same
        // instance is now reused in all sessions.

        @Override
        public void sessionStatusChanged(@Nonnull final SessionID sessionID, @Nonnull final InstanceTag receiverTag) {
            OtrEngineListenerUtil.sessionStatusChanged(
                    OtrEngineListenerUtil.duplicate(listeners),
                    sessionID, receiverTag);
        }

        @Override
        public void multipleInstancesDetected(@Nonnull final SessionID sessionID) {
            OtrEngineListenerUtil.multipleInstancesDetected(
                    OtrEngineListenerUtil.duplicate(listeners), sessionID);
        }

        @Override
        public void outgoingSessionChanged(@Nonnull final SessionID sessionID) {
            OtrEngineListenerUtil.outgoingSessionChanged(
                    OtrEngineListenerUtil.duplicate(listeners), sessionID);
        }
    };

    /**
     * Fetches the existing session with this {@link SessionID} or creates a new
     * {@link Session} if one does not exist.
     *
     * @param sessionID The session's ID.
     * @return Returns Session instance that corresponds to provided sessionID.
     */
    public Session getSession(@Nonnull final SessionID sessionID) {

        if (sessionID.equals(SessionID.EMPTY)) {
            throw new IllegalArgumentException();
        }

        synchronized (sessions) {
            Session session = sessions.get(sessionID);
            if (session == null) {
                // Don't differentiate between existing but null and
                // non-existing. If we do not get a valid instance, then we
                // create a new instance.
                session = new SessionImpl(sessionID, this.host);
                session.addOtrEngineListener(sessionManagerListener);
                sessions.put(sessionID, session);
            }
            return session;
        }
    }

    /**
     * Add a new OtrEngineListener.
     *
     * @param l the listener
     */
    public void addOtrEngineListener(@Nonnull final OtrEngineListener l) {
        Objects.requireNonNull(l, "null is not a valid listener");
        synchronized (listeners) {
            if (!listeners.contains(l)) {
                listeners.add(l);
            }
        }
    }

    /**
     * Remove a registered OtrEngineListener.
     *
     * @param l the listener
     */
    public void removeOtrEngineListener(@Nonnull final OtrEngineListener l) {
        Objects.requireNonNull(l, "null is not a valid listener");
        synchronized (listeners) {
            listeners.remove(l);
        }
    }
}