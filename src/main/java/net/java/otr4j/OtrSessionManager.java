/*
 * otr4j, the open source java otr librar
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j;

import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.Vector;

import net.java.otr4j.session.Session;
import net.java.otr4j.session.SessionID;

/**
 * @author George Politis
 */
public class OtrSessionManager {

    public OtrSessionManager(OtrEngineHost host) {
        if (host == null)
            throw new IllegalArgumentException("OtrEngineHost is required.");

        this.setHost(host);
    }

    private OtrEngineHost host;
    private Map<SessionID, Session> sessions;

    public Session getSession(SessionID sessionID) {

        if (sessionID == null || sessionID.equals(SessionID.Empty))
            throw new IllegalArgumentException();

        if (sessions == null)
            sessions = new Hashtable<SessionID, Session>();

        if (!sessions.containsKey(sessionID)) {
            Session session = new Session(sessionID, getHost());
            sessions.put(sessionID, session);

            session.addOtrEngineListener(new OtrEngineListener() {

                public void sessionStatusChanged(SessionID sessionID) {
                    for (OtrEngineListener l : listeners)
                        l.sessionStatusChanged(sessionID);
                }

                public void multipleInstancesDetected(SessionID sessionID) {
                    for (OtrEngineListener l : listeners)
                        l.multipleInstancesDetected(sessionID);
                }

                public void outgoingSessionChanged(SessionID sessionID) {
                    for (OtrEngineListener l : listeners)
                        l.outgoingSessionChanged(sessionID);
                }
            });
            return session;
        } else
            return sessions.get(sessionID);
    }

    private void setHost(OtrEngineHost host) {
        this.host = host;
    }

    private OtrEngineHost getHost() {
        return host;
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
}
