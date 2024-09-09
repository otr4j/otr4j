/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */
package net.java.otr4j.api;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Utility class for safely handling the processing of OtrEngineListener
 * listeners.
 */
@SuppressWarnings("PMD.AvoidCatchingGenericException")
public final class OtrEngineListeners {

    private static final Logger LOGGER = Logger.getLogger(OtrEngineListeners.class.getName());

    private OtrEngineListeners() {
        // static methods only. No need to instantiate this utility class.
    }

    /**
     * Thread-safely duplicate list of OtrEngineListener listeners.
     * <p>
     * The duplicated list can be used to safely iterate over without the need
     * of locking the original list instance. That means that there is no risk
     * of ConcurrentModificationException. This list is a momentary snapsnot and
     * will not reflect updates/modifications on the original list.
     *
     * @param listeners Original list of listeners that, additionally, must be
     * handled thread-safely.
     * @return Returns duplicated list of listeners. (For one-time use.)
     */
    public static List<OtrEngineListener> duplicate(final List<OtrEngineListener> listeners) {
        synchronized (listeners) {
            return new ArrayList<>(listeners);
        }
    }

    /**
     * Safely call sessionStatusChanged on all listeners in provided iterable.
     *
     * @param listeners All listeners to be called.
     * @param sessionID the session ID
     * @param receiver The receiver instance.
     */
    public static void sessionStatusChanged(final Iterable<OtrEngineListener> listeners, final SessionID sessionID,
            final InstanceTag receiver) {
        for (final OtrEngineListener l : listeners) {
            try {
                // Calling the listeners in order to inform of events. As a service to the user we log any problems
                // that occur while calling listeners.
                l.sessionStatusChanged(sessionID, receiver);
            } catch (final RuntimeException | AssertionError e) {
                LOGGER.log(Level.WARNING, "Faulty listener! Runtime exception thrown while calling 'sessionStatusChanged' on listener '" + l.getClass().getCanonicalName() + "' for session " + sessionID, e);
            }
        }
    }

    /**
     * Safely call multipleInstancesDetected on all listeners in provided
     * iterable.
     *
     * @param listeners All listeners to be called.
     * @param sessionID the session ID
     */
    public static void multipleInstancesDetected(final Iterable<OtrEngineListener> listeners, final SessionID sessionID) {
        for (final OtrEngineListener l : listeners) {
            try {
                // Calling the listeners in order to inform of events. As a service to the user we log any problems that
                // occur while calling listeners.
                l.multipleInstancesDetected(sessionID);
            } catch (final RuntimeException | AssertionError e) {
                LOGGER.log(Level.WARNING, "Faulty listener! Runtime exception thrown while calling 'multipleInstancesDetected' on listener '" + l.getClass().getCanonicalName() + "' for session " + sessionID, e);
            }
        }
    }

    /**
     * Safely call outgoingSessionChanged on all listeners in provided iterable.
     *
     * @param listeners All listeners to be called.
     * @param sessionID the session ID
     */
    public static void outgoingSessionChanged(final Iterable<OtrEngineListener> listeners, final SessionID sessionID) {
        for (final OtrEngineListener l : listeners) {
            try {
                // Calling the listeners in order to inform of events. As a
                // service to the user we log any problems that occur while
                // calling listeners.
                l.outgoingSessionChanged(sessionID);
            } catch (final RuntimeException | AssertionError e) {
                LOGGER.log(Level.WARNING, "Faulty listener! Runtime exception thrown while calling 'outgoingSessionChanged' on listener '" + l.getClass().getCanonicalName() + "' for session " + sessionID, e);
            }
        }
    }
}
