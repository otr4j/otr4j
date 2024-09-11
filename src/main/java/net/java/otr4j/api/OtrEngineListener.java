/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.api;

/**
 * This interface should be implemented by the host application. It notifies
 * about session status changes.
 *
 * @author George Politis
 */
// TODO consider implementing defaults such that not all methods require overriding.
public interface OtrEngineListener {

    /**
     * Event triggered in case of session status changes.
     *
     * @param sessionID The session ID.
     * @param receiver  The receiver instance for which the status has changed.
     *                  (It might not be the active outgoing session.) The
     *                  receiver instance tag may be {@link InstanceTag#ZERO_TAG}
     *                  in case an OTR v2 session was changed.
     */
    void sessionStatusChanged(SessionID sessionID, InstanceTag receiver);

    /**
     * Event triggered in case multiple instances are detected.
     *
     * @param sessionID The session ID
     */
    void multipleInstancesDetected(SessionID sessionID);

    /**
     * Event triggered in case the outgoing session has changed.
     *
     * @param sessionID The session ID
     */
    // TODO consider to completely drop the default outgoing session. It's better to have the host application be explicit.
    void outgoingSessionChanged(SessionID sessionID);
}
