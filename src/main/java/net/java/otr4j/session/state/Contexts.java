/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.session.state;

import net.java.otr4j.api.Event;
import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.api.OtrEngineHost;
import net.java.otr4j.api.OtrEngineHosts;
import net.java.otr4j.api.OtrException;
import net.java.otr4j.api.SessionID;
import net.java.otr4j.io.ErrorMessage;
import net.java.otr4j.util.Unit;

import static net.java.otr4j.api.OtrEngineHosts.getReplyForUnreadableMessage;

/**
 * Utility class for Context interface.
 */
public final class Contexts {

    private Contexts() {
        // No need to instantiate utility class.
    }

    /**
     * Signal both the local user and the remote party that a message is received that was unreadable.
     *
     * @param context the context instance
     * @param identifier the error identifier for predefined errors defined by OTRv4 or empty-string for not predefined.
     * @param message the textual error message.
     * @throws OtrException In case of failure to inject the remote message into the chat transport.
     */
    public static void signalUnreadableMessage(final Context context, final String identifier, final String message)
            throws OtrException {
        final OtrEngineHost host = context.getHost();
        final SessionID sessionID = context.getSessionID();
        final InstanceTag tag = context.getReceiverInstanceTag();
        OtrEngineHosts.handleEvent(host, sessionID, tag, Event.UNREADABLE_MESSAGE_RECEIVED, Unit.UNIT);
        final String replymsg = getReplyForUnreadableMessage(host, sessionID, identifier, message);
        context.injectMessage(new ErrorMessage(identifier, replymsg));
    }
}
