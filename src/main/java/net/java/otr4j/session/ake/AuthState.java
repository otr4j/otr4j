/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.session.ake;

import net.java.otr4j.api.OtrException;
import net.java.otr4j.api.Version;
import net.java.otr4j.messages.AbstractEncodedMessage;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.net.ProtocolException;

/**
 * Interface for the AKE states.
 * <p>
 * This interface defines the methods that need to be implemented. Implementors are expected to be immutable. That is,
 * they may receive some support data at construction time, but they are not supposed to mutate data inside. Instead,
 * for each receiving message, which should entail a state transition, we should instantiate a new state with the
 * appropriate set of initial data.
 *
 * @author Danny van Heumen
 */
public interface AuthState {

    /**
     * Creation timestamp for the instance.
     * <p>
     * The timestamp indicates when the instance was created. As we should always work with the most recent state, we
     * can determine, based on the timestamp information, which is the most recent instance of AuthState.
     *
     * @return Returns the creation timestamp.
     */
    long getTimestamp();

    /**
     * Initiate a new AKE. Caller needs to send
     *
     * @param context        Context.
     * @param version        Initiate AKE using protocol version.
     * @return Returns DHCommitMessage with which we can initiate an AKE.
     */
    @Nonnull
    AbstractEncodedMessage initiate(AuthContext context, Version version);

    /**
     * Handle AKE message.
     *
     * @param context The current AKE context.
     * @param message The message to be handled.
     * @return Returns message to be injected into the transport stream to continue the AKE process. In case of 'null'
     * no message needs to be injected after handling this message.
     * @throws ProtocolException Throws exception in case of bad message content. (Note that an AbstractEncodedMessage
     * instance is provided, so failures should only occur based on bad message content.)
     * @throws OtrException Throws OtrException in case of unexpected situations during message processing, such as
     * verification and validation exceptions.
     */
    @Nonnull
    Result handle(AuthContext context, AbstractEncodedMessage message) throws ProtocolException, OtrException;

    /**
     * Result of AKE state handling.
     */
    final class Result {
        /**
         * The response to send to the other party, if applicable.
         */
        @Nullable
        public final AbstractEncodedMessage response;

        /**
         * The security parameters on which to base the encrypted session.
         */
        @Nullable
        public final SecurityParameters params;

        Result() {
            this.response = null;
            this.params = null;
        }

        Result(@Nullable final AbstractEncodedMessage response, @Nullable final SecurityParameters params) {
            this.response = response;
            this.params = params;
        }
    }

    /**
     * Get active protocol version in AKE negotiation.
     * <p>
     * Returns a version &gt; 0 in case of an active AKE negotiation in which a protocol version is already negotiated.
     * Returns 0 in case no negotiation is in progress.
     *
     * @return Returns active protocol version in AKE negotiation. (Or 0 if not in progress.)
     */
    Version getVersion();
}
