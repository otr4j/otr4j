/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.api;

import com.google.errorprone.annotations.Immutable;

import javax.annotation.Nonnull;

import static java.util.Objects.requireNonNull;

/**
 * Session ID. Session ID is used to identify a single session based on
 * {@code (local account, remote account, protocol)} triple.
 *
 * @author George Politis
 */
@Immutable
public final class SessionID {

    @Nonnull
    private final String localAccountID;

    @Nonnull
    private final String remoteUserID;

    @Nonnull
    private final String protocolName;

    /**
     * A unique ID for an OTR session between two accounts.
     *
     * @param localAccountID the local account used for this conversation
     * @param remoteUserID the remote user on the other side of the conversation
     * @param protocolName the messaging protocol used for the conversation
     */
    public SessionID(final String localAccountID, final String remoteUserID, final String protocolName) {
        this.localAccountID = requireNonNull(localAccountID);
        this.remoteUserID = requireNonNull(remoteUserID);
        this.protocolName = requireNonNull(protocolName);
    }

    /**
     * Get local account ID.
     *
     * @return the {@code String} representing the local account
     */
    @Nonnull
    public String getAccountID() {
        return this.localAccountID;
    }

    /**
     * Get remote user ID.
     *
     * @return the {@code String} representing the remote user
     */
    @Nonnull
    public String getUserID() {
        return this.remoteUserID;
    }

    /**
     * Get protocol name.
     *
     * @return Returns protocol name.
     */
    @Nonnull
    public String getProtocolName() {
        return this.protocolName;
    }

    @Override
    public String toString() {
        return this.localAccountID + '_' + this.protocolName + '_' + this.remoteUserID;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + this.localAccountID.hashCode();
        result = prime * result + this.protocolName.hashCode();
        result = prime * result + this.remoteUserID.hashCode();
        return result;
    }

    @Override
    public boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        final SessionID other = (SessionID) obj;
        if (!this.localAccountID.equals(other.localAccountID)) {
            return false;
        }
        if (!this.protocolName.equals(other.protocolName)) {
            return false;
        }
        return this.remoteUserID.equals(other.remoteUserID);
    }
}
