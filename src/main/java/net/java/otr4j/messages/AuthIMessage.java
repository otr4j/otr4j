/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.messages;

import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.api.Session.Version;
import net.java.otr4j.crypto.OtrCryptoEngine4.Sigma;
import net.java.otr4j.io.OtrOutputStream;

import javax.annotation.Nonnull;
import java.util.Objects;

import static java.util.Objects.requireNonNull;

/**
 * OTRv4 Interactive DAKE Auth-I Message.
 */
public final class AuthIMessage extends AbstractEncodedMessage {

    static final byte MESSAGE_AUTH_I = (byte) 0x37;

    /**
     * The ring signature (sigma).
     */
    @Nonnull
    public final Sigma sigma;

    /**
     * Constructor for Auth-I message.
     *
     * @param senderInstance    the sender instance tag
     * @param receiverInstance the receiver instance tag
     * @param sigma             the ring signature
     */
    public AuthIMessage(final InstanceTag senderInstance, final InstanceTag receiverInstance,
            final Sigma sigma) {
        super(Version.FOUR, senderInstance, receiverInstance);
        this.sigma = requireNonNull(sigma);
    }

    @Override
    public int getType() {
        return MESSAGE_AUTH_I;
    }

    @Override
    public void writeTo(final OtrOutputStream writer) {
        super.writeTo(writer);
        writer.write(this.sigma);
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        if (!super.equals(o)) {
            return false;
        }
        final AuthIMessage that = (AuthIMessage) o;
        return this.sigma.equals(that.sigma);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), this.sigma);
    }
}
