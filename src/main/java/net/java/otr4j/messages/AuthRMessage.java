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
import net.java.otr4j.crypto.ed448.Point;
import net.java.otr4j.io.OtrOutputStream;

import javax.annotation.Nonnull;
import java.math.BigInteger;
import java.util.Objects;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.util.Integers.requireInRange;

/**
 * OTRv4 Interactive DAKE Auth R Message.
 */
public final class AuthRMessage extends AbstractEncodedMessage {

    /**
     * Byte code identifier for Auth-R message type.
     */
    static final byte MESSAGE_AUTH_R = (byte) 0x36;

    /**
     * The client profile payload.
     */
    @Nonnull
    public final ClientProfilePayload clientProfile;

    /**
     * ECDH public key 'X'.
     */
    @Nonnull
    public final Point x;

    /**
     * DH public key 'A'.
     */
    @Nonnull
    public final BigInteger a;

    /**
     * The ring signature.
     */
    @Nonnull
    public final Sigma sigma;

    /**
     * The first ECDH public key to be used after DAKE completes.
     */
    @Nonnull
    public final Point firstECDHPublicKey;

    /**
     * The first DH public key to be used after DAKE completes.
     */
    @Nonnull
    public final BigInteger firstDHPublicKey;

    /**
     * Auth-R Message as used in OTRv4.
     *
     * @param protocolVersion       the protocol version
     * @param senderInstance        the sender instance tag
     * @param receiverInstance      the receiver instance tag
     * @param clientProfile         the client profile (as payload)
     * @param x                     the ECDH public key 'X'
     * @param a                     the DH public key 'A'
     * @param sigma                 the ring signature
     * @param ourFirstECDHPublicKey the first ECDH public key to be used once DAKE has completed
     * @param ourFirstDHPublicKey   the first DH public key to be used once DAKE has completed
     */
    public AuthRMessage(final int protocolVersion, final InstanceTag senderInstance, final InstanceTag receiverInstance,
            final ClientProfilePayload clientProfile, final Point x, final BigInteger a, final Sigma sigma,
            final Point ourFirstECDHPublicKey, final BigInteger ourFirstDHPublicKey) {
        super(requireInRange(Version.FOUR, Version.FOUR, protocolVersion), senderInstance, receiverInstance);
        this.clientProfile = requireNonNull(clientProfile);
        this.x = requireNonNull(x);
        this.a = requireNonNull(a);
        this.sigma = requireNonNull(sigma);
        this.firstECDHPublicKey = requireNonNull(ourFirstECDHPublicKey);
        this.firstDHPublicKey = requireNonNull(ourFirstDHPublicKey);
    }

    @Override
    public int getType() {
        return MESSAGE_AUTH_R;
    }

    @Override
    public void writeTo(final OtrOutputStream writer) {
        super.writeTo(writer);
        writer.write(this.clientProfile);
        writer.writePoint(this.x);
        writer.writeBigInt(this.a);
        writer.write(this.sigma);
        writer.writePoint(this.firstECDHPublicKey);
        writer.writeBigInt(this.firstDHPublicKey);
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
        final AuthRMessage that = (AuthRMessage) o;
        return clientProfile.equals(that.clientProfile) && x.constantTimeEquals(that.x) && a.equals(that.a)
                && sigma.equals(that.sigma) && firstECDHPublicKey.constantTimeEquals(that.firstECDHPublicKey)
                && firstDHPublicKey.equals(that.firstDHPublicKey);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), clientProfile, x, a, sigma, firstECDHPublicKey, firstDHPublicKey);
    }
}
