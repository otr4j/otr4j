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
import net.java.otr4j.api.Version;
import net.java.otr4j.io.OtrOutputStream;

import javax.annotation.Nonnull;
import java.util.Arrays;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.util.ByteArrays.constantTimeEquals;

/**
 * OTRv2/OTRv3 AKE DH-Commit message.
 *
 * @author George Politis
 * @author Danny van Heumen
 */
public final class DHCommitMessage extends AbstractEncodedMessage {

    /**
     * Byte code identifier for DH-Commit message type.
     */
    static final int MESSAGE_DH_COMMIT = 0x02;

    /**
     * The encrypted DH public key.
     */
    @Nonnull
    public final byte[] dhPublicKeyEncrypted;
    /**
     * The DH public key hash.
     */
    @Nonnull
    public final byte[] dhPublicKeyHash;

    /**
     * Constructor to the DH commit message.
     *
     * @param protocolVersion      the protocol version
     * @param dhPublicKeyHash      the DH public key hash
     * @param dhPublicKeyEncrypted the encrypted DH public key
     * @param senderInstance       the sender instance tag
     * @param receiverInstance     the receiver instance tag
     */
    public DHCommitMessage(final Version protocolVersion, final byte[] dhPublicKeyHash, final byte[] dhPublicKeyEncrypted,
            final InstanceTag senderInstance, final InstanceTag receiverInstance) {
        super(protocolVersion, senderInstance, receiverInstance);
        if (protocolVersion != Version.TWO && protocolVersion != Version.THREE) {
            throw new IllegalArgumentException("illegal version");
        }
        this.dhPublicKeyEncrypted = requireNonNull(dhPublicKeyEncrypted);
        this.dhPublicKeyHash = requireNonNull(dhPublicKeyHash);
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + Arrays.hashCode(this.dhPublicKeyEncrypted);
        result = prime * result + Arrays.hashCode(this.dhPublicKeyHash);
        return result;
    }

    @SuppressWarnings("ShortCircuitBoolean")
    @Override
    public boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }
        if (!super.equals(obj)) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final DHCommitMessage other = (DHCommitMessage) obj;
        return constantTimeEquals(this.dhPublicKeyEncrypted, other.dhPublicKeyEncrypted)
                & constantTimeEquals(this.dhPublicKeyHash, other.dhPublicKeyHash);
    }

    @Override
    public void writeTo(final OtrOutputStream writer) {
        super.writeTo(writer);
        writer.writeData(this.dhPublicKeyEncrypted);
        writer.writeData(this.dhPublicKeyHash);
    }

    @Override
    public int getType() {
        return MESSAGE_DH_COMMIT;
    }
}
