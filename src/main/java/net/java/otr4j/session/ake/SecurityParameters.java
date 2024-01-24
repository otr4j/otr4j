/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.session.ake;

import net.java.otr4j.api.Version;
import net.java.otr4j.crypto.DHKeyPairOTR3;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.crypto.SharedSecret;

import javax.annotation.Nonnull;
import javax.crypto.interfaces.DHPublicKey;
import java.security.interfaces.DSAPublicKey;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.crypto.DHKeyPairOTR3.verifyDHPublicKey;

/**
 * Container that stores all the security parameters that were negotiated during
 * AKE. These parameters are passed on to initiate the encrypted message state.
 *
 * @author Danny van Heumen
 */
public final class SecurityParameters {

    private final Version version;
    private final DHKeyPairOTR3 localDHKeyPair;
    private final DSAPublicKey remoteLongTermPublicKey;
    private final DHPublicKey remoteDHPublicKey;
    private final SharedSecret s;

    SecurityParameters(final Version version, final DHKeyPairOTR3 localDHKeyPair, final DSAPublicKey remoteLongTermPublicKey,
            final DHPublicKey remoteDHPublicKey, final SharedSecret s) {
        if (version != Version.TWO && version != Version.THREE) {
            throw new IllegalArgumentException("Illegal version value specified.");
        }
        this.version = requireNonNull(version);
        this.localDHKeyPair = requireNonNull(localDHKeyPair);
        this.remoteLongTermPublicKey = requireNonNull(remoteLongTermPublicKey);
        try {
            this.remoteDHPublicKey = verifyDHPublicKey(remoteDHPublicKey);
        } catch (final OtrCryptoException ex) {
            throw new IllegalArgumentException("Illegal D-H Public Key provided.", ex);
        }
        this.s = requireNonNull(s);
    }

    /**
     * Get the protocol version.
     *
     * @return Returns protocol version.
     */
    @Nonnull
    public Version getVersion() {
        return this.version;
    }

    /**
     * Get the local DH keypair.
     *
     * @return Returns the DH key pair.
     */
    @Nonnull
    public DHKeyPairOTR3 getLocalDHKeyPair() {
        return this.localDHKeyPair;
    }

    /**
     * Get the remote long-term DSA public key.
     *
     * @return Returns the DSA public key.
     */
    @Nonnull
    public DSAPublicKey getRemoteLongTermPublicKey() {
        return this.remoteLongTermPublicKey;
    }

    /**
     * Get the remote DH public key.
     *
     * @return Returns the DH public key.
     */
    @Nonnull
    public DHPublicKey getRemoteDHPublicKey() {
        return this.remoteDHPublicKey;
    }

    /**
     * Get the shared secret 's'.
     *
     * @return The shared secret 's'.
     */
    @Nonnull
    public SharedSecret getS() {
        return this.s;
    }
}
