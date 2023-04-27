/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.api;

import net.java.otr4j.api.Session.Version;
import net.java.otr4j.crypto.ed448.Point;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.security.interfaces.DSAPublicKey;
import java.util.Collection;
import java.util.Objects;
import java.util.Set;

import static java.util.Arrays.asList;
import static java.util.Collections.singleton;
import static java.util.Collections.unmodifiableSet;
import static java.util.Objects.requireNonNull;
import static net.java.otr4j.util.Collections.requireAbsent;
import static net.java.otr4j.util.Collections.requireElements;
import static net.java.otr4j.util.Collections.requireMinElements;

/**
 * The validated representation of the ClientProfile.
 */
public final class ClientProfile {

    private static final Collection<Integer> MANDATORY_VERSIONS = singleton(Version.FOUR);

    private static final Collection<Integer> FORBIDDEN_VERSIONS = asList(Version.ONE, Version.TWO);

    /**
     * Owner's instance tag.
     */
    @Nonnull
    private final InstanceTag instanceTag;

    /**
     * Public key of the long-term Ed448 keypair.
     */
    @Nonnull
    private final Point longTermPublicKey;

    /**
     * Public key of the Ed448 Forging key.
     */
    @Nonnull
    private final Point forgingKey;

    /**
     * List of supported versions.
     */
    @Nonnull
    private final Set<Integer> versions;

    /**
     * DSA public key.
     */
    @Nullable
    private final DSAPublicKey dsaPublicKey;

    /**
     * Constructor for the client profile instance.
     *
     * @param instanceTag       The instance tag. As the instance tag is now part of the client profile, it should be
     *                          persistent such that other clients can rely on the client information for next time you
     *                          are establishing secure communications.
     * @param longTermPublicKey The long-term Ed448 public key. This is the public key of the key pair provided at
     *                          {@link OtrEngineHost#getLongTermKeyPair(SessionID)}.
     * @param forgingKey        The Ed448 Forging public key. The key can be generated using
     *                          {@link net.java.otr4j.crypto.ed448.EdDSAKeyPair#generate(java.security.SecureRandom)}.
     * @param versions          supported protocol versions
     * @param dsaPublicKey      The DSA public key. This is the public key of the key pair provided at
     *                          {@link OtrEngineHost#getLocalKeyPair(SessionID)}.
     */
    public ClientProfile(final InstanceTag instanceTag, final Point longTermPublicKey, final Point forgingKey,
            final Set<Integer> versions, @Nullable final DSAPublicKey dsaPublicKey) {
        // TODO should check for `> 0` instance tag?
        this.instanceTag = requireNonNull(instanceTag);
        this.longTermPublicKey = requireNonNull(longTermPublicKey);
        this.forgingKey = requireNonNull(forgingKey);
        this.versions = unmodifiableSet(requireMinElements(1, requireElements(MANDATORY_VERSIONS,
                requireAbsent(FORBIDDEN_VERSIONS, versions))));
        this.dsaPublicKey = dsaPublicKey;
    }

    /**
     * Get the instance tag.
     *
     * @return Returns the instance tag.
     */
    @Nonnull
    public InstanceTag getInstanceTag() {
        return this.instanceTag;
    }

    /**
     * Get the long-term Ed448 public key.
     *
     * @return Returns the public key.
     */
    @Nonnull
    public Point getLongTermPublicKey() {
        return this.longTermPublicKey;
    }

    /**
     * Get the Forging public key.
     *
     * @return Returns the public key.
     */
    @Nonnull
    public Point getForgingKey() {
        return this.forgingKey;
    }

    /**
     * Get the supported OTR protocol versions.
     *
     * @return Returns the versions.
     */
    @Nonnull
    public Set<Integer> getVersions() {
        return this.versions;
    }

    /**
     * The long-term DSA public key. (Used in OTRv3.)
     *
     * @return Returns the public key.
     */
    @Nullable
    public DSAPublicKey getDsaPublicKey() {
        return this.dsaPublicKey;
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        final ClientProfile that = (ClientProfile) o;
        return Objects.equals(instanceTag, that.instanceTag)
                && Objects.equals(longTermPublicKey, that.longTermPublicKey)
                && Objects.equals(forgingKey, that.forgingKey)
                && Objects.equals(versions, that.versions)
                && Objects.equals(dsaPublicKey, that.dsaPublicKey);
    }

    @Override
    public int hashCode() {
        return Objects.hash(instanceTag, longTermPublicKey, forgingKey, versions, dsaPublicKey);
    }
}
