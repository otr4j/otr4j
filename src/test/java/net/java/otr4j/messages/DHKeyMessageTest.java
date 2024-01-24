/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.messages;

import net.java.otr4j.api.Version;
import org.junit.Test;

import javax.crypto.interfaces.DHPublicKey;
import java.security.SecureRandom;

import static net.java.otr4j.api.InstanceTag.SMALLEST_TAG;
import static net.java.otr4j.crypto.DHKeyPairOTR3.generateDHKeyPair;

public final class DHKeyMessageTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final DHPublicKey publicKey = generateDHKeyPair(RANDOM).getPublic();

    @Test
    public void testDHKeyMessageProtocolVersionValid() {
        new DHKeyMessage(Version.THREE, publicKey, SMALLEST_TAG, SMALLEST_TAG);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testDHKeyMessageProtocolVersionIllegalValue() {
        new DHKeyMessage(Version.FOUR, publicKey, SMALLEST_TAG, SMALLEST_TAG);
    }
}
