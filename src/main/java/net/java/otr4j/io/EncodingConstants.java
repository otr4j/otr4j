/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.io;

/**
 * Serialization constants.
 *
 * @author George Politis
 */
final class EncodingConstants {

    static final int TYPE_LEN_BYTE = 1;
    static final int TYPE_LEN_SHORT = 2;
    static final int TYPE_LEN_INT = 4;
    static final int TYPE_LEN_LONG = 8;
    static final int TYPE_LEN_MAC = 20;
    static final int TYPE_LEN_CTR = 8;

    static final int DATA_LEN = TYPE_LEN_INT;
    static final int TLV_LEN = TYPE_LEN_SHORT;

    /**
     * Public Key type DSA type value for serialization.
     */
    static final int PUBLIC_KEY_TYPE_DSA = 0;

    static final int DSA_SIGNATURE_LENGTH_BYTES = 40;

    static final int EDDSA_SIGNATURE_LENGTH_BYTES = 114;

    static final int MAC_OTR4_LENGTH_BYTES = 64;

    static final int FINGERPRINT_LENGTH_BYTES = 56;

    static final int SSID_LENGTH_BYTES = 8;

    // XSalsa20 IV (nonce)
    static final int NONCE_LENGTH_BYTES = 24;

    static final int POINT_LENGTH_BYTES = 57;

    private EncodingConstants() {
        // No need to instantiate class.
    }
}
