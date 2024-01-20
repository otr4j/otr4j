/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.crypto;

import com.google.errorprone.annotations.CheckReturnValue;
import net.java.otr4j.crypto.ed448.EdDSAKeyPair;
import net.java.otr4j.crypto.ed448.Point;
import net.java.otr4j.crypto.ed448.Scalar;
import net.java.otr4j.crypto.ed448.ValidationException;
import net.java.otr4j.io.OtrEncodable;
import net.java.otr4j.io.OtrInputStream;
import net.java.otr4j.io.OtrOutputStream;
import net.java.otr4j.util.ByteArrays;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.engines.ChaCha7539Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import javax.annotation.Nonnull;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.ProtocolException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;

import static java.util.Objects.requireNonNull;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.AUTH;
import static net.java.otr4j.crypto.OtrCryptoEngine4.KDFUsage.FINGERPRINT;
import static net.java.otr4j.crypto.ed448.Ed448.basePoint;
import static net.java.otr4j.crypto.ed448.Ed448.containsPoint;
import static net.java.otr4j.crypto.ed448.Ed448.multiplyByBase;
import static net.java.otr4j.crypto.ed448.Ed448.order;
import static net.java.otr4j.crypto.ed448.Scalar.SCALAR_LENGTH_BYTES;
import static net.java.otr4j.crypto.ed448.Scalar.decodeScalar;
import static net.java.otr4j.crypto.ed448.Scalars.clamp;
import static net.java.otr4j.util.ByteArrays.allZeroBytes;
import static net.java.otr4j.util.ByteArrays.clear;
import static net.java.otr4j.util.ByteArrays.requireLengthAtLeast;
import static net.java.otr4j.util.ByteArrays.requireLengthExactly;
import static net.java.otr4j.util.Integers.requireAtLeast;
import static net.java.otr4j.util.Integers.requireEquals;
import static net.java.otr4j.util.SecureRandoms.randomBytes;

/**
 * Crypto engine for OTRv4.
 */
public final class OtrCryptoEngine4 {

    /**
     * Bit-size for SHAKE-256.
     */
    private static final int SHAKE_256_LENGTH_BITS = 256;

    /**
     * Length of a fingerprint in bytes.
     */
    private static final int FINGERPRINT_LENGTH_BYTES = 56;

    /**
     * Length of a Root key in bytes.
     */
    public static final int ROOT_KEY_LENGTH_BYTES = 64;

    /**
     * Length of HashToScalar array of bytes.
     */
    private static final int HASH_TO_SCALAR_LENGTH_BYTES = 57;

    /**
     * Prefix used in key derivation functions.
     */
    private static final byte[] OTR4_PREFIX = {'O', 'T', 'R', 'v', '4'};

    /**
     * Length of the ChaCha20 encryption/decryption key in bytes.
     */
    private static final int CHACHA20_KEY_LENGTH_BYTES = 32;

    /**
     * Length of the ChaCha20 IV in bytes.
     */
    private static final int CHACHA20_IV_LENGTH_BYTES = 12;

    /**
     * Fixed IV of all zero-bytes.
     */
    private static final byte[] IV = new byte[CHACHA20_IV_LENGTH_BYTES];

    /**
     * Length of MessageKeys encryption key in bytes.
     */
    static final int MK_ENC_LENGTH_BYTES = 64;

    /**
     * Length of the MessageKeys MAC code in bytes.
     */
    public static final int MK_MAC_LENGTH_BYTES = 64;

    /**
     * Length of the Authenticator code in bytes.
     */
    public static final int AUTHENTICATOR_LENGTH_BYTES = 64;

    /**
     * Length of Extra Symmetric Key in bytes.
     */
    public static final int EXTRA_SYMMETRIC_KEY_LENGTH_BYTES = 64;

    /**
     * Length of the context prefix in the Extra Symmetric Key TLV payload in bytes.
     */
    public static final int EXTRA_SYMMETRIC_KEY_CONTEXT_LENGTH_BYTES = 4;

    /**
     * KDF Usage IDs.
     */
    public enum KDFUsage {
        /**
         * Usage ID for Fingerprint.
         */
        FINGERPRINT((byte) 0x00),
        /**
         * Usage ID for Brace Key generation on every third iteration.
         */
        THIRD_BRACE_KEY((byte) 0x01),
        /**
         * Usage ID for Brace Key generation on other iterations.
         */
        BRACE_KEY((byte) 0x02),
        /**
         * Usage ID for shared secret.
         */
        SHARED_SECRET((byte) 0x03),
        /**
         * Usage ID for SSID.
         */
        SSID((byte) 0x04),
        /**
         * Usage ID for Bob's client profile used in Auth-R message.
         */
        AUTH_R_BOB_CLIENT_PROFILE((byte) 0x05),
        /**
         * Usage ID for Alice's client profile used in Auth-R message.
         */
        AUTH_R_ALICE_CLIENT_PROFILE((byte) 0x06),
        /**
         * Usage ID for Phi in Auth-R message.
         */
        AUTH_R_PHI((byte) 0x07),
        /**
         * Usage ID for Bob's client profile used in Auth-I message.
         */
        AUTH_I_BOB_CLIENT_PROFILE((byte) 0x08),
        /**
         * Usage ID for Alice's client profile used in Auth-I message.
         */
        AUTH_I_ALICE_CLIENT_PROFILE((byte) 0x09),
        /**
         * Usage ID for Phi in Auth-I message.
         */
        AUTH_I_PHI((byte) 0x0A),
        /**
         * Usage First Root Key.
         */
        FIRST_ROOT_KEY((byte) 0x0B),
        /**
         * Usage ID for generating a root key.
         */
        ROOT_KEY((byte) 0x12),
        /**
         * Usage ID for generating a chain key.
         */
        CHAIN_KEY((byte) 0x13),
        /**
         * Usage ID for generating the next chain key.
         */
        NEXT_CHAIN_KEY((byte) 0x14),
        /**
         * Usage ID for generating a message key.
         */
        MESSAGE_KEY((byte) 0x15),
        /**
         * Usage ID for generating a MAC key.
         */
        MAC_KEY((byte) 0x16),
        /**
         * Usage ID for generating the Extra Symmetric Key.
         */
        EXTRA_SYMMETRIC_KEY((byte) 0x17),
        /**
         * Usage ID for generating the Authenticator MAC value.
         */
        AUTHENTICATOR((byte) 0x18),
        /**
         * Usage ID for generating the secret used in the SMP negotiation.
         */
        SMP_SECRET((byte) 0x19),
        /**
         * Usage ID for generating the authentication code for the ring signatures.
         */
        AUTH((byte) 0x1A),
        /**
         * Usage ID for SMP value 0x01.
         */
        SMP_VALUE_0X01((byte) 0x01),
        /**
         * Usage ID for SMP value 0x02.
         */
        SMP_VALUE_0X02((byte) 0x02),
        /**
         * Usage ID for SMP value 0x03.
         */
        SMP_VALUE_0X03((byte) 0x03),
        /**
         * Usage ID for SMP value 0x04.
         */
        SMP_VALUE_0X04((byte) 0x04),
        /**
         * Usage ID for SMP value 0x05.
         */
        SMP_VALUE_0X05((byte) 0x05),
        /**
         * Usage ID for SMP value 0x06.
         */
        SMP_VALUE_0X06((byte) 0x06),
        /**
         * Usage ID for SMP value 0x07.
         */
        SMP_VALUE_0X07((byte) 0x07),
        /**
         * Usage ID for SMP value 0x08.
         */
        SMP_VALUE_0X08((byte) 0x08);

        private final byte value;

        KDFUsage(final byte value) {
            this.value = value;
        }
    }

    private OtrCryptoEngine4() {
        // No need to instantiate utility class.
    }

    /**
     * Produce fingerprint for public key.
     *
     * @param publicKey  The public key to use as part of the fingerprint.
     * @param forgingKey The forging key to use as part of the fingerprint.
     * @return Returns the fingerprint derived from the provided public key.
     */
    public static byte[] fingerprint(final Point publicKey, final Point forgingKey) {
        return hwc(FINGERPRINT_LENGTH_BYTES, FINGERPRINT, publicKey.encode(), forgingKey.encode());
    }

    /**
     * KDF function.
     *
     * @param usageID    the usage ID
     * @param input      the input
     * @param outputSize the output size in bytes
     * @return Returns the resulting digest value.
     */
    @CheckReturnValue
    public static byte[] kdf(final int outputSize, final KDFUsage usageID, final byte[]... input) {
        requireAtLeast(0, outputSize);
        final byte[] dst = new byte[outputSize];
        kdf(dst, 0, dst.length, usageID, input);
        return dst;
    }

    /**
     * KDF function with result written to dst parameter.
     *
     * @param dst        the destination location for the resulting digest value
     * @param offset     the offset in the destination
     * @param usageID    the usage ID
     * @param input      the input
     * @param outputSize the output size in bytes
     */
    public static void kdf(final byte[] dst, final int offset, final int outputSize, final KDFUsage usageID,
            final byte[]... input) {
        assert Arrays.stream(input).noneMatch(ByteArrays::allZeroBytes)
                : "Sanity-checking for all-zero byte-arrays as these are often an indication of a bug.";
        shake256(dst, offset, outputSize, usageID, input);
    }

    /**
     * HWC function.
     *
     * @param usageID    the usage ID
     * @param outputSize the output size in bytes
     * @param input      the input
     * @return Returns the resulting digest value.
     */
    @Nonnull
    public static byte[] hwc(final int outputSize, final KDFUsage usageID, final byte[]... input) {
        requireAtLeast(0, outputSize);
        final byte[] result = new byte[outputSize];
        shake256(result, 0, result.length, usageID, input);
        return result;
    }

    /**
     * HCMAC function.
     *
     * @param usageID    the usage ID
     * @param outputSize the output size in bytes
     * @param input      the input
     * @return Returns the resulting digest value.
     */
    @Nonnull
    public static byte[] hcmac(final KDFUsage usageID, final int outputSize, final byte[]... input) {
        requireAtLeast(0, outputSize);
        final byte[] result = new byte[outputSize];
        shake256(result, 0, outputSize, usageID, input);
        return result;
    }

    /**
     * KDF_1 key derivation function.
     * <p>
     * "KDF_1(usageID || values, output_size) = SHAKE-256("OTRv4" || usageID || values, size)"
     *
     * @param dst        The destination byte array, with 32 bytes available for KDF_1 result.
     * @param offset     The offset position to start writing to the destination byte array.
     * @param usageID    The usage ID to be mixed in with the input to KDF1.
     * @param input      The input data to KDF_1.
     * @param outputSize The size of the derivative output.
     */
    private static void shake256(final byte[] dst, final int offset, final int outputSize, final KDFUsage usageID,
            final byte[]... input) {
        requireNonNull(dst);
        requireAtLeast(0, outputSize);
        final SHAKEDigest digest = new SHAKEDigest(SHAKE_256_LENGTH_BITS);
        digest.update(OTR4_PREFIX, 0, OTR4_PREFIX.length);
        digest.update(usageID.value);
        for (final byte[] entry : input) {
            assert !allZeroBytes(entry) : "Expected non-zero bytes for input. This may indicate that a critical bug is present, or it may be a false warning.";
            digest.update(entry, 0, entry.length);
        }
        digest.doFinal(dst, offset, outputSize);
    }

    /**
     * Generate a new random value in Z_q.
     *
     * @param random SecureRandom instance
     * @return Returns a newly generated random value.
     */
    public static Scalar generateRandomValueInZq(final SecureRandom random) {
        final byte[] value = randomBytes(random, new byte[SCALAR_LENGTH_BYTES]);
        final byte[] h = new byte[SCALAR_LENGTH_BYTES];
        final SHAKEDigest digest = new SHAKEDigest(SHAKE_256_LENGTH_BITS);
        digest.update(value, 0, value.length);
        digest.doFinal(h, 0, h.length);
        clamp(h);
        return decodeScalar(h);
    }

    /**
     * HashToScalar.
     * <p>
     * As defined in section "HashToScalar" in OTRv4 specification.
     *
     * @param usageID The usage ID to be mixed in with the input to KDF1.
     * @param d       array of bytes
     * @return Returns derived scalar value.
     */
    @Nonnull
    public static Scalar hashToScalar(final KDFUsage usageID, final byte[]... d) {
        // "Compute h = KDF_1(d, 64) as an unsigned value, little-endian."
        final byte[] h = hwc(HASH_TO_SCALAR_LENGTH_BYTES, usageID, d);
        try {
            // FIXME spec says: interpret as little-endian scalar value, but nowhere it says that `mod q` is necessary?
            // "Return h (mod q)"
            return decodeScalar(h);
        } finally {
            clear(h);
        }
    }

    /**
     * Verify Point instance as EdDSA public key.
     *
     * @param point EdDSA public key, represented as Point.
     * @throws OtrCryptoException Thrown in case point is illegal, i.e. does not lie on the Ed448-Goldilocks curve.
     */
    public static void verifyEdDSAPublicKey(final Point point) throws OtrCryptoException {
        if (!containsPoint(point)) {
            throw new OtrCryptoException("Illegal public key.");
        }
    }

    /**
     * Decode an EdDSA public key from RFC 8032 byte-encoding.
     *
     * @param pointBytes The bytes representing point.
     * @return Returns Point instance.
     * @throws OtrCryptoException Throws in case of bytes contain invalid data.
     */
    @Nonnull
    public static Point decodePoint(final byte[] pointBytes) throws OtrCryptoException {
        try {
            return Point.decodePoint(pointBytes);
        } catch (final ValidationException ex) {
            throw new OtrCryptoException("Invalid Ed448 point data.", ex);
        }
    }

    /**
     * Derive additional extra symmetric keys from the extra symmetric key, that is used as basis.
     *
     * @param index   the index, i.e. the counter for which key is derived.
     * @param context the context value from the TLV payload. (first 4 bytes of the TLV payload)
     * @param baseKey the extra symmetric key, acquired through the Double Ratchet algorithm.
     * @return Returns the derived extra symmetric key.
     */
    @Nonnull
    public static byte[] deriveExtraSymmetricKey(final int index, final byte[] context, final byte[] baseKey) {
        final byte[] idx = {(byte) (index & 0xff), (byte) ((index >>> 8) & 0xff)};
        requireLengthExactly(EXTRA_SYMMETRIC_KEY_CONTEXT_LENGTH_BYTES, context);
        requireLengthExactly(EXTRA_SYMMETRIC_KEY_LENGTH_BYTES, baseKey);
        final byte[] instanceKey = new byte[EXTRA_SYMMETRIC_KEY_LENGTH_BYTES];
        final SHAKEDigest digest = new SHAKEDigest(SHAKE_256_LENGTH_BITS);
        digest.update(OTR4_PREFIX, 0, OTR4_PREFIX.length);
        digest.update(idx, 0, idx.length);
        digest.update(context, 0, context.length);
        digest.update(baseKey, 0, baseKey.length);
        digest.doFinal(instanceKey, 0, EXTRA_SYMMETRIC_KEY_LENGTH_BYTES);
        return instanceKey;
    }

    /**
     * Encrypt a message using ChaCha20 defined by RFC7539, given the specified key. The nonce is fixed to all
     * zero-bytes, as we expect to use a new key for every encryption operation.
     *
     * @param mkEnc   the secret key used for encryption (at least 32 bytes)
     * @param message the plaintext message to be encrypted (non-null)
     * @return Returns the encrypted content.
     */
    @Nonnull
    public static byte[] encrypt(final byte[] mkEnc, final byte[] message) {
        requireLengthAtLeast(CHACHA20_KEY_LENGTH_BYTES, mkEnc);
        requireNonNull(message);
        final byte[] key = Arrays.copyOf(mkEnc, CHACHA20_KEY_LENGTH_BYTES);
        assert !allZeroBytes(key) : "Expected non-zero byte array for a key. Something critical might be going wrong.";
        try {
            final ChaCha7539Engine engine = new ChaCha7539Engine();
            engine.init(true, new ParametersWithIV(new KeyParameter(key, 0, key.length), IV));
            final byte[] out = new byte[message.length];
            if (engine.processBytes(message, 0, message.length, out, 0) != message.length) {
                throw new IllegalStateException("Expected to process exactly full size of the message.");
            }
            return out;
        } finally {
            clear(key);
        }
    }

    /**
     * Decrypt a ciphertext using ChaCha20 defined by RFC7539, given the specified key.
     *
     * @param mkEnc      the secret key used for decryption (at least 32 bytes)
     * @param ciphertext te ciphertext to be decrypted (non-null)
     * @return Returns the decrypted (plaintext) content.
     */
    @Nonnull
    public static byte[] decrypt(final byte[] mkEnc, final byte[] ciphertext) {
        requireLengthAtLeast(CHACHA20_KEY_LENGTH_BYTES, mkEnc);
        requireNonNull(ciphertext);
        final byte[] key = Arrays.copyOf(mkEnc, CHACHA20_KEY_LENGTH_BYTES);
        assert !allZeroBytes(key) : "Expected non-zero byte array for a key. Something critical might be going wrong.";
        try {
            final ChaCha7539Engine engine = new ChaCha7539Engine();
            engine.init(false, new ParametersWithIV(new KeyParameter(key, 0, key.length), IV));
            final byte[] out = new byte[ciphertext.length];
            if (engine.processBytes(ciphertext, 0, ciphertext.length, out, 0) != ciphertext.length) {
                throw new IllegalStateException("Expected to process exactly full size of the message.");
            }
            return out;
        } finally {
            clear(key);
        }
    }

    /**
     * Ring signature generation. (RSig)
     *
     * @param random          A secure random instance.
     * @param longTermKeyPair The long-term Ed448 key pair.
     * @param A1              Public key to be included in the signature.
     * @param A2              Public key to be included in the signature.
     * @param A3              Public key to be included in the signature.
     * @param m               The message for which the signature should be generated.
     * @return Returns the sigma values that represent the ring signature.
     */
    @SuppressWarnings({"PMD.FormalParameterNamingConventions", "PMD.LocalVariableNamingConventions", "PMD.AvoidLiteralsInIfCondition"})
    @Nonnull
    public static Sigma ringSign(final SecureRandom random, final EdDSAKeyPair longTermKeyPair, final Point A1,
            final Point A2, final Point A3, final byte[] m) {
        if (!containsPoint(longTermKeyPair.getPublicKey()) || !containsPoint(A1) || !containsPoint(A2) || !containsPoint(A3)) {
            throw new IllegalArgumentException("Illegal point provided. Points need to be on curve Ed448.");
        }
        if (A1.equals(A2) || A2.equals(A3) || A1.equals(A3)) {
            throw new IllegalArgumentException("Some of the points are equal. It defeats the purpose of the ring signature.");
        }
        final Point longTermPublicKey = longTermKeyPair.getPublicKey();
        // Calculate equality to each of the provided public keys.
        final int eq1 = Point.constantTimeEquals(longTermPublicKey, A1) ? 1 : 0;
        final int eq2 = Point.constantTimeEquals(longTermPublicKey, A2) ? 1 : 0;
        final int eq3 = Point.constantTimeEquals(longTermPublicKey, A3) ? 1 : 0;
        requireEquals(1, eq1 + eq2 + eq3, "BUG: expected long-term keypair to match exactly one of 3 public keys.");
        // "Pick random values t, c2, c3, r2, r3 in q."
        final Scalar t = generateRandomValueInZq(random);
        Scalar ci = generateRandomValueInZq(random);
        Scalar ri = generateRandomValueInZq(random);
        Scalar cj = generateRandomValueInZq(random);
        Scalar rj = generateRandomValueInZq(random);
        Scalar ck = generateRandomValueInZq(random);
        Scalar rk = generateRandomValueInZq(random);
        // Either `t*G` or `ri*G + ci*A1`, with `eq1==1` for first case, `eq1==0` for second case.
        final Point T1 = multiplyByBase(t.multiply(eq1)).add(
                multiplyByBase(ri.multiply(1 - eq1)).add(A1.multiply(ci.multiply(1 - eq1))));
        final Point T2 = multiplyByBase(t.multiply(eq2)).add(
                multiplyByBase(rj.multiply(1 - eq2)).add(A2.multiply(cj.multiply(1 - eq2))));
        final Point T3 = multiplyByBase(t.multiply(eq3)).add(
                multiplyByBase(rk.multiply(1 - eq3)).add(A3.multiply(ck.multiply(1 - eq3))));
        // "Compute c = HashToScalar(0x1D || G || q || A1 || A2 || A3 || T1 || T2 || T3 || m)."
        final Scalar q = order();
        final Scalar c;
        try (ByteArrayOutputStream buffer = new ByteArrayOutputStream()) {
            final OtrOutputStream encoder = new OtrOutputStream(buffer);
            encoder.writePoint(basePoint())
                    .writeScalar(q)
                    .writePoint(A1)
                    .writePoint(A2)
                    .writePoint(A3)
                    .writePoint(T1)
                    .writePoint(T2)
                    .writePoint(T3)
                    .writeData(m);
            c = hashToScalar(AUTH, buffer.toByteArray());
        } catch (final IOException e) {
            throw new IllegalStateException("Failed to write point to buffer.", e);
        }
        // Either "Compute c1 = c - c2 - c3 (mod q)." or use existing value for ci.
        ci = c.subtract(cj).subtract(ck).mod(q).multiply(eq1).add(ci.multiply(1 - eq1));
        cj = c.subtract(ci).subtract(ck).mod(q).multiply(eq2).add(cj.multiply(1 - eq2));
        ck = c.subtract(ci).subtract(cj).mod(q).multiply(eq3).add(ck.multiply(1 - eq3));
        // Either "Compute r1 = t1 - c1 * a1 (mod q)." or use existing value for ri.
        final Scalar ai = longTermKeyPair.getSecretKey();
        ri = t.subtract(ci.multiply(ai)).mod(q).multiply(eq1).add(ri.multiply(1 - eq1));
        rj = t.subtract(cj.multiply(ai)).mod(q).multiply(eq2).add(rj.multiply(1 - eq2));
        rk = t.subtract(ck.multiply(ai)).mod(q).multiply(eq3).add(rk.multiply(1 - eq3));
        Scalar.clear(ai);
        return new Sigma(ci, ri, cj, rj, ck, rk);
    }

    /**
     * Ring signature verification. (RVrf)
     *
     * @param A1    Public key 1.
     * @param A2    Public key 2.
     * @param A3    Public key 3.
     * @param sigma The sigma containing the ring signature components.
     * @param m     The message for which the signature was generated.
     * @throws OtrCryptoException In case verification fails on sigma, or in case A1, A2 or A3 contains an illegal
     *                            value.
     */
    @SuppressWarnings({"PMD.FormalParameterNamingConventions", "PMD.LocalVariableNamingConventions"})
    public static void ringVerify(final Point A1, final Point A2, final Point A3, final Sigma sigma, final byte[] m)
            throws OtrCryptoException {
        if (!containsPoint(A1) || !containsPoint(A2) || !containsPoint(A3)) {
            throw new OtrCryptoException("One of the public keys is invalid.");
        }
        final Scalar q = order();
        // "Parse sigma to retrieve components (c1, r1, c2, r2, c3, r3)."
        // Parsing happened outside of this method already. We expect a "sigma" instance to be provided.
        // "Compute T1 = G * r1 + A1 * c1"
        final Point T1 = multiplyByBase(sigma.r1).add(A1.multiply(sigma.c1));
        // "Compute T2 = G * r2 + A2 * c2"
        final Point T2 = multiplyByBase(sigma.r2).add(A2.multiply(sigma.c2));
        // "Compute T3 = G * r3 + A3 * c3"
        final Point T3 = multiplyByBase(sigma.r3).add(A3.multiply(sigma.c3));
        // "Compute c = HashToScalar(0x1D || G || q || A1 || A2 || A3 || T1 || T2 || T3 || m)."
        final Scalar c;
        try (ByteArrayOutputStream buffer = new ByteArrayOutputStream()) {
            final OtrOutputStream encoder = new OtrOutputStream(buffer);
            encoder.writePoint(basePoint())
                    .writeScalar(q)
                    .writePoint(A1)
                    .writePoint(A2)
                    .writePoint(A3)
                    .writePoint(T1)
                    .writePoint(T2)
                    .writePoint(T3)
                    .writeData(m);
            c = hashToScalar(AUTH, buffer.toByteArray());
        } catch (final IOException e) {
            throw new IllegalStateException("Failed to write point to buffer.", e);
        }
        // "Check if c ≟ c1 + c2 + c3 (mod q). If it is true, verification succeeds. If not, it fails."
        if (!Scalar.constantTimeEquals(c, sigma.c1.add(sigma.c2).add(sigma.c3).mod(q))) {
            throw new OtrCryptoException("Ring signature failed verification.");
        }
    }

    /**
     * Data structure that captures all related data for 'sigma' in the Ring Signature.
     */
    public static final class Sigma implements OtrEncodable {
        private final Scalar c1;
        private final Scalar r1;
        private final Scalar c2;
        private final Scalar r2;
        private final Scalar c3;
        private final Scalar r3;

        private Sigma(final Scalar c1, final Scalar r1, final Scalar c2, final Scalar r2, final Scalar c3,
                final Scalar r3) {
            this.c1 = requireNonNull(c1);
            this.r1 = requireNonNull(r1);
            this.c2 = requireNonNull(c2);
            this.r2 = requireNonNull(r2);
            this.c3 = requireNonNull(c3);
            this.r3 = requireNonNull(r3);
        }

        /**
         * Read from OTR input stream and parse raw OTR data to extract sigma.
         *
         * @param in the OTR input stream
         * @return Returns sigma as parsed from the data.
         * @throws ProtocolException In case of failure to read sigma from input.
         */
        public static Sigma readFrom(final OtrInputStream in) throws ProtocolException {
            final Scalar c1 = in.readScalar();
            final Scalar r1 = in.readScalar();
            final Scalar c2 = in.readScalar();
            final Scalar r2 = in.readScalar();
            final Scalar c3 = in.readScalar();
            final Scalar r3 = in.readScalar();
            return new Sigma(c1, r1, c2, r2, c3, r3);
        }

        /**
         * Write sigma to provided OtrOutputStream.
         *
         * @param out The output stream.
         */
        @Override
        public void writeTo(final OtrOutputStream out) {
            out.writeScalar(this.c1);
            out.writeScalar(this.r1);
            out.writeScalar(this.c2);
            out.writeScalar(this.r2);
            out.writeScalar(this.c3);
            out.writeScalar(this.r3);
        }

        @SuppressWarnings("ShortCircuitBoolean")
        @Override
        public boolean equals(final Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            final Sigma sigma = (Sigma) o;
            return Scalar.constantTimeEquals(this.c1, sigma.c1) & Scalar.constantTimeEquals(this.r1, sigma.r1)
                    & Scalar.constantTimeEquals(this.c2, sigma.c2) & Scalar.constantTimeEquals(this.r2, sigma.r2)
                    & Scalar.constantTimeEquals(this.c3, sigma.c3) & Scalar.constantTimeEquals(this.r3, sigma.r3);
        }

        @Override
        public int hashCode() {
            return Objects.hash(this.c1, this.r1, this.c2, this.r2, this.c3, this.r3);
        }
    }
}
