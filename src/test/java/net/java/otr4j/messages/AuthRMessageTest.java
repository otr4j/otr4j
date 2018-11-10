/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.messages;

import net.java.otr4j.api.ClientProfile;
import net.java.otr4j.api.Session;
import net.java.otr4j.api.Session.Version;
import net.java.otr4j.crypto.DHKeyPair;
import net.java.otr4j.crypto.DSAKeyPair;
import net.java.otr4j.crypto.OtrCryptoEngine4.Sigma;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.crypto.ed448.ECDHKeyPair;
import net.java.otr4j.crypto.ed448.EdDSAKeyPair;
import net.java.otr4j.crypto.ed448.Point;
import net.java.otr4j.io.OtrInputStream;
import net.java.otr4j.io.OtrOutputStream;
import org.junit.Test;

import javax.annotation.Nonnull;
import java.math.BigInteger;
import java.net.ProtocolException;
import java.security.SecureRandom;
import java.util.Collections;

import static net.java.otr4j.api.InstanceTag.HIGHEST_TAG;
import static net.java.otr4j.api.InstanceTag.SMALLEST_TAG;
import static net.java.otr4j.crypto.OtrCryptoEngine4.ringSign;
import static net.java.otr4j.util.SecureRandoms.randomBytes;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

@SuppressWarnings("ConstantConditions")
public final class AuthRMessageTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    private static final DSAKeyPair DSA_KEYPAIR = DSAKeyPair.generateDSAKeyPair();

    private static final Point FORGING_KEY = ECDHKeyPair.generate(RANDOM).getPublicKey();

    private static final EdDSAKeyPair ED_DSA_KEYPAIR = EdDSAKeyPair.generate(RANDOM);

    private static final Point X = ECDHKeyPair.generate(RANDOM).getPublicKey();

    private static final BigInteger A = DHKeyPair.generate(RANDOM).getPublicKey();

    private static final ClientProfilePayload PAYLOAD = ClientProfilePayload.sign(
            new ClientProfile(SMALLEST_TAG, ED_DSA_KEYPAIR.getPublicKey(), FORGING_KEY,
                    Collections.singleton(Session.Version.FOUR), DSA_KEYPAIR.getPublic()),
            Long.MAX_VALUE / 1000, DSA_KEYPAIR, ED_DSA_KEYPAIR);

    @Test
    public void testConstruction() {
        final byte[] m = randomBytes(RANDOM, new byte[150]);
        final Sigma sigma = generateSigma(ED_DSA_KEYPAIR, m);
        final AuthRMessage message = new AuthRMessage(Session.Version.FOUR, SMALLEST_TAG, HIGHEST_TAG, PAYLOAD, X, A, sigma);
        assertEquals(Session.Version.FOUR, message.protocolVersion);
        assertEquals(SMALLEST_TAG, message.senderInstanceTag);
        assertEquals(HIGHEST_TAG, message.receiverInstanceTag);
        assertEquals(PAYLOAD, message.getClientProfile());
        assertEquals(X, message.getX());
        assertEquals(A, message.getA());
        assertEquals(sigma, message.getSigma());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructionIllegalProtocolVersionOne() {
        final byte[] m = randomBytes(RANDOM, new byte[150]);
        final Sigma sigma = generateSigma(ED_DSA_KEYPAIR, m);
        new AuthRMessage(Session.Version.ONE, SMALLEST_TAG, HIGHEST_TAG, PAYLOAD, X, A, sigma);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructionIllegalProtocolVersionTwo() {
        final byte[] m = randomBytes(RANDOM, new byte[150]);
        final Sigma sigma = generateSigma(ED_DSA_KEYPAIR, m);
        new AuthRMessage(Session.Version.TWO, SMALLEST_TAG, HIGHEST_TAG, PAYLOAD, X, A, sigma);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructionIllegalProtocolVersionThree() {
        final byte[] m = randomBytes(RANDOM, new byte[150]);
        final Sigma sigma = generateSigma(ED_DSA_KEYPAIR, m);
        new AuthRMessage(Session.Version.THREE, SMALLEST_TAG, HIGHEST_TAG, PAYLOAD, X, A, sigma);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructionNullSenderTag() {
        final byte[] m = randomBytes(RANDOM, new byte[150]);
        final Sigma sigma = generateSigma(ED_DSA_KEYPAIR, m);
        new AuthRMessage(Session.Version.FOUR, null, HIGHEST_TAG, PAYLOAD, X, A, sigma);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructionNullReceiverTag() {
        final byte[] m = randomBytes(RANDOM, new byte[150]);
        final Sigma sigma = generateSigma(ED_DSA_KEYPAIR, m);
        new AuthRMessage(Version.FOUR, SMALLEST_TAG, null, PAYLOAD, X, A, sigma);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructionNullClientProfilePayload() {
        final byte[] m = randomBytes(RANDOM, new byte[150]);
        final Sigma sigma = generateSigma(ED_DSA_KEYPAIR, m);
        new AuthRMessage(Session.Version.FOUR, SMALLEST_TAG, HIGHEST_TAG, null, X, A, sigma);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructionNullX() {
        final byte[] m = randomBytes(RANDOM, new byte[150]);
        final Sigma sigma = generateSigma(ED_DSA_KEYPAIR, m);
        new AuthRMessage(Session.Version.FOUR, SMALLEST_TAG, HIGHEST_TAG, PAYLOAD, null, A, sigma);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructionNullA() {
        final byte[] m = randomBytes(RANDOM, new byte[150]);
        final Sigma sigma = generateSigma(ED_DSA_KEYPAIR, m);
        new AuthRMessage(Version.FOUR, SMALLEST_TAG, HIGHEST_TAG, PAYLOAD, X, null, sigma);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructionNullSigma() {
        new AuthRMessage(Session.Version.FOUR, SMALLEST_TAG, HIGHEST_TAG, PAYLOAD, X, A, null);
    }

    @Test
    public void testEncodeMessage() throws ProtocolException, OtrCryptoException, ValidationException {
//        final ClientProfilePayload payload = PAYLOAD;
        final ClientProfilePayload payload = ClientProfilePayload.readFrom(new OtrInputStream(new byte[] {0, 0, 0, 7, 0, 1, 0, 0, 1, 0, 0, 2, 0, 16, 99, -90, -11, 13, 49, -123, -91, 24, 117, -50, -47, 17, -38, 46, -1, 77, -125, -32, 85, -127, 117, 62, 69, -8, -105, -8, -110, 25, -45, 87, 108, 102, -123, -90, 95, 110, 124, 91, 76, -124, -57, 101, -75, -122, 40, -61, -73, -11, -16, 107, 31, -76, -111, -87, 29, 58, -128, 0, 3, 0, 18, 78, 68, 127, 98, 110, 116, 127, 29, -65, -46, 14, 43, -97, 4, 46, 6, -123, -119, -14, -107, 0, 70, 5, -25, 37, 114, 55, -99, 30, 59, -70, 10, -4, 85, -17, -53, 110, -68, 31, -1, 36, -23, -117, 104, 83, -73, -8, -84, -68, -65, 109, 127, 120, 15, -13, -78, 0, 0, 4, 0, 0, 0, 1, 52, 0, 5, 0, 32, -60, -101, -91, -29, 83, -9, 0, 6, 0, 0, 0, 0, 1, 0, -113, 121, 53, -39, -71, -86, -23, -65, -85, -19, -120, 122, -49, 73, 81, -74, -13, 46, -59, -98, 59, -81, 55, 24, -24, -22, -60, -106, 31, 62, -3, 54, 6, -25, 67, 81, -87, -60, 24, 51, 57, -72, 9, -25, -62, -82, 28, 83, -101, -89, 71, 91, -123, -48, 17, -83, -72, -76, 121, -121, 117, 73, -124, 105, 92, -84, 14, -113, 20, -77, 54, 8, 40, -94, 47, -6, 39, 17, 10, 61, 98, -87, -109, 69, 52, 9, -96, -2, 105, 108, 70, 88, -8, 75, -35, 32, -127, -100, 55, 9, -96, 16, 87, -79, -107, -83, -51, 0, 35, 61, -70, 84, -124, -74, 41, 31, -99, 100, -114, -8, -125, 68, -122, 119, -105, -100, -20, 4, -76, 52, -90, -84, 46, 117, -23, -104, 93, -30, 61, -80, 41, 47, -63, 17, -116, -97, -6, -99, -127, -127, -25, 51, -115, -73, -110, -73, 48, -41, -71, -29, 73, 89, 47, 104, 9, -104, 114, 21, 57, 21, -22, 61, 107, -117, 70, 83, -58, 51, 69, -113, -128, 59, 50, -92, -62, -32, -14, 114, -112, 37, 110, 78, 63, -118, 59, 8, 56, -95, -60, 80, -28, -31, -116, 26, 41, -93, 125, -33, 94, -95, 67, -34, 75, 102, -1, 4, -112, 62, -43, -49, 22, 35, -31, 88, -44, -121, -58, 8, -23, 127, 33, 28, -40, 29, -54, 35, -53, 110, 56, 7, 101, -8, 34, -29, 66, -66, 72, 76, 5, 118, 57, 57, 96, 28, -42, 103, 0, 0, 0, 28, -70, -10, -106, -90, -123, 120, -9, -33, -34, -25, -6, 103, -55, 119, -57, -123, -17, 50, -78, 51, -70, -27, -128, -64, -68, -43, 105, 93, 0, 0, 1, 0, 22, -90, 92, 88, 32, 72, 80, 112, 78, 117, 2, -93, -105, 87, 4, 13, 52, -38, 58, 52, 120, -63, 84, -44, -28, -91, -64, 45, 36, 46, -32, 79, -106, -26, 30, 75, -48, -112, 74, -67, -84, -113, 55, -18, -79, -32, -97, 49, -126, -46, 60, -112, 67, -53, 100, 47, -120, 0, 65, 96, -19, -7, -54, 9, -77, 32, 118, -89, -100, 50, -90, 39, -14, 71, 62, -111, -121, -101, -94, -60, -25, 68, -67, 32, -127, 84, 76, -75, 91, -128, 44, 54, -115, 31, -88, 62, -44, -119, -23, 78, 15, -96, 104, -114, 50, 66, -118, 92, 120, -60, 120, -58, -115, 5, 39, -73, 28, -102, 58, -69, 11, 11, -31, 44, 68, 104, -106, 57, -25, -45, -50, 116, -37, 16, 26, 101, -86, 43, -121, -10, 76, 104, 38, -37, 62, -57, 47, 75, 85, -103, -125, 75, -76, -19, -80, 47, 124, -112, -23, -92, -106, -45, -91, 93, 83, 91, -21, -4, 69, -44, -10, 25, -10, 63, 61, -19, -69, -121, 57, 37, -62, -14, 36, -32, 119, 49, 41, 109, -88, -121, -20, 30, 71, 72, -8, 126, -5, 95, -34, -73, 84, -124, 49, 107, 34, 50, -34, -27, 83, -35, -81, 2, 17, 43, 13, 31, 2, -38, 48, -105, 50, 36, -2, 39, -82, -38, -117, -99, 75, 41, 34, -39, -70, -117, -29, -98, -39, -31, 3, -90, 60, 82, -127, 11, -58, -120, -73, -30, -19, 67, 22, -31, -17, 23, -37, -34, 0, 0, 1, 0, 101, 109, 72, -110, -66, -30, -106, 54, 54, 118, -23, -36, 17, 82, 0, -52, 93, 33, -20, -53, 1, -27, -59, -34, 63, 44, -92, -11, -90, -69, -79, -62, 67, 67, 15, -122, -91, -35, 99, 125, -108, -81, -68, 117, 40, 3, -111, -57, -119, -122, 33, 4, -4, 110, -94, 107, 35, 44, -59, -22, -48, 117, 84, -86, 26, -122, -95, -52, -54, 89, -126, 71, 75, 16, -48, -7, 77, -119, 93, 7, 35, 87, -85, -66, 46, -126, 45, -81, -57, -59, -35, -81, 8, -99, 45, 20, 109, -96, 40, -70, -77, -107, 90, 123, -31, 64, -96, -67, 54, -53, -1, 122, 82, -65, 42, 29, 29, -75, 10, -47, 80, -25, 67, -46, -22, 50, -110, 122, -69, 75, -79, -48, 43, -87, 18, -12, 58, -49, 66, -117, -101, 60, -54, -61, 49, 21, 45, 51, -124, 62, -24, -115, 21, -79, 93, -107, 22, 77, 30, -72, 105, -125, -105, 72, 17, -55, 62, 84, -17, 10, -69, -97, -38, 117, 16, 50, -2, 93, 122, -18, 79, 116, 55, -7, -113, 26, -13, 104, -29, 111, 2, 107, 35, -41, 109, 20, 9, 84, 67, -79, 10, -18, 21, -7, -84, 125, -18, -86, -74, -8, 32, -20, -121, 87, 95, 32, -122, -28, -43, 39, 90, -58, 126, 14, 23, -127, -71, -76, 26, -19, -99, -118, 63, 94, 69, 26, 70, 58, -26, 36, 118, 72, 38, -60, -34, 121, -127, 43, 82, -58, 25, -82, -22, 100, 6, 30, 0, 7, 0, 0, 0, 28, 118, -49, 64, -30, 73, -13, -98, 59, -87, -100, 125, -88, 85, -71, -69, 11, 106, 92, 112, -94, 126, -44, -111, 24, 120, 59, -64, -119, 0, 0, 0, 28, -97, -119, -59, -127, 90, 94, 20, 120, -33, -88, -39, -43, 100, -49, 49, 90, -6, 110, -108, 11, -7, 19, 126, -99, 18, -116, -120, 28, 109, -58, 123, 64, -90, 63, 60, -63, 32, 51, 93, 17, -61, 51, -75, 125, -48, -87, -127, -53, 42, -119, -77, 114, 37, 9, 110, 53, -10, -70, -97, -109, 12, -109, -64, -49, 26, 74, 51, 57, 44, 92, -19, 83, -63, 13, 96, -114, -5, 42, 26, 29, 9, -26, 38, 85, -128, -37, -72, 59, -40, 118, -16, 40, 89, -109, -85, 61, 70, 66, 59, 108, -83, 13, 55, 48, 88, -75, -62, 100, 84, 121, 86, -99, 33, -20, -78, 96, -8, -16, -2, 57, 39, 111, -18, 45, -49, 4, -49, 9, 27, -108, -45, -70, -4, -47, -77, 61, -111, 76, 126, 82, 58, 0}));
//        System.err.println("Payload: " + Arrays.toString(new OtrOutputStream().write(payload).toByteArray()));
//        final Point x = X;
        final Point x = new OtrInputStream(new byte[] {74, -33, -34, 20, -76, 91, 42, -128, -31, 3, -76, 66, 10, -5, 105, 82, -64, -15, 98, 72, -27, -41, -47, 25, 87, 107, -87, 13, -97, 48, 99, -41, 8, 72, 113, -93, -77, -37, -73, 19, 125, 49, -69, -42, 41, 46, -111, -21, 14, -15, -121, -84, 123, 35, 9, 26, -128})
                .readPoint();
//        System.err.println("X: " + Arrays.toString(x.encode()));
//        final BigInteger a = A;
        final BigInteger a = new OtrInputStream(new byte[] {0, 0, 1, -128, -19, -112, -121, -90, -77, 112, -67, 83, -79, -101, 122, -4, -89, -69, -106, 92, 72, 106, 84, -11, -37, 13, 65, -40, -106, 52, 65, 55, -120, 120, -48, -119, -92, -17, 90, 7, 107, 83, -46, 105, -16, -20, -77, -69, 80, 89, 31, -65, -82, -125, -73, 63, 88, -67, 86, 81, 77, 85, 22, 84, 9, -31, 16, -4, -21, 117, 102, 53, 100, 86, 90, 5, -107, 64, 50, -127, 11, 14, -127, -22, -109, -13, -39, -88, -55, -32, 55, -88, -44, 120, -119, 59, -96, -69, -76, 25, 118, -116, 61, -118, 81, 25, 55, -17, 37, 118, 71, 105, 35, 22, 19, 43, -124, 121, -20, 108, 93, -10, 117, 113, 14, 66, -17, -117, 72, -121, 113, 118, -64, -27, -59, 26, 80, 83, -31, -37, 107, -58, -102, 28, -95, -79, -119, -33, 123, -9, -126, 48, -40, -45, 70, 67, 101, -102, 110, 77, 39, 112, 21, -42, 124, -2, 121, -34, -118, 119, 87, -42, 8, -54, -33, 11, 22, 78, -82, 106, -87, 48, -40, 37, 127, -124, -45, 40, 73, 64, -79, 25, -70, 74, -27, -34, -91, 32, 126, -14, 100, -99, -121, 6, -104, -11, 57, 19, 110, 77, -43, 76, 32, -28, -65, -5, -88, -75, 99, -79, 17, -63, 51, 19, -22, -89, 29, -1, 71, -35, -115, -107, -94, 112, -113, 72, 22, -102, 55, 69, -103, 72, -77, -21, -91, -61, -123, 22, 57, -78, 16, -68, -103, -35, -12, -7, 22, -25, -127, 6, 86, -119, -41, -82, 83, 86, 33, 50, 44, 77, -127, -63, -2, 84, 28, 124, 71, 25, 112, -85, -55, 126, 56, -59, -126, 65, 73, 7, -1, -78, 50, -49, -103, 29, -108, 9, -104, 15, -34, 11, -128, 15, 51, -68, 40, -36, -39, -66, 2, 106, 68, 29, 63, 127, -105, 20, -53, 12, -55, 65, -107, -74, -19, 67, -72, 83, -67, 109, 70, -105, -35, 91, -29, -47, -121, -4, -109, -13, -96, -37, 67, 117, -54, -125, -71, 27, -79, -17, -24, 54, 57, -14, 33, 113, 89, 29, 33, -98, 59, -62, 86, -27, -117, -15, -11, -128, 24, -89, -60, 107, -52, 15, 90, -65, 70, -50, 63, -23, -124, 9, -62, 95, 93, -40, 98, -45, -115, 71})
                .readBigInt();
//        System.err.println("A: " + Arrays.toString(new OtrOutputStream().writeBigInt(a).toByteArray()));
//        final byte[] m = new byte[] {-90, 84, 16, 36, 45, -96, 111, -13, -53, -2, 87, -36, 34, 99, -76, -121, 126, -51, -12, -97, 34, -95, -110, -100, -126, 3, -118, -104, 80, -107, 8, -15, 92, 67, -65, 36, 53, 73, -63, -25, 15, 83, 11, 54, -77, -25, 68, -105, -46, 63, 118, -40, -87, -106, -121, -124, -55, -88, 3, 78, 36, 12, 121, -3, -52, 123, -118, 117, 26, -73, -74, -76, -16, 114, 37, 81, 117, -87, 0, 107, -59, 93, -90, 89, -74, -68, -33, 12, -111, -56, 17, -90, -87, 29, -20, -15, 14, -63, -52, 77, -124, -83, 28, -85, 124, 97, -18, -77, -111, 43, -44, 48, -119, 7, -127, -111, 49, 13, -37, 10, 4, -5, -92, -51, -1, 75, -42, 87, 73, -112, 2, 72, 119, 81, -29, -10, -118, -62, 20, -30, 32, -81, 114, 11, -80, 82, 110, 13, -79, -43};
//        final Sigma sigma = generateSigma(ED_DSA_KEYPAIR, m);
        final Sigma sigma = Sigma.readFrom(new OtrInputStream(new byte[] {-102, -52, 41, -91, 17, 80, 67, 86, -117, 109, 40, 47, 124, 106, 45, 50, 83, -78, 79, 35, 84, 46, 57, 103, -101, -67, -93, 2, -36, 99, 68, 2, 64, 100, -65, -48, 11, 47, 126, -10, 61, -42, -41, -74, -87, 54, 103, -6, 4, -60, -66, 51, -53, -102, -93, 40, 0, 103, 46, 8, 4, 120, -68, 109, 14, 48, -87, 108, 78, 62, -122, 18, 6, 95, 71, -110, 92, -119, -122, 113, -73, 36, -61, -66, -29, 47, 108, 5, -21, -36, -46, -56, -118, 113, -25, -43, -102, -82, -8, -27, 70, -85, -94, 60, -71, 55, 31, -54, -18, -102, -45, 107, 9, 0, -17, 125, -87, 52, -94, 72, -127, -95, 93, 47, 36, 125, -79, -67, 39, 100, 54, -106, -54, -55, 101, -108, 86, 87, 105, -121, -113, -4, 18, -104, -123, -65, -74, -23, -18, 90, -49, -3, 38, 98, -82, -34, 38, -63, -37, -17, -109, 42, 51, -14, -28, -22, 96, -47, 72, 36, 0, 24, -44, 60, 42, 19, -89, -30, -89, 22, -34, 27, -60, -125, 19, 13, 59, 5, -59, 120, -55, -52, 8, 50, -38, 1, 87, 98, 13, 118, 75, 86, 104, 36, -28, -60, 117, 111, 105, -51, 78, -97, 125, -98, 13, 7, -97, 47, -75, -37, -95, -31, 52, -21, 80, 17, 37, 0, 115, 13, 2, 70, -106, -118, 86, -47, -127, 84, -12, 116, 60, -103, 72, -107, 28, 70, -5, -22, 62, -15, 0, 61, -85, 12, 55, -40, 71, 28, 106, 85, 127, 55, -54, -73, -119, 7, -38, 1, -73, -43, -22, -94, -19, 28, -10, -38, -14, 42, 110, 6, -49, -88, 74, 8, 0, -96, -89, -126, 44, 116, 101, 125, 26, 21, 64, -63, 19, -36, 74, 110, 63, 63, 76, 120, -88, -6, -110, 121, -76, 95, -111, -57, 68, -114, -1, -112, 37, 36, 14, -9, 16, 91, 101, -96, 46, 105, -110, -104, 3, -103, -127, -35, 100, 2, 25, -64, 74, 35, -54, 124, 17, 0}));
//        System.err.println("Sigma: " + Arrays.toString(new OtrOutputStream().write(sigma).toByteArray()));
        final AuthRMessage message = new AuthRMessage(Session.Version.FOUR, SMALLEST_TAG, HIGHEST_TAG, payload, x, a, sigma);
//        System.err.println("Result: " + Arrays.toString(new OtrOutputStream().write(message).toByteArray()));
        final byte[] expected = new byte[] {0, 4, 54, 0, 0, 1, 0, -1, -1, -1, -1, 0, 0, 0, 7, 0, 1, 0, 0, 1, 0, 0, 2, 0, 16, 99, -90, -11, 13, 49, -123, -91, 24, 117, -50, -47, 17, -38, 46, -1, 77, -125, -32, 85, -127, 117, 62, 69, -8, -105, -8, -110, 25, -45, 87, 108, 102, -123, -90, 95, 110, 124, 91, 76, -124, -57, 101, -75, -122, 40, -61, -73, -11, -16, 107, 31, -76, -111, -87, 29, 58, -128, 0, 3, 0, 18, 78, 68, 127, 98, 110, 116, 127, 29, -65, -46, 14, 43, -97, 4, 46, 6, -123, -119, -14, -107, 0, 70, 5, -25, 37, 114, 55, -99, 30, 59, -70, 10, -4, 85, -17, -53, 110, -68, 31, -1, 36, -23, -117, 104, 83, -73, -8, -84, -68, -65, 109, 127, 120, 15, -13, -78, 0, 0, 4, 0, 0, 0, 1, 52, 0, 5, 0, 32, -60, -101, -91, -29, 83, -9, 0, 6, 0, 0, 0, 0, 1, 0, -113, 121, 53, -39, -71, -86, -23, -65, -85, -19, -120, 122, -49, 73, 81, -74, -13, 46, -59, -98, 59, -81, 55, 24, -24, -22, -60, -106, 31, 62, -3, 54, 6, -25, 67, 81, -87, -60, 24, 51, 57, -72, 9, -25, -62, -82, 28, 83, -101, -89, 71, 91, -123, -48, 17, -83, -72, -76, 121, -121, 117, 73, -124, 105, 92, -84, 14, -113, 20, -77, 54, 8, 40, -94, 47, -6, 39, 17, 10, 61, 98, -87, -109, 69, 52, 9, -96, -2, 105, 108, 70, 88, -8, 75, -35, 32, -127, -100, 55, 9, -96, 16, 87, -79, -107, -83, -51, 0, 35, 61, -70, 84, -124, -74, 41, 31, -99, 100, -114, -8, -125, 68, -122, 119, -105, -100, -20, 4, -76, 52, -90, -84, 46, 117, -23, -104, 93, -30, 61, -80, 41, 47, -63, 17, -116, -97, -6, -99, -127, -127, -25, 51, -115, -73, -110, -73, 48, -41, -71, -29, 73, 89, 47, 104, 9, -104, 114, 21, 57, 21, -22, 61, 107, -117, 70, 83, -58, 51, 69, -113, -128, 59, 50, -92, -62, -32, -14, 114, -112, 37, 110, 78, 63, -118, 59, 8, 56, -95, -60, 80, -28, -31, -116, 26, 41, -93, 125, -33, 94, -95, 67, -34, 75, 102, -1, 4, -112, 62, -43, -49, 22, 35, -31, 88, -44, -121, -58, 8, -23, 127, 33, 28, -40, 29, -54, 35, -53, 110, 56, 7, 101, -8, 34, -29, 66, -66, 72, 76, 5, 118, 57, 57, 96, 28, -42, 103, 0, 0, 0, 28, -70, -10, -106, -90, -123, 120, -9, -33, -34, -25, -6, 103, -55, 119, -57, -123, -17, 50, -78, 51, -70, -27, -128, -64, -68, -43, 105, 93, 0, 0, 1, 0, 22, -90, 92, 88, 32, 72, 80, 112, 78, 117, 2, -93, -105, 87, 4, 13, 52, -38, 58, 52, 120, -63, 84, -44, -28, -91, -64, 45, 36, 46, -32, 79, -106, -26, 30, 75, -48, -112, 74, -67, -84, -113, 55, -18, -79, -32, -97, 49, -126, -46, 60, -112, 67, -53, 100, 47, -120, 0, 65, 96, -19, -7, -54, 9, -77, 32, 118, -89, -100, 50, -90, 39, -14, 71, 62, -111, -121, -101, -94, -60, -25, 68, -67, 32, -127, 84, 76, -75, 91, -128, 44, 54, -115, 31, -88, 62, -44, -119, -23, 78, 15, -96, 104, -114, 50, 66, -118, 92, 120, -60, 120, -58, -115, 5, 39, -73, 28, -102, 58, -69, 11, 11, -31, 44, 68, 104, -106, 57, -25, -45, -50, 116, -37, 16, 26, 101, -86, 43, -121, -10, 76, 104, 38, -37, 62, -57, 47, 75, 85, -103, -125, 75, -76, -19, -80, 47, 124, -112, -23, -92, -106, -45, -91, 93, 83, 91, -21, -4, 69, -44, -10, 25, -10, 63, 61, -19, -69, -121, 57, 37, -62, -14, 36, -32, 119, 49, 41, 109, -88, -121, -20, 30, 71, 72, -8, 126, -5, 95, -34, -73, 84, -124, 49, 107, 34, 50, -34, -27, 83, -35, -81, 2, 17, 43, 13, 31, 2, -38, 48, -105, 50, 36, -2, 39, -82, -38, -117, -99, 75, 41, 34, -39, -70, -117, -29, -98, -39, -31, 3, -90, 60, 82, -127, 11, -58, -120, -73, -30, -19, 67, 22, -31, -17, 23, -37, -34, 0, 0, 1, 0, 101, 109, 72, -110, -66, -30, -106, 54, 54, 118, -23, -36, 17, 82, 0, -52, 93, 33, -20, -53, 1, -27, -59, -34, 63, 44, -92, -11, -90, -69, -79, -62, 67, 67, 15, -122, -91, -35, 99, 125, -108, -81, -68, 117, 40, 3, -111, -57, -119, -122, 33, 4, -4, 110, -94, 107, 35, 44, -59, -22, -48, 117, 84, -86, 26, -122, -95, -52, -54, 89, -126, 71, 75, 16, -48, -7, 77, -119, 93, 7, 35, 87, -85, -66, 46, -126, 45, -81, -57, -59, -35, -81, 8, -99, 45, 20, 109, -96, 40, -70, -77, -107, 90, 123, -31, 64, -96, -67, 54, -53, -1, 122, 82, -65, 42, 29, 29, -75, 10, -47, 80, -25, 67, -46, -22, 50, -110, 122, -69, 75, -79, -48, 43, -87, 18, -12, 58, -49, 66, -117, -101, 60, -54, -61, 49, 21, 45, 51, -124, 62, -24, -115, 21, -79, 93, -107, 22, 77, 30, -72, 105, -125, -105, 72, 17, -55, 62, 84, -17, 10, -69, -97, -38, 117, 16, 50, -2, 93, 122, -18, 79, 116, 55, -7, -113, 26, -13, 104, -29, 111, 2, 107, 35, -41, 109, 20, 9, 84, 67, -79, 10, -18, 21, -7, -84, 125, -18, -86, -74, -8, 32, -20, -121, 87, 95, 32, -122, -28, -43, 39, 90, -58, 126, 14, 23, -127, -71, -76, 26, -19, -99, -118, 63, 94, 69, 26, 70, 58, -26, 36, 118, 72, 38, -60, -34, 121, -127, 43, 82, -58, 25, -82, -22, 100, 6, 30, 0, 7, 0, 0, 0, 28, 118, -49, 64, -30, 73, -13, -98, 59, -87, -100, 125, -88, 85, -71, -69, 11, 106, 92, 112, -94, 126, -44, -111, 24, 120, 59, -64, -119, 0, 0, 0, 28, -97, -119, -59, -127, 90, 94, 20, 120, -33, -88, -39, -43, 100, -49, 49, 90, -6, 110, -108, 11, -7, 19, 126, -99, 18, -116, -120, 28, 109, -58, 123, 64, -90, 63, 60, -63, 32, 51, 93, 17, -61, 51, -75, 125, -48, -87, -127, -53, 42, -119, -77, 114, 37, 9, 110, 53, -10, -70, -97, -109, 12, -109, -64, -49, 26, 74, 51, 57, 44, 92, -19, 83, -63, 13, 96, -114, -5, 42, 26, 29, 9, -26, 38, 85, -128, -37, -72, 59, -40, 118, -16, 40, 89, -109, -85, 61, 70, 66, 59, 108, -83, 13, 55, 48, 88, -75, -62, 100, 84, 121, 86, -99, 33, -20, -78, 96, -8, -16, -2, 57, 39, 111, -18, 45, -49, 4, -49, 9, 27, -108, -45, -70, -4, -47, -77, 61, -111, 76, 126, 82, 58, 0, 74, -33, -34, 20, -76, 91, 42, -128, -31, 3, -76, 66, 10, -5, 105, 82, -64, -15, 98, 72, -27, -41, -47, 25, 87, 107, -87, 13, -97, 48, 99, -41, 8, 72, 113, -93, -77, -37, -73, 19, 125, 49, -69, -42, 41, 46, -111, -21, 14, -15, -121, -84, 123, 35, 9, 26, -128, 0, 0, 1, -128, -19, -112, -121, -90, -77, 112, -67, 83, -79, -101, 122, -4, -89, -69, -106, 92, 72, 106, 84, -11, -37, 13, 65, -40, -106, 52, 65, 55, -120, 120, -48, -119, -92, -17, 90, 7, 107, 83, -46, 105, -16, -20, -77, -69, 80, 89, 31, -65, -82, -125, -73, 63, 88, -67, 86, 81, 77, 85, 22, 84, 9, -31, 16, -4, -21, 117, 102, 53, 100, 86, 90, 5, -107, 64, 50, -127, 11, 14, -127, -22, -109, -13, -39, -88, -55, -32, 55, -88, -44, 120, -119, 59, -96, -69, -76, 25, 118, -116, 61, -118, 81, 25, 55, -17, 37, 118, 71, 105, 35, 22, 19, 43, -124, 121, -20, 108, 93, -10, 117, 113, 14, 66, -17, -117, 72, -121, 113, 118, -64, -27, -59, 26, 80, 83, -31, -37, 107, -58, -102, 28, -95, -79, -119, -33, 123, -9, -126, 48, -40, -45, 70, 67, 101, -102, 110, 77, 39, 112, 21, -42, 124, -2, 121, -34, -118, 119, 87, -42, 8, -54, -33, 11, 22, 78, -82, 106, -87, 48, -40, 37, 127, -124, -45, 40, 73, 64, -79, 25, -70, 74, -27, -34, -91, 32, 126, -14, 100, -99, -121, 6, -104, -11, 57, 19, 110, 77, -43, 76, 32, -28, -65, -5, -88, -75, 99, -79, 17, -63, 51, 19, -22, -89, 29, -1, 71, -35, -115, -107, -94, 112, -113, 72, 22, -102, 55, 69, -103, 72, -77, -21, -91, -61, -123, 22, 57, -78, 16, -68, -103, -35, -12, -7, 22, -25, -127, 6, 86, -119, -41, -82, 83, 86, 33, 50, 44, 77, -127, -63, -2, 84, 28, 124, 71, 25, 112, -85, -55, 126, 56, -59, -126, 65, 73, 7, -1, -78, 50, -49, -103, 29, -108, 9, -104, 15, -34, 11, -128, 15, 51, -68, 40, -36, -39, -66, 2, 106, 68, 29, 63, 127, -105, 20, -53, 12, -55, 65, -107, -74, -19, 67, -72, 83, -67, 109, 70, -105, -35, 91, -29, -47, -121, -4, -109, -13, -96, -37, 67, 117, -54, -125, -71, 27, -79, -17, -24, 54, 57, -14, 33, 113, 89, 29, 33, -98, 59, -62, 86, -27, -117, -15, -11, -128, 24, -89, -60, 107, -52, 15, 90, -65, 70, -50, 63, -23, -124, 9, -62, 95, 93, -40, 98, -45, -115, 71, -102, -52, 41, -91, 17, 80, 67, 86, -117, 109, 40, 47, 124, 106, 45, 50, 83, -78, 79, 35, 84, 46, 57, 103, -101, -67, -93, 2, -36, 99, 68, 2, 64, 100, -65, -48, 11, 47, 126, -10, 61, -42, -41, -74, -87, 54, 103, -6, 4, -60, -66, 51, -53, -102, -93, 40, 0, 103, 46, 8, 4, 120, -68, 109, 14, 48, -87, 108, 78, 62, -122, 18, 6, 95, 71, -110, 92, -119, -122, 113, -73, 36, -61, -66, -29, 47, 108, 5, -21, -36, -46, -56, -118, 113, -25, -43, -102, -82, -8, -27, 70, -85, -94, 60, -71, 55, 31, -54, -18, -102, -45, 107, 9, 0, -17, 125, -87, 52, -94, 72, -127, -95, 93, 47, 36, 125, -79, -67, 39, 100, 54, -106, -54, -55, 101, -108, 86, 87, 105, -121, -113, -4, 18, -104, -123, -65, -74, -23, -18, 90, -49, -3, 38, 98, -82, -34, 38, -63, -37, -17, -109, 42, 51, -14, -28, -22, 96, -47, 72, 36, 0, 24, -44, 60, 42, 19, -89, -30, -89, 22, -34, 27, -60, -125, 19, 13, 59, 5, -59, 120, -55, -52, 8, 50, -38, 1, 87, 98, 13, 118, 75, 86, 104, 36, -28, -60, 117, 111, 105, -51, 78, -97, 125, -98, 13, 7, -97, 47, -75, -37, -95, -31, 52, -21, 80, 17, 37, 0, 115, 13, 2, 70, -106, -118, 86, -47, -127, 84, -12, 116, 60, -103, 72, -107, 28, 70, -5, -22, 62, -15, 0, 61, -85, 12, 55, -40, 71, 28, 106, 85, 127, 55, -54, -73, -119, 7, -38, 1, -73, -43, -22, -94, -19, 28, -10, -38, -14, 42, 110, 6, -49, -88, 74, 8, 0, -96, -89, -126, 44, 116, 101, 125, 26, 21, 64, -63, 19, -36, 74, 110, 63, 63, 76, 120, -88, -6, -110, 121, -76, 95, -111, -57, 68, -114, -1, -112, 37, 36, 14, -9, 16, 91, 101, -96, 46, 105, -110, -104, 3, -103, -127, -35, 100, 2, 25, -64, 74, 35, -54, 124, 17, 0};
        assertArrayEquals(expected, new OtrOutputStream().write(message).toByteArray());
    }

    private static Sigma generateSigma(@Nonnull final EdDSAKeyPair keypair, @Nonnull final byte[] message) {
        final ECDHKeyPair pair1 = ECDHKeyPair.generate(RANDOM);
        final ECDHKeyPair pair2 = ECDHKeyPair.generate(RANDOM);
        return ringSign(RANDOM, keypair, keypair.getPublicKey(), pair1.getPublicKey(), pair2.getPublicKey(), message);
    }
}