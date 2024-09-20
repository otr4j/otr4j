/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.session;

import net.java.otr4j.api.OtrEngineHost;
import net.java.otr4j.api.OtrException;
import net.java.otr4j.api.SessionID;
import net.java.otr4j.api.Version;
import org.apache.commons.lang3.RandomStringUtils;
import org.junit.Test;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.regex.Pattern;

import static java.nio.charset.StandardCharsets.UTF_8;
import static net.java.otr4j.api.InstanceTag.ZERO_VALUE;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests for OTR Fragmenter.
 *
 * @author Danny van Heumen
 */
@SuppressWarnings("ConstantConditions")
public class FragmenterTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final int senderTagOTRv4 = 0x5a73a599;
    private final int receiverTagOTRv4 = 0x27e31597;

    private static final String getSpecV4MessageFull = "?OTR:AAMDJ+MVmSfjFZcAAAAAAQAAAAIAAADA1g5IjD1ZGLDVQEyCgCyn9hbrL3KAbGDdzE2ZkMyTKl7XfkSxh8YJnudstiB74i4BzT0W2haClg6dMary/jo9sMudwmUdlnKpIGEKXWdvJKT+hQ26h9nzMgEditLB8vjPEWAJ6gBXvZrY6ZQrx3gb4v0UaSMOMiR5sB7Eaulb2Yc6RmRnnlxgUUC2alosg4WIeFN951PLjScajVba6dqlDi+q1H5tPvI5SWMN7PCBWIJ41+WvF+5IAZzQZYgNaVLbAAAAAAAAAAEAAAAHwNiIi5Ms+4PsY/L2ipkTtquknfx6HodLvk3RAAAAAA==.";
    private static final String[] specV4MessageParts208 = new String[] {
            "?OTR|3c5b5f03|5a73a599|27e31597,00001,00003,?OTR:AAMDJ+MVmSfjFZcAAAAAAQAAAAIAAADA1g5IjD1ZGLDVQEyCgCyn9hbrL3KAbGDdzE2ZkMyTKl7XfkSxh8YJnudstiB74i4BzT0W2haClg6dMary/jo9sMudwmUdlnKpIGEKXWdvJKT+hQ26h9nzMgEditLB8v,",
            "?OTR|3c5b5f03|5a73a599|27e31597,00002,00003,jPEWAJ6gBXvZrY6ZQrx3gb4v0UaSMOMiR5sB7Eaulb2Yc6RmRnnlxgUUC2alosg4WIeFN951PLjScajVba6dqlDi+q1H5tPvI5SWMN7PCBWIJ41+WvF+5IAZzQZYgNaVLbAAAAAAAAAAEAAAAHwNiIi5Ms+4PsY/L2i,",
            "?OTR|3c5b5f03|5a73a599|27e31597,00003,00003,pkTtquknfx6HodLvk3RAAAAAA==.,"
    };

    private final int senderTagOTRv3 = 0x5a73a599;
    private final int receiverTagOTRv3 = 0x27e31597;

    private static final String specV3MessageFull = "?OTR:AAMDJ+MVmSfjFZcAAAAAAQAAAAIAAADA1g5IjD1ZGLDVQEyCgCyn9hbrL3KAbGDdzE2ZkMyTKl7XfkSxh8YJnudstiB74i4BzT0W2haClg6dMary/jo9sMudwmUdlnKpIGEKXWdvJKT+hQ26h9nzMgEditLB8vjPEWAJ6gBXvZrY6ZQrx3gb4v0UaSMOMiR5sB7Eaulb2Yc6RmRnnlxgUUC2alosg4WIeFN951PLjScajVba6dqlDi+q1H5tPvI5SWMN7PCBWIJ41+WvF+5IAZzQZYgNaVLbAAAAAAAAAAEAAAAHwNiIi5Ms+4PsY/L2ipkTtquknfx6HodLvk3RAAAAAA==.";
    private static final String[] specV3MessageParts199 = new String[] {
            "?OTR|5a73a599|27e31597,00001,00003,?OTR:AAMDJ+MVmSfjFZcAAAAAAQAAAAIAAADA1g5IjD1ZGLDVQEyCgCyn9hbrL3KAbGDdzE2ZkMyTKl7XfkSxh8YJnudstiB74i4BzT0W2haClg6dMary/jo9sMudwmUdlnKpIGEKXWdvJKT+hQ26h9nzMgEditLB8v,",
            "?OTR|5a73a599|27e31597,00002,00003,jPEWAJ6gBXvZrY6ZQrx3gb4v0UaSMOMiR5sB7Eaulb2Yc6RmRnnlxgUUC2alosg4WIeFN951PLjScajVba6dqlDi+q1H5tPvI5SWMN7PCBWIJ41+WvF+5IAZzQZYgNaVLbAAAAAAAAAAEAAAAHwNiIi5Ms+4PsY/L2i,",
            "?OTR|5a73a599|27e31597,00003,00003,pkTtquknfx6HodLvk3RAAAAAA==.,"
    };

    private static final String specV2MessageFull = "?OTR:AAEDAAAAAQAAAAEAAADAVf3Ei72ZgFeKqWvLMnuVPVCwxktsOZ1QdjeLp6jn62mCVtlY9nS6sRkecpjuLYHRxyTdRu2iEVtSsjZqK55ovZ35SfkOPHeFYa9BIuxWi9djHMVKQ8KOVGAVLibjZ6P8LreDSKtWDv9YQjIEnkwFVGCPfpBq2SX4VTQfJAQXHggR8izKxPvluXUdG9rIPh4cac98++VLdIuFMiEXjUIoTX2rEzunaCLMy0VIfowlRsgsKGrwhCCv7hBWyglbzwz+AAAAAAAAAAQAAAF2SOrJvPUerB9mtf4bqQDFthfoz/XepysnYuReHHEXKe+BFkaEoMNGiBl4TCLZx72DvmZwKCewWRH1+W66ggrXKw2VdVl+vLsmzxNyWChGLfBTL5/3SUF09BfmCEl03Ckk7htAgyAQcBf90RJznZndv7HwVAi3syupi0sQDdOKNPyObR5FRtqyqudttWmSdmGCGFcZ/fZqxQNsHB8QuYaBiGL7CDusES+wwfn8Q7BGtoJzOPDDx6KyIyox/flPx2DZDJIZrMz9b0V70a9kqKLo/wcGhvHO6coCyMxenBAacLJ1DiINLKoYOoJTM7zcxsGnvCxaDZCvsmjx3j8Yc5r3i3ylllCQH2/lpr/xCvXFarGtG7+wts+UqstS9SThLBQ9Ojq4oPsX7HBHKvq19XU3/ChIgWMy+bczc5gpkC/eLAIGfJ0D5DJsl68vMXSmCoFK0HTwzzNa7lnZK4IutYPBNBCv0pWORQqDpskEz96YOGyB8+gtpFgCrkuV1bSB9SRVmEBfDtKPQFhKowAAAAA=.";

    private static final String[] specV2MessageParts318 = new String[] {
            "?OTR,1,3,?OTR:AAEDAAAAAQAAAAEAAADAVf3Ei72ZgFeKqWvLMnuVPVCwxktsOZ1QdjeLp6jn62mCVtlY9nS6sRkecpjuLYHRxyTdRu2iEVtSsjZqK55ovZ35SfkOPHeFYa9BIuxWi9djHMVKQ8KOVGAVLibjZ6P8LreDSKtWDv9YQjIEnkwFVGCPfpBq2SX4VTQfJAQXHggR8izKxPvluXUdG9rIPh4cac98++VLdIuFMiEXjUIoTX2rEzunaCLMy0VIfowlRsgsKGrwhCCv7hBWyglbzwz+AAAAAAAAAAQAAAF2SOr,",
            "?OTR,2,3,JvPUerB9mtf4bqQDFthfoz/XepysnYuReHHEXKe+BFkaEoMNGiBl4TCLZx72DvmZwKCewWRH1+W66ggrXKw2VdVl+vLsmzxNyWChGLfBTL5/3SUF09BfmCEl03Ckk7htAgyAQcBf90RJznZndv7HwVAi3syupi0sQDdOKNPyObR5FRtqyqudttWmSdmGCGFcZ/fZqxQNsHB8QuYaBiGL7CDusES+wwfn8Q7BGtoJzOPDDx6KyIyox/flPx2DZDJIZrMz9b0V70a9kqKLo/wcGhvHO6coCyMxenBAacLJ1DiI,",
            "?OTR,3,3,NLKoYOoJTM7zcxsGnvCxaDZCvsmjx3j8Yc5r3i3ylllCQH2/lpr/xCvXFarGtG7+wts+UqstS9SThLBQ9Ojq4oPsX7HBHKvq19XU3/ChIgWMy+bczc5gpkC/eLAIGfJ0D5DJsl68vMXSmCoFK0HTwzzNa7lnZK4IutYPBNBCv0pWORQqDpskEz96YOGyB8+gtpFgCrkuV1bSB9SRVmEBfDtKPQFhKowAAAAA=.,"
    };

    private final SessionID sessionID = new SessionID("bob@chatnetwork", "alice@chatnetwork", "chat");

    @Test(expected = NullPointerException.class)
    @SuppressWarnings("ResultOfObjectAllocationIgnored")
    public void testNullSecureRandomConstruction() {
        new Fragmenter(RANDOM, null, sessionID);
    }

    @Test(expected = NullPointerException.class)
    @SuppressWarnings("ResultOfObjectAllocationIgnored")
    public void testNullHostConstruction() {
        new Fragmenter(RANDOM, null, sessionID);
    }

    @Test(expected = NullPointerException.class)
    public void testNullSessionID() {
        final OtrEngineHost host = host(100);
        new Fragmenter(RANDOM, host, null);
    }

    @Test
    @SuppressWarnings("ResultOfObjectAllocationIgnored")
    public void testConstruction() {
        new Fragmenter(RANDOM, host(100), sessionID);
    }

    @Test
    public void testFragmentNullInstructionsCompute() throws OtrException {
        final OtrEngineHost host = mock(OtrEngineHost.class);
        when(host.getMaxFragmentSize(any(SessionID.class))).thenReturn(Integer.MAX_VALUE);
        final String message = "Some message that shouldn't be fragmented.";

        final Fragmenter fragmenter = new Fragmenter(RANDOM, host, this.sessionID);
        final int number = fragmenter.numberOfFragments(Version.THREE, message);
        assertEquals(1, number);
        verify(host, times(1)).getMaxFragmentSize(isA(SessionID.class));
    }

    @Test
    public void testFragmentNullInstructionsFragment() throws OtrException {
        final OtrEngineHost host = mock(OtrEngineHost.class);
        when(host.getMaxFragmentSize(any(SessionID.class))).thenReturn(Integer.MAX_VALUE);
        final String message = "?OTR:" + Base64.getEncoder().encodeToString("Some message that shouldn't be fragmented.".getBytes(UTF_8)) + ".";
        final Fragmenter fragmenter = new Fragmenter(RANDOM, host, this.sessionID);
        final String[] fragments = fragmenter.fragment(Version.THREE, senderTagOTRv3, receiverTagOTRv3, message);
        assertArrayEquals(new String[] {message}, fragments);
        verify(host, times(1)).getMaxFragmentSize(isA(SessionID.class));
    }

    @Test
    public void testUnlimitedSizedFragmentToSingleMessage() throws OtrException {
        final OtrEngineHost host = host(Integer.MAX_VALUE);

        Fragmenter fragmenter = new Fragmenter(RANDOM, host, this.sessionID);
        String[] msg = fragmenter.fragment(Version.THREE, senderTagOTRv3, receiverTagOTRv3, specV3MessageFull);
        assertArrayEquals(new String[] {specV3MessageFull}, msg);
        verify(host, times(1)).getMaxFragmentSize(isA(SessionID.class));
    }

    @Test
    public void testUnlimitedSizedFragmentToSingleMessageV2() throws OtrException {
        final OtrEngineHost host = host(Integer.MAX_VALUE);

        Fragmenter fragmenter = new Fragmenter(RANDOM, host, this.sessionID);
        String[] msg = fragmenter.fragment(Version.TWO, ZERO_VALUE, ZERO_VALUE, specV2MessageFull);
        assertArrayEquals(new String[] {specV2MessageFull}, msg);
        verify(host, times(1)).getMaxFragmentSize(isA(SessionID.class));
    }

    @Test
    public void testLargeEnoughFragmentToSingleMessage() throws OtrException {
        final OtrEngineHost host = host(354);

        Fragmenter fragmenter = new Fragmenter(RANDOM, host, this.sessionID);
        String[] msg = fragmenter.fragment(Version.THREE, senderTagOTRv3, receiverTagOTRv3, specV3MessageFull);
        assertArrayEquals(new String[] {specV3MessageFull}, msg);
        verify(host, times(1)).getMaxFragmentSize(isA(SessionID.class));
    }

    @Test
    public void testLargeEnoughFragmentToSingleMessageV2() throws OtrException {
        final OtrEngineHost host = host(830);

        Fragmenter fragmenter = new Fragmenter(RANDOM, host, this.sessionID);
        String[] msg = fragmenter.fragment(Version.TWO, ZERO_VALUE, ZERO_VALUE, specV2MessageFull);
        assertArrayEquals(new String[] {specV2MessageFull}, msg);
        verify(host, times(1)).getMaxFragmentSize(isA(SessionID.class));
    }

    @Test
    public void testCalculateNumberOfFragmentsUnlimitedSize() throws OtrException {
        final OtrEngineHost host = host(Integer.MAX_VALUE);

        Fragmenter fragmenter = new Fragmenter(RANDOM, host, this.sessionID);
        int num = fragmenter.numberOfFragments(Version.THREE, specV3MessageFull);
        assertEquals(1, num);
        verify(host, times(1)).getMaxFragmentSize(isA(SessionID.class));
    }

    @Test
    public void testCalculateNumberOfFragmentsLargeEnoughSize() throws OtrException {
        final OtrEngineHost host = host(1000);

        Fragmenter fragmenter = new Fragmenter(RANDOM, host, this.sessionID);
        int num = fragmenter.numberOfFragments(Version.THREE, specV3MessageFull);
        assertEquals(1, num);
        verify(host, times(1)).getMaxFragmentSize(isA(SessionID.class));
    }

    @Test
    public void testCalculateNumberOfFragmentsNumFragmentsSmallFragmentSize() throws OtrException {
        final OtrEngineHost host = host(199);

        Fragmenter fragmenter = new Fragmenter(RANDOM, host, this.sessionID);
        int num = fragmenter.numberOfFragments(Version.THREE, specV3MessageFull);
        assertEquals(3, num);
        verify(host, times(1)).getMaxFragmentSize(isA(SessionID.class));
    }

    @Test
    public void testCalculateNumberOfFragmentsNumFragmentsSmallFragmentSize2() throws OtrException {
        final OtrEngineHost host = host(80);

        Fragmenter fragmenter = new Fragmenter(RANDOM, host, this.sessionID);
        int num = fragmenter.numberOfFragments(Version.THREE, specV3MessageFull);
        assertEquals(9, num);
        verify(host, times(1)).getMaxFragmentSize(isA(SessionID.class));
    }

    @Test(expected = OtrException.class)
    public void testFragmentSizeTooSmallForOverhead() throws OtrException {
        final OtrEngineHost host = host(35);

        Fragmenter fragmenter = new Fragmenter(RANDOM, host, this.sessionID);
        fragmenter.numberOfFragments(Version.THREE, specV3MessageFull);
    }

    @Test(expected = OtrException.class)
    public void testFragmentSizeTooSmallForPayload() throws OtrException {
        Fragmenter fragmenter = new Fragmenter(RANDOM, host(36), this.sessionID);
        fragmenter.numberOfFragments(Version.THREE, specV3MessageFull);
    }

    @Test
    public void testV3MessageToSplit() throws OtrException {
        final OtrEngineHost host = host(199);

        Fragmenter fragmenter = new Fragmenter(RANDOM, host, this.sessionID);
        String[] msg = fragmenter.fragment(Version.THREE, senderTagOTRv3, receiverTagOTRv3, specV3MessageFull);
        assertArrayEquals(specV3MessageParts199, msg);
        verify(host, times(1)).getMaxFragmentSize(isA(SessionID.class));
    }

    @Test
    public void testV2MessageToSplit() throws OtrException {
        final OtrEngineHost host = host(318);

        Fragmenter fragmenter = new Fragmenter(RANDOM, host, this.sessionID);
        String[] msg = fragmenter.fragment(Version.TWO, ZERO_VALUE, ZERO_VALUE, specV2MessageFull);
        assertArrayEquals(specV2MessageParts318, msg);
        verify(host, times(1)).getMaxFragmentSize(isA(SessionID.class));
    }

    @Test
    public void testV1ComputeHeaderSize() throws OtrException {
        Fragmenter fragmenter = new Fragmenter(RANDOM, host(310), this.sessionID);
        assertEquals(1, fragmenter.numberOfFragments(Version.ONE, specV2MessageFull));
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testV1MessageToSplit() throws OtrException {
        Fragmenter fragmenter = new Fragmenter(RANDOM, host(310), this.sessionID);
        assertArrayEquals(new String[] {specV2MessageFull}, fragmenter.fragment(Version.ONE, ZERO_VALUE, ZERO_VALUE, specV2MessageFull));
    }

    @Test(expected = OtrException.class)
    public void testExceedProtocolMaximumNumberOfFragments() throws OtrException {
        final String veryLongString = "?OTR:" + new String(new char[65537]).replace('\0', 'a') + ".";
        Fragmenter fragmenter = new Fragmenter(RANDOM, host(37), this.sessionID);
        fragmenter.fragment(Version.THREE, senderTagOTRv3, receiverTagOTRv3, veryLongString);
    }

    @Test
    public void testFragmentPatternsV3() throws OtrException {
        final Pattern OTRv3_FRAGMENT_PATTERN = Pattern.compile("^\\?OTR\\|[0-9abcdef]{8}\\|[0-9abcdef]{8},\\d{5},\\d{5},[a-zA-Z0-9+/=?:.]+,$");
        final String payload = "?OTR:" + Base64.getEncoder().encodeToString(RandomStringUtils.random(1700).getBytes(UTF_8)) + ".";
        final OtrEngineHost host = host(150);
        Fragmenter fragmenter = new Fragmenter(RANDOM, host, this.sessionID);
        String[] msg = fragmenter.fragment(Version.THREE, senderTagOTRv3, receiverTagOTRv3, payload);
        int count = 1;
        for (String part : msg) {
            assertTrue(OTRv3_FRAGMENT_PATTERN.matcher(part).matches());
            // Test monotonic increase of part numbers ...
            int partNumber = Integer.parseInt(part.substring(23, 28), 10);
            assertEquals(count, partNumber);
            count++;
        }
        verify(host, times(1)).getMaxFragmentSize(isA(SessionID.class));
    }

    @Test
    public void testFragmentPatternsV2() throws OtrException {
        final Pattern OTRv2_FRAGMENT_PATTERN = Pattern.compile("^\\?OTR,\\d{1,5},\\d{1,5},[a-zA-Z0-9+/=?:.]+,$");
        final String payload = "?OTR:" + Base64.getEncoder().encodeToString(RandomStringUtils.random(700).getBytes(UTF_8)) + ".";
        final OtrEngineHost host = host(150);
        final Fragmenter fragmenter = new Fragmenter(RANDOM, host, this.sessionID);
        final String[] msg = fragmenter.fragment(Version.TWO, ZERO_VALUE, ZERO_VALUE, payload);
        int count = 1;
        for (final String part : msg) {
            assertTrue(OTRv2_FRAGMENT_PATTERN.matcher(part).matches());
            // Test monotonic increase of part numbers ...
            final String temp = part.substring(5, 11);
            int partNumber = Integer.parseInt(temp.substring(0, temp.indexOf(',')), 10);
            assertEquals(count, partNumber);
            count++;
        }
        verify(host, times(1)).getMaxFragmentSize(isA(SessionID.class));
    }

    @Test
    public void testPreventFragmentationOfPlainTextMessage() throws OtrException {
        final OtrEngineHost host = host(150);
        final Fragmenter fragmenter = new Fragmenter(RANDOM, host, this.sessionID);
        assertArrayEquals(new String[] {"Hello world!"}, fragmenter.fragment(Version.THREE, senderTagOTRv3, receiverTagOTRv3, "Hello world!"));
    }

    @Test
    public void testMessageFitsWithoutFragmentation() throws OtrException {
        final OtrEngineHost host = host(45);
        final Fragmenter fragmenter = new Fragmenter(RANDOM, host, this.sessionID);
        assertEquals(1, fragmenter.numberOfFragments(Version.FOUR, "?OTR:abc"));
    }

    @Test(expected = OtrException.class)
    public void testOTRv4OverheadTooLarge() throws OtrException {
        final OtrEngineHost host = host(45);
        final Fragmenter fragmenter = new Fragmenter(RANDOM, host, this.sessionID);
        assertEquals(0, fragmenter.numberOfFragments(Version.FOUR, "?OTR:abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz"));
    }

    @Test
    public void testNumberOfFragmentsForOTRv4() throws OtrException {
        final OtrEngineHost host = host(46);
        final Fragmenter fragmenter = new Fragmenter(RANDOM, host, this.sessionID);
        assertEquals(57, fragmenter.numberOfFragments(Version.FOUR, "?OTR:abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz"));
    }

    @Test
    public void testFragmentOTRv4SpecExample() throws OtrException {
        final OtrEngineHost host = host(208);
        final SecureRandom fakeRandom = new SecureRandom() {

            private static final long serialVersionUID = 1L;

            @Override
            public int nextInt() {
                return 0x3c5b5f03;
            }
        };
        final Fragmenter fragmenter = new Fragmenter(fakeRandom, host, this.sessionID);
        assertArrayEquals(specV4MessageParts208, fragmenter.fragment(Version.FOUR, senderTagOTRv4, receiverTagOTRv4,
                getSpecV4MessageFull));
    }

    @Test(expected = OtrException.class)
    public void testFragmentOTRv4SizeTooSmall() throws OtrException {
        final OtrEngineHost host = host(45);
        final Fragmenter fragmenter = new Fragmenter(RANDOM, host, this.sessionID);
        fragmenter.fragment(Version.FOUR, senderTagOTRv4, receiverTagOTRv4, getSpecV4MessageFull);
    }

    @Test(expected = OtrException.class)
    public void testFragmentOTRv4SizeTooSmallForHeader() throws OtrException {
        final OtrEngineHost host = host(44);
        final Fragmenter fragmenter = new Fragmenter(RANDOM, host, this.sessionID);
        fragmenter.fragment(Version.FOUR, senderTagOTRv4, receiverTagOTRv4, getSpecV4MessageFull);
    }

    @Test
    public void testFragmentOTRv4MessageSizeExactlyRight() throws OtrException {
        final String message = "?OTR:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.";
        final OtrEngineHost host = host(46);
        final Fragmenter fragmenter = new Fragmenter(RANDOM, host, this.sessionID);
        assertArrayEquals(new String[] {message}, fragmenter.fragment(Version.FOUR, senderTagOTRv4, receiverTagOTRv4, message));
    }

    @Test
    public void testFragmentOTRv4MessageSizeRequiresFragmentation() throws OtrException {
        final Pattern OTRv4_FRAGMENT_PATTERN = Pattern.compile("^\\?OTR\\|[0-9abcdef]{8}\\|[0-9abcdef]{8}\\|[0-9abcdef]{8},\\d{5},\\d{5},[a-zA-Z0-9+/=?:.]+,$");
        final String message = "?OTR:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.";
        final OtrEngineHost host = host(46);
        final Fragmenter fragmenter = new Fragmenter(RANDOM, host, this.sessionID);
        final String[] fragments = fragmenter.fragment(Version.FOUR, senderTagOTRv4, receiverTagOTRv4, message);
        assertEquals(47, fragments.length);
        for (final String fragment : fragments) {
            assertEquals(46, fragment.length());
            assertTrue(OTRv4_FRAGMENT_PATTERN.matcher(fragment).matches());
        }
    }

    /**
     * Create mock OtrEngineHost which returns the provided instructions.
     *
     * @param maxFragmentSize the maximum fragment size
     * @return returns mock host
     */
    private OtrEngineHost host(final int maxFragmentSize) {
        final OtrEngineHost host = mock(OtrEngineHost.class);
        when(host.getMaxFragmentSize(any(SessionID.class)))
                .thenReturn(maxFragmentSize);
        return host;
    }
}
