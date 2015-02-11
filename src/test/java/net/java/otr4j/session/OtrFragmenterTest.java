package net.java.otr4j.session;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import java.io.IOException;
import java.util.regex.Pattern;

import net.java.otr4j.OtrEngineHost;
import net.java.otr4j.OtrPolicy;
import net.java.otr4j.io.SerializationUtils;

import org.apache.commons.lang3.RandomStringUtils;
import org.bouncycastle.util.encoders.Base64;
import org.junit.Test;

/**
 * Tests for OTR Fragmenter.
 *
 * TODO substitute nice compact mock for elaborate OtrPolicy implementations
 *
 * @author Danny van Heumen
 */
public class OtrFragmenterTest {

	private static final OtrPolicy POLICY_V23 = new OtrPolicy() {

		public boolean getAllowV1() {
			return false;
		}

		public boolean getAllowV2() {
			return true;
		}

		public boolean getAllowV3() {
			return true;
		}

		public boolean getRequireEncryption() {
			return false;
		}

		public boolean getSendWhitespaceTag() {
			return false;
		}

		public boolean getWhitespaceStartAKE() {
			return false;
		}

		public boolean getErrorStartAKE() {
			return false;
		}

		public int getPolicy() {
			return 0;
		}

		public boolean getEnableAlways() {
			return true;
		}

		public boolean getEnableManual() {
			return false;
		}
		
		public void setAllowV1(boolean value) {}
		public void setAllowV2(boolean value) {}
		public void setAllowV3(boolean value) {}
		public void setRequireEncryption(boolean value) {}
		public void setSendWhitespaceTag(boolean value) {}
		public void setWhitespaceStartAKE(boolean value) {}
		public void setErrorStartAKE(boolean value) {}
		public void setEnableAlways(boolean value) {}
		public void setEnableManual(boolean value) {}
	};

	private static final OtrPolicy POLICY_V3 = new OtrPolicy() {

		public boolean getAllowV1() {
			return false;
		}

		public boolean getAllowV2() {
			return false;
		}

		public boolean getAllowV3() {
			return true;
		}

		public boolean getRequireEncryption() {
			return false;
		}

		public boolean getSendWhitespaceTag() {
			return false;
		}

		public boolean getWhitespaceStartAKE() {
			return false;
		}

		public boolean getErrorStartAKE() {
			return false;
		}

		public int getPolicy() {
			return 0;
		}

		public boolean getEnableAlways() {
			return true;
		}

		public boolean getEnableManual() {
			return false;
		}
		
		public void setAllowV1(boolean value) {}
		public void setAllowV2(boolean value) {}
		public void setAllowV3(boolean value) {}
		public void setRequireEncryption(boolean value) {}
		public void setSendWhitespaceTag(boolean value) {}
		public void setWhitespaceStartAKE(boolean value) {}
		public void setErrorStartAKE(boolean value) {}
		public void setEnableAlways(boolean value) {}
		public void setEnableManual(boolean value) {}
	};

	private static final OtrPolicy POLICY_V2 = new OtrPolicy() {

		public boolean getAllowV1() {
			return false;
		}

		public boolean getAllowV2() {
			return true;
		}

		public boolean getAllowV3() {
			return false;
		}

		public boolean getRequireEncryption() {
			return false;
		}

		public boolean getSendWhitespaceTag() {
			return false;
		}

		public boolean getWhitespaceStartAKE() {
			return false;
		}

		public boolean getErrorStartAKE() {
			return false;
		}

		public int getPolicy() {
			return 0;
		}

		public boolean getEnableAlways() {
			return true;
		}

		public boolean getEnableManual() {
			return false;
		}
		
		public void setAllowV1(boolean value) {}
		public void setAllowV2(boolean value) {}
		public void setAllowV3(boolean value) {}
		public void setRequireEncryption(boolean value) {}
		public void setSendWhitespaceTag(boolean value) {}
		public void setWhitespaceStartAKE(boolean value) {}
		public void setErrorStartAKE(boolean value) {}
		public void setEnableAlways(boolean value) {}
		public void setEnableManual(boolean value) {}
	};

	private static final OtrPolicy POLICY_V1 = new OtrPolicy() {

		public boolean getAllowV1() {
			return true;
		}

		public boolean getAllowV2() {
			return false;
		}

		public boolean getAllowV3() {
			return false;
		}

		public boolean getRequireEncryption() {
			return false;
		}

		public boolean getSendWhitespaceTag() {
			return false;
		}

		public boolean getWhitespaceStartAKE() {
			return false;
		}

		public boolean getErrorStartAKE() {
			return false;
		}

		public int getPolicy() {
			return 0;
		}

		public boolean getEnableAlways() {
			return true;
		}

		public boolean getEnableManual() {
			return false;
		}
		
		public void setAllowV1(boolean value) {}
		public void setAllowV2(boolean value) {}
		public void setAllowV3(boolean value) {}
		public void setRequireEncryption(boolean value) {}
		public void setSendWhitespaceTag(boolean value) {}
		public void setWhitespaceStartAKE(boolean value) {}
		public void setErrorStartAKE(boolean value) {}
		public void setEnableAlways(boolean value) {}
		public void setEnableManual(boolean value) {}
	};

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

	@Test(expected = NullPointerException.class)
	@SuppressWarnings("ResultOfObjectAllocationIgnored")
	public void testNullPolicyConstruction() {
		new OtrFragmenter(null, host(100));
	}

	@Test(expected = NullPointerException.class)
	@SuppressWarnings("ResultOfObjectAllocationIgnored")
	public void testNullHostConstruction() {
		Session session = createSessionMock(null, 0, 0);
		new OtrFragmenter(session, null);
	}

	@Test
	@SuppressWarnings("ResultOfObjectAllocationIgnored")
	public void testConstruction() {
		Session session = createSessionMock(null, 0, 0);
		new OtrFragmenter(session, host(100));
	}
	
	@Test
	public void testGetHost() {
		Session session = createSessionMock(null, 0, 0);
		OtrEngineHost host = host(100);
		OtrFragmenter fragmenter = new OtrFragmenter(session, host);
		assertSame(host, fragmenter.getHost());
	}

	@Test
	public void testFragmentNullInstructionsCompute() throws IOException {
		final OtrEngineHost host = mock(OtrEngineHost.class);
		when(host.getMaxFragmentSize(any(SessionID.class))).thenReturn(Integer.MAX_VALUE);
		final String message = "Some message that shouldn't be fragmented.";
		
		final OtrFragmenter fragmenter = new OtrFragmenter(this.createSessionMock(POLICY_V3, 0, 0), host);
		final int number = fragmenter.numberOfFragments(message);
		assertEquals(1, number);
		verify(host, times(1)).getMaxFragmentSize(any(SessionID.class));
	}

	@Test
	public void testFragmentNullInstructionsFragment() throws IOException {
		final OtrEngineHost host = mock(OtrEngineHost.class);
		when(host.getMaxFragmentSize(any(SessionID.class))).thenReturn(Integer.MAX_VALUE);
		final String message = "Some message that shouldn't be fragmented.";
		
		final OtrFragmenter fragmenter = new OtrFragmenter(this.createSessionMock(POLICY_V3, 0, 0), host);
		final String[] fragments = fragmenter.fragment(message);
		assertArrayEquals(new String[] {message}, fragments);
		verify(host, times(1)).getMaxFragmentSize(any(SessionID.class));
	}

	@Test
	public void testUnlimitedSizedFragmentToSingleMessage() throws IOException {
		final Session session = createSessionMock(POLICY_V3, 0, 0);
		final OtrEngineHost host = host(Integer.MAX_VALUE);
		
		OtrFragmenter fragmenter = new OtrFragmenter(session, host);
		String[] msg = fragmenter.fragment(specV3MessageFull);
		assertArrayEquals(new String[] {specV3MessageFull}, msg);
		verify(host, times(1)).getMaxFragmentSize(any(SessionID.class));
	}

	@Test
	public void testUnlimitedSizedFragmentToSingleMessageV2() throws IOException {
		final Session session = createSessionMock(POLICY_V2, 0, 0);
		final OtrEngineHost host = host(Integer.MAX_VALUE);
		
		OtrFragmenter fragmenter = new OtrFragmenter(session, host);
		String[] msg = fragmenter.fragment(specV2MessageFull);
		assertArrayEquals(new String[] {specV2MessageFull}, msg);
		verify(host, times(1)).getMaxFragmentSize(any(SessionID.class));
	}

	@Test
	public void testLargeEnoughFragmentToSingleMessage() throws IOException {
		final Session session = createSessionMock(POLICY_V3, 0, 0);
		final OtrEngineHost host = host(354);
		
		OtrFragmenter fragmenter = new OtrFragmenter(session, host);
		String[] msg = fragmenter.fragment(specV3MessageFull);
		assertArrayEquals(new String[] {specV3MessageFull}, msg);
		verify(host, times(1)).getMaxFragmentSize(any(SessionID.class));
	}

	@Test
	public void testLargeEnoughFragmentToSingleMessageV2() throws IOException {
		final Session session = createSessionMock(POLICY_V2, 0, 0);
		final OtrEngineHost host = host(830);
		
		OtrFragmenter fragmenter = new OtrFragmenter(session, host);
		String[] msg = fragmenter.fragment(specV2MessageFull);
		assertArrayEquals(new String[] {specV2MessageFull}, msg);
		verify(host, times(1)).getMaxFragmentSize(any(SessionID.class));
	}

	@Test
	public void testCalculateNumberOfFragmentsUnlimitedSize() throws IOException {
		final Session session = createSessionMock(POLICY_V3, 0, 0);
		final OtrEngineHost host = host(Integer.MAX_VALUE);
		
		OtrFragmenter fragmenter = new OtrFragmenter(session, host);
		int num = fragmenter.numberOfFragments(specV3MessageFull);
		assertEquals(1, num);
		verify(host, times(1)).getMaxFragmentSize(any(SessionID.class));
	}

	@Test
	public void testCalculateNumberOfFragmentsLargeEnoughSize() throws IOException {
		final Session session = createSessionMock(POLICY_V3, 0, 0);
		final OtrEngineHost host = host(1000);
		
		OtrFragmenter fragmenter = new OtrFragmenter(session, host);
		int num = fragmenter.numberOfFragments(specV3MessageFull);
		assertEquals(1, num);
		verify(host, times(1)).getMaxFragmentSize(any(SessionID.class));
	}

	@Test
	public void testCalculateNumberOfFragmentsNumFragmentsSmallFragmentSize() throws IOException {
		final Session session = createSessionMock(POLICY_V3, 0, 0);
		final OtrEngineHost host = host(199);

		OtrFragmenter fragmenter = new OtrFragmenter(session, host);
		int num = fragmenter.numberOfFragments(specV3MessageFull);
		assertEquals(3, num);
		verify(host, times(1)).getMaxFragmentSize(any(SessionID.class));
	}

	@Test
	public void testCalculateNumberOfFragmentsNumFragmentsSmallFragmentSize2() throws IOException {
		final Session session = createSessionMock(POLICY_V3, 0, 0);
		final OtrEngineHost host = host(80);

		OtrFragmenter fragmenter = new OtrFragmenter(session, host);
		int num = fragmenter.numberOfFragments(specV3MessageFull);
		assertEquals(9, num);
		verify(host, times(1)).getMaxFragmentSize(any(SessionID.class));
	}

	@Test(expected = IOException.class)
	public void testFragmentSizeTooSmallForOverhead() throws IOException {
		final Session session = createSessionMock(POLICY_V3, 0, 0);
		final OtrEngineHost host = host(35);

		OtrFragmenter fragmenter = new OtrFragmenter(session, host);
		fragmenter.numberOfFragments(specV3MessageFull);
	}
	
	@Test(expected = IOException.class)
	public void testFragmentSizeTooSmallForPayload() throws IOException {
		Session session = createSessionMock(POLICY_V3, 0, 0);
		OtrFragmenter fragmenter = new OtrFragmenter(session, host(OtrFragmenter.computeHeaderV3Size()));
		fragmenter.numberOfFragments(specV3MessageFull);
	}

	@Test
	public void testV3MessageToSplit() throws IOException {
		final Session session = createSessionMock(POLICY_V3, 0x5a73a599, 0x27e31597);
		final OtrEngineHost host = host(199);
		
		OtrFragmenter fragmenter = new OtrFragmenter(session, host);
		String[] msg = fragmenter.fragment(specV3MessageFull);
		assertArrayEquals(specV3MessageParts199, msg);
		verify(host, times(1)).getMaxFragmentSize(any(SessionID.class));
	}

	@Test
	public void testV2MessageToSplit() throws IOException {
		final Session session = createSessionMock(POLICY_V2, 0, 0);
		final OtrEngineHost host = host(318);
		
		OtrFragmenter fragmenter = new OtrFragmenter(session, host);
		String[] msg = fragmenter.fragment(specV2MessageFull);
		assertArrayEquals(specV2MessageParts318, msg);
		verify(host, times(1)).getMaxFragmentSize(any(SessionID.class));
	}

	@Test(expected = UnsupportedOperationException.class)
	public void testV1ComputeHeaderSize() throws IOException {
		Session session = createSessionMock(POLICY_V1, 0, 0);
		OtrFragmenter fragmenter = new OtrFragmenter(session, host(310));
		fragmenter.numberOfFragments(specV2MessageFull);
	}

	@Test(expected = UnsupportedOperationException.class)
	public void testV1MessageToSplit() throws IOException {
		Session session = createSessionMock(POLICY_V1, 0, 0);
		OtrFragmenter fragmenter = new OtrFragmenter(session, host(310));
		fragmenter.fragment(specV2MessageFull);
	}

	@Test
	public void testEnsureV3WhenMultipleVersionsAllowed() throws IOException {
		final Session session = createSessionMock(POLICY_V23, 0x5a73a599, 0x27e31597);
		final OtrEngineHost host = host(199);
		
		OtrFragmenter fragmenter = new OtrFragmenter(session, host);
		String[] msg = fragmenter.fragment(specV3MessageFull);
		assertArrayEquals(specV3MessageParts199, msg);
		verify(host, times(1)).getMaxFragmentSize(any(SessionID.class));
	}
	
	@Test(expected = IOException.class)
	public void testExceedProtocolMaximumNumberOfFragments() throws IOException {
		final String veryLongString = new String(new char[65537]).replace('\0', 'a');
		Session session = createSessionMock(POLICY_V3, 0x5a73a599, 0x27e31597);
		OtrFragmenter fragmenter = new OtrFragmenter(session, host(OtrFragmenter.computeHeaderV3Size() + 1));
		fragmenter.fragment(veryLongString);
	}
	
	@Test
	public void testFragmentPatternsV3() throws IOException {		
		final Pattern OTRv3_FRAGMENT_PATTERN = Pattern.compile("^\\?OTR\\|[0-9abcdef]{8}\\|[0-9abcdef]{8},\\d{5},\\d{5},[a-zA-Z0-9\\+/=\\?:]+,$");
		final String payload = new String(Base64.encode(RandomStringUtils.random(1700).getBytes(SerializationUtils.UTF8)));
		final Session session = createSessionMock(POLICY_V3, 0x0a73a599, 0x00000007);
		final OtrEngineHost host = host(150);
		
		OtrFragmenter fragmenter = new OtrFragmenter(session, host);
		String[] msg = fragmenter.fragment(payload);
		int count = 1;
		for (String part : msg) {
			assertTrue(OTRv3_FRAGMENT_PATTERN.matcher(part).matches());
			// Test monotonic increase of part numbers ...
			int partNumber = Integer.parseInt(part.substring(23, 28), 10);
			assertEquals(count, partNumber);
			count++;
		}
		verify(host, times(1)).getMaxFragmentSize(any(SessionID.class));
	}
	
	@Test
	public void testFragmentPatternsV2() throws IOException {		
		final Pattern OTRv2_FRAGMENT_PATTERN = Pattern.compile("^\\?OTR,\\d{1,5},\\d{1,5},[a-zA-Z0-9\\+/=\\?:]+,$");
		final String payload = new String(Base64.encode(RandomStringUtils.random(700).getBytes(SerializationUtils.UTF8)));
		final Session session = createSessionMock(POLICY_V2, 0, 0);
		final OtrEngineHost host = host(150);
		
		OtrFragmenter fragmenter = new OtrFragmenter(session, host);
		String[] msg = fragmenter.fragment(payload);
		int count = 1;
		for (String part : msg) {
			assertTrue(OTRv2_FRAGMENT_PATTERN.matcher(part).matches());
			// Test monotonic increase of part numbers ...
			String temp = part.substring(5, 11);
			int partNumber = Integer.parseInt(temp.substring(0, temp.indexOf(',')), 10);
			assertEquals(count, partNumber);
			count++;
		}
		verify(host, times(1)).getMaxFragmentSize(any(SessionID.class));
	}
	
	/**
	 * Create mock OtrEngineHost which returns the provided instructions.
	 *
	 * @param instructions the fragmentation instructions
	 * @return returns mock host
	 */
	private OtrEngineHost host(final int maxFragmentSize) {
		final OtrEngineHost host = mock(OtrEngineHost.class);
		when(host.getMaxFragmentSize(any(SessionID.class)))
				.thenReturn(maxFragmentSize);
		return host;
	}

	/**
	 * Create a session mock using provided arguments.
	 * 
	 * @param policy
	 *            OTR policy
	 * @param sender
	 *            sender instance id
	 * @param receiver
	 *            receiver instance id
	 * @return returns session mock
	 */
	private Session createSessionMock(final OtrPolicy policy, final int sender,
			final int receiver) {
		InstanceTag senderInstance = mock(InstanceTag.class);
		when(senderInstance.getValue()).thenReturn(sender);
		InstanceTag receiverInstance = mock(InstanceTag.class);
		when(receiverInstance.getValue()).thenReturn(receiver);
		Session session = mock(Session.class);
		when(session.getSenderInstanceTag()).thenReturn(senderInstance);
		when(session.getReceiverInstanceTag()).thenReturn(
				receiverInstance);
		when(session.getSessionPolicy()).thenReturn(policy);
		return session;
	}
}
