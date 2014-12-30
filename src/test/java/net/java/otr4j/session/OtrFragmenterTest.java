package net.java.otr4j.session;

import static org.junit.Assert.*;

import java.io.IOException;
import java.util.regex.Pattern;

import net.java.otr4j.OtrEngineHost;
import net.java.otr4j.OtrPolicy;

import org.apache.commons.lang3.RandomStringUtils;
import org.bouncycastle.util.encoders.Base64;
import org.junit.Test;
import org.mockito.Mockito;

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
	public void testNullPolicyConstruction() {
		FragmenterInstructions instructions = new FragmenterInstructions(2, 100);
		new OtrFragmenter(null, host(instructions));
	}

	@Test(expected = NullPointerException.class)
	public void testNullHostConstruction() {
		Session session = createSessionMock(null, 0, 0);
		new OtrFragmenter(session, null);
	}

	@Test
	public void testConstruction() {
		Session session = createSessionMock(null, 0, 0);
		FragmenterInstructions instructions = new FragmenterInstructions(2, 100);
		new OtrFragmenter(session, host(instructions));
	}
	
	@Test
	public void testGetHost() {
		Session session = createSessionMock(null, 0, 0);
		FragmenterInstructions instructions = new FragmenterInstructions(2, 100);
		OtrEngineHost host = host(instructions);
		OtrFragmenter fragmenter = new OtrFragmenter(session, host);
		assertSame(host, fragmenter.getHost());
	}

	@Test
	public void testFragmentNullInstructionsCompute() throws IOException {
		final OtrEngineHost host = Mockito.mock(OtrEngineHost.class);
		Mockito.when(host.getFragmenterInstructions(Mockito.any(SessionID.class))).thenReturn(null);
		final String message = "Some message that shouldn't be fragmented.";
		
		final OtrFragmenter fragmenter = new OtrFragmenter(this.createSessionMock(POLICY_V3, 0, 0), host);
		final int number = fragmenter.numberOfFragments(message);
		assertEquals(1, number);
		Mockito.verify(host, Mockito.times(1)).getFragmenterInstructions(Mockito.any(SessionID.class));
	}

	@Test
	public void testFragmentNullInstructionsFragment() throws IOException {
		final OtrEngineHost host = Mockito.mock(OtrEngineHost.class);
		Mockito.when(host.getFragmenterInstructions(Mockito.any(SessionID.class))).thenReturn(null);
		final String message = "Some message that shouldn't be fragmented.";
		
		final OtrFragmenter fragmenter = new OtrFragmenter(this.createSessionMock(POLICY_V3, 0, 0), host);
		final String[] fragments = fragmenter.fragment(message);
		assertArrayEquals(new String[] {message}, fragments);
		Mockito.verify(host, Mockito.times(1)).getFragmenterInstructions(Mockito.any(SessionID.class));
	}

	@Test
	public void testUnlimitedSizedFragmentToSingleMessage() throws IOException {
		final Session session = createSessionMock(POLICY_V3, 0, 0);
		final FragmenterInstructions instructions = new FragmenterInstructions(-1, -1);
		final OtrEngineHost host = host(instructions);
		
		OtrFragmenter fragmenter = new OtrFragmenter(session, host);
		String[] msg = fragmenter.fragment(specV3MessageFull);
		assertArrayEquals(new String[] {specV3MessageFull}, msg);
		Mockito.verify(host, Mockito.times(1)).getFragmenterInstructions(Mockito.any(SessionID.class));
	}

	@Test
	public void testUnlimitedSizedFragmentToSingleMessageV2() throws IOException {
		final Session session = createSessionMock(POLICY_V2, 0, 0);
		final FragmenterInstructions instructions = new FragmenterInstructions(-1, -1);
		final OtrEngineHost host = host(instructions);
		
		OtrFragmenter fragmenter = new OtrFragmenter(session, host);
		String[] msg = fragmenter.fragment(specV2MessageFull);
		assertArrayEquals(new String[] {specV2MessageFull}, msg);
		Mockito.verify(host, Mockito.times(1)).getFragmenterInstructions(Mockito.any(SessionID.class));
	}

	@Test
	public void testLargeEnoughFragmentToSingleMessage() throws IOException {
		final Session session = createSessionMock(POLICY_V3, 0, 0);
		final FragmenterInstructions instructions = new FragmenterInstructions(-1, 354);
		final OtrEngineHost host = host(instructions);
		
		OtrFragmenter fragmenter = new OtrFragmenter(session, host);
		String[] msg = fragmenter.fragment(specV3MessageFull);
		assertArrayEquals(new String[] {specV3MessageFull}, msg);
		Mockito.verify(host, Mockito.times(1)).getFragmenterInstructions(Mockito.any(SessionID.class));
	}

	@Test
	public void testLargeEnoughFragmentToSingleMessageV2() throws IOException {
		final Session session = createSessionMock(POLICY_V2, 0, 0);
		final FragmenterInstructions instructions = new FragmenterInstructions(-1, 830);
		final OtrEngineHost host = host(instructions);
		
		OtrFragmenter fragmenter = new OtrFragmenter(session, host);
		String[] msg = fragmenter.fragment(specV2MessageFull);
		assertArrayEquals(new String[] {specV2MessageFull}, msg);
		Mockito.verify(host, Mockito.times(1)).getFragmenterInstructions(Mockito.any(SessionID.class));
	}

	@Test
	public void testCalculateNumberOfFragmentsUnlimitedSize() throws IOException {
		final Session session = createSessionMock(POLICY_V3, 0, 0);
		final FragmenterInstructions instructions = new FragmenterInstructions(-1, -1);
		final OtrEngineHost host = host(instructions);
		
		OtrFragmenter fragmenter = new OtrFragmenter(session, host);
		int num = fragmenter.numberOfFragments(specV3MessageFull);
		assertEquals(1, num);
		Mockito.verify(host, Mockito.times(1)).getFragmenterInstructions(Mockito.any(SessionID.class));
	}

	@Test
	public void testCalculateNumberOfFragmentsLargeEnoughSize() throws IOException {
		final Session session = createSessionMock(POLICY_V3, 0, 0);
		final FragmenterInstructions instructions = new FragmenterInstructions(-1, 1000);
		final OtrEngineHost host = host(instructions);
		
		OtrFragmenter fragmenter = new OtrFragmenter(session, host);
		int num = fragmenter.numberOfFragments(specV3MessageFull);
		assertEquals(1, num);
		Mockito.verify(host, Mockito.times(1)).getFragmenterInstructions(Mockito.any(SessionID.class));
	}

	@Test
	public void testCalculateNumberOfFragmentsNumFragmentsSmallFragmentSize() throws IOException {
		final Session session = createSessionMock(POLICY_V3, 0, 0);;
		final FragmenterInstructions instructions = new FragmenterInstructions(-1, 199);
		final OtrEngineHost host = host(instructions);

		OtrFragmenter fragmenter = new OtrFragmenter(session, host);
		int num = fragmenter.numberOfFragments(specV3MessageFull);
		assertEquals(3, num);
		Mockito.verify(host, Mockito.times(1)).getFragmenterInstructions(Mockito.any(SessionID.class));
	}

	@Test
	public void testCalculateNumberOfFragmentsNumFragmentsSmallFragmentSize2() throws IOException {
		final Session session = createSessionMock(POLICY_V3, 0, 0);;
		final FragmenterInstructions instructions = new FragmenterInstructions(-1, 80);
		final OtrEngineHost host = host(instructions);

		OtrFragmenter fragmenter = new OtrFragmenter(session, host);
		int num = fragmenter.numberOfFragments(specV3MessageFull);
		assertEquals(9, num);
		Mockito.verify(host, Mockito.times(1)).getFragmenterInstructions(Mockito.any(SessionID.class));
	}

	@Test(expected = IOException.class)
	public void testFragmentSizeTooSmallForOverhead() throws IOException {
		final Session session = createSessionMock(POLICY_V3, 0, 0);;
		final FragmenterInstructions instructions = new FragmenterInstructions(-1, 35);
		final OtrEngineHost host = host(instructions);

		OtrFragmenter fragmenter = new OtrFragmenter(session, host);
		fragmenter.numberOfFragments(specV3MessageFull);
	}
	
	@Test(expected = IOException.class)
	public void testFragmentSizeTooSmallForPayload() throws IOException {
		Session session = createSessionMock(POLICY_V3, 0, 0);
		FragmenterInstructions instructions = new FragmenterInstructions(-1,
				OtrFragmenter.computeHeaderV3Size());
		OtrFragmenter fragmenter = new OtrFragmenter(session, host(instructions));
		fragmenter.numberOfFragments(specV3MessageFull);
	}

	@Test(expected = IOException.class)
	public void testNumFragmentsTooLimited() throws IOException {
		Session session = createSessionMock(POLICY_V3, 0, 0);
		FragmenterInstructions instructions = new FragmenterInstructions(2, 100);
		OtrFragmenter fragmenter = new OtrFragmenter(session, host(instructions));
		fragmenter.fragment(specV3MessageFull);
	}

	@Test
	public void testV3MessageToSplit() throws IOException {
		final Session session = createSessionMock(POLICY_V3, 0x5a73a599, 0x27e31597);
		final FragmenterInstructions instructions = new FragmenterInstructions(1000, 199);
		final OtrEngineHost host = host(instructions);
		
		OtrFragmenter fragmenter = new OtrFragmenter(session, host);
		String[] msg = fragmenter.fragment(specV3MessageFull);
		assertArrayEquals(specV3MessageParts199, msg);
		Mockito.verify(host, Mockito.times(1)).getFragmenterInstructions(Mockito.any(SessionID.class));
	}

	@Test
	public void testV2MessageToSplit() throws IOException {
		final Session session = createSessionMock(POLICY_V2, 0, 0);
		final FragmenterInstructions instructions = new FragmenterInstructions(-1, 318);
		final OtrEngineHost host = host(instructions);
		
		OtrFragmenter fragmenter = new OtrFragmenter(session, host);
		String[] msg = fragmenter.fragment(specV2MessageFull);
		assertArrayEquals(specV2MessageParts318, msg);
		Mockito.verify(host, Mockito.times(1)).getFragmenterInstructions(Mockito.any(SessionID.class));
	}

	@Test(expected = UnsupportedOperationException.class)
	public void testV1ComputeHeaderSize() throws IOException {
		Session session = createSessionMock(POLICY_V1, 0, 0);
		FragmenterInstructions instructions = new FragmenterInstructions(-1, 310);
		OtrFragmenter fragmenter = new OtrFragmenter(session, host(instructions));
		fragmenter.numberOfFragments(specV2MessageFull);
	}

	@Test(expected = UnsupportedOperationException.class)
	public void testV1MessageToSplit() throws IOException {
		Session session = createSessionMock(POLICY_V1, 0, 0);
		FragmenterInstructions instructions = new FragmenterInstructions(-1, 310);
		OtrFragmenter fragmenter = new OtrFragmenter(session, host(instructions));
		fragmenter.fragment(specV2MessageFull);
	}

	@Test
	public void testEnsureV3WhenMultipleVersionsAllowed() throws IOException {
		final Session session = createSessionMock(POLICY_V23, 0x5a73a599, 0x27e31597);
		final FragmenterInstructions instructions = new FragmenterInstructions(-1, 199);
		final OtrEngineHost host = host(instructions);
		
		OtrFragmenter fragmenter = new OtrFragmenter(session, host);
		String[] msg = fragmenter.fragment(specV3MessageFull);
		assertArrayEquals(specV3MessageParts199, msg);
		Mockito.verify(host, Mockito.times(1)).getFragmenterInstructions(Mockito.any(SessionID.class));
	}
	
	@Test(expected = IOException.class)
	public void testExceedProtocolMaximumNumberOfFragments() throws IOException {
		final String veryLongString = new String(new char[65537]).replace('\0', 'a');
		Session session = createSessionMock(POLICY_V3, 0x5a73a599, 0x27e31597);
		FragmenterInstructions instructions = new FragmenterInstructions(-1,
				OtrFragmenter.computeHeaderV3Size() + 1);
		OtrFragmenter fragmenter = new OtrFragmenter(session, host(instructions));
		fragmenter.fragment(veryLongString);
	}
	
	@Test
	public void testFragmentPatternsV3() throws IOException {		
		final Pattern OTRv3_FRAGMENT_PATTERN = Pattern.compile("^\\?OTR\\|[0-9abcdef]{8}\\|[0-9abcdef]{8},\\d{5},\\d{5},[a-zA-Z0-9\\+/=\\?:]+,$");
		final String payload = new String(Base64.encode(RandomStringUtils.random(1700).getBytes("UTF-8")));
		final Session session = createSessionMock(POLICY_V3, 0x0a73a599, 0x00000007);
		final FragmenterInstructions instructions = new FragmenterInstructions(
				-1, 150);
		final OtrEngineHost host = host(instructions);
		
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
		Mockito.verify(host, Mockito.times(1)).getFragmenterInstructions(Mockito.any(SessionID.class));
	}
	
	@Test
	public void testFragmentPatternsV2() throws IOException {		
		final Pattern OTRv2_FRAGMENT_PATTERN = Pattern.compile("^\\?OTR,\\d{1,5},\\d{1,5},[a-zA-Z0-9\\+/=\\?:]+,$");
		final String payload = new String(Base64.encode(RandomStringUtils.random(700).getBytes("UTF-8")));
		final Session session = createSessionMock(POLICY_V2, 0, 0);
		final FragmenterInstructions instructions = new FragmenterInstructions(-1, 150);
		final OtrEngineHost host = host(instructions);
		
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
		Mockito.verify(host, Mockito.times(1)).getFragmenterInstructions(Mockito.any(SessionID.class));
	}
	
	/**
	 * Create mock OtrEngineHost which returns the provided instructions.
	 *
	 * @param instructions the fragmentation instructions
	 * @return returns mock host
	 */
	private OtrEngineHost host(final FragmenterInstructions instructions) {
		final OtrEngineHost host = Mockito.mock(OtrEngineHost.class);
		Mockito.when(
				host.getFragmenterInstructions(Mockito.any(SessionID.class)))
				.thenReturn(instructions);
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
		InstanceTag senderInstance = Mockito.mock(InstanceTag.class);
		Mockito.when(senderInstance.getValue()).thenReturn(sender);
		InstanceTag receiverInstance = Mockito.mock(InstanceTag.class);
		Mockito.when(receiverInstance.getValue()).thenReturn(receiver);
		Session session = Mockito.mock(Session.class);
		Mockito.when(session.getSenderInstanceTag()).thenReturn(senderInstance);
		Mockito.when(session.getReceiverInstanceTag()).thenReturn(
				receiverInstance);
		Mockito.when(session.getSessionPolicy()).thenReturn(policy);
		return session;
	}
}
