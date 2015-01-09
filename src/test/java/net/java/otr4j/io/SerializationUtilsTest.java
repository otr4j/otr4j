package net.java.otr4j.io;

import java.io.IOException;

import junit.framework.Assert;

import org.junit.Test;

public class SerializationUtilsTest {

	@Test
	public void testOTRQueryMessageV1NotOTREncoded() {
		Assert.assertFalse(SerializationUtils.otrEncoded("?OTR? some other content ..."));
	}
	
	@Test
	public void testOTRQueryMessageV2NotOTREncoded() {
		Assert.assertFalse(SerializationUtils.otrEncoded("?OTRv2? some other content ..."));
	}
	
	@Test
	public void testOTRQueryMessageV23NotOTREncoded() {
		Assert.assertFalse(SerializationUtils.otrEncoded("?OTRv23? some other content ..."));
	}
	
	@Test
	public void testCorrectOTREncodingDetection() {
		Assert.assertTrue(SerializationUtils.otrEncoded("?OTR:AAMDJ+MVmSfjFZcAAAAAAQAAAAIAAADA1g5IjD1ZGLDVQEyCgCyn9hbrL3KAbGDdzE2ZkMyTKl7XfkSxh8YJnudstiB74i4BzT0W2haClg6dMary/jo9sMudwmUdlnKpIGEKXWdvJKT+hQ26h9nzMgEditLB8vjPEWAJ6gBXvZrY6ZQrx3gb4v0UaSMOMiR5sB7Eaulb2Yc6RmRnnlxgUUC2alosg4WIeFN951PLjScajVba6dqlDi+q1H5tPvI5SWMN7PCBWIJ41+WvF+5IAZzQZYgNaVLbAAAAAAAAAAEAAAAHwNiIi5Ms+4PsY/L2ipkTtquknfx6HodLvk3RAAAAAA==."));
	}

	@Test
	public void testOTRv2FragmentNotOTREncoded() {
		Assert.assertFalse(SerializationUtils.otrEncoded("?OTR,1,3,?OTR:AAMDJ+MVmSfjFZcAAAAAAQAAAAIAAADA1g5IjD1ZGLDVQEyCgCyn9hbrL3KAbGDdzE2ZkMyTKl7XfkSxh8YJnudstiB74i4BzT0W2haClg6dMary/jo9sMudwmUdlnKpIGEKXWdvJKT+hQ26h9nzMgEditLB8v,"));
	}

	@Test
	public void testOTRv3FragmentNotOTREncoded() {
		Assert.assertFalse(SerializationUtils.otrEncoded("?OTR|5a73a599|27e31597,00001,00003,?OTR:AAMDJ+MVmSfjFZcAAAAAAQAAAAIAAADA1g5IjD1ZGLDVQEyCgCyn9hbrL3KAbGDdzE2ZkMyTKl7XfkSxh8YJnudstiB74i4BzT0W2haClg6dMary/jo9sMudwmUdlnKpIGEKXWdvJKT+hQ26h9nzMgEditLB8v,"));
	}

	@Test(expected = IOException.class)
	public void testToMessageWrongProtocolVersion() throws Exception {
		SerializationUtils
				.toMessage("?OTR:AAQDdAYBciqzcLcAAAAAAQAAAAIAAADAh7NAcXJNpXa8qw89tvx4eoxhR3iaTx4omdj34HRpgMXDGIR7Kp4trQ+L5k8INcse58RJWHQPYW+dgKMkwrpCNJIgaqjzaiJC5+QPylSchrAB78MNZiCLXW7YU3dSic1Pm0dpa57wwiFp7sfSm00GEcE7M1bRe7Pr1zgb8KP/5PJUeI7IVmYTDj5ONWUsyoocD40RQ+Bu+I7GLgb7WICGZ6mpof3UGEFFmJLB5lDfunhCqb0d3MRP0G6k/8YJzjIlAAAAAAAAAAEAAAAF8VtymMJceqLiPIYPjRTLmlr5gQPirDY87QAAAAA=.");
	}

}
