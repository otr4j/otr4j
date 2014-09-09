package net.java.otr4j.session;

import org.junit.Assert;
import org.junit.Test;

/**
 * Fragmenter Instructions tests.
 *
 * @author Danny van Heumen
 */
public class FragmenterInstructionsTest {

	@Test
	public void testConstruction() {
		FragmenterInstructions instructions = new FragmenterInstructions(1, 100);
		Assert.assertEquals(1, instructions.maxFragmentsAllowed);
		Assert.assertEquals(100, instructions.maxFragmentSize);
	}
}
