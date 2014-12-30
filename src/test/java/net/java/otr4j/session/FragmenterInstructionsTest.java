package net.java.otr4j.session;

import static org.junit.Assert.*;

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
		assertEquals(1, instructions.maxFragmentsAllowed);
		assertEquals(100, instructions.maxFragmentSize);
	}
	
	@Test
	public void testVerifyNullInstructions() {
		FragmenterInstructions instructions = FragmenterInstructions.verify(null);
		assertEquals(FragmenterInstructions.UNLIMITED, instructions.maxFragmentsAllowed);
		assertEquals(FragmenterInstructions.UNLIMITED, instructions.maxFragmentSize);
	}
	
	@Test
	public void testVerifyCorrectInstructionsUnlimited() {
		FragmenterInstructions instructions = FragmenterInstructions.verify(new FragmenterInstructions(FragmenterInstructions.UNLIMITED, FragmenterInstructions.UNLIMITED));
		assertEquals(FragmenterInstructions.UNLIMITED, instructions.maxFragmentsAllowed);
		assertEquals(FragmenterInstructions.UNLIMITED, instructions.maxFragmentSize);
	}
	
	@Test
	public void testVerifyCorrectInstructionsPositiveValues() {
		FragmenterInstructions instructions = FragmenterInstructions.verify(new FragmenterInstructions(4, 210));
		assertEquals(4, instructions.maxFragmentsAllowed);
		assertEquals(210, instructions.maxFragmentSize);
	}
	
	@Test(expected = IllegalArgumentException.class)
	public void testVerifyBadFragmentsNumber() {
		FragmenterInstructions.verify(new FragmenterInstructions(-4, 50));
	}
	
	@Test(expected = IllegalArgumentException.class)
	public void testVerifyBadFragmentSize() {
		FragmenterInstructions.verify(new FragmenterInstructions(4, -50));
	}
	
	@Test(expected = IllegalArgumentException.class)
	public void testVerifyBadBoth() {
		FragmenterInstructions.verify(new FragmenterInstructions(-180, -50));
	}
}
