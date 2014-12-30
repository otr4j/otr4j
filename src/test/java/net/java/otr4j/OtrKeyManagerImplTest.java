package net.java.otr4j;

import static org.junit.Assert.*;

import org.junit.Test;

import net.java.otr4j.session.SessionID;

public class OtrKeyManagerImplTest {

	private SessionID aliceSessionID = new SessionID("Alice@Wonderland",
			"Bob@Wonderland", "Scytale");

	@Test
	public void test() throws Exception {
		OtrKeyManager keyManager = new OtrKeyManagerImpl("otr.properties");
		keyManager.generateLocalKeyPair(aliceSessionID);

		keyManager.verify(aliceSessionID);
		assertTrue(keyManager.isVerified(aliceSessionID));
	}
}
