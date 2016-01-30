
package net.java.otr4j.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Collection;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import net.java.otr4j.OtrException;
import net.java.otr4j.io.SerializationUtils;
import net.java.otr4j.session.Session;
import net.java.otr4j.test.dummyclient.DummyClient;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

/**
 * Test that Socialist Millionaire Protocol verification is working.
 *
 * @author Hans-Christoph Steiner
 */
@RunWith(Parameterized.class)
public class SMPTest {

    private static final int DEFAULT_TIMEOUT_MS = 10000;
    private static final String SIMPLE_PASSWORD = "MATCH";
    private final String snippet;

    public SMPTest(final String snippet) {
        this.snippet = snippet;
    }

    @Parameters
    public static Collection<Object[]> data() {
        // this crazy format is needed by JUnit:
        // https://github.com/junit-team/junit/wiki/Parameterized-tests
        ArrayList<Object[]> list = new ArrayList<Object[]>(TestStrings.unicodes.length);
        for (String string : TestStrings.unicodes)
            list.add(new Object[] {
                    string
            });
        return list;
    }

    private static class SMPTestResult {

        private final int aliceResult;
        private final int bobResult;

        public SMPTestResult(final int aliceResult, final int bobResult) {
            this.aliceResult = aliceResult;
            this.bobResult = bobResult;
        }

        public int getAliceResult() {
            return this.aliceResult;
        }

        public int getBobResult() {
            return this.bobResult;
        }

    }

    SMPTestResult runSMPTest(final String question, final String alicePassword,
            final String bobPassword) throws InterruptedException, OtrException {
        final CountDownLatch aliceLock = new CountDownLatch(1);
        final CountDownLatch bobLock = new CountDownLatch(1);
        final DummyClient[] convo = DummyClient.getConversation(aliceLock, bobLock);
        final DummyClient alice = convo[0];
        final DummyClient bob = convo[1];

        assertTrue(DummyClient.forceStartOtr(alice, bob));
        assertEquals(DummyClient.NOTSET, alice.getVerified());
        assertEquals(DummyClient.NOTSET, bob.getVerified());

        final Session aliceSession = alice.getSession();
        final Session bobSession = bob.getSession();

        assertFalse(aliceSession.isSmpInProgress());
        assertFalse(bobSession.isSmpInProgress());
        aliceSession.initSmp(question, alicePassword);

        assertTrue(aliceSession.isSmpInProgress());
        assertFalse(bobSession.isSmpInProgress());
        bob.pollReceivedMessage();

        // wait for the password prompt that is triggered by:
        // OtrEngineHost.askForSecret()
        assertTrue(bobLock.await(DEFAULT_TIMEOUT_MS, TimeUnit.MILLISECONDS));

        // make sure that the SMP question arrived intact
        String bobReceivedQuestion = bob.getSmpQuestion(bobSession.getSessionID());
        assertEquals(question, bobReceivedQuestion);
        if (question != null) {
            assertEquals(question.length(), bobReceivedQuestion.length());
            assertEquals(question.getBytes(SerializationUtils.UTF8).length,
                    bobReceivedQuestion.getBytes(SerializationUtils.UTF8).length);
            assertEquals(question.getBytes(SerializationUtils.UTF8).length,
                    bobReceivedQuestion.getBytes(SerializationUtils.UTF8).length);
        }

        bobSession.respondSmp(question, bobPassword);
        assertTrue(aliceSession.isSmpInProgress());
        assertTrue(bobSession.isSmpInProgress());

        // SMP2
        alice.pollReceivedMessage();
        assertTrue(aliceSession.isSmpInProgress());
        assertTrue(bobSession.isSmpInProgress());

        // SMP3
        bob.pollReceivedMessage();
        assertTrue(aliceSession.isSmpInProgress());
        assertFalse(bobSession.isSmpInProgress());

        // SMP4
        alice.pollReceivedMessage();
        assertFalse(aliceSession.isSmpInProgress());
        assertFalse(bobSession.isSmpInProgress());

        // wait for SMP to complete
        assertTrue(aliceLock.await(DEFAULT_TIMEOUT_MS, TimeUnit.MILLISECONDS));

        return new SMPTestResult(alice.getVerified(), bob.getVerified());
    }

    @Test(timeout = DEFAULT_TIMEOUT_MS)
    public void goodPasswordNoQuestion() throws Exception {
        final SMPTestResult result = runSMPTest(null, this.snippet, this.snippet);
        assertEquals(DummyClient.VERIFIED, result.getAliceResult());
        assertEquals(DummyClient.VERIFIED, result.getBobResult());
    }

    @Test(timeout = DEFAULT_TIMEOUT_MS)
    public void goodPasswordWithQuestion() throws Exception {
        // isolate the effects of encodings to the question
        final SMPTestResult result = runSMPTest(this.snippet, SIMPLE_PASSWORD, SIMPLE_PASSWORD);
        assertEquals(DummyClient.VERIFIED, result.getAliceResult());
        assertEquals(DummyClient.VERIFIED, result.getBobResult());
    }

    @Test(timeout = DEFAULT_TIMEOUT_MS)
    public void badPasswordNoQuestion() throws Exception {
        final SMPTestResult result = runSMPTest(null, this.snippet, "BAD" + this.snippet);
        assertEquals(DummyClient.UNVERIFIED, result.getAliceResult());
        assertEquals(DummyClient.UNVERIFIED, result.getBobResult());
    }

    @Test(timeout = DEFAULT_TIMEOUT_MS)
    public void badPasswordWithQuestion() throws Exception {
        // isolate the effects of encodings to the question
        final SMPTestResult result =
                runSMPTest(this.snippet, SIMPLE_PASSWORD, SIMPLE_PASSWORD + "NOT");
        assertEquals(DummyClient.UNVERIFIED, result.getAliceResult());
        assertEquals(DummyClient.UNVERIFIED, result.getBobResult());
    }
}
