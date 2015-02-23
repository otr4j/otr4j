
package net.java.otr4j.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.Collection;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import net.java.otr4j.OtrException;
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

    private static final int DEFAULT_TIMEOUT_MS = 2000;
    private static final String SIMPLE_PASSWORD = "MATCH";
    private final String snippet;

    public SMPTest(final String snippet) {
        this.snippet = snippet;
    }

    // TODO these currently cause an Exception when used as question:
    // "nullshere:\0\0andhere:\0",
    // "tabbackslashT\t",
    // "backslashR\r",
    // "NEWLINE\n",
    @Parameters
    public static Collection<Object[]> data() {
        return Arrays
                .asList(new Object[][] {
                        { "plainAscii" },
                        { "" },
                        { "བོད་རིགས་ཀྱི་བོད་སྐད་བརྗོད་པ་དང་ "
                                + "བོད་རིགས་མང་ཆེ་བ་ནི་ནང་ཆོས་བྱེད་པ་དང་" },
                        { "تبتی قوم (Tibetan people)" },
                        { "Учените твърдят, че тибетците нямат" },
                        { "Câung-cŭk (藏族, Câung-ngṳ̄: བོད་པ་)" },
                        { "チベット系民族（チベットけいみんぞく）" },
                        { "原始汉人与原始藏缅人约在公元前4000年左右分开。" },
                        { "Տիբեթացիներ (ինքնանվանումը՝ պյոբա)," },
                        { "... Gezginci olarak" },
                        { "شْتَن Xotan" },
                        { "Tibeťané jsou" },
                        { "ئاچاڭ- تىبەت مىللىتى" },
                        { "Miscellaneous Symbols and Pictographs[1][2]"
                                + "Official Unicode Consortium code chart (PDF)" },
                        { "Royal Thai (ราชาศัพท์)" }, { "טיילאנדיש123 (ภาษาไทย)" },
                        { "ជើងអក្សរ cheung âksâr" }, { "중화인민공화국에서는 기본적으로 한족은 " },
                        { "पाठ्यांशः अत्र उपलभ्यतेसर्जनसामान्यलक्षणम्/Share-" },
                        { "திபெத்துக்கு வெகள்" },
                        { "អក្សរសាស្រ្តខែ្មរមានប្រវ៌ត្តជាងពីរពាន់ឆ្នាំមកហើយ " }, });
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
