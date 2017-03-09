/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j;

import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

import net.java.otr4j.session.InstanceTag;
import net.java.otr4j.session.SessionID;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

public class OtrEngineListenerUtilTest {

    private Level originalLoggingLevel;

    @Before
    public void setUp() {
        final Logger logger = Logger.getLogger("net.java.otr4j");
        originalLoggingLevel = logger.getLevel();
        logger.setLevel(Level.SEVERE);
    }

    @After
    public void tearDown() {
        Logger.getLogger("net.java.otr4j").setLevel(originalLoggingLevel);
    }

    @Test
    public void testSessionStatusChangedGoodListeners() {
        final SessionID s = new SessionID("localAccountID", "remoteAccountID", "protocolName");
        final OtrEngineListener l1 = mock(OtrEngineListener.class);
        final OtrEngineListener l2 = mock(OtrEngineListener.class);
        OtrEngineListenerUtil.sessionStatusChanged(Arrays.asList(l1, l2), s, InstanceTag.ZERO_TAG);
        verify(l1).sessionStatusChanged(s, InstanceTag.ZERO_TAG);
        verify(l2).sessionStatusChanged(s, InstanceTag.ZERO_TAG);
    }

    @Test
    public void testSessionStatusChangedWithFaultyListener() {
        final SessionID s = new SessionID("localAccountID", "remoteAccountID", "protocolName");
        final OtrEngineListener l1 = mock(OtrEngineListener.class);
        final OtrEngineListener l2 = mock(OtrEngineListener.class);
        doThrow(new IllegalStateException("bad stuff happened")).when(l1).sessionStatusChanged(s, InstanceTag.ZERO_TAG);
        OtrEngineListenerUtil.sessionStatusChanged(Arrays.asList(l1, l2), s, InstanceTag.ZERO_TAG);
        verify(l1).sessionStatusChanged(s, InstanceTag.ZERO_TAG);
        verify(l2).sessionStatusChanged(s, InstanceTag.ZERO_TAG);
    }

    @Test
    public void testMultipleInstancesChangedGoodListeners() {
        final SessionID s = new SessionID("localAccountID", "remoteAccountID", "protocolName");
        final OtrEngineListener l1 = mock(OtrEngineListener.class);
        final OtrEngineListener l2 = mock(OtrEngineListener.class);
        OtrEngineListenerUtil.multipleInstancesDetected(Arrays.asList(l1, l2), s);
        verify(l1).multipleInstancesDetected(s);
        verify(l2).multipleInstancesDetected(s);
    }

    @Test
    public void testMultipleInstancesChangedWithFaultyListener() {
        final SessionID s = new SessionID("localAccountID", "remoteAccountID", "protocolName");
        final OtrEngineListener l1 = mock(OtrEngineListener.class);
        final OtrEngineListener l2 = mock(OtrEngineListener.class);
        doThrow(new IllegalStateException("bad stuff happened")).when(l1).multipleInstancesDetected(s);
        OtrEngineListenerUtil.multipleInstancesDetected(Arrays.asList(l1, l2), s);
        verify(l1).multipleInstancesDetected(s);
        verify(l2).multipleInstancesDetected(s);
    }

    @Test
    public void testOutgoingSessionChangedGoodListeners() {
        final SessionID s = new SessionID("localAccountID", "remoteAccountID", "protocolName");
        final OtrEngineListener l1 = mock(OtrEngineListener.class);
        final OtrEngineListener l2 = mock(OtrEngineListener.class);
        OtrEngineListenerUtil.outgoingSessionChanged(Arrays.asList(l1, l2), s);
        verify(l1).outgoingSessionChanged(s);
        verify(l2).outgoingSessionChanged(s);
    }

    @Test
    public void testOutgoingSessionChangedWithFaultyListener() {
        final SessionID s = new SessionID("localAccountID", "remoteAccountID", "protocolName");
        final OtrEngineListener l1 = mock(OtrEngineListener.class);
        final OtrEngineListener l2 = mock(OtrEngineListener.class);
        doThrow(new IllegalStateException("bad stuff happened")).when(l1).outgoingSessionChanged(s);
        OtrEngineListenerUtil.outgoingSessionChanged(Arrays.asList(l1, l2), s);
        verify(l1).outgoingSessionChanged(s);
        verify(l2).outgoingSessionChanged(s);
    }
}
