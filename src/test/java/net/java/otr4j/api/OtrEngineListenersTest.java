/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.api;

import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

public class OtrEngineListenersTest {

    private Level originalLoggingLevel;

    @Before
    public void setUp() {
        final Logger logger = Logger.getLogger(OtrEngineListeners.class.getName());
        originalLoggingLevel = logger.getLevel();
        logger.setLevel(Level.OFF);
    }

    @After
    public void tearDown() {
        Logger.getLogger(OtrEngineListeners.class.getName()).setLevel(originalLoggingLevel);
    }

    @Test
    public void testSessionStatusChangedGoodListeners() {
        final SessionID s = new SessionID("localAccountID", "remoteAccountID", "protocolName");
        final OtrEngineListener l1 = mock(OtrEngineListener.class);
        final OtrEngineListener l2 = mock(OtrEngineListener.class);
        OtrEngineListeners.sessionStatusChanged(Arrays.asList(l1, l2), s, InstanceTag.ZERO_TAG);
        verify(l1).sessionStatusChanged(s, InstanceTag.ZERO_TAG);
        verify(l2).sessionStatusChanged(s, InstanceTag.ZERO_TAG);
    }

    @Test
    public void testSessionStatusChangedWithFaultyListener() {
        final SessionID s = new SessionID("localAccountID", "remoteAccountID", "protocolName");
        final OtrEngineListener l1 = mock(OtrEngineListener.class);
        final OtrEngineListener l2 = mock(OtrEngineListener.class);
        doThrow(new IllegalStateException("bad stuff happened")).when(l1).sessionStatusChanged(s, InstanceTag.ZERO_TAG);
        OtrEngineListeners.sessionStatusChanged(Arrays.asList(l1, l2), s, InstanceTag.ZERO_TAG);
        verify(l1).sessionStatusChanged(s, InstanceTag.ZERO_TAG);
        verify(l2).sessionStatusChanged(s, InstanceTag.ZERO_TAG);
    }
}
