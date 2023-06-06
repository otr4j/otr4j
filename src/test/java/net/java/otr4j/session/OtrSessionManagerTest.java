/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.session;

import net.java.otr4j.api.OtrEngineHost;
import net.java.otr4j.api.OtrEngineListener;
import net.java.otr4j.api.OtrPolicy;
import net.java.otr4j.api.Session;
import net.java.otr4j.api.SessionID;
import net.java.otr4j.crypto.DSAKeyPair;
import net.java.otr4j.crypto.ed448.EdDSAKeyPair;
import org.junit.Test;

import java.security.SecureRandom;

import static net.java.otr4j.api.OtrPolicy.OPPORTUNISTIC;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Tests for OtrSessionManager.
 *
 * @author Danny van Heumen
 */
@SuppressWarnings("ConstantConditions")
public class OtrSessionManagerTest {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final EdDSAKeyPair EDDSA_KEY_PAIR = EdDSAKeyPair.generate(RANDOM);
    private static final EdDSAKeyPair FORGING_KEY_PAIR = EdDSAKeyPair.generate(RANDOM);
    private static final DSAKeyPair DSA_KEY_PAIR = DSAKeyPair.generateDSAKeyPair(RANDOM);

    @Test
    public void testGetSession() {
        final OtrEngineHost host = mock(OtrEngineHost.class);
        when(host.getSessionPolicy(any(SessionID.class))).thenReturn(new OtrPolicy(OPPORTUNISTIC));
        when(host.getLocalKeyPair(any(SessionID.class))).thenReturn(DSA_KEY_PAIR);
        when(host.getLongTermKeyPair(any(SessionID.class))).thenReturn(EDDSA_KEY_PAIR);
        when(host.getForgingKeyPair(any(SessionID.class))).thenReturn(FORGING_KEY_PAIR);
        when(host.restoreClientProfilePayload()).thenReturn(new byte[0]);
        final OtrSessionManager mgr = new OtrSessionManager(host);
        final SessionID sid = new SessionID("user", "dude", "xmpp");
        final Session first = mgr.getSession(sid);
        assertNotNull(first);
        assertEquals(sid, first.getSessionID());
        final Session second = mgr.getSession(sid);
        assertSame(first, second);
    }

    @Test(expected = NullPointerException.class)
    public void testGetNullSession() {
        final OtrEngineHost host = mock(OtrEngineHost.class);
        final OtrSessionManager mgr = new OtrSessionManager(host);
        mgr.getSession(null);
    }

    @Test(expected = NullPointerException.class)
    public void testAddNullListener() {
        final OtrEngineHost host = mock(OtrEngineHost.class);
        final OtrSessionManager mgr = new OtrSessionManager(host);
        mgr.addOtrEngineListener(null);
    }

    @Test
    public void testAddValidListener() {
        final OtrEngineHost host = mock(OtrEngineHost.class);
        final OtrSessionManager mgr = new OtrSessionManager(host);
        final OtrEngineListener l = mock(OtrEngineListener.class);
        mgr.addOtrEngineListener(l);
    }

    @Test(expected = NullPointerException.class)
    public void testRemoveNullListener() {
        final OtrEngineHost host = mock(OtrEngineHost.class);
        final OtrSessionManager mgr = new OtrSessionManager(host);
        mgr.removeOtrEngineListener(null);
    }

    @Test
    public void testRemoveValidListener() {
        final OtrEngineHost host = mock(OtrEngineHost.class);
        final OtrSessionManager mgr = new OtrSessionManager(host);
        final OtrEngineListener l = mock(OtrEngineListener.class);
        mgr.removeOtrEngineListener(l);
    }
}
