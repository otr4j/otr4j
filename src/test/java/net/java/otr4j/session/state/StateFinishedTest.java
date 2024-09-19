/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.session.state;

import net.java.otr4j.api.ClientProfileTestUtils;
import net.java.otr4j.api.Event;
import net.java.otr4j.api.OtrEngineHost;
import net.java.otr4j.api.OtrException;
import net.java.otr4j.api.OtrPolicy;
import net.java.otr4j.api.SessionID;
import net.java.otr4j.api.Version;
import net.java.otr4j.crypto.DHKeyPair;
import net.java.otr4j.crypto.DHKeyPairOTR3;
import net.java.otr4j.crypto.ed448.ECDHKeyPair;
import net.java.otr4j.crypto.ed448.Ed448;
import net.java.otr4j.crypto.ed448.EdDSAKeyPair;
import net.java.otr4j.io.ErrorMessage;
import net.java.otr4j.messages.AuthRMessage;
import net.java.otr4j.messages.ClientProfilePayload;
import net.java.otr4j.messages.DataMessage;
import net.java.otr4j.messages.DataMessage4;
import net.java.otr4j.messages.IdentityMessage;
import net.java.otr4j.messages.RevealSignatureMessage;
import net.java.otr4j.session.ake.StateInitial;
import net.java.otr4j.session.dake.DAKEInitial;
import net.java.otr4j.util.Unit;
import org.junit.Test;

import java.net.ProtocolException;
import java.security.SecureRandom;
import java.util.Collections;

import static net.java.otr4j.api.InstanceTag.HIGHEST_TAG;
import static net.java.otr4j.api.InstanceTag.SMALLEST_TAG;
import static net.java.otr4j.api.InstanceTag.ZERO_TAG;
import static net.java.otr4j.api.SessionStatus.FINISHED;
import static net.java.otr4j.api.Version.NONE;
import static net.java.otr4j.session.state.State.FLAG_IGNORE_UNREADABLE;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("ConstantConditions")
public class StateFinishedTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    private static final ClientProfileTestUtils UTILS = new ClientProfileTestUtils();

    @Test(expected = NullPointerException.class)
    public void testConstructNullAuthState() {
        new StateFinished(null, DAKEInitial.instance());
    }

    @Test(expected = NullPointerException.class)
    public void testConstructNullDAKEState() {
        new StateFinished(StateInitial.instance(), null);
    }

    @Test
    public void testConstruct() {
        new StateFinished(StateInitial.instance(), DAKEInitial.instance());
    }

    @Test
    public void testExpectProtocolVersionIsZero() {
        final StateFinished state = new StateFinished(StateInitial.instance(), DAKEInitial.instance());
        assertEquals(NONE, state.getVersion());
        assertEquals(FINISHED, state.getStatus());
    }

    @Test(expected = IncorrectStateException.class)
    public void testGetSMPHandlerFails() throws IncorrectStateException {
        final StateFinished state = new StateFinished(StateInitial.instance(), DAKEInitial.instance());
        state.getSmpHandler();
    }

    @Test(expected = IncorrectStateException.class)
    public void testGetExtraSymmetricKeyFails() throws IncorrectStateException {
        final StateFinished state = new StateFinished(StateInitial.instance(), DAKEInitial.instance());
        state.getExtraSymmetricKey();
    }

    @Test(expected = IncorrectStateException.class)
    public void testGetRemotePublicKeyFails() throws IncorrectStateException {
        final StateFinished state = new StateFinished(StateInitial.instance(), DAKEInitial.instance());
        state.getRemoteInfo();
    }

    @Test
    public void testDestroy() {
        new StateFinished(StateInitial.instance(), DAKEInitial.instance()).destroy();
    }

    @Test
    public void testEnd() {
        final Context context = mock(Context.class);
        final StateFinished state = new StateFinished(StateInitial.instance(), DAKEInitial.instance());
        state.end(context);
        verify(context).transition(eq(state), isA(StatePlaintext.class));
    }

    @Test
    public void testTransformSending() {
        final Context context = mock(Context.class);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        when(context.getHost()).thenReturn(host);
        final SessionID sessionID = new SessionID("alice", "bob", "network");
        when(context.getSessionID()).thenReturn(sessionID);
        when(context.getReceiverInstanceTag()).thenReturn(ZERO_TAG);
        final StateFinished state = new StateFinished(StateInitial.instance(), DAKEInitial.instance());
        assertNull(state.transformSending(context, "Hello world!", Collections.emptySet(), (byte) 0));
        verify(host).handleEvent(eq(sessionID), eq(ZERO_TAG), eq(Event.SESSION_FINISHED), eq(Unit.UNIT));
    }

    @Test
    public void testTransformSendingNullMessage() {
        final Context context = mock(Context.class);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        when(context.getHost()).thenReturn(host);
        final SessionID sessionID = new SessionID("alice", "bob", "network");
        when(context.getSessionID()).thenReturn(sessionID);
        final StateFinished state = new StateFinished(StateInitial.instance(), DAKEInitial.instance());
        assertNull(state.transformSending(context, null, Collections.emptySet(), (byte) 0));
    }

    @Test(expected = NullPointerException.class)
    public void testTransformSendingNullContext() {
        final StateFinished state = new StateFinished(StateInitial.instance(), DAKEInitial.instance());
        assertNull(state.transformSending(null, "Hello world!", Collections.emptySet(), (byte) 0));
    }

    @Test
    public void testHandleDataMessage() throws OtrException {
        final Context context = mock(Context.class);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        when(context.getHost()).thenReturn(host);
        final SessionID sessionID = new SessionID("alice", "bob", "network");
        when(context.getSessionID()).thenReturn(sessionID);
        when(host.getReplyForUnreadableMessage(eq(sessionID), anyString())).thenReturn("Cannot read this.");

        final DHKeyPairOTR3 keypair = DHKeyPairOTR3.generateDHKeyPair(RANDOM);
        final StateFinished state = new StateFinished(StateInitial.instance(), DAKEInitial.instance());
        final DataMessage message = new DataMessage(Version.THREE, (byte) 0, 1, 1, keypair.getPublic(),
                new byte[16], new byte[0], new byte[20], new byte[0], SMALLEST_TAG, HIGHEST_TAG);
        assertNull(state.handleDataMessage(context, message).content);
        verify(host, never()).handleEvent(eq(sessionID), eq(SMALLEST_TAG), eq(Event.UNREADABLE_MESSAGE_RECEIVED), eq(Unit.UNIT));
        verify(context).injectMessage(isA(ErrorMessage.class));
    }

    @Test
    public void testHandleDataMessageIgnoreUnreadable() throws OtrException {
        final Context context = mock(Context.class);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        when(context.getHost()).thenReturn(host);
        final SessionID sessionID = new SessionID("alice", "bob", "network");
        when(context.getSessionID()).thenReturn(sessionID);
        when(host.getReplyForUnreadableMessage(eq(sessionID), anyString())).thenReturn("Cannot read this.");

        final DHKeyPairOTR3 keypair = DHKeyPairOTR3.generateDHKeyPair(RANDOM);
        final StateFinished state = new StateFinished(StateInitial.instance(), DAKEInitial.instance());
        final DataMessage message = new DataMessage(Version.THREE, FLAG_IGNORE_UNREADABLE, 1, 1, keypair.getPublic(),
                new byte[16], new byte[0], new byte[20], new byte[0], SMALLEST_TAG, HIGHEST_TAG);
        assertNull(state.handleDataMessage(context, message).content);
        verify(host, never()).handleEvent(eq(sessionID), eq(SMALLEST_TAG), eq(Event.UNREADABLE_MESSAGE_RECEIVED), eq(Unit.UNIT));
        verify(context, never()).injectMessage(isA(ErrorMessage.class));
    }

    @Test(expected = NullPointerException.class)
    public void testHandleDataMessageNullContext() throws OtrException {
        final OtrEngineHost host = mock(OtrEngineHost.class);
        final SessionID sessionID = new SessionID("alice", "bob", "network");
        when(host.getReplyForUnreadableMessage(eq(sessionID), anyString())).thenReturn("Cannot read this.");

        final DHKeyPairOTR3 keypair = DHKeyPairOTR3.generateDHKeyPair(RANDOM);
        final StateFinished state = new StateFinished(StateInitial.instance(), DAKEInitial.instance());
        final DataMessage message = new DataMessage(Version.THREE, (byte) 0, 1, 1, keypair.getPublic(),
                new byte[16], new byte[0], new byte[20], new byte[0], SMALLEST_TAG, HIGHEST_TAG);
        state.handleDataMessage(null, message);
    }

    @Test(expected = NullPointerException.class)
    public void testHandleDataMessageNullMessage() throws OtrException {
        final Context context = mock(Context.class);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        when(context.getHost()).thenReturn(host);
        final SessionID sessionID = new SessionID("alice", "bob", "network");
        when(context.getSessionID()).thenReturn(sessionID);
        when(host.getReplyForUnreadableMessage(eq(sessionID), anyString())).thenReturn("Cannot read this.");

        final StateFinished state = new StateFinished(StateInitial.instance(), DAKEInitial.instance());
        state.handleDataMessage(context, (DataMessage) null);
    }

    @SuppressWarnings("resource")
    @Test
    public void testHandleDataMessage4() throws OtrException {
        final Context context = mock(Context.class);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        when(context.getHost()).thenReturn(host);
        final SessionID sessionID = new SessionID("alice", "bob", "network");
        when(context.getSessionID()).thenReturn(sessionID);
        when(host.getReplyForUnreadableMessage(eq(sessionID), anyString())).thenReturn("Cannot read this.");

        final StateFinished state = new StateFinished(StateInitial.instance(), DAKEInitial.instance());
        final ECDHKeyPair ecdh = ECDHKeyPair.generate(RANDOM);
        final DHKeyPair dh = DHKeyPair.generate(RANDOM);
        final DataMessage4 message = new DataMessage4(SMALLEST_TAG, HIGHEST_TAG, (byte) 0, 0, 0, 0,
                ecdh.publicKey(), dh.publicKey(), new byte[80], new byte[64], new byte[0]);
        assertNull(state.handleDataMessage(context, message).content);
        verify(host, never()).handleEvent(eq(sessionID), eq(SMALLEST_TAG), eq(Event.UNREADABLE_MESSAGE_RECEIVED), eq(Unit.UNIT));
        verify(context).injectMessage(isA(ErrorMessage.class));
    }

    @SuppressWarnings("resource")
    @Test
    public void testHandleDataMessage4IgnoreUnreadable() throws OtrException {
        final Context context = mock(Context.class);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        when(context.getHost()).thenReturn(host);
        final SessionID sessionID = new SessionID("alice", "bob", "network");
        when(context.getSessionID()).thenReturn(sessionID);
        when(host.getReplyForUnreadableMessage(eq(sessionID), anyString())).thenReturn("Cannot read this.");

        final StateFinished state = new StateFinished(StateInitial.instance(), DAKEInitial.instance());
        final ECDHKeyPair ecdh = ECDHKeyPair.generate(RANDOM);
        final DHKeyPair dh = DHKeyPair.generate(RANDOM);
        final DataMessage4 message = new DataMessage4(SMALLEST_TAG, HIGHEST_TAG, FLAG_IGNORE_UNREADABLE, 0, 0, 0,
                ecdh.publicKey(), dh.publicKey(), new byte[80], new byte[64], new byte[0]);
        assertNull(state.handleDataMessage(context, message).content);
        verify(host, never()).handleEvent(eq(sessionID), eq(SMALLEST_TAG), eq(Event.UNREADABLE_MESSAGE_RECEIVED), eq(Unit.UNIT));
        verify(context, never()).injectMessage(isA(ErrorMessage.class));
    }

    @Test(expected = NullPointerException.class)
    public void testHandleDataMessage4NullMessage() throws OtrException {
        final Context context = mock(Context.class);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        when(context.getHost()).thenReturn(host);
        final SessionID sessionID = new SessionID("alice", "bob", "network");
        when(context.getSessionID()).thenReturn(sessionID);
        when(host.getReplyForUnreadableMessage(eq(sessionID), anyString())).thenReturn("Cannot read this.");

        final StateFinished state = new StateFinished(StateInitial.instance(), DAKEInitial.instance());
        state.handleDataMessage(context, (DataMessage4) null);
    }

    @SuppressWarnings("resource")
    @Test(expected = NullPointerException.class)
    public void testHandleDataMessage4NullContext() throws OtrException {
        final StateFinished state = new StateFinished(StateInitial.instance(), DAKEInitial.instance());
        final ECDHKeyPair ecdh = ECDHKeyPair.generate(RANDOM);
        final DHKeyPair dh = DHKeyPair.generate(RANDOM);
        final DataMessage4 message = new DataMessage4(SMALLEST_TAG, HIGHEST_TAG, (byte) 0, 0, 0, 0,
                ecdh.publicKey(), dh.publicKey(), new byte[80], new byte[64], new byte[0]);
        state.handleDataMessage(null, message);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testHandleDAKEMessageNonIdentityMessage() throws OtrException, ProtocolException {
        final Context context = mock(Context.class);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        when(context.getHost()).thenReturn(host);
        final SessionID sessionID = new SessionID("alice", "bob", "network");
        when(context.getSessionID()).thenReturn(sessionID);
        when(host.getReplyForUnreadableMessage(eq(sessionID), anyString())).thenReturn("Cannot read this.");

        final StateFinished state = new StateFinished(StateInitial.instance(), DAKEInitial.instance());
        state.handleEncodedMessage4(context, new RevealSignatureMessage(Version.THREE, new byte[0], new byte[0],
                new byte[0], SMALLEST_TAG, HIGHEST_TAG));
    }

    @SuppressWarnings("resource")
    @Test
    public void testHandleDAKEMessageIdentityMessage() throws OtrException, ProtocolException {
        final Context context = mock(Context.class);
        final OtrEngineHost host = mock(OtrEngineHost.class);
        when(context.getHost()).thenReturn(host);
        final OtrPolicy policy = new OtrPolicy(OtrPolicy.OPPORTUNISTIC);
        when(context.getSessionPolicy()).thenReturn(policy);
        when(context.secureRandom()).thenReturn(RANDOM);
        when(context.getSenderInstanceTag()).thenReturn(SMALLEST_TAG);
        when(context.getReceiverInstanceTag()).thenReturn(HIGHEST_TAG);
        final SessionID sessionID = new SessionID("alice", "bob", "network");
        when(context.getSessionID()).thenReturn(sessionID);
        when(host.getReplyForUnreadableMessage(eq(sessionID), anyString())).thenReturn("Cannot read this.");
        when(host.getLongTermKeyPair(eq(sessionID))).thenReturn(EdDSAKeyPair.generate(RANDOM));
        final ClientProfilePayload profile = UTILS.createClientProfile();
        when(context.getClientProfilePayload()).thenReturn(profile);
        final StateFinished state = new StateFinished(StateInitial.instance(), DAKEInitial.instance());
        final ECDHKeyPair ecdh1 = ECDHKeyPair.generate(RANDOM);
        final DHKeyPair dh1 = DHKeyPair.generate(RANDOM);
        final DHKeyPair dh2 = DHKeyPair.generate(RANDOM);

        state.handleEncodedMessage4(context, new IdentityMessage(SMALLEST_TAG, HIGHEST_TAG, profile,
                Ed448.identity(), dh1.publicKey(), ecdh1.publicKey(), dh2.publicKey()));
        verify(context, never()).injectMessage(isA(AuthRMessage.class));
    }
}