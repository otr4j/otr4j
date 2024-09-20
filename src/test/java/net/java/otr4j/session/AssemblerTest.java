/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.session;

import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.io.Fragment;
import net.java.otr4j.util.Classes;
import org.junit.Test;

import java.net.ProtocolException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Arrays.asList;
import static java.util.Collections.shuffle;
import static net.java.otr4j.io.MessageProcessor.parseMessage;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Tests for OTR Assembler.
 *
 * @author Danny van Heumen
 */
@SuppressWarnings("ConstantConditions")
public final class AssemblerTest {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String helloWorldBase64 = Base64.getEncoder().encodeToString("Hello World!".getBytes(UTF_8));

    @Test
    public void testAssembleSinglePartMessage() throws ProtocolException {
        final InstanceTag tag = InstanceTag.random(RANDOM);
        final Fragment data = (Fragment) parseMessage(String.format("?OTR|ff123456|%08x,00001,00001,test,", tag.getValue()));
        final Assembler ass = new Assembler();
        assertEquals("test", ass.accumulate(data));
    }

    @Test
    public void testAssembleTwoPartMessage() throws ProtocolException {
        final InstanceTag tag = InstanceTag.random(RANDOM);
        final Assembler ass = new Assembler();
        assertNull(ass.accumulate((Fragment) parseMessage(String.format("?OTR|ff123456|%08x,00001,00002,abcdef,", tag.getValue()))));
        assertEquals("abcdeffedcba", ass.accumulate((Fragment) parseMessage(
                String.format("?OTR|ff123456|%08x,00002,00002,fedcba,", tag.getValue()))));
    }

    @Test
    public void testAssembleFourPartMessage() throws ProtocolException {
        final InstanceTag tag = InstanceTag.random(RANDOM);
        final Assembler assembler = new Assembler();
        assertNull(assembler.accumulate((Fragment) parseMessage(String.format("?OTR|ff123456|%08x,00001,00004,a,",
                tag.getValue()))));
        assertNull(assembler.accumulate((Fragment) parseMessage(String.format("?OTR|ff123456|%08x,00002,00004,b,",
                tag.getValue()))));
        assertNull(assembler.accumulate((Fragment) parseMessage(String.format("?OTR|ff123456|%08x,00003,00004,c,",
                tag.getValue()))));
        assertEquals("abcd", assembler.accumulate((Fragment) parseMessage(String.format("?OTR|ff123456|%08x,00004,00004,d,",
                tag.getValue()))));
        assertTrue(Classes.readField(Map.class, assembler, "inOrder", "accumulations").isEmpty());
    }

    @Test
    public void testConstruction() {
        new Assembler();
    }

    @Test(expected = NullPointerException.class)
    public void testNullMessage() throws ProtocolException {
        final Assembler assembler = new Assembler();
        assembler.accumulate(null);
    }

    @Test
    public void testAssemblySingleFragment() throws ProtocolException {
        final Fragment fragment = (Fragment) parseMessage(String.format("?OTR|3c5b5f03|5a73a599|27e31597,00001,00001,%s,",
                helloWorldBase64));
        final Assembler assembler = new Assembler();
        assertEquals(helloWorldBase64, assembler.accumulate(fragment));
        assertTrue(Classes.readField(Map.class, assembler, "outOfOrder", "fragments").isEmpty());
    }

    @Test
    public void testAssembleTwoPartMessageOTRv4() throws ProtocolException {
        final Fragment part1 = (Fragment) parseMessage("?OTR|3c5b5f03|5a73a599|27e31597,00001,00002,"
                + helloWorldBase64.substring(0, 8) + ",");
        final Fragment part2 = (Fragment) parseMessage("?OTR|3c5b5f03|5a73a599|27e31597,00002,00002,"
                + helloWorldBase64.substring(8) + ",");
        final Assembler assembler = new Assembler();
        assertNull(assembler.accumulate(part1));
        assertEquals(helloWorldBase64, assembler.accumulate(part2));
    }

    @Test
    public void testAssembleSixteenPartMessage() throws ProtocolException {
        final String[] parts = new String[] {
                "?OTR|3c5b5f03|5a73a599|27e31597,00001,00016,S,",
                "?OTR|3c5b5f03|5a73a599|27e31597,00002,00016,G,",
                "?OTR|3c5b5f03|5a73a599|27e31597,00003,00016,V,",
                "?OTR|3c5b5f03|5a73a599|27e31597,00004,00016,s,",
                "?OTR|3c5b5f03|5a73a599|27e31597,00005,00016,b,",
                "?OTR|3c5b5f03|5a73a599|27e31597,00006,00016,G,",
                "?OTR|3c5b5f03|5a73a599|27e31597,00007,00016,8,",
                "?OTR|3c5b5f03|5a73a599|27e31597,00008,00016,g,",
                "?OTR|3c5b5f03|5a73a599|27e31597,00009,00016,V,",
                "?OTR|3c5b5f03|5a73a599|27e31597,00010,00016,2,",
                "?OTR|3c5b5f03|5a73a599|27e31597,00011,00016,9,",
                "?OTR|3c5b5f03|5a73a599|27e31597,00012,00016,y,",
                "?OTR|3c5b5f03|5a73a599|27e31597,00013,00016,b,",
                "?OTR|3c5b5f03|5a73a599|27e31597,00014,00016,G,",
                "?OTR|3c5b5f03|5a73a599|27e31597,00015,00016,Q,",
                "?OTR|3c5b5f03|5a73a599|27e31597,00016,00016,h,",
        };
        final Assembler assembler = new Assembler();
        for (int i = 0; i < parts.length - 1; i++) {
            assertNull(assembler.accumulate((Fragment) parseMessage(parts[i])));
        }
        assertEquals(helloWorldBase64, assembler.accumulate((Fragment) parseMessage(parts[parts.length - 1])));
        assertTrue(Classes.readField(Map.class, assembler, "outOfOrder", "fragments").isEmpty());
    }

    @Test
    public void testAssembleSixteenPartMessageShuffled() throws ProtocolException {
        final List<String> parts = asList(
                "?OTR|3c5b5f03|5a73a599|27e31597,00001,00016,S,",
                "?OTR|3c5b5f03|5a73a599|27e31597,00002,00016,G,",
                "?OTR|3c5b5f03|5a73a599|27e31597,00003,00016,V,",
                "?OTR|3c5b5f03|5a73a599|27e31597,00004,00016,s,",
                "?OTR|3c5b5f03|5a73a599|27e31597,00005,00016,b,",
                "?OTR|3c5b5f03|5a73a599|27e31597,00006,00016,G,",
                "?OTR|3c5b5f03|5a73a599|27e31597,00007,00016,8,",
                "?OTR|3c5b5f03|5a73a599|27e31597,00008,00016,g,",
                "?OTR|3c5b5f03|5a73a599|27e31597,00009,00016,V,",
                "?OTR|3c5b5f03|5a73a599|27e31597,00010,00016,2,",
                "?OTR|3c5b5f03|5a73a599|27e31597,00011,00016,9,",
                "?OTR|3c5b5f03|5a73a599|27e31597,00012,00016,y,",
                "?OTR|3c5b5f03|5a73a599|27e31597,00013,00016,b,",
                "?OTR|3c5b5f03|5a73a599|27e31597,00014,00016,G,",
                "?OTR|3c5b5f03|5a73a599|27e31597,00015,00016,Q,",
                "?OTR|3c5b5f03|5a73a599|27e31597,00016,00016,h,");
        shuffle(parts);
        final Assembler assembler = new Assembler();
        for (int i = 0; i < parts.size() - 1; i++) {
            assertNull(assembler.accumulate((Fragment) parseMessage(parts.get(i))));
        }
        assertEquals(helloWorldBase64, assembler.accumulate((Fragment) parseMessage(parts.get(parts.size() - 1))));
        assertTrue(Classes.readField(Map.class, assembler, "outOfOrder", "fragments").isEmpty());
    }

    @Test
    public void testAssemblyEmptyFragment() throws ProtocolException {
        final Fragment fragment = (Fragment) parseMessage("?OTR|3c5b5f03|5a73a599|27e31597,00001,00001,,");
        final Assembler assembler = new Assembler();
        assertEquals("", assembler.accumulate(fragment));
    }

    @Test(expected = ProtocolException.class)
    public void testAssembleTwoPartMessageDriftingTotalDown() throws ProtocolException {
        final Fragment part1 = (Fragment) parseMessage("?OTR|3c5b5f03|5a73a599|27e31597,00001,00003,"
                + helloWorldBase64.substring(0, 8) + ",");
        final Fragment part2 = (Fragment) parseMessage("?OTR|3c5b5f03|5a73a599|27e31597,00002,00002,"
                + helloWorldBase64.substring(8) + ",");
        final Assembler assembler = new Assembler();
        assertNull(assembler.accumulate(part1));
        assembler.accumulate(part2);
    }

    @Test(expected = ProtocolException.class)
    public void testAssembleTwoPartMessageDriftingTotalUp() throws ProtocolException {
        final Fragment part1 = (Fragment) parseMessage("?OTR|3c5b5f03|5a73a599|27e31597,00001,00002,"
                + helloWorldBase64.substring(0, 8) + ",");
        final Fragment part2 = (Fragment) parseMessage("?OTR|3c5b5f03|5a73a599|27e31597,00002,00003,"
                + helloWorldBase64.substring(8) + ",");
        final Assembler assembler = new Assembler();
        assertNull(assembler.accumulate(part1));
        assembler.accumulate(part2);
    }

    @Test(expected = ProtocolException.class)
    public void testFragmentReceivedMultipleTimesIgnoring() throws ProtocolException {
        final Assembler assembler = new Assembler();
        final Fragment fragment;
        try {
            fragment = (Fragment) parseMessage("?OTR|3c5b5f03|5a73a599|27e31597,00001,00002,,");
            assertNull(assembler.accumulate(fragment));
        } catch (final ProtocolException e) {
            fail("Did not expect to fail sending message the first time.");
            throw new IllegalStateException("Failed!");
        }
        assembler.accumulate(fragment);
    }

    @Test
    public void testMaintainMaxMessagesInAssembly() throws ProtocolException {
        final int expectedLimit = 100;
        final Assembler assembler = new Assembler();
        for (int i = 0; i < expectedLimit + 3; i++) {
            final int msgID = i;
            final int senderID = -1 - i;
            final int receiverID = Integer.MAX_VALUE - i;
            assembler.accumulate((Fragment) parseMessage(String.format("?OTR|%08X|%08X|%08X,00001,00003,He,", msgID, senderID, receiverID)));
            assembler.accumulate((Fragment) parseMessage(String.format("?OTR|%08X|%08X|%08X,00002,00003,ll,", msgID, senderID, receiverID)));
            assertEquals(Math.min(expectedLimit, i+1), Classes.readField(LinkedHashMap.class, assembler, "outOfOrder", "fragments").size());
        }
    }
}
