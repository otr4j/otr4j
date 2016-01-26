/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package net.java.otr4j.session;

import java.net.ProtocolException;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * Tests for OTR Assembler.
 *
 * @author Danny van Heumen
 */
public class OtrAssemblerTest {

    @Test
    public void testCorrectParsingOf32bitsInteger() throws ProtocolException {
        final InstanceTag tag = new InstanceTag(0.99999645d);
        final String data = String.format("?OTR|ff123456|%08x,00001,00002,test,", tag.getValue());
        final OtrAssembler ass = new OtrAssembler(tag);
        assertNull(ass.accumulate(data));
    }

    @Test(expected = ProtocolException.class)
    public void testCorrectDisallowOf33bitsInteger() throws ProtocolException {
        final InstanceTag tag = new InstanceTag(0.99999645d);
        final String data = String.format("?OTR|ff123456|1%08x,00001,00002,test,", tag.getValue());
        final OtrAssembler ass = new OtrAssembler(tag);
        ass.accumulate(data);
    }

    @Test(expected = ProtocolException.class)
    public void testCorrectDisallowEmptyPayload() throws ProtocolException {
        final InstanceTag tag = new InstanceTag(0.99999645d);
        final String data = String.format("?OTR|ff123456|%08x,00001,00002,,", tag.getValue());
        final OtrAssembler ass = new OtrAssembler(tag);
        ass.accumulate(data);
    }

    @Test(expected = ProtocolException.class)
    public void testCorrectDisallowTrailingData() throws ProtocolException {
        final InstanceTag tag = new InstanceTag(0.99999645d);
        final String data = String.format("?OTR|ff123456|%08x,00001,00002,test,invalid", tag.getValue());
        final OtrAssembler ass = new OtrAssembler(tag);
        ass.accumulate(data);
    }

    @Test(expected = ProtocolException.class)
    public void testCorrectDisallowNegativeK() throws ProtocolException {
        final InstanceTag tag = new InstanceTag(0.99999645d);
        final String data = String.format("?OTR|ff123456|%08x,-0001,00002,test,", tag.getValue());
        final OtrAssembler ass = new OtrAssembler(tag);
        ass.accumulate(data);
    }

    @Test(expected = ProtocolException.class)
    public void testCorrectDisallowKLargerThanN() throws ProtocolException {
        final InstanceTag tag = new InstanceTag(0.99999645d);
        final String data = String.format("?OTR|ff123456|%08x,00003,00002,test,", tag.getValue());
        final OtrAssembler ass = new OtrAssembler(tag);
        ass.accumulate(data);
    }

    @Test(expected = ProtocolException.class)
    public void testCorrectDisallowKOverUpperBound() throws ProtocolException {
        final InstanceTag tag = new InstanceTag(0.99999645d);
        final String data = String.format("?OTR|ff123456|%08x,65536,65536,test,", tag.getValue());
        final OtrAssembler ass = new OtrAssembler(tag);
        ass.accumulate(data);
    }

    @Test
    public void testCorrectMaximumNFragments() throws ProtocolException {
        final InstanceTag tag = new InstanceTag(0.99999645d);
        final String data = String.format("?OTR|ff123456|%08x,00001,65535,test,", tag.getValue());
        final OtrAssembler ass = new OtrAssembler(tag);
        assertNull(ass.accumulate(data));
    }

    @Test(expected = ProtocolException.class)
    public void testCorrectDisallowNOverUpperBound() throws ProtocolException {
        final InstanceTag tag = new InstanceTag(0.99999645d);
        final String data = String.format("?OTR|ff123456|%08x,00001,65536,test,", tag.getValue());
        final OtrAssembler ass = new OtrAssembler(tag);
        ass.accumulate(data);
    }
}
