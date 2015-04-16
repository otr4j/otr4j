package net.java.otr4j.session;

import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Danny van Heumen
 */
public class InstanceTagTest {

    @Test
    public void testConstructZeroTag() {
        InstanceTag tag = new InstanceTag(0);
        assertEquals(0, tag.getValue());
    }

    @Test
    public void testConstructSmallestTag() {
        InstanceTag tag = new InstanceTag(InstanceTag.SMALLEST_VALUE);
        assertEquals(InstanceTag.SMALLEST_VALUE, tag.getValue());
    }

    @Test(expected = IllegalArgumentException.class)
    @SuppressWarnings("ResultOfObjectAllocationIgnored")
    public void testConstructTooSmallTagLowerBound() {
        new InstanceTag(1);
    }

    @Test(expected = IllegalArgumentException.class)
    @SuppressWarnings("ResultOfObjectAllocationIgnored")
    public void testConstructTooSmallTagUpperBound() {
        new InstanceTag(255);
    }

    @Test
    public void testConstructorRatioZero() {
        InstanceTag tag = new InstanceTag(0d);
        assertEquals(InstanceTag.SMALLEST_VALUE, tag.getValue());
    }

    @Test(expected = IllegalArgumentException.class)
    @SuppressWarnings("ResultOfObjectAllocationIgnored")
    public void testConstructorRatioNegativeRatio() {
        new InstanceTag(-0.25d);
    }

    @Test(expected = IllegalArgumentException.class)
    @SuppressWarnings("ResultOfObjectAllocationIgnored")
    public void testConstructorRatioTooHigh() {
        new InstanceTag(2d);
    }

    @Test
    @SuppressWarnings("ResultOfObjectAllocationIgnored")
    public void testConstructorRatioValid() {
        InstanceTag tag = new InstanceTag(0.25);
        assertEquals(1073742015, tag.getValue());
    }

    @Test
    public void testConstructLargestTag() {
        InstanceTag tag = new InstanceTag(InstanceTag.HIGHEST_VALUE);
        // Make sure that value gets preserved as is.
        assertEquals(0xffffffff, InstanceTag.HIGHEST_VALUE & tag.getValue());
    }

    @Test
    public void testConstructSomeOtherLargeValue() {
        InstanceTag tag = new InstanceTag(0xedcbafed);
        // Just testing another arbitrary value in signed int's negative area.
        assertEquals(0xedcbafed, 0xedcbafed & tag.getValue());
    }

    /**
     * A quick check of the area in which the tag values are distributed.
     * This thing isn't fool proof, but should work in almost all cases.
     */
    @Test
    public void testConstructorRandomness() {
        int[] distr = new int[1000];
        InstanceTag tag;
        int val;
        long longval;
        int idx;
        for (int i = 0; i < 500000; i++) {
            tag = new InstanceTag();
            val = tag.getValue();
            assertFalse("" + val, 0 <= val && val < InstanceTag.SMALLEST_VALUE);
            // convert to long preserving bits (i.e. don't convert negative int to negative long
            longval = val & 0xffffffffL;
            idx = (int) ((double) (longval - 0x00000100L) / 0xfffffeffL * distr.length);
            distr[idx]++;
        }
        for (int part : distr) {
            assertTrue(part > 0);
        }
    }
}
