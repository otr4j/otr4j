/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.io;

import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.api.Version;
import org.junit.Test;

import java.net.ProtocolException;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;
import static net.java.otr4j.api.InstanceTag.ZERO_TAG;
import static net.java.otr4j.io.Fragment.parseFragment;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

@SuppressWarnings("ConstantConditions")
public final class FragmentTest {

    private static final String helloWorldBase64 = Base64.getEncoder().encodeToString("Hello World!".getBytes(UTF_8));

    private static final String formatVersion4 = "?OTR|3c5b5f03|5a73a599|27e31597,00001,00001,%s,";

    @Test(expected = NullPointerException.class)
    public void testParseNullMessage() throws ProtocolException {
        parseFragment(null);
    }

    @Test(expected = ProtocolException.class)
    public void testParseEmptyMessage() throws ProtocolException {
        parseFragment("");
    }

    @Test(expected = ProtocolException.class)
    public void testParseArbitraryTextMessage() throws ProtocolException {
        parseFragment("This is an arbitrary message that is definitely not a fragment.");
    }

    @Test
    public void testCorrectParsingOf32bitsInteger() throws ProtocolException {
        final InstanceTag tag = new InstanceTag(0.99999645d);
        assertNotNull(parseFragment(String.format("?OTR|ff123456|%08x,00001,00002,test,", tag.getValue())));
    }

    @Test(expected = ProtocolException.class)
    public void testCorrectDisallowOf33bitsInteger() throws ProtocolException {
        final InstanceTag tag = new InstanceTag(0.99999645d);
        parseFragment(String.format("?OTR|ff123456|1%08x,00001,00002,test,", tag.getValue()));
    }

    @Test
    public void testCorrectDisallowEmptyPayload() throws ProtocolException {
        final InstanceTag tag = new InstanceTag(0.99999645d);
        assertEquals("", parseFragment(String.format("?OTR|ff123456|%08x,00001,00002,,", tag.getValue())).getContent());
    }

    @Test
    public void testParseSingleFragmentOTRv4() throws ProtocolException {
        final Fragment fragment = parseFragment(String.format(formatVersion4, helloWorldBase64));
        assertEquals(Version.FOUR, fragment.getVersion());
        assertEquals(0x3c5b5f03, fragment.getIdentifier());
        assertEquals(new InstanceTag(0x5a73a599), fragment.getSenderTag());
        assertEquals(new InstanceTag(0x27e31597), fragment.getReceiverTag());
        assertEquals(1, fragment.getIndex());
        assertEquals(1, fragment.getTotal());
        assertEquals(helloWorldBase64, fragment.getContent());
    }

    @Test
    public void testParseSingleFragmentOTRv3() throws ProtocolException {
        final Fragment fragment = parseFragment(String.format("?OTR|5a73a599|27e31597,00001,00001,%s,", helloWorldBase64));
        assertEquals(Version.THREE, fragment.getVersion());
        assertEquals(0, fragment.getIdentifier());
        assertEquals(new InstanceTag(0x5a73a599), fragment.getSenderTag());
        assertEquals(new InstanceTag(0x27e31597), fragment.getReceiverTag());
        assertEquals(1, fragment.getIndex());
        assertEquals(1, fragment.getTotal());
        assertEquals(helloWorldBase64, fragment.getContent());
    }

    @Test
    public void testParseSingleFragmentOTRv2() throws ProtocolException {
        final Fragment fragment = parseFragment("?OTR,1,3,?OTR:AAEDAAAAAQAAAAEAAADAVf3Ei72ZgFeKqWvLMnuVPVCwxktsOZ1QdjeLp6jn62mCVtlY9nS6sRkecpjuLYHRxyTdRu2iEVtSsjZqK55ovZ35SfkOPHeFYa9BIuxWi9djHMVKQ8KOVGAVLibjZ6P8LreDSKtWDv9YQjIEnkwFVGCPfpBq2SX4VTQfJAQXHggR8izKxPvluXUdG9rIPh4cac98++VLdIuFMiEXjUIoTX2rEzunaCLMy0VIfowlRsgsKGrwhCCv7hBWyglbzwz+AAAAAAAAAAQAAAF2SOr,");
        assertEquals(Version.TWO, fragment.getVersion());
        assertEquals(0, fragment.getIdentifier());
        assertEquals(ZERO_TAG, fragment.getSenderTag());
        assertEquals(ZERO_TAG, fragment.getReceiverTag());
        assertEquals(1, fragment.getIndex());
        assertEquals(3, fragment.getTotal());
        assertEquals("?OTR:AAEDAAAAAQAAAAEAAADAVf3Ei72ZgFeKqWvLMnuVPVCwxktsOZ1QdjeLp6jn62mCVtlY9nS6sRkecpjuLYHRxyTdRu2iEVtSsjZqK55ovZ35SfkOPHeFYa9BIuxWi9djHMVKQ8KOVGAVLibjZ6P8LreDSKtWDv9YQjIEnkwFVGCPfpBq2SX4VTQfJAQXHggR8izKxPvluXUdG9rIPh4cac98++VLdIuFMiEXjUIoTX2rEzunaCLMy0VIfowlRsgsKGrwhCCv7hBWyglbzwz+AAAAAAAAAAQAAAF2SOr",
                fragment.getContent());
    }

    @Test
    public void testParseSingleFragmentOTRv4HighBitIdentifier() throws ProtocolException {
        final Fragment fragment = parseFragment(String.format("?OTR|ffffffff|5a73a599|27e31597,00001,00001,%s,", helloWorldBase64));
        assertEquals(Version.FOUR, fragment.getVersion());
        assertEquals(0xffffffff, fragment.getIdentifier());
    }

    @Test
    public void testParseSingleFragmentOTRv4HighBitSenderTag() throws ProtocolException {
        final Fragment fragment = parseFragment(String.format("?OTR|3c5b5f03|ffffffff|27e31597,00001,00001,%s,", helloWorldBase64));
        assertEquals(Version.FOUR, fragment.getVersion());
        assertEquals(new InstanceTag(0xffffffff), fragment.getSenderTag());
    }

    @Test
    public void testParseSingleFragmentOTRv4HighBitReceiverTag() throws ProtocolException {
        final Fragment fragment = parseFragment(String.format("?OTR|3c5b5f03|5a73a599|ffffffff,00001,00001,%s,", helloWorldBase64));
        assertEquals(Version.FOUR, fragment.getVersion());
        assertEquals(new InstanceTag(0xffffffff), fragment.getReceiverTag());
    }

    @Test
    public void testParseSingleFragmentOTRv3HighBitSenderTag() throws ProtocolException {
        final Fragment fragment = parseFragment(String.format("?OTR|ffffffff|27e31597,00001,00001,%s,", helloWorldBase64));
        assertEquals(Version.THREE, fragment.getVersion());
        assertEquals(new InstanceTag(0xffffffff), fragment.getSenderTag());
    }

    @Test
    public void testParseSingleFragmentOTRv3HighBitReceiverTag() throws ProtocolException {
        final Fragment fragment = parseFragment(String.format("?OTR|5a73a599|ffffffff,00001,00001,%s,", helloWorldBase64));
        assertEquals(Version.THREE, fragment.getVersion());
        assertEquals(new InstanceTag(0xffffffff), fragment.getReceiverTag());
    }

    @Test(expected = ProtocolException.class)
    public void testParseSingleFragmentIllegalSenderTag() throws ProtocolException {
        parseFragment(String.format("?OTR|3c5b5f03|00000001|27e31597,00001,00001,%s,", helloWorldBase64));
    }

    @Test(expected = ProtocolException.class)
    public void testParseSingleFragmentIllegalReceiverTag() throws ProtocolException {
        parseFragment(String.format("?OTR|3c5b5f03|5a73a599|00000001,00001,00001,%s,", helloWorldBase64));
    }

    @Test(expected = ProtocolException.class)
    public void testParseSingleFragmentIllegalIndexZero() throws ProtocolException {
        parseFragment(String.format("?OTR|3c5b5f03|5a73a599|27e31597,00000,00001,%s,", helloWorldBase64));
    }

    @Test(expected = ProtocolException.class)
    public void testParseSingleFragmentIllegalIndexOverMaximum() throws ProtocolException {
        parseFragment(String.format("?OTR|3c5b5f03|5a73a599|27e31597,65536,65536,%s,", helloWorldBase64));
    }

    @Test(expected = ProtocolException.class)
    public void testParseSingleFragmentIllegalTotalBelowIndex() throws ProtocolException {
        parseFragment(String.format("?OTR|3c5b5f03|5a73a599|27e31597,00001,00000,%s,", helloWorldBase64));
    }

    @Test(expected = ProtocolException.class)
    public void testParseSingleFragmentIllegalTotalOverMaximum() throws ProtocolException {
        parseFragment(String.format("?OTR|3c5b5f03|5a73a599|27e31597,00001,65536,%s,", helloWorldBase64));
    }

    @Test(expected = ProtocolException.class)
    public void testCorrectDisallowTrailingData() throws ProtocolException {
        final InstanceTag tag = new InstanceTag(0.99999645d);
        parseFragment(String.format("?OTR|ff123456|%08x,00001,00002,test,invalid", tag.getValue()));
    }

    @Test(expected = ProtocolException.class)
    public void testCorrectDisallowNegativeK() throws ProtocolException {
        final InstanceTag tag = new InstanceTag(0.99999645d);
        parseFragment(String.format("?OTR|ff123456|%08x,-0001,00002,test,", tag.getValue()));
    }

    @Test(expected = ProtocolException.class)
    public void testCorrectDisallowKLargerThanN() throws ProtocolException {
        final InstanceTag tag = new InstanceTag(0.99999645d);
        parseFragment(String.format("?OTR|ff123456|%08x,00003,00002,test,", tag.getValue()));
    }

    @Test(expected = ProtocolException.class)
    public void testCorrectDisallowKOverUpperBound() throws ProtocolException {
        final InstanceTag tag = new InstanceTag(0.99999645d);
        parseFragment(String.format("?OTR|ff123456|%08x,65536,65536,test,", tag.getValue()));
    }

    @Test
    public void testCorrectMaximumNFragments() throws ProtocolException {
        final InstanceTag tag = new InstanceTag(0.99999645d);
        final Fragment fragment = parseFragment(String.format("?OTR|ff123456|%08x,00001,65535,test,", tag.getValue()));
        assertEquals(65535, fragment.getTotal());
    }

    @Test(expected = ProtocolException.class)
    public void testCorrectDisallowNOverUpperBound() throws ProtocolException {
        final InstanceTag tag = new InstanceTag(0.99999645d);
        parseFragment(String.format("?OTR|ff123456|%08x,00001,65536,test,", tag.getValue()));
    }

    @Test
    public void testOTRv3FormattedFragment() throws ProtocolException {
        final Fragment fragment = parseFragment(String.format("?OTR|5a73a599|27e31597,00001,00001,%s,", helloWorldBase64));
        assertEquals(Version.THREE, fragment.getVersion());
    }

    @Test
    public void testIncompleteFragmentParsing() throws ProtocolException {
        final String source = String.format("?OTR|3c5b5f03|5a73a599|27e31597,00001,00001,%s,", helloWorldBase64);
        for (int i = 0; i < source.length() - 1; i++) {
            try {
                parseFragment(source.substring(0, i));
                fail("Did not expect incomplete fragment to be processed successfully.");
            } catch (final ProtocolException expected) {
                // expected failure, continue
            }
        }
        assertEquals(helloWorldBase64, parseFragment(source).getContent());
    }

    @Test
    public void testFragmentationFormatLegalVariations() throws ProtocolException {
        final String[] variants = new String[] {
                "?OTR|c5b5f03|5a73a599|27e31597,00001,00001,%s,",
                "?OTR|C5B5F03|5A73A599|27E31597,00001,00001,%s,",
                "?OTR|5b5f03|5a73a599|27e31597,00001,00001,%s,",
                "?OTR|b5f03|5a73a599|27e31597,00001,00001,%s,",
                "?OTR|5f03|5a73a599|27e31597,00001,00001,%s,",
                "?OTR|f03|5a73a599|27e31597,00001,00001,%s,",
                "?OTR|03|5a73a599|27e31597,00001,00001,%s,",
                "?OTR|3|5a73a599|27e31597,00001,00001,%s,",
                "?OTR|3c5b5f03|a73a599|27e31597,00001,00001,%s,",
                "?OTR|3c5b5f03|73a599|27e31597,00001,00001,%s,",
                "?OTR|3c5b5f03|3a599|27e31597,00001,00001,%s,",
                "?OTR|3c5b5f03|a599|27e31597,00001,00001,%s,",
                "?OTR|3c5b5f03|599|27e31597,00001,00001,%s,",
//            "?OTR|3c5b5f03|99|27e31597,00001,00001,%s,", // illegal because of too small instance tag
//            "?OTR|3c5b5f03|9|27e31597,00001,00001,%s,", // illegal because of too small instance tag
                "?OTR|3c5b5f03|5a73a599|7e31597,00001,00001,%s,",
                "?OTR|3c5b5f03|5a73a599|e31597,00001,00001,%s,",
                "?OTR|3c5b5f03|5a73a599|31597,00001,00001,%s,",
                "?OTR|3c5b5f03|5a73a599|1597,00001,00001,%s,",
                "?OTR|3c5b5f03|5a73a599|597,00001,00001,%s,",
//            "?OTR|3c5b5f03|5a73a599|97,00001,00001,%s,", // illegal because of too small instance tag
//            "?OTR|3c5b5f03|5a73a599|7,00001,00001,%s,", // illegal because of too small instance tag
                "?OTR|3c5b5f03|5a73a599|27e31597,0001,00001,%s,",
                "?OTR|3c5b5f03|5a73a599|27e31597,001,00001,%s,",
                "?OTR|3c5b5f03|5a73a599|27e31597,01,00001,%s,",
                "?OTR|3c5b5f03|5a73a599|27e31597,1,00001,%s,",
                "?OTR|3c5b5f03|5a73a599|27e31597,00001,0001,%s,",
                "?OTR|3c5b5f03|5a73a599|27e31597,00001,001,%s,",
                "?OTR|3c5b5f03|5a73a599|27e31597,00001,01,%s,",
                "?OTR|3c5b5f03|5a73a599|27e31597,00001,1,%s,",
        };
        for (final String variant : variants) {
            assertNotNull(parseFragment(String.format(variant, helloWorldBase64)));
        }
    }

    @Test
    public void testFragmentationFormatIllegalVariations() {
        final String[] variants = new String[] {
                "?OTR|3c5b5f03|5a73a599|27e31597,00001,00001,%s",
                "?OTR|3c5b5f03|5a73a599|27e31597,00001,,%s,",
                "?OTR|3c5b5f03|5a73a599|27e31597,,00001,%s,",
                "?OTR|3c5b5f03|5a73a599|,00001,00001,%s,",
                "?OTR|3c5b5f03||27e31597,00001,00001,%s,",
                "?OTR||5a73a599|27e31597,00001,00001,%s,",
                "?OT|c5b5f03|5a73a599|27e31597,00001,00001,%s,",
                "?O|c5b5f03|5a73a599|27e31597,00001,00001,%s,",
                "?|c5b5f03|5a73a599|27e31597,00001,00001,%s,",
                "|c5b5f03|5a73a599|27e31597,00001,00001,%s,",
                "?TR|c5b5f03|5a73a599|27e31597,00001,00001,%s,",
                "?OR|c5b5f03|5a73a599|27e31597,00001,00001,%s,",
                "?R|c5b5f03|5a73a599|27e31597,00001,00001,%s,",
                "OTR|c5b5f03|5a73a599|27e31597,00001,00001,%s,",
                "TR|c5b5f03|5a73a599|27e31597,00001,00001,%s,",
                "R|c5b5f03|5a73a599|27e31597,00001,00001,%s,",
                "?OTRc5b5f03|5a73a599|27e31597,00001,00001,%s,",
                "?OTR|c5b5f035a73a599|27e31597,00001,00001,%s,",
                "?OTR|c5b5f03|5a73a59927e31597,00001,00001,%s,",
                "?OTR|c5b5f03|5a73a599|27e3159700001,00001,%s,",
                "?OTR|c5b5f03|5a73a599|27e31597,0000100001,%s,",
                "?OTR|c5b5f03|5a73a599|27e31597,00001,00001%s,",
                "?OTR|c5g5f03|5a73a599|27e31597,00001,00001,%s,",
                "?OTR|c5b5f03|5a73g599|27e31597,00001,00001,%s,",
                "?OTR|c5b5f03|5a73a599|27e315g7,00001,00001,%s,",
                "?OTR|c5b5f03|5a73a599|27e31597,00a01,00001,%s,",
                "?OTR|c5b5f03|5a73a599|27e31597,00001,000b1,%s,",
                "?OTR|c5b5f03|5a73a599|27e31597,00001,00001,%s.",
                "?OTR|c5b5f03|5a73a599|27e31597,00001,-0001,%s,",
                "?OTR|c5b5f03|5a73a599|27e31597,-0001,00001,%s,",
        };
        for (final String variant : variants) {
            try {
                parseFragment(String.format(variant, helloWorldBase64));
                fail("Did not expect to successfully parse an illegal variant of fragment.");
            } catch (final ProtocolException expected) {
                // failure expected, continue
            }
        }
    }

    @Test(expected = ProtocolException.class)
    public void testFragmentIndexZero() throws ProtocolException {
        parseFragment("?OTR|3c5b5f03|5a73a599|27e31597,00000,00001,,");
    }

    @Test(expected = ProtocolException.class)
    public void testFragmentTotalZero() throws ProtocolException {
        parseFragment("?OTR|3c5b5f03|5a73a599|27e31597,00001,00000,,");
    }

    @Test(expected = ProtocolException.class)
    public void testFragmentIndexLargerThanTotal() throws ProtocolException {
        parseFragment("?OTR|3c5b5f03|5a73a599|27e31597,00002,00001,,");
    }

    @Test(expected = ProtocolException.class)
    public void testFragmentIndexMuchLargerThanTotal() throws ProtocolException {
        parseFragment("?OTR|3c5b5f03|5a73a599|27e31597,11111,00001,,");
    }

    @Test(expected = ProtocolException.class)
    public void testFragmentIndexOverMaximum() throws ProtocolException {
        parseFragment("?OTR|3c5b5f03|5a73a599|27e31597,65536,00001,,");
    }

    @Test(expected = ProtocolException.class)
    public void testFragmentTotalOverMaximum() throws ProtocolException {
        parseFragment("?OTR|3c5b5f03|5a73a599|27e31597,00001,65536,,");
    }
}
