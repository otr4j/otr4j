/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.io;

import net.java.otr4j.api.Version;
import net.java.otr4j.crypto.DHKeyPairOTR3;
import net.java.otr4j.messages.AbstractEncodedMessage;
import net.java.otr4j.messages.DHKeyMessage;
import net.java.otr4j.messages.EncodedMessageParser;
import net.java.otr4j.messages.RevealSignatureMessage;
import org.junit.Test;

import javax.crypto.interfaces.DHPublicKey;
import java.math.BigInteger;
import java.security.SecureRandom;

import static net.java.otr4j.api.InstanceTag.ZERO_TAG;
import static net.java.otr4j.crypto.DHKeyPairOTR3.generateDHKeyPair;
import static net.java.otr4j.io.MessageProcessor.writeMessage;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class IOTest {

    private final SecureRandom secureRandom = new SecureRandom();

    public interface EncodedMessageTextSample {

        String DataMessage1 = "?OTR:AAIDAAAAAAEAAAABAAAAwCcGDemZNMCfOZl4ACf8L2G2G2qXDX6gJxKXBEgOjA7U/lgQJ+UklQzp0txnWqAhQ8HDfmGoMeo5Ez0N8X1xlXq8f3UL/fPrp7X2JW9JHr2fi541oPmtJpLtbSlIA+ri8Y1ptoxTriIyMWsngvSAkwFWb7lcDyJwXsc3ZUVi2xG/6ggdU+XxZe7ow5KfTK0usMIBnAGOfpygel6UBk7UPGRd9rWFaq1JOqkFopcKhar4IMydeaJa3AFbfrrmSYqqowAAAAAAAAABAAAABkOjnTF/CcaT9PEoW1n+hukkVE+RtvCNpSn4AAAAAA==.";
        // From OTR page.
        String DataMessage2 = "?OTR:AAEDAAAAAQAAAAEAAADAVf3Ei72ZgFeKqWvLMnuVPVCwxktsOZ1QdjeLp6jn62mCVtlY9nS6sRkecpjuLYHRxyTdRu2iEVtSsjZqK55ovZ35SfkOPHeFYa9BIuxWi9djHMVKQ8KOVGAVLibjZ6P8LreDSKtWDv9YQjIEnkwFVGCPfpBq2SX4VTQfJAQXHggR8izKxPvluXUdG9rIPh4cac98++VLdIuFMiEXjUIoTX2rEzunaCLMy0VIfowlRsgsKGrwhCCv7hBWyglbzwz+AAAAAAAAAAQAAAF2SOrJvPUerB9mtf4bqQDFthfoz/XepysnYuReHHEXKe+BFkaEoMNGiBl4TCLZx72DvmZwKCewWRH1+W66ggrXKw2VdVl+vLsmzxNyWChGLfBTL5/3SUF09BfmCEl03Ckk7htAgyAQcBf90RJznZndv7HwVAi3syupi0sQDdOKNPyObR5FRtqyqudttWmSdmGCGFcZ/fZqxQNsHB8QuYaBiGL7CDusES+wwfn8Q7BGtoJzOPDDx6KyIyox/flPx2DZDJIZrMz9b0V70a9kqKLo/wcGhvHO6coCyMxenBAacLJ1DiINLKoYOoJTM7zcxsGnvCxaDZCvsmjx3j8Yc5r3i3ylllCQH2/lpr/xCvXFarGtG7+wts+UqstS9SThLBQ9Ojq4oPsX7HBHKvq19XU3/ChIgWMy+bczc5gpkC/eLAIGfJ0D5DJsl68vMXSmCoFK0HTwzzNa7lnZK4IutYPBNBCv0pWORQqDpskEz96YOGyB8+gtpFgCrkuV1bSB9SRVmEBfDtKPQFhKowAAAAA=.";
        String DHCommitMessageText = "?OTR:AAICAAAAxM277nE7lEH30XWAryFZW4WDW2BUKE4fK/PFJcFGGyR7Z3SoIviHLphSDudtgiflruKOJ3PoeTV7py5fa0JwsvpDRjkSR9Fa5qfePlG7PfYSoSzYb81VJzIOK38gPH0TeG4/FNx7ywM3vFm0nGXkfmAICtp6BAZpM4WUFnWhB2rl1VTzo2YoUdspTXSHiEt3FSu5oo3EsF0TAmimMRBSB4AZH0R5WgBcxUVEtJOa6WIJ6HhJ/zjoh18vJgjAAN9kpJkuEbQAAAAgQLGeTiq4iYf91VxTPHw0T1arydZuMYK16y6DrAizgfo=.";
        String DHKeyMessageText = "?OTR:AAIKAAAAwDQlc11etGIBTSMB/rI9hgRTWfIfWhA+jmgDwpUDjdh8uilY0UXPrcH17+/9cRUjWxQdObavVNICPpuwHra2Xnz0S9nq6IRW2Fq9yaH51vg8AEliqHaDqfr5cMBFEAIqfJFC8v5IvMN4pfehHWgh+fjMHujXZYzJOTv2KXwq8GtD9kq2xIsCOglZ6aQ/jpHq0PoGdLfw1oD8DBvjWI7iJcg7pu2jL4WeEp6bxLcJqrYHob18qxCmKAwYvj8ScIkgPA==.";
        String RevealSignatureMessageText = "?OTR:AAIRAAAAEBpB31X97veB2M9tUUiU7pkAAAHSPp5PTQpf+akbmE0aBPViimS1S4t1HWCjtyNg+Sgd9ZoeaQIG5me2VRTqDJHb/ZF2cV0ru/uWUmRObXwtm+URnWEYWRuwUr2Q/2A2Ueo7eYfbOG3sOQrqFK4XWHesduhAzrGKGlZ0bjlHyi6C/+4eli8KsnFe7ii9fV6gYPBsTDevr8taPdh0JYfwB6F3NEPiT6sv/jskfGeVkjYvIQZ6KNUmcF5eXn6kOWqEq/67KWtWpiFJ92qAdCJjhDnwOlxSxaL4wHJd3dSgWU5XCQv18eoUpleCNrQCjNxLsZFTibee38wKx6Mq2eMkpjvqmhrD13t9iGEFWS5Gp4AezaLooTPXlJ6I1vB8288oG+06h6Nx1KkgUrLGwuUWL0BAamgxuqraf1G3SlxY3sU3/KRyMHAtBdufGJSydpgeKRyi0jl240q8FhVtIE8ysPJGmORs9+skP8qnY8Ljdp1TQGq19aNyrS02AuK9hegpEubmUmyv8jpqPIpj98RvjqfREyd5PreGDC7i8Z/SfdiHR/PgpW1yUdBSxqMFfOXCb/VlhgNXwBjXvYuS1Xk8GZz67q25QahD1S2znzzKX6bOd2w0ubwCOZ8PowDFPcmT2aPE7Ke14zPijVLJ2uoT3whSO1LMONpy/f87.";
        String SignatureMessageText = "?OTR:AAISAAAB0r0CzJSXTbcMeSVFQ/9kSPNW7P9BLYGn2zfIJALhXU0L8jGxUce4sZWNKhPA8QF8duBHlV1rXrZjJqSyYFaFQV1uAU6WrdgCus9T2cqqDE0VICwzHfbiz/RNt0FZSERGNtmLF/qHY+yHZwOKI4P3F9XP9/OSSCixSo1dRa8JxrPAgyYU8Y9bNudRTnIgdaKpCX0wVXcIe2Axp0Ni0YXmDSUAJACfiY9ShGjW2d3HPZiDLvlJVW44Fp73lijJQWXmxXQ6tu59yTyNyAqZUMqbSiM6HukH8wuLTHVWkWN63KdxdXC9OAMXMTHTECmDuK9oD5/LFTZOGTQ202g5p4Mbkokbh2fMW7GhpLwAT8Y4De5sy9DfFotobjHBKktxnF+z/LYDcNQyY6EE2iLK0R4qLzrNZA4uifePZAhqawx5fKfd30b8xUIMEjobTm2Cz4osjYyUMRtQWtNjsG2wp3m4nQ+lJfLwtfWg53og8o/kidulGuEiCg3CYSfT2Mzw5o9t5kswBdnRWwUvP6VNP3s6mOFg2s3WZ7HTisK7IWOyEfilyTa7IMGxwDriDayykaXZA5/x+7LZFHy7qNOTxt1cWQ1+Elr4NKYwSOXe6H7LtCb/4GiKxEwB8qnthM2xLxbvZuIGC0qbqQ==.";

        String QueryMessage_Bizzare = "?OTRv?";
        String QueryMessage_V1_CASE1 = "?OTR?";
        String QueryMessage_V1_CASE2 = "?OTR?v?";
        String QueryMessage_V2 = "?OTRv2?";
        String QueryMessage_V12 = "?OTR?v2?";
        String QueryMessage_V14x = "?OTRv24x?";
        String QueryMessage_V124x = "?OTR?v24x?";
        String QueryMessage_CommonRequest = "?OTR?v2? Bob has requested an Off-the-Record private conversation &lt;http://otr.cypherpunks.ca/&gt;.  However, you do not have a plugin to support that. See http://otr.cypherpunks.ca/ for more information.";
        String PlainText_V12 = "This is a plain text that has hidden support for V1 and V2! \t  \t\t\t\t \t \t \t    \t\t  \t  \t \t  \t ";
        String PlainText_V1 = "This is a plain text that has hidden support for V1! \t  \t\t\t\t \t \t \t    \t\t  \t ";
        String PlainText_UTF8 = "Αυτό είναι απλό UTF-8 κείμενο!";
    }

    @Test
    public void testIOShort() throws Exception {
        int source = 10;
        final byte[] converted = new OtrOutputStream().writeShort(source).toByteArray();
        int result = new OtrInputStream(converted).readShort();
        assertEquals(source, result);
    }

    @Test
    public void testIOData() throws Exception {
        byte[] source = new byte[] {1, 1, 1, 1};
        byte[] converted = new OtrOutputStream().writeData(source).toByteArray();
        byte[] result = new OtrInputStream(converted).readData();
        assertArrayEquals(source, result);
    }

    @Test
    public void testIOBigInt() throws Exception {
        DHKeyPairOTR3 pair = generateDHKeyPair(this.secureRandom);
        BigInteger source = pair.getPublic().getY();
        byte[] converted = new OtrOutputStream().writeBigInt(source).toByteArray();
        BigInteger result = new OtrInputStream(converted).readBigInt();
        assertEquals(source, result);
    }

    @Test
    public void testIODHPublicKey() throws Exception {
        DHKeyPairOTR3 pair = generateDHKeyPair(this.secureRandom);
        DHPublicKey source = pair.getPublic();
        byte[] converted = new OtrOutputStream().writeDHPublicKey(source).toByteArray();
        DHPublicKey result = new OtrInputStream(converted).readDHPublicKey();
        assertEquals(source.getY(), result.getY());
    }

    @Test
    public void testIODHKeyMessage() throws Exception {
        DHKeyPairOTR3 pair = generateDHKeyPair(this.secureRandom);
        DHKeyMessage source = new DHKeyMessage(Version.THREE, pair.getPublic(), ZERO_TAG, ZERO_TAG);
        String base64 = writeMessage(source);
        EncodedMessage message = (EncodedMessage) MessageProcessor.parseMessage(base64);
        final AbstractEncodedMessage result = EncodedMessageParser.parseEncodedMessage(message);
        assertEquals(source, result);
    }

    @Test
    public void testIORevealSignature() throws Exception {
        Version protocolVersion = Version.TWO;
        byte[] xEncrypted = new byte[] {1, 2, 3, 4};
        byte[] xEncryptedMAC = new byte[EncodingConstants.TYPE_LEN_MAC];
        for (int i = 0; i < xEncryptedMAC.length; i++) {
            xEncryptedMAC[i] = (byte) i;
        }
        byte[] revealedKey = new byte[] {1, 2, 3, 4};
        RevealSignatureMessage source = new RevealSignatureMessage(
                protocolVersion, xEncrypted, xEncryptedMAC, revealedKey, ZERO_TAG, ZERO_TAG);
        String base64 = writeMessage(source);
        EncodedMessage message = (EncodedMessage) MessageProcessor.parseMessage(base64);
        final AbstractEncodedMessage result = EncodedMessageParser.parseEncodedMessage(message);
        assertEquals(source, result);
    }
}
