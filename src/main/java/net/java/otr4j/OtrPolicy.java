/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j;

/**
 * @author George Politis
 */
public class OtrPolicy {

    public static final int ALLOW_V1 = 0x01;
    public static final int ALLOW_V2 = 0x02;
    // ALLOW_V3 is set to 0x40 for compatibility with older versions
    public static final int ALLOW_V3 = 0x40;
    public static final int REQUIRE_ENCRYPTION = 0x04;
    public static final int SEND_WHITESPACE_TAG = 0x8;
    public static final int WHITESPACE_START_AKE = 0x10;
    public static final int ERROR_START_AKE = 0x20;
    public static final int VERSION_MASK = (ALLOW_V1 | ALLOW_V2 | ALLOW_V3);

    // The four old version 1 policies correspond to the following combinations
    // of flags (adding an allowance for version 2 of the protocol):

    public static final int NEVER = 0x00;
    public static final int OPPORTUNISTIC = (ALLOW_V1 | ALLOW_V2 | ALLOW_V3
            | SEND_WHITESPACE_TAG | WHITESPACE_START_AKE | ERROR_START_AKE);
    public static final int OTRL_POLICY_MANUAL = (ALLOW_V1 | ALLOW_V2 | ALLOW_V3);
    public static final int OTRL_POLICY_ALWAYS = (ALLOW_V1 | ALLOW_V2 | ALLOW_V3
            | REQUIRE_ENCRYPTION | WHITESPACE_START_AKE | ERROR_START_AKE);
    public static final int OTRL_POLICY_DEFAULT = OPPORTUNISTIC;

    public OtrPolicy() {
        this.setPolicy(NEVER);
    }

    public OtrPolicy(int policy) {
        this.setPolicy(policy);
    }

    private int policy;

    public int getPolicy() {
        return policy;
    }

    private void setPolicy(int policy) {
        this.policy = policy;
    }

    public boolean getAllowV1() {
        return (policy & OtrPolicy.ALLOW_V1) != 0;
    }

    public boolean getAllowV2() {
        return (policy & OtrPolicy.ALLOW_V2) != 0;
    }

    public boolean getAllowV3() {
        return (policy & OtrPolicy.ALLOW_V3) != 0;
    }

    public boolean getErrorStartAKE() {
        return (policy & OtrPolicy.ERROR_START_AKE) != 0;
    }

    public boolean getRequireEncryption() {
        return getEnableManual()
                && (policy & OtrPolicy.REQUIRE_ENCRYPTION) != 0;
    }

    public boolean getSendWhitespaceTag() {
        return (policy & OtrPolicy.SEND_WHITESPACE_TAG) != 0;
    }

    public boolean getWhitespaceStartAKE() {
        return (policy & OtrPolicy.WHITESPACE_START_AKE) != 0;
    }

    public void setAllowV1(boolean value) {
        if (value)
            policy |= ALLOW_V1;
        else
            policy &= ~ALLOW_V1;
    }

    public void setAllowV2(boolean value) {
        if (value)
            policy |= ALLOW_V2;
        else
            policy &= ~ALLOW_V2;
    }

    public void setAllowV3(boolean value) {
        if (value)
            policy |= ALLOW_V3;
        else
            policy &= ~ALLOW_V3;
    }

    public void setErrorStartAKE(boolean value) {
        if (value)
            policy |= ERROR_START_AKE;
        else
            policy &= ~ERROR_START_AKE;
    }

    public void setRequireEncryption(boolean value) {
        if (value)
            policy |= REQUIRE_ENCRYPTION;
        else
            policy &= ~REQUIRE_ENCRYPTION;
    }

    public void setSendWhitespaceTag(boolean value) {
        if (value)
            policy |= SEND_WHITESPACE_TAG;
        else
            policy &= ~SEND_WHITESPACE_TAG;
    }

    public void setWhitespaceStartAKE(boolean value) {
        if (value)
            policy |= WHITESPACE_START_AKE;
        else
            policy &= ~WHITESPACE_START_AKE;
    }

    public boolean getEnableAlways() {
        return getEnableManual() && getErrorStartAKE()
                && getSendWhitespaceTag() && getWhitespaceStartAKE();
    }

    public void setEnableAlways(boolean value) {
        if (value)
            setEnableManual(true);

        setErrorStartAKE(value);
        setSendWhitespaceTag(value);
        setWhitespaceStartAKE(value);

    }

    public boolean getEnableManual() {
        return getAllowV1() && getAllowV2() && getAllowV3();
    }

    public void setEnableManual(boolean value) {
        setAllowV1(value);
        setAllowV2(value);
        setAllowV3(value);
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this)
            return true;
        if (obj == null || obj.getClass() != this.getClass())
            return false;

        OtrPolicy policy = (OtrPolicy) obj;

        return policy.getPolicy() == this.getPolicy();
    }

    @Override
    public int hashCode() {
        return this.getPolicy();
    }
}
