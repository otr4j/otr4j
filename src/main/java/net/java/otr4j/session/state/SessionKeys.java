/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session.state;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.annotation.Nonnull;

import javax.crypto.interfaces.DHPublicKey;

import net.java.otr4j.OtrException;
import net.java.otr4j.crypto.OtrCryptoEngine;
import net.java.otr4j.io.SerializationUtils;

/**
 * @author George Politis
 * @author Danny van Heumen
 */
public class SessionKeys {
    // TODO consider making this class totally package-protected. Keys and counters are mutable and are used in Session. I don't think they need to be exposed outside of package.

    public static final int PREVIOUS = 0;
    public static final int CURRENT = 1;
    public static final byte HIGH_SEND_BYTE = (byte) 0x01;
    public static final byte HIGH_RECEIVE_BYTE = (byte) 0x02;
    public static final byte LOW_SEND_BYTE = (byte) 0x02;
    public static final byte LOW_RECEIVE_BYTE = (byte) 0x01;

    private static final Logger LOGGER = Logger.getLogger(SessionKeys.class.getName());

    private final String keyDescription;

    private int localKeyID;
    private int remoteKeyID;
    private DHPublicKey remoteKey;
    private KeyPair localPair;

    private byte[] sendingAESKey;
    private byte[] receivingAESKey;
    private byte[] sendingMACKey;
    private byte[] receivingMACKey;
    private boolean isUsedReceivingMACKey;
    private BigInteger s;
    private boolean isHigh;

    public SessionKeys(final int localKeyIndex, final int remoteKeyIndex) {
        final StringBuilder desc = new StringBuilder();
        if (localKeyIndex == 0) {
            desc.append("(Previous local, ");
        } else {
            desc.append("(Most recent local, ");
        }
        if (remoteKeyIndex == 0) {
            desc.append("Previous remote)");
        } else {
            desc.append("Most recent remote)");
        }
        this.keyDescription = desc.toString();
    }

    public void setLocalPair(final KeyPair keyPair, final int localPairKeyID) {
        this.localPair = keyPair;
        this.localKeyID = localPairKeyID;
        LOGGER.log(Level.FINEST, "{0} current local key ID: {1}",
                new Object[]{keyDescription, this.localKeyID});
        this.reset();
    }

    public void setRemoteDHPublicKey(final DHPublicKey pubKey, final int remoteKeyID) {
        this.remoteKey = pubKey;
        this.remoteKeyID = remoteKeyID;
        LOGGER.log(Level.FINEST, "{0} current remote key ID: {1}",
                new Object[]{keyDescription, this.remoteKeyID});
        this.reset();
    }

    private final byte[] sendingCtr = new byte[16];
    private final byte[] receivingCtr = new byte[16];

    public void incrementSendingCtr() {
        LOGGER.log(Level.FINEST, "Incrementing counter for (localkeyID, remoteKeyID) = ({0},{1})",
                new Object[]{localKeyID, remoteKeyID});
        for (int i = 7; i >= 0; i--) {
            if (++sendingCtr[i] != 0) {
                break;
            }
        }
    }

    public byte[] getSendingCtr() {
        return sendingCtr;
    }

    public byte[] getReceivingCtr() {
        return receivingCtr;
    }

    public void setReceivingCtr(@Nonnull final byte[] ctr) {
        System.arraycopy(ctr, 0, receivingCtr, 0, ctr.length);
    }

    private void reset() {
        LOGGER.log(Level.FINEST, "Resetting {0} session keys.", keyDescription);
        Arrays.fill(this.sendingCtr, (byte) 0x00);
        Arrays.fill(this.receivingCtr, (byte) 0x00);
        this.sendingAESKey = null;
        this.receivingAESKey = null;
        this.sendingMACKey = null;
        this.receivingMACKey = null;
        this.setIsUsedReceivingMACKey(false);
        this.s = null;
        if (localPair != null && remoteKey != null) {
            this.isHigh = ((DHPublicKey) localPair.getPublic()).getY()
                    .abs().compareTo(remoteKey.getY().abs()) == 1;
        }
    }

    private byte[] h1(@Nonnull final byte b) throws OtrException {
        final byte[] secbytes;
        try {
            secbytes = SerializationUtils.writeMpi(getS());
        } catch (IOException ex) {
            throw new OtrException(ex);
        }
        final int len = secbytes.length + 1;
        final ByteBuffer buff = ByteBuffer.allocate(len);
        buff.put(b);
        buff.put(secbytes);
        return OtrCryptoEngine.sha1Hash(buff.array());
    }

    public byte[] getSendingAESKey() throws OtrException {
        if (sendingAESKey != null) {
            return sendingAESKey;
        }

        final byte sendbyte;
        if (this.isHigh) {
            sendbyte = HIGH_SEND_BYTE;
        } else {
            sendbyte = LOW_SEND_BYTE;
        }

        final byte[] h1 = h1(sendbyte);

        final byte[] key = new byte[OtrCryptoEngine.AES_KEY_BYTE_LENGTH];
        final ByteBuffer buff = ByteBuffer.wrap(h1);
        buff.get(key);
        LOGGER.finest("Calculated sending AES key.");
        this.sendingAESKey = key;
        return sendingAESKey;
    }

    public byte[] getReceivingAESKey() throws OtrException {
        if (receivingAESKey != null) {
            return receivingAESKey;
        }

        final byte receivebyte;
        if (this.isHigh) {
            receivebyte = HIGH_RECEIVE_BYTE;
        } else {
            receivebyte = LOW_RECEIVE_BYTE;
        }

        final byte[] h1 = h1(receivebyte);

        final byte[] key = new byte[OtrCryptoEngine.AES_KEY_BYTE_LENGTH];
        final ByteBuffer buff = ByteBuffer.wrap(h1);
        buff.get(key);
        LOGGER.finest("Calculated receiving AES key.");
        this.receivingAESKey = key;

        return receivingAESKey;
    }

    public byte[] getSendingMACKey() throws OtrException {
        if (sendingMACKey != null) {
            return sendingMACKey;
        }

        sendingMACKey = OtrCryptoEngine.sha1Hash(getSendingAESKey());
        LOGGER.finest("Calculated sending MAC key.");
        return sendingMACKey;
    }

    public byte[] getReceivingMACKey() throws OtrException {
        if (receivingMACKey == null) {
            receivingMACKey = OtrCryptoEngine.sha1Hash(getReceivingAESKey());
            LOGGER.finest("Calculated receiving MAC key.");
        }
        return receivingMACKey;
    }

    private BigInteger getS() throws OtrException {
        if (s == null) {
            s = OtrCryptoEngine.generateSecret(localPair.getPrivate(), remoteKey);
            LOGGER.finest("Calculated new shared secret S.");
        }
        return s;
    }

    public void setS(final BigInteger s) {
        this.s = s;
    }

    public void setIsUsedReceivingMACKey(final boolean isUsedReceivingMACKey) {
        this.isUsedReceivingMACKey = isUsedReceivingMACKey;
    }

    public boolean getIsUsedReceivingMACKey() {
        return isUsedReceivingMACKey;
    }

    public int getLocalKeyID() {
        return localKeyID;
    }

    public int getRemoteKeyID() {
        return remoteKeyID;
    }

    public DHPublicKey getRemoteKey() {
        return remoteKey;
    }

    public KeyPair getLocalPair() {
        return localPair;
    }

}