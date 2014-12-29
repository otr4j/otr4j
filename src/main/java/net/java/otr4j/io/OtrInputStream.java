package net.java.otr4j.io;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.interfaces.DHPublicKey;

import net.java.otr4j.crypto.OtrCryptoEngineImpl;
import net.java.otr4j.io.messages.SignatureX;

public class OtrInputStream extends FilterInputStream implements
		SerializationConstants {

	public OtrInputStream(InputStream in) {
		super(in);
	}

	/**
	 * Reads from the stream while checking possible border and error conditions
	 * like a requested size of zero or the stream does not contain enough data.
	 *
	 * @param length
	 *            amount of bytes to read from the stream
	 * @return the read bytes
	 * @throws IOException
	 *             the exact amount of requested bytes could not be read from
	 *             the stream.
	 */
	private byte[] checkedRead(int length) throws IOException {
		if (length == 0) {
			return new byte[0];
		}
		byte[] b = new byte[length];
		int bytesRead = read(b);
		if (bytesRead != length) {
			throw new IOException(
					"Unable to read the required amount of bytes from the stream. Expected were "
							+ length + " bytes but I could only read "
							+ bytesRead + " bytes.");
		}
		return b;
	}

	private int readNumber(int length) throws IOException {
		byte[] b = checkedRead(length);

		int value = 0;
		for (int i = 0; i < b.length; i++) {
			int shift = (b.length - 1 - i) * 8;
			value += (b[i] & 0x000000FF) << shift;
		}

		return value;
	}

	public int readByte() throws IOException {
		return readNumber(TYPE_LEN_BYTE);
	}

	public int readInt() throws IOException {
		return readNumber(TYPE_LEN_INT);
	}

	public int readShort() throws IOException {
		return readNumber(TYPE_LEN_SHORT);
	}

	public byte[] readCtr() throws IOException {
		return checkedRead(TYPE_LEN_CTR);
	}

	public byte[] readMac() throws IOException {
		return checkedRead(TYPE_LEN_MAC);
	}

	public BigInteger readBigInt() throws IOException {
		byte[] b = readData();
		return new BigInteger(1, b);
	}

	public byte[] readData() throws IOException {
		int dataLen = readNumber(DATA_LEN);
		return checkedRead(dataLen);
	}

	public PublicKey readPublicKey() throws IOException {
		int type = readShort();
		switch (type) {
		case 0:
			BigInteger p = readBigInt();
			BigInteger q = readBigInt();
			BigInteger g = readBigInt();
			BigInteger y = readBigInt();
			DSAPublicKeySpec keySpec = new DSAPublicKeySpec(y, p, q, g);
			KeyFactory keyFactory;
			try {
				keyFactory = KeyFactory.getInstance("DSA");
			} catch (NoSuchAlgorithmException e) {
				throw new IOException();
			}
			try {
				return keyFactory.generatePublic(keySpec);
			} catch (InvalidKeySpecException e) {
				throw new IOException();
			}
		default:
			throw new UnsupportedOperationException();
		}
	}

	public DHPublicKey readDHPublicKey() throws IOException {
		BigInteger gyMpi = readBigInt();
		try {
			return new OtrCryptoEngineImpl().getDHPublicKey(gyMpi);
		} catch (Exception ex) {
			throw new IOException();
		}
	}

	public byte[] readTlvData() throws IOException {
		int len = readNumber(TYPE_LEN_SHORT);
		return checkedRead(len);
	}

	public byte[] readSignature(PublicKey pubKey) throws IOException {
		if (!pubKey.getAlgorithm().equals("DSA"))
			throw new UnsupportedOperationException();

		DSAPublicKey dsaPubKey = (DSAPublicKey) pubKey;
		DSAParams dsaParams = dsaPubKey.getParams();
		return checkedRead(dsaParams.getQ().bitLength() / 4);
	}

	public SignatureX readMysteriousX() throws IOException {
		PublicKey pubKey = readPublicKey();
		int dhKeyID = readInt();
		byte[] sig = readSignature(pubKey);
		return new SignatureX(pubKey, dhKeyID, sig);
	}
}
