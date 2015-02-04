/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package net.java.otr4j.io;

/**
 * 
 * @author George Politis
 */
public interface SerializationConstants {

	public static final String HEAD = "?OTR";
	public static final char HEAD_ENCODED = ':';
	public static final char HEAD_ERROR = ' ';
	public static final char HEAD_QUERY_Q = '?';
	public static final char HEAD_QUERY_V = 'v';
	public static final String ERROR_PREFIX = "Error:";

	public static final int TYPE_LEN_BYTE = 1;
	public static final int TYPE_LEN_SHORT = 2;
	public static final int TYPE_LEN_INT = 4;
	public static final int TYPE_LEN_MAC = 20;
	public static final int TYPE_LEN_CTR = 8;

	public static final int DATA_LEN = TYPE_LEN_INT;
	public static final int TLV_LEN = TYPE_LEN_SHORT;

    public static final String RequestMessage = "Your contact is requesting to start an encrypted chat. Please install an app that supports OTR: https://github.com/otr4j/otr4j/wiki/Apps";
}
