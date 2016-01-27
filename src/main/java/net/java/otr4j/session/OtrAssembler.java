/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package net.java.otr4j.session;

import java.math.BigInteger;
import java.net.ProtocolException;

/**
 *
 * @author Felix Eckhofer
 *
 */
public final class OtrAssembler {

    private static final int MAX_FRAGMENTS = 65535;

	public OtrAssembler(final InstanceTag ownInstance) {
		this.ownInstance = ownInstance;
		discard();
	}

	/**
	 * Accumulated fragment thus far.
	 */
	private StringBuffer fragment;

	/**
	 * Number of last fragment received.
	 * This variable must be able to store an unsigned short value.
	 */
	private int fragmentCur;

	/**
	 * Total number of fragments in message.
	 * This variable must be able to store an unsigned short value.
	 */
	private int fragmentMax;

	/**
	 * Relevant instance tag.
	 * OTRv3 fragments with a different instance tag are discarded.
	 */
	private final InstanceTag ownInstance;

	private static final String HEAD_FRAGMENT_V2 = "?OTR,";
	private static final String HEAD_FRAGMENT_V3 = "?OTR|";

	/**
	 * Appends a message fragment to the internal buffer and returns
	 * the full message if msgText was no fragmented message or all
	 * the fragments have been combined. Returns null, if there are
	 * fragments pending or an invalid fragment was received.
	 * <p>
	 * A fragmented OTR message looks like this:
	 * (V2) ?OTR,k,n,piece-k,
	 *  or
	 * (V3) ?OTR|sender_instance|receiver_instance,k,n,piece-k,
	 *
	 * @param msgText Message to be processed.
	 *
	 * @return String with the accumulated message or
	 *         null if the message was incomplete or malformed
     * @throws ProtocolException MVN_PASS_JAVADOC_INSPECTION
     * @throws UnknownInstanceException MVN_PASS_JAVADOC_INSPECTION
	 */
	public String accumulate(String msgText)
		throws ProtocolException, UnknownInstanceException {
		// if it's a fragment, remove everything before "k,n,piece-k"
		if (msgText.startsWith(HEAD_FRAGMENT_V2)) {
			// v2
			msgText = msgText.substring(
					HEAD_FRAGMENT_V2.length());
		} else if (msgText.startsWith(HEAD_FRAGMENT_V3)) {
			// v3
			msgText = msgText.substring(
					HEAD_FRAGMENT_V3.length());

			// break away the v2 part
			String[] instancePart = msgText.split(",", 2);
			// split the two instance ids
			String[] instances = instancePart[0].split("\\|", 2);

			if (instancePart.length != 2 || instances.length != 2) {
				discard();
				throw new ProtocolException();
			}

            // parse receiver instance tag
			final int receiverInstance;
			try {
                // Verify length before parsing as BigInteger, as BigInteger
                // will support much larger tag values even though they are not
                // valid according to spec. With conversion to int they will be
                // truncated without warning, so we need to discover invalid
                // tags before parsing.
                if (instances[1].length() > 8) {
                    throw new ProtocolException("Invalid receiver instance id: " + instances[1] + ". Instance tag is too big.");
                }
				receiverInstance = new BigInteger(instances[1], 16).intValue();
			} catch (NumberFormatException e) {
				discard();
				throw new ProtocolException("Invalid receiver instance id: " + instances[1]);
			}

            // FIXME should we also verify that the sender instance tag of the fragment is valid? The sender instance tag is now ignored completely.

			if (receiverInstance != 0 &&
					receiverInstance != ownInstance.getValue()) {
				// discard message for different instance id
				throw new UnknownInstanceException(
						"Message for unknown instance tag " +
						String.valueOf(receiverInstance) +
						" received: " + msgText);
			}

			// continue with v2 part of fragment
			msgText = instancePart[1];
		} else {
			// not a fragmented message
			discard();
			return msgText;
		}

		String[] params = msgText.split(",", 4);

		int k, n;
		try {
			k = Integer.parseInt(params[0]);
			n = Integer.parseInt(params[1]);
		} catch (NumberFormatException e) {
			discard();
			throw new ProtocolException("Bad format for parameters");
		} catch (ArrayIndexOutOfBoundsException e) {
			discard();
			throw new ProtocolException("Expected at least 2 parameters");
		}

		if (k <= 0 || k > MAX_FRAGMENTS || n <= 0 || n > MAX_FRAGMENTS || k > n
                || params.length != 4 || params[2].isEmpty()
                || !params[3].isEmpty()) {
			discard();
			throw new ProtocolException("Expected exactly 4 parameters and parameters according to specification");
		}

		msgText = params[2];

		if (k == 1) {
			// first fragment
			discard();
			fragmentCur = k;
			fragmentMax = n;
			fragment.append(msgText);
		} else if (n == fragmentMax && k == fragmentCur+1) {
			// consecutive fragment
			fragmentCur++;
			fragment.append(msgText);
		} else {
			// out-of-order fragment
			discard();
			throw new ProtocolException();
		}

		if (n == k && n > 0) {
			String result = fragment.toString();
			discard();
			return result;
		} else {
			return null; // incomplete fragment
		}
	}

	/**
	 * Discard current fragment buffer and reset the counters.
	 */
	public void discard() {
		fragment = new StringBuffer();
		fragmentCur = 0;
		fragmentMax = 0;
	}

}
