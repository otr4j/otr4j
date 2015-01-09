package net.java.otr4j.session;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import net.java.otr4j.OtrEngineListener;
import net.java.otr4j.OtrException;
import net.java.otr4j.OtrPolicy;
import net.java.otr4j.io.messages.AbstractMessage;

public interface Session {

	public static interface OTRv {
		public static final int ONE = 1;

		public static final int TWO = 2;

		public static final int THREE = 3;

		public static final Set<Integer> ALL = new HashSet<Integer>(
				Arrays.asList(new Integer[] { ONE, TWO, THREE }));
	}

	public abstract SessionStatus getSessionStatus();

	public abstract SessionID getSessionID();

	public abstract void injectMessage(AbstractMessage m) throws OtrException;

	public abstract KeyPair getLocalKeyPair() throws OtrException;

	public abstract OtrPolicy getSessionPolicy();

	public abstract String transformReceiving(String content)
			throws OtrException;

	public abstract String[] transformSending(String content, List<TLV> tlvs)
			throws OtrException;

	public abstract String[] transformSending(String content)
			throws OtrException;

	public abstract void startSession() throws OtrException;

	public abstract void endSession() throws OtrException;

	public abstract void refreshSession() throws OtrException;

	public abstract PublicKey getRemotePublicKey();

	public abstract void addOtrEngineListener(OtrEngineListener l);

	public abstract void removeOtrEngineListener(OtrEngineListener l);

	public abstract void initSmp(String question, String secret)
			throws OtrException;

	public abstract void respondSmp(String question, String secret)
			throws OtrException;

	public abstract void abortSmp() throws OtrException;
	
	public abstract boolean isSmpInProgress();

	public abstract BigInteger getS();

	// OTRv3 methods
	public abstract List<Session> getInstances();

	public abstract Session getOutgoingInstance();

	public abstract boolean setOutgoingInstance(InstanceTag tag);

	public abstract InstanceTag getSenderInstanceTag();

	public abstract InstanceTag getReceiverInstanceTag();

	public abstract void setReceiverInstanceTag(InstanceTag tag);

	public abstract void setProtocolVersion(int protocolVersion);

	public abstract int getProtocolVersion();

	public abstract void respondSmp(
			InstanceTag receiverTag, String question, String secret)
					throws OtrException;

	public abstract SessionStatus getSessionStatus(InstanceTag tag);

	public abstract PublicKey getRemotePublicKey(InstanceTag tag);
}