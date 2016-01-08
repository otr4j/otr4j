package net.java.otr4j.session;

import java.net.ProtocolException;

public class UnknownInstanceException extends ProtocolException {
    private static final long serialVersionUID = -9038076875471875721L;

	public UnknownInstanceException(String host) {
		super(host);
	}
}
