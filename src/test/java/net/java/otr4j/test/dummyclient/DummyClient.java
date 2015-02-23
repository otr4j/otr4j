
package net.java.otr4j.test.dummyclient;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Queue;
import java.util.concurrent.CountDownLatch;
import java.util.logging.Logger;

import net.java.otr4j.OtrEngineHost;
import net.java.otr4j.OtrException;
import net.java.otr4j.OtrPolicy;
import net.java.otr4j.crypto.OtrCryptoEngine;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.session.InstanceTag;
import net.java.otr4j.session.Session;
import net.java.otr4j.session.SessionID;
import net.java.otr4j.session.SessionStatus;
import net.java.otr4j.session.TLV;

/**
 * Created by gp on 2/5/14.
 */
public class DummyClient {

    private Logger logger;
	private final String account;
	private Session session;
	private OtrPolicy policy;
	private Connection connection;
	private MessageProcessor processor;
	private Queue<ProcessedTestMessage> processedMsgs = new LinkedList<ProcessedTestMessage>();

    private CountDownLatch lock;
    private int verified = NOTSET;
    public static final int NOTSET = 0;
    public static final int UNVERIFIED = 1;
    public static final int VERIFIED = 2;

    public static DummyClient[] getConversation() {
        DummyClient bob = new DummyClient("Bob@Wonderland");
        bob.setPolicy(new OtrPolicy(OtrPolicy.ALLOW_V2 | OtrPolicy.ALLOW_V3
                | OtrPolicy.ERROR_START_AKE));

        DummyClient alice = new DummyClient("Alice@Wonderland");
        alice.setPolicy(new OtrPolicy(OtrPolicy.ALLOW_V2
                | OtrPolicy.ALLOW_V3 | OtrPolicy.ERROR_START_AKE));

        Server server = new PriorityServer();
        alice.connect(server);
        bob.connect(server);
        return new DummyClient[] { alice, bob };
    }

    public static DummyClient[] getConversation(CountDownLatch aliceLock, CountDownLatch bobLock) {
		DummyClient bob = new DummyClient("Bob@Wonderland", bobLock);
		bob.setPolicy(new OtrPolicy(OtrPolicy.ALLOW_V2 | OtrPolicy.ALLOW_V3
				| OtrPolicy.ERROR_START_AKE));

		DummyClient alice = new DummyClient("Alice@Wonderland", aliceLock);
		alice.setPolicy(new OtrPolicy(OtrPolicy.ALLOW_V2
				| OtrPolicy.ALLOW_V3 | OtrPolicy.ERROR_START_AKE));

		Server server = new PriorityServer();
		alice.connect(server);
		bob.connect(server);
		return new DummyClient[] { alice, bob };
	}

	public static boolean forceStartOtr(DummyClient alice, DummyClient bob)
			throws OtrException {
		bob.secureSession(alice.getAccount());

		alice.pollReceivedMessage(); // Query
		bob.pollReceivedMessage(); // DH-Commit
		alice.pollReceivedMessage(); // DH-Key
		bob.pollReceivedMessage(); // Reveal signature
		alice.pollReceivedMessage(); // Signature

		if (bob.getSession().getSessionStatus() != SessionStatus.ENCRYPTED)
			return false;
		if (alice.getSession().getSessionStatus() != SessionStatus.ENCRYPTED)
			return false;
		return true;
	}

	public DummyClient(String account) {
	    this(account, null);
	}

	public DummyClient(String account, CountDownLatch lock) {
	    this.lock = lock;
	    logger = Logger.getLogger(account);
		this.account = account;
	}

	public Session getSession() {
		return session;
	}

	public String getAccount() {
		return account;
	}

	public int getVerified() {
	    return verified;
	}

	public void setPolicy(OtrPolicy policy) {
		this.policy = policy;
	}

	public void send(String recipient, String s) throws OtrException {
		if (session == null) {
			final SessionID sessionID = new SessionID(account, recipient, "DummyProtocol");
			session = new Session(sessionID, new DummyOtrEngineHostImpl());
		}

		String[] outgoingMessage = session.transformSending(s, (List<TLV>) null);
		for (String part : outgoingMessage) {
			connection.send(recipient, part);
		}
	}

	public void exit() throws OtrException {
		this.processor.stop();
		if (session != null)
			session.endSession();
	}

	public void receive(String sender, String s) throws OtrException {
		this.processor.enqueue(sender, s);
	}

	public void connect(Server server) {
		this.processor = new MessageProcessor();
		new Thread(this.processor).start();
		this.connection = server.connect(this);
	}

    public void stop() {
        this.processor.stop();
    }

    public void stopBeforeProcessingNextMessage() {
        this.processor.stopBeforeProcessingNextMessage();
    }

    public TestMessage getNextTestMessage() {
        return this.processor.getNextTestMessage();
    }

	public void secureSession(String recipient) throws OtrException {
		if (session == null) {
			final SessionID sessionID = new SessionID(account, recipient, "DummyProtocol");
			session = new Session(sessionID, new DummyOtrEngineHostImpl());
		}

		session.startSession();
	}

	public Connection getConnection() {
		return connection;
	}

	public ProcessedTestMessage pollReceivedMessage() {
		synchronized (processedMsgs) {
			ProcessedTestMessage m;
			while ((m = processedMsgs.poll()) == null) {
                logger.finest("polling");
				try {
					processedMsgs.wait();
				} catch (InterruptedException e) {
				}
			}

			return m;
		}
	}

	class MessageProcessor implements Runnable {
		private final Queue<TestMessage> messageQueue = new LinkedList<TestMessage>();
		private boolean stopped;
        private boolean stopBeforeProcessingNextMessage;
        private TestMessage m;

		private void process(TestMessage m) throws OtrException {
			if (session == null) {
				final SessionID sessionID = new SessionID(account, m.getSender(), "DummyProtocol");
				session = new Session(sessionID, new DummyOtrEngineHostImpl());
			}

			String receivedMessage = session.transformReceiving(m.getContent());
			synchronized (processedMsgs) {
				processedMsgs.add(new ProcessedTestMessage(m, receivedMessage));
				processedMsgs.notify();
			}
		}

		public void run() {
			synchronized (messageQueue) {
				while (true) {

                    m = messageQueue.poll();

					if (m == null) {
						try {
							messageQueue.wait();
						} catch (InterruptedException e) {

						}
					} else {
						try {
                            if (stopBeforeProcessingNextMessage) {
                                break;
                            } else {
							process(m);
                            }
						} catch (OtrException e) {
							e.printStackTrace();
						}
					}

					if (stopped)
						break;
				}
			}
		}

		public void enqueue(String sender, String s) {
			synchronized (messageQueue) {
				messageQueue.add(new TestMessage(sender, s));
				messageQueue.notify();
			}
		}

		public void stop() {
			stopped = true;

			synchronized (messageQueue) {
				messageQueue.notify();
			}
		}

        public void stopBeforeProcessingNextMessage() {
            stopBeforeProcessingNextMessage = true;
        }

        public TestMessage getNextTestMessage() {
            while (true) {
                if (m == null) {
                    logger.finest("polling");
                    try {
                        Thread.sleep(500);
                    } catch (InterruptedException e) {
                    }
                } else {
                    return m;
                }

                if (stopped)
                    return null;
            }
        }
	}

	public class DummyOtrEngineHostImpl implements OtrEngineHost {

	    private HashMap<SessionID, KeyPair> keypairs = new HashMap<SessionID, KeyPair>();

		public void injectMessage(SessionID sessionID, String msg) throws OtrException {
			connection.send(sessionID.getUserID(), msg);

			String msgDisplay = (msg.length() > 10) ? msg.substring(0, 10)
					+ "..." : msg;
			logger.finest("IM injects message: " + msgDisplay);
		}

		public void smpError(SessionID sessionID, int tlvType, boolean cheated)
				throws OtrException {
			logger.severe("SM verification error with user: " + sessionID);
		}

		public void smpAborted(SessionID sessionID) throws OtrException {
			logger.severe("SM verification has been aborted by user: "
					+ sessionID);
		}

		public void finishedSessionMessage(SessionID sessionID, String msgText) throws OtrException {
			logger.severe("SM session was finished. You shouldn't send messages to: "
					+ sessionID);
		}

		public void requireEncryptedMessage(SessionID sessionID, String msgText)
				throws OtrException {
			logger.severe("Message can't be sent while encrypted session is not established: "
					+ sessionID);
		}

		public void unreadableMessageReceived(SessionID sessionID)
				throws OtrException {
			logger.warning("Unreadable message received from: " + sessionID);
		}

		public void unencryptedMessageReceived(SessionID sessionID, String msg)
				throws OtrException {
			logger.warning("Unencrypted message received: " + msg + " from "
					+ sessionID);
		}

		public void showError(SessionID sessionID, String error)
				throws OtrException {
			logger.severe("IM shows error to user: " + error);
		}

        public KeyPair getLocalKeyPair(SessionID paramSessionID) {
            KeyPair keypair = this.keypairs.get(paramSessionID);
            if (keypair == null) {
                try {
                    KeyPairGenerator kg = KeyPairGenerator.getInstance("DSA");
                    keypair = kg.genKeyPair();
                    this.keypairs.put(paramSessionID, keypair);
                } catch (NoSuchAlgorithmException e) {
                    logger.severe(e.getMessage());
                }
            }
            return keypair;
        }

		public OtrPolicy getSessionPolicy(SessionID ctx) {
			return policy;
		}

		public byte[] getLocalFingerprintRaw(SessionID sessionID) {
			try {
				return new OtrCryptoEngine()
						.getFingerprintRaw(getLocalKeyPair(sessionID)
								.getPublic());
			} catch (OtrCryptoException e) {
				e.printStackTrace();
			}
			return null;
		}

		public void askForSecret(SessionID sessionID, InstanceTag receiverTag, String question) {
            logger.finer("Ask for secret from: " + sessionID
                    + ", instanceTag: " + receiverTag + ", question: " + question);
            if (lock != null)
                lock.countDown();
		}

		public void verify(SessionID sessionID, String fingerprint, boolean approved) {
            logger.finer("Session was verified: " + sessionID);
            if (approved)
                logger.fine("Your answer was approved");
            else
                logger.fine("Your answer for the question was verified."
                        + "You should ask your opponent too or check shared secret.");
            verified = VERIFIED;
            if (lock != null)
                lock.countDown();
		}

		public void unverify(SessionID sessionID, String fingerprint) {
            logger.fine("Session was not verified: " + sessionID + "  fingerprint: " + fingerprint);
            verified = UNVERIFIED;
            if (lock != null)
                lock.countDown();
		}

		public String getReplyForUnreadableMessage(SessionID sessionID) {
            return "You sent me an unreadable encrypted message.";
		}

		public String getFallbackMessage(SessionID sessionID) {
            return "Off-the-Record private conversation has been requested. However, you do not have a plugin to support that.";
		}

		public void messageFromAnotherInstanceReceived(SessionID sessionID) {

		}

		public void multipleInstancesDetected(SessionID sessionID) {

		}

		public int getMaxFragmentSize(SessionID sessionID) {
			return Integer.MAX_VALUE;
		}
	}
}
