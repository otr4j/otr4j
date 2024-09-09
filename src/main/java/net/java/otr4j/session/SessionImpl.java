/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.session;

import com.google.errorprone.annotations.concurrent.GuardedBy;
import net.java.otr4j.api.ClientProfile;
import net.java.otr4j.api.Event;
import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.api.OfferStatus;
import net.java.otr4j.api.OtrEngineHost;
import net.java.otr4j.api.OtrEngineHosts;
import net.java.otr4j.api.OtrEngineListener;
import net.java.otr4j.api.OtrEngineListeners;
import net.java.otr4j.api.OtrException;
import net.java.otr4j.api.OtrPolicy;
import net.java.otr4j.api.RemoteInfo;
import net.java.otr4j.api.Session;
import net.java.otr4j.api.SessionID;
import net.java.otr4j.api.SessionStatus;
import net.java.otr4j.api.TLV;
import net.java.otr4j.api.Version;
import net.java.otr4j.crypto.DSAKeyPair;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.crypto.ed448.EdDSAKeyPair;
import net.java.otr4j.crypto.ed448.Point;
import net.java.otr4j.io.EncodedMessage;
import net.java.otr4j.io.ErrorMessage;
import net.java.otr4j.io.Fragment;
import net.java.otr4j.io.Message;
import net.java.otr4j.io.OtrEncodables;
import net.java.otr4j.io.OtrInputStream;
import net.java.otr4j.io.PlainTextMessage;
import net.java.otr4j.io.QueryMessage;
import net.java.otr4j.messages.AbstractEncodedMessage;
import net.java.otr4j.messages.ClientProfilePayload;
import net.java.otr4j.messages.ValidationException;
import net.java.otr4j.session.ake.AuthState;
import net.java.otr4j.session.ake.StateInitial;
import net.java.otr4j.session.dake.DAKEInitial;
import net.java.otr4j.session.dake.DAKEState;
import net.java.otr4j.session.state.Context;
import net.java.otr4j.session.state.IncorrectStateException;
import net.java.otr4j.session.state.State;
import net.java.otr4j.session.state.StateEncrypted;
import net.java.otr4j.session.state.StatePlaintext;
import net.java.otr4j.util.Unit;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.net.ProtocolException;
import java.security.SecureRandom;
import java.security.interfaces.DSAPublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.time.temporal.ChronoUnit.DAYS;
import static java.time.temporal.ChronoUnit.HOURS;
import static java.util.Collections.emptyMap;
import static java.util.Collections.singletonList;
import static java.util.Objects.requireNonNull;
import static java.util.logging.Level.FINE;
import static java.util.logging.Level.FINEST;
import static java.util.logging.Level.INFO;
import static java.util.logging.Level.WARNING;
import static net.java.otr4j.api.InstanceTag.ZERO_TAG;
import static net.java.otr4j.api.OtrEngineHosts.handleEvent;
import static net.java.otr4j.api.OtrEngineHosts.restoreClientProfilePayload;
import static net.java.otr4j.api.OtrEngineHosts.updateClientProfilePayload;
import static net.java.otr4j.api.OtrEngineListeners.duplicate;
import static net.java.otr4j.api.OtrEngineListeners.outgoingSessionChanged;
import static net.java.otr4j.api.OtrEngineListeners.sessionStatusChanged;
import static net.java.otr4j.api.OtrPolicys.allowedVersions;
import static net.java.otr4j.api.SessionStatus.ENCRYPTED;
import static net.java.otr4j.api.SessionStatus.PLAINTEXT;
import static net.java.otr4j.api.Version.FOUR;
import static net.java.otr4j.api.Version.THREE;
import static net.java.otr4j.api.Version.TWO;
import static net.java.otr4j.io.MessageProcessor.parseMessage;
import static net.java.otr4j.io.MessageProcessor.writeMessage;
import static net.java.otr4j.messages.ClientProfilePayload.signClientProfile;
import static net.java.otr4j.messages.EncodedMessageParser.checkAuthRMessage;
import static net.java.otr4j.messages.EncodedMessageParser.checkDHKeyMessage;
import static net.java.otr4j.messages.EncodedMessageParser.parseEncodedMessage;
import static net.java.otr4j.session.api.SMPStatus.INPROGRESS;
import static net.java.otr4j.session.state.State.FLAG_IGNORE_UNREADABLE;
import static net.java.otr4j.session.state.State.FLAG_NONE;
import static net.java.otr4j.util.Objects.requireEquals;

/**
 * Implementation of the OTR session.
 * <p>
 * otr4j Session supports OTRv2's single session as well as OTRv3's multiple
 * sessions, even simultaneously (at least in theory). Support is managed
 * through the concept of slave sessions. As OTRv2 does not recognize instance
 * tags, there can be only a single session. The master (non-slave) session will
 * represent the OTRv2 status. (As well as have an instance tag value of 0.)
 * <p>
 * OTRv3 will establish all of its sessions in the {@link #slaveSessions} map.
 * The master session only functions as the inbound rendezvous point, but any
 * outbound activity as well as the session status itself is managed within a
 * (dedicated) slave session.
 * <p>
 * There is an added complication in the fact that DH Commit message may be sent
 * with a receiver tag. At first instance, we have not yet communicated our
 * sender instance tag to our buddy. Therefore we (need to) allow DH Commit
 * messages to be sent without a receiver tag. As a consequence, we may receive
 * multiple DH Key messages in return, in case multiple client (instances) feel
 * inclined to respond. In the case where we send a DH Commit message without
 * receiver tag, we keep AKE state progression on the master session. This means
 * that the master session AKE state is set to AWAITING_DHKEY with appropriate
 * OTR protocol version. When receiving DH Key message(s) - for this particular
 * case - we copy AKE state to the (possibly newly created) slave sessions and
 * continue AKE message handling there.
 * <p>
 * SessionImpl is thread-safe. Thread-safety is achieved by serializing method calls of a session instance to the
 * corresponding master session. As the master session contains itself as master session, we can serialize both master
 * and slave sessions without concerns. Given that both synchronize to the master, we cannot use two slaves at the same
 * time. On the other hand, there are no complications with potential dead-locks, given that there is only one lock to
 * take.
 *
 * @author George Politis
 * @author Danny van Heumen
 */
// TODO consider moving away from recursive use of Session, to delegating class with a number of instances of Session for each instance, with OTRv2 using zero-instance-tag. (Can delegating class be stateless? Would simplify managing thread-safety.)
// TODO consider reducing complexity.
// TODO how does that work when receiving an ?OTR ERROR message while in encrypted session? These messages are not authenticated, so can be injected. Is there a way of selective handling to avoid interference?
// TODO what happens with existing "active" version3-session if client disconnects then reconnects and establishes OTRv4 session? (with exact same instance-tag as necessary by client-profile)
@SuppressWarnings({"PMD.TooManyFields"})
final class SessionImpl implements Session, Context {

    private static final String DEFAULT_FALLBACK_MESSAGE = "Your contact is requesting to start an encrypted chat. Please install an app that supports OTR: https://github.com/otr4j/otr4j/wiki/Apps";

    private static final int DEFAULT_CLIENTPROFILE_EXPIRATION_DAYS = 14;
    
    private static final int CLIENTPROFILE_EXPIRATION_POJECTION_HOURS = 12;

    /**
     * Session state contains the currently active message state of the session.
     * <p>
     * The message state, being plaintext, encrypted or finished, is the
     * instance that contains the logic concerning message handling for both
     * incoming and outgoing messages, and everything related to this message
     * state.
     */
    @Nonnull
    private volatile State sessionState;

    /**
     * Slave sessions contain the mappings of instance tags to outgoing
     * sessions. In case of the master session, it is initialized with an empty
     * instance. In case of slaves the slaveSessions instance is initialized to
     * an (immutable) empty map.
     */
    @GuardedBy("masterSession")
    @Nonnull
    private final Map<InstanceTag, SessionImpl> slaveSessions;

    @Nonnull
    private final SessionID sessionID;

    /**
     * The currently selected slave session that will be used as the session
     * for outgoing messages.
     */
    // TODO how can the master session be outgoing but also there can be slave sessions? (Should we prevent slave session for instance zero?)
    @GuardedBy("masterSession")
    @Nonnull
    private SessionImpl outgoingSession;

    /**
     * Flag indicating whether this instance is a master session or a slave session.
     * <p>
     * This field will contain the master session instance for all slaves. It will self-reference in case of the master
     * session instance. Therefore, the master session need never be null.
     */
    @GuardedBy("itself")
    @Nonnull
    private final SessionImpl masterSession;

    /**
     * The Engine Host instance. This is a reference to the host logic that uses
     * OTR. The reference is used to call back into the program logic in order
     * to query for parameters that are determined by the program logic.
     */
    @Nonnull
    private final OtrEngineHost host;

    @SuppressWarnings({"NonConstantLogger", "PMD.LoggerIsNotStaticFinal"})
    @Nonnull
    private final Logger logger;

    /**
     * Offer status for whitespace-tagged message indicating OTR supported.
     */
    @GuardedBy("masterSession")
    @Nonnull
    private OfferStatus offerStatus;

    /**
     * The sender-tag is the instance-tag from the client-profile.
     * Note: this sender instance-tag must be same as instance-tag in ClientProfile. (`profilePayload`)
     */
    @Nonnull
    private final InstanceTag senderTag;

    /**
     * Receiver instance tag.
     * <p>
     * The receiver tag is only used in OTRv3. In case of OTRv2 the instance tag
     * will be zero-tag ({@link InstanceTag#ZERO_TAG}).
     */
    @Nonnull
    private final InstanceTag receiverTag;

    /**
     * OTR-encoded message-assembler.
     */
    @GuardedBy("masterSession")
    private final Assembler assembler = new Assembler();

    /**
     * Message fragmenter.
     */
    @GuardedBy("masterSession")
    @Nonnull
    private final Fragmenter fragmenter;

    /**
     * Secure random instance to be used for this Session. This single SecureRandom instance is there to be shared among
     * the classes in this package in order to support this specific Session instance. The SecureRandom instance should
     * not be shared between sessions.
     */
    @Nonnull
    private final SecureRandom secureRandom;

    /**
     * List of registered listeners.
     * <p>
     * Synchronized access is required. This is currently managed in methods
     * accessing the list.
     */
    @GuardedBy("masterSession")
    private final ArrayList<OtrEngineListener> listeners = new ArrayList<>();

    /**
     * Listener for propagating events from slave sessions to the listeners of
     * the master session. The same instance is reused for all slave sessions.
     */
    @GuardedBy("masterSession")
    private final OtrEngineListener slaveSessionsListener = new OtrEngineListener() {

        @GuardedBy("SessionImpl.this.masterSession")
        @Override
        public void sessionStatusChanged(final SessionID sessionID, final InstanceTag receiver) {
            OtrEngineListeners.sessionStatusChanged(duplicate(SessionImpl.this.listeners), sessionID, receiver);
        }

        @GuardedBy("SessionImpl.this.masterSession")
        @Override
        public void multipleInstancesDetected(final SessionID sessionID) {
            throw new IllegalStateException("Multiple instances should be detected in the master session. This event should never have happened.");
        }

        @GuardedBy("SessionImpl.this.masterSession")
        @Override
        public void outgoingSessionChanged(final SessionID sessionID) {
            throw new IllegalStateException("Outgoing session changes should be performed in the master session only. This event should never have happened.");
        }
    };

    /**
     * Constructor for setting up a master session.
     * <p>
     * Package-private constructor for creating new sessions. To create a sessions without using the OTR session
     * manager, we offer a static method that (indirectly) provides access to the session implementation. See
     * {@link OtrSessionManager#createSession(SessionID, OtrEngineHost)}.
     * <p>
     * This constructor constructs a master session instance.
     *
     * @param sessionID The session ID
     * @param host      The OTR engine host listener.
     */
    SessionImpl(final SessionID sessionID, final OtrEngineHost host) {
        this(null, sessionID, host, ZERO_TAG, new SecureRandom());
    }

    /**
     * Constructor for setting up either a master or a slave session. (Only masters construct a slave session.)
     *
     * @param masterSession The master session instance. The provided instance is set as the master session. In case of
     *                      the master session, null can be provided to indicate that this session instance is the
     *                      master session. Providing null, sets the master session instance to this session.
     * @param sessionID     The session ID.
     * @param host          OTR engine host instance.
     * @param receiverTag   The receiver instance tag. The receiver instance tag is allowed to be ZERO.
     * @param secureRandom  The secure random instance.
     */
    private SessionImpl(@Nullable final SessionImpl masterSession, final SessionID sessionID, final OtrEngineHost host,
            final InstanceTag receiverTag, final SecureRandom secureRandom) {
        this.masterSession = masterSession == null ? this : masterSession;
        assert this.masterSession.masterSession == this.masterSession : "BUG: expected master session to be its own master session. This is likely an illegal state.";
        this.secureRandom = requireNonNull(secureRandom);
        this.sessionID = requireNonNull(sessionID);
        this.logger = Logger.getLogger(sessionID.getAccountID() + "-->" + sessionID.getUserID());
        this.host = requireNonNull(host);
        this.receiverTag = requireNonNull(receiverTag);
        this.fragmenter = new Fragmenter(this.secureRandom, this.host, this.sessionID);
        this.offerStatus = OfferStatus.IDLE;
        // Master session uses the map to manage slave sessions. Slave sessions do not use the map.
        if (this.masterSession == this) {
            this.slaveSessions = new HashMap<>(0);
        } else {
            this.slaveSessions = emptyMap();
        }
        this.outgoingSession = this;
        this.sessionState = new StatePlaintext(StateInitial.instance(), DAKEInitial.instance());
        // Initialize the Client Profile and payload.
        if (this.masterSession == this) {
            ClientProfilePayload payload;
            ClientProfile profile;
            try {
                payload = ClientProfilePayload.readFrom(new OtrInputStream(restoreClientProfilePayload(this.host)));
                // Validate the client-profile against far future, because constructing the master session is not
                // concerned with the current validity of our own client-profile, but instead with ensuring that a
                // consistent profile is provided. In case of errors, construct a new client-profile from scratch.
                // An expired profile will be discovered upon the next request for our client-profile for OTRv4 session
                // initialization.
                profile = payload.validate(Instant.ofEpochMilli(0));
                this.logger.log(FINE, "Successfully restored client profile from OTR Engine Host.");
            } catch (final OtrCryptoException | ProtocolException | ValidationException e) {
                this.logger.log(FINE,
                        "Failed to load client profile from OTR Engine Host. Generating new client profile… (Problem: {0})",
                        e.getMessage());
                // REMARK the host is expected to behave correctly, such that these callbacks do not cause runtime-exceptions. If this is the case, the account's master session will fail to construct. (Go with OtrException?)
                final OtrPolicy policy = this.host.getSessionPolicy(sessionID);
                final EdDSAKeyPair longTermKeyPair = this.host.getLongTermKeyPair(sessionID);
                final Point longTermPublicKey = longTermKeyPair.getPublicKey();
                final Point forgingPublicKey = this.host.getForgingKeyPair(sessionID).getPublicKey();
                final List<Version> versions;
                final DSAKeyPair legacyKeyPair;
                final DSAPublicKey legacyPublicKey;
                if (policy.isAllowV3()) {
                    versions = List.of(THREE, FOUR);
                    legacyKeyPair = this.host.getLocalKeyPair(sessionID);
                    legacyPublicKey = legacyKeyPair.getPublic();
                } else {
                    versions = List.of(FOUR);
                    legacyKeyPair = null;
                    legacyPublicKey = null;
                }
                profile = new ClientProfile(InstanceTag.random(secureRandom), longTermPublicKey, forgingPublicKey,
                        versions, legacyPublicKey);
                payload = signClientProfile(profile,
                        Instant.now().plus(DEFAULT_CLIENTPROFILE_EXPIRATION_DAYS, ChronoUnit.DAYS).getEpochSecond(),
                        legacyKeyPair, longTermKeyPair);
                updateClientProfilePayload(this.host, OtrEncodables.encode(payload));
            }
            // Verify consistent use of long-term (identity) keypairs…
            requireEquals(profile.getLongTermPublicKey(), this.host.getLongTermKeyPair(this.sessionID).getPublicKey(),
                    "Long-term keypair provided by OtrEngineHost must be same as in the client profile.");
            final DSAPublicKey profileDSAPublicKey = profile.getDsaPublicKey();
            if (profileDSAPublicKey != null) {
                requireEquals(profileDSAPublicKey, this.host.getLocalKeyPair(this.sessionID).getPublic(),
                        "Local (OTRv3) keypair provided by OtrEngineHost must be same as in the client profile.");
            }
            // Note: the client-profile payload is not stored in SessionImpl such that the host-application
            // (OtrEngineHost) can function as synchronization hub for all (master) sessions that share the same
            // client-profile.
            this.senderTag = profile.getInstanceTag();
        } else {
            this.senderTag = this.masterSession.senderTag;
        }
    }

    @Override
    @Nonnull
    public SecureRandom secureRandom() {
        return this.secureRandom;
    }

    @Nonnull
    @Override
    public DSAKeyPair getLocalKeyPair() {
        return this.host.getLocalKeyPair(this.sessionID);
    }

    @Override
    public EdDSAKeyPair getLongTermKeyPair() {
        return this.host.getLongTermKeyPair(this.sessionID);
    }

    // TODO needs renaming, Context.getClientProfilePayload is no longer a constant-time "getter", as it may update the client-profile payload.
    @Nonnull
    @Override
    public ClientProfilePayload getClientProfilePayload() {
        // Note: the profile-payload (and client profile) are only relevant during AKE stage. Afterwards, we take
        // relevant data from the profile that is maintained locally and we do not need to refer back to the profile
        // itself.
        // Project expiration some hours into the future to anticipate and account for delays on remote client. Some
        // messaging networks do not have a notion of "off-line", so there can be significant delays in response without
        // an OTR-session being considered aborted/abandoned.
        ClientProfilePayload payload;
        try {
            final byte[] data = restoreClientProfilePayload(this.host);
            // Allow zero-length client-profile payload, such that host-application is ultimately in control of whether
            // and when to force a profile refresh. This also allows host-application to influence when policy and
            // keypairs are re-acquired from the host-application.
            payload = data.length == 0 ? null : ClientProfilePayload.readFrom(new OtrInputStream(data));
        } catch (final OtrCryptoException | ProtocolException | ValidationException e) {
            // The host-application manages the client-profile payload as an opaque blob. In case no profile exists, an
            // empty byte-array can be returned to reflect this. The host-application must not return a corrupted,
            // incomplete or incorrect client-profile payload.
            throw new IllegalStateException("Host-application provided illegal client-profile payload.", e);
        }
        if (payload != null && !payload.expired(Instant.now().plus(CLIENTPROFILE_EXPIRATION_POJECTION_HOURS, HOURS))) {
            // REMARK we do not currently check the payload against host-returned policy and keypairs. The host is expected to return consistent, correct data.
            return payload;
        }
        // Payload was either purged by host-application, or present but expired, or the host call-back failed due to a
        // bad implementation. Create a new profile.
        final OtrPolicy policy = this.host.getSessionPolicy(this.sessionID);
        final EdDSAKeyPair longTermKeyPair = this.host.getLongTermKeyPair(this.sessionID);
        final List<Version> versions;
        final DSAKeyPair legacyKeyPair;
        final DSAPublicKey legacyPublicKey;
        if (policy.isAllowV3()) {
            versions = List.of(THREE, FOUR);
            legacyKeyPair = this.host.getLocalKeyPair(this.sessionID);
            legacyPublicKey = legacyKeyPair.getPublic();
        } else {
            versions = List.of(FOUR);
            legacyKeyPair = null;
            legacyPublicKey = null;
        }
        // Note: refreshing client-profile maintains current sender instance-tag.
        final ClientProfile profile = new ClientProfile(this.senderTag, longTermKeyPair.getPublicKey(),
                this.host.getForgingKeyPair(this.sessionID).getPublicKey(), versions, legacyPublicKey);
        payload = signClientProfile(profile,
                Instant.now().plus(DEFAULT_CLIENTPROFILE_EXPIRATION_DAYS, DAYS).getEpochSecond(),
                legacyKeyPair, longTermKeyPair);
        updateClientProfilePayload(this.host, OtrEncodables.encode(payload));
        return payload;
    }

    @GuardedBy("masterSession")
    @Override
    public void setAuthState(final AuthState state) {
        if (this.sessionState.getAuthState().getTimestamp() > state.getTimestamp()) {
            throw new IllegalArgumentException("BUG: we always expect to replace a state instance with a more recent state.");
        }
        this.sessionState.setAuthState(state);
    }

    @GuardedBy("masterSession")
    @Override
    public void setDAKEState(final DAKEState state) {
        if (this.sessionState.getDAKEState().getTimestamp() > state.getTimestamp()) {
            throw new IllegalArgumentException("BUG: we always expect to replace a state instance with a more recent state.");
        }
        this.sessionState.setDAKEState(state);
    }

    @GuardedBy("masterSession")
    @Override
    public void transition(final State fromState, final State toState) {
        requireEquals(this.sessionState, fromState,
                "BUG: provided \"from\" state is not the current state. Expected " + this.sessionState + ", but got " + fromState);
        this.logger.log(FINE, "Transitioning to message state: {0}", toState);
        this.sessionState = requireNonNull(toState);
        if (fromState.getStatus() != ENCRYPTED && toState.getStatus() == ENCRYPTED
                && this.masterSession.getOutgoingSession().getSessionStatus() == PLAINTEXT) {
            // This behavior is adopted to preserve behavior between otr4j before refactoring and after. Originally,
            // the master session would contain some fields that would indicate session status even though a slave
            // session was created. Now we ensure that once we have secured the session, we also switch to that
            // session such that subsequently sent messages are already encrypted, even if the client does not
            // explicitly switch.
            this.logger.finest("Switching to the just-secured session, as the previous state was an insecure state.");
            this.masterSession.setOutgoingSession(getReceiverInstanceTag());
        }
        fromState.destroy();
        sessionStatusChanged(duplicate(this.listeners), this.sessionID, this.receiverTag);
    }

    @Override
    @Nonnull
    public SessionID getSessionID() {
        return this.sessionID;
    }

    @Override
    @Nonnull
    public OtrEngineHost getHost() {
        return this.host;
    }

    @Override
    @Nonnull
    public OfferStatus getOfferStatus() {
        synchronized (this.masterSession) {
            return this.offerStatus;
        }
    }

    @Override
    public void setOfferStatusSent() {
        synchronized (this.masterSession) {
            this.offerStatus = OfferStatus.SENT;
        }
    }

    @Override
    @Nonnull
    @SuppressWarnings("PMD.CognitiveComplexity")
    public Result transformReceiving(final String msgText) throws OtrException {
        synchronized (this.masterSession) {
            this.logger.log(FINEST, "Entering {0} session.", this.masterSession == this ? "master" : "slave");

            if (msgText.length() == 0) {
                return new Result(ZERO_TAG, PLAINTEXT, false, false, msgText);
            }

            final OtrPolicy policy = getSessionPolicy();
            if (!policy.viable()) {
                this.logger.info("Policy does not allow any version of OTR. OTR messages will not be processed at all.");
                return new Result(ZERO_TAG, PLAINTEXT, false, false, msgText);
            }

            final Message m;
            try {
                m = parseMessage(msgText);
            } catch (final ProtocolException e) {
                throw new OtrException("Invalid message received.", e);
            }

            if (m instanceof PlainTextMessage) {
                if (this.offerStatus == OfferStatus.SENT) {
                    this.offerStatus = OfferStatus.REJECTED;
                }
            } else {
                this.offerStatus = OfferStatus.ACCEPTED;
            }

            // REMARK evaluate inter-play between master and slave sessions. How much of certainty do we have if we reset the state from within one of the AKE states, that we actually reset sufficiently? In most cases, context.setState will manipulate the slave session, not the master session, so the influence limited. (Consider redesigning now that the Rust implementation, otrr, uses a different approach.)
            if (this.masterSession == this && m instanceof Fragment && (((Fragment) m).getVersion() == THREE
                    || ((Fragment) m).getVersion() == FOUR)) {
                final Fragment fragment = (Fragment) m;

                if (fragment.getSenderTag().equals(ZERO_TAG)) {
                    this.logger.log(INFO, "Message fragment contains 0 sender tag. Ignoring message. (Message ID: {0}, index: {1}, total: {2})",
                            new Object[] {fragment.getIdentifier(), fragment.getIndex(), fragment.getTotal()});
                    return new Result(ZERO_TAG, PLAINTEXT, true, false, null);
                }

                if (!fragment.getReceiverTag().equals(ZERO_TAG)
                        && fragment.getReceiverTag().getValue() != this.senderTag.getValue()) {
                    // The message is not intended for us. Discarding...
                    this.logger.finest("Received a message fragment with receiver instance tag that is different from ours. Ignore this message.");
                    handleEvent(this.host, this.sessionID, fragment.getReceiverTag(), Event.MESSAGE_FOR_ANOTHER_INSTANCE_RECEIVED,
                            Unit.UNIT);
                    return new Result(ZERO_TAG, PLAINTEXT, true, false, null);
                }

                if (!this.slaveSessions.containsKey(fragment.getSenderTag())) {
                    // TODO be more selective before creating new session instances, to avoid creating instances for bad messages.
                    final SessionImpl newSlaveSession = new SessionImpl(this, this.sessionID, this.host,
                            fragment.getSenderTag(), this.secureRandom);
                    newSlaveSession.addOtrEngineListener(this.slaveSessionsListener);
                    this.slaveSessions.put(fragment.getSenderTag(), newSlaveSession);
                }

                final SessionImpl slave = this.slaveSessions.get(fragment.getSenderTag());
                synchronized (slave.masterSession) {
                    return slave.handleFragment(fragment);
                }
            } else if (this.masterSession == this && m instanceof EncodedMessage
                    && (((EncodedMessage) m).version == THREE || ((EncodedMessage) m).version == FOUR)) {
                final EncodedMessage message = (EncodedMessage) m;

                if (message.senderTag.equals(ZERO_TAG)) {
                    // An encoded message without a sender instance tag is always bad.
                    this.logger.warning("Encoded message is missing sender instance tag. Ignoring message.");
                    return new Result(ZERO_TAG, PLAINTEXT, true, false, null);
                }

                if (!message.receiverTag.equals(ZERO_TAG) && !message.receiverTag.equals(this.senderTag)) {
                    // The message is not intended for us. Discarding...
                    this.logger.finest("Received an encoded message with receiver instance tag that is different from ours. Ignore this message.");
                    handleEvent(this.host, this.sessionID, message.receiverTag, Event.MESSAGE_FOR_ANOTHER_INSTANCE_RECEIVED,
                            Unit.UNIT);
                    return new Result(ZERO_TAG, PLAINTEXT, true, false, null);
                }

                if (!this.slaveSessions.containsKey(message.senderTag)) {
                    // TODO be more selective before creating new session instances, to avoid creating instances for bad messages.
                    final SessionImpl newSlaveSession = new SessionImpl(this, this.sessionID, this.host,
                            message.senderTag, this.secureRandom);
                    newSlaveSession.addOtrEngineListener(this.slaveSessionsListener);
                    this.slaveSessions.put(message.senderTag, newSlaveSession);
                }

                final SessionImpl slave = this.slaveSessions.get(message.senderTag);
                this.logger.log(FINEST, "Delegating to slave session for instance tag {0}",
                        message.senderTag.getValue());
                synchronized (slave.masterSession) {
                    return slave.handleEncodedMessage(message);
                }
            }

            this.logger.log(FINE, "Received message with type {0}", m.getClass());
            if (m instanceof Fragment) {
                return handleFragment((Fragment) m);
            } else if (m instanceof EncodedMessage) {
                return handleEncodedMessage((EncodedMessage) m);
            } else if (m instanceof ErrorMessage) {
                handleErrorMessage((ErrorMessage) m);
                return new Result(ZERO_TAG, PLAINTEXT, false, false, null);
            } else if (m instanceof PlainTextMessage) {
                return handlePlainTextMessage((PlainTextMessage) m);
            } else if (m instanceof QueryMessage) {
                handleQueryMessage((QueryMessage) m);
                return new Result(ZERO_TAG, PLAINTEXT, false, false, null);
            } else {
                // At this point, the message m has a known type, but support was not implemented at this point in the code.
                // This should be considered a programming error. We should handle any known message type gracefully.
                // Unknown messages are caught earlier.
                throw new UnsupportedOperationException("This message type is not supported. Support is expected to be implemented for all known message types.");
            }
        }
    }

    /**
     * Handle message that is an OTR fragment.
     *
     * @param fragment fragment message.
     * @return Returns assembled and processed result of message fragment, in case fragment is final fragment. Or return
     * null in case fragment is not the last fragment and processing is delayed until remaining fragments are received.
     */
    @GuardedBy("masterSession")
    @Nonnull
    private Result handleFragment(final Fragment fragment) throws OtrException {
        assert this.masterSession != this || fragment.getVersion() == TWO
                : "BUG: Expect to only handle OTRv2 message fragments on master session. All other fragments should be handled on dedicated slave session.";
        final String reassembledText;
        try {
            reassembledText = this.assembler.accumulate(fragment);
            if (reassembledText == null) {
                this.logger.log(FINEST, "Fragment received, but message is still incomplete.");
                return new Result(this.receiverTag, PLAINTEXT, false, false, null);
            }
        } catch (final ProtocolException e) {
            this.logger.log(FINE, "Rejected message fragment from sender instance "
                    + fragment.getSenderTag().getValue(), e);
            return new Result(this.receiverTag, PLAINTEXT, true, false, null);
        }
        final EncodedMessage message;
        try {
            final Message m = parseMessage(reassembledText);
            if (!(m instanceof EncodedMessage)) {
                this.logger.log(FINE, "Expected fragments to combine into an encoded message, but was something else. {0}",
                        m.getClass().getName());
                return new Result(this.receiverTag, PLAINTEXT, true, false, null);
            }
            message = (EncodedMessage) m;
        } catch (final ProtocolException e) {
            this.logger.log(WARNING, "Reassembled message violates the OTR protocol for encoded messages.", e);
            return new Result(this.receiverTag, PLAINTEXT, true, false, null);
        }
        // There is no good reason why the reassembled message should have any other protocol version, sender
        // instance tag or receiver instance tag than the fragments themselves. For now, be safe and drop any
        // inconsistencies to ensure that the inconsistencies cannot be exploited.
        if (message.version != fragment.getVersion() || !message.senderTag.equals(fragment.getSenderTag())
                || !message.receiverTag.equals(fragment.getReceiverTag())) {
            this.logger.log(INFO, "Inconsistent OTR-encoded message: message contains different protocol version, sender tag or receiver tag than last received fragment. Message is ignored.");
            return new Result(this.receiverTag, PLAINTEXT, true, false, null);
        }
        return handleEncodedMessage(message);
    }

    /**
     * Handle any kind of encoded message. (Either Data message or any type of AKE message.)
     *
     * @param message The encoded message.
     * @return Returns result of handling message, typically decrypting encoded messages or null if no presentable result.
     * @throws OtrException In case of failure to process.
     */
    @GuardedBy("masterSession")
    @Nonnull
    private Result handleEncodedMessage(final EncodedMessage message) throws OtrException {
        assert this.masterSession != this || message.version == TWO : "BUG: We should not process encoded message in master session for protocol version 3 or higher.";
        assert !message.senderTag.equals(ZERO_TAG) : "BUG: No encoded message without sender instance tag should reach this point.";
        if (message.version == THREE && checkDHKeyMessage(message)) {
            // NOTE to myself: we check for DH-Key messages, because we would have sent a DH-Commit message with a 0
            // receiver tag, therefore the AKE-context is not yet part of a dedicated session instance. Therefore, the
            // DH-Key message, which *does* have the instance tag we need, needs to be redirected to the proper session
            // instance *together with* the AKE-context in its current state, such that processing can continue on a
            // per-instance basis.
            // Copy state to slave session, as this is the earliest moment that we know the instance tag of the other party.
            synchronized (this.masterSession.masterSession) {
                final AuthState slaveAuthState = this.sessionState.getAuthState();
                final AuthState masterAuthState = this.masterSession.sessionState.getAuthState();
                if (slaveAuthState.getTimestamp() < masterAuthState.getTimestamp()) {
                    this.sessionState.setAuthState(masterAuthState);
                }
            }
        } else if (checkAuthRMessage(message)) {
            // REMARK why don't we check for `version == FOUR` like we do with DH-Key message above?
            assert this != this.masterSession : "We expected to be working inside a slave session instead of a master session.";
            // Check if the master-session contains a newer DAKE state. If so, copy it to the destined slave now. This
            // solves a situation where we did not know the receiver-tag yet, so we sent the Identity-message to
            // receiver-tag `0` and now that we receive a response we first discover the receiver-tag(s). Now to
            // continue the DAKE where we left off on a specific instance, we need to copy the DAKE-state from master
            // to specific instance (slave) and then continue processing the message on that instance.
            // However, if the instance's DAKE-state is newer, it means that we most likely responded to a DAKE session
            // that was initiated from the specific instance already.
            synchronized (this.masterSession.masterSession) {
                final DAKEState slaveDAKEState = this.sessionState.getDAKEState();
                final DAKEState masterDAKEState = this.masterSession.sessionState.getDAKEState();
                if (slaveDAKEState.getTimestamp() < masterDAKEState.getTimestamp()) {
                    this.sessionState.setDAKEState(masterDAKEState);
                }
            }
        }
        try {
            final State.Result result = this.sessionState.handleEncodedMessage(this, parseEncodedMessage(message));
            return new Result(this.receiverTag, result.status, result.rejected, result.confidential, result.content);
        } catch (final ProtocolException e) {
            this.logger.log(FINE, "An illegal message was received. Processing was aborted.", e);
            return new Result(this.receiverTag, this.sessionState.getStatus(), true, false, null);
        }
    }

    @GuardedBy("masterSession")
    private void handleQueryMessage(final QueryMessage queryMessage) throws OtrException {
        assert this.masterSession == this : "BUG: handleQueryMessage should only ever be called from the master session, as no instance tags are known.";
        this.logger.log(FINEST, "{0} received a query message from {1} through {2}.",
                new Object[] {this.sessionID.getAccountID(), this.sessionID.getUserID(), this.sessionID.getProtocolName()});

        final OtrPolicy policy = getSessionPolicy();
        if (queryMessage.getVersions().contains(FOUR) && policy.isAllowV4()) {
            this.logger.finest("Query message with V4 support found. Sending Identity Message.");
            respondAuth(FOUR, ZERO_TAG);
        } else if (queryMessage.getVersions().contains(THREE) && policy.isAllowV3()) {
            this.logger.finest("Query message with V3 support found. Sending D-H Commit Message.");
            respondAuth(THREE, ZERO_TAG);
        } else if (queryMessage.getVersions().contains(TWO) && policy.isAllowV2()) {
            this.logger.finest("Query message with V2 support found. Sending D-H Commit Message.");
            respondAuth(TWO, ZERO_TAG);
        } else {
            this.logger.info("Query message received, but none of the versions are acceptable. They are either excluded by policy or through lack of support.");
        }
    }

    @GuardedBy("masterSession")
    private void handleErrorMessage(final ErrorMessage errorMessage)
            throws OtrException {
        assert this.masterSession == this : "BUG: handleErrorMessage should only ever be called from the master session, as no instance tags are known.";
        this.logger.log(FINEST, "{0} received an error message from {1} through {2}.",
                new Object[] {this.sessionID.getAccountID(), this.sessionID.getUserID(), this.sessionID.getProtocolName()});
        handleEvent(this.host, this.sessionID, this.receiverTag, Event.ERROR, "OTR error: " + errorMessage.error);
        final OtrPolicy policy = this.getSessionPolicy();
        if (!policy.viable() || !policy.isErrorStartAKE()) {
            return;
        }
        // TODO should we really start re-negotiation if we are in encrypted message state, because unauthenticated stray/malicious error messages can interfere with messaging state.
        // Re-negotiate if we got an error and we are in ENCRYPTED message state
        this.logger.finest("Error message starts AKE.");
        final Set<Version> versions = allowedVersions(policy);
        this.logger.finest("Sending Query");
        this.injectMessage(new QueryMessage(versions));
    }

    @Override
    public void injectMessage(final Message m) throws OtrException {
        synchronized (this.masterSession) {
            final String serialized = writeMessage(m);
            final String[] fragments;
            if (m instanceof QueryMessage) {
                assert this.masterSession == this : "Expected query messages to only be sent from Master session!";
                assert !(m instanceof PlainTextMessage)
                        : "PlainText messages (with possible whitespace tag) should not end up here. We should not append the fallback message to a whitespace-tagged plaintext message.";
                final int spaceForFallbackMessage = this.host.getMaxFragmentSize(this.sessionID) - 1 - serialized.length();
                fragments = new String[] {serialized + ' ' + getFallbackMessage(this.sessionID, spaceForFallbackMessage)};
            } else if (m instanceof AbstractEncodedMessage) {
                final AbstractEncodedMessage encoded = (AbstractEncodedMessage) m;
                fragments = this.fragmenter.fragment(encoded.protocolVersion, encoded.senderTag.getValue(),
                        encoded.receiverTag.getValue(), serialized);
            } else {
                fragments = new String[] {serialized};
            }
            for (final String fragment : fragments) {
                this.host.injectMessage(this.sessionID, fragment);
            }
        }
    }

    @Nonnull
    private String getFallbackMessage(final SessionID sessionID, final int spaceLeft) {
        if (spaceLeft <= 0) {
            return "";
        }
        String fallback = OtrEngineHosts.getFallbackMessage(this.host, sessionID);
        if (fallback == null || fallback.isEmpty()) {
            fallback = DEFAULT_FALLBACK_MESSAGE;
        }
        if (fallback.length() > spaceLeft) {
            fallback = fallback.substring(0, spaceLeft);
        }
        return fallback;
    }

    @GuardedBy("masterSession")
    @Nonnull
    private Result handlePlainTextMessage(final PlainTextMessage message) {
        assert this.masterSession == this : "BUG: handlePlainTextMessage should only ever be called from the master session, as no instance tags are known.";
        this.logger.log(FINEST, "{0} received a plaintext message from {1} through {2}.",
                new Object[] {this.sessionID.getAccountID(), this.sessionID.getUserID(), this.sessionID.getProtocolName()});
        final State.Result result = this.sessionState.handlePlainTextMessage(this, message);
        if (message.getVersions().isEmpty()) {
            this.logger.finest("Received plaintext message without the whitespace tag.");
        } else {
            this.logger.finest("Received plaintext message with the whitespace tag.");
            handleWhitespaceTag(message);
        }
        return new Result(ZERO_TAG, result.status, result.rejected, 
                result.confidential, result.content);
    }

    @GuardedBy("masterSession")
    private void handleWhitespaceTag(final PlainTextMessage plainTextMessage) {
        final OtrPolicy policy = getSessionPolicy();
        if (!policy.isWhitespaceStartAKE()) {
            // no policy w.r.t. starting AKE on whitespace tag
            return;
        }
        this.logger.finest("WHITESPACE_START_AKE is set, processing whitespace-tagged message.");
        if (plainTextMessage.getVersions().contains(FOUR) && policy.isAllowV4()) {
            this.logger.finest("V4 tag found. Sending Identity Message.");
            try {
                respondAuth(FOUR, ZERO_TAG);
            } catch (final OtrException e) {
                this.logger.log(WARNING, "An exception occurred while constructing and sending Identity message. (OTRv4)", e);
            }
        } else if (plainTextMessage.getVersions().contains(THREE) && policy.isAllowV3()) {
            this.logger.finest("V3 tag found. Sending D-H Commit Message.");
            try {
                respondAuth(THREE, ZERO_TAG);
            } catch (final OtrException e) {
                this.logger.log(WARNING, "An exception occurred while constructing and sending DH commit message. (OTRv3)", e);
            }
        } else if (plainTextMessage.getVersions().contains(TWO) && policy.isAllowV2()) {
            this.logger.finest("V2 tag found. Sending D-H Commit Message.");
            try {
                respondAuth(TWO, ZERO_TAG);
            } catch (final OtrException e) {
                this.logger.log(WARNING, "An exception occurred while constructing and sending DH commit message. (OTRv2)", e);
            }
        } else {
            this.logger.info("Message with whitespace tags received, but none of the tags are useful. They are either excluded by policy or by lack of support.");
        }
    }

    /**
     * Transform message to be sent to content that is sendable over the IM
     * network. Do not include any TLVs in the message.
     *
     * @param msgText the (normal) message content
     * @return Returns the (array of) messages to be sent over IM network.
     * @throws OtrException OtrException in case of exceptions.
     */
    @Override
    @Nonnull
    public String[] transformSending(final String msgText) throws OtrException {
        synchronized (this.masterSession) {
            return this.transformSending(msgText, Collections.emptyList());
        }
    }

    /**
     * Transform message to be sent to content that is sendable over the IM
     * network.
     *
     * @param msgText the (normal) message content
     * @param tlvs    TLV items (must not be null, may be an empty list)
     * @return Returns the (array of) messages to be sent over IM network.
     * @throws OtrException OtrException in case of exceptions.
     */
    // TODO report message queued to host application instead of error. (Maybe make text of OtrEngineHost#requireEncryptedMessage conditional on whether or not queueing is enabled.)
    @Override
    @Nonnull
    public String[] transformSending(final String msgText, final Iterable<TLV> tlvs)
            throws OtrException {
        synchronized (this.masterSession) {
            if (this.masterSession == this && this.outgoingSession != this) {
                return this.outgoingSession.transformSending(msgText, tlvs);
            }
            final Message m = this.sessionState.transformSending(this, msgText, tlvs, FLAG_NONE);
            if (m == null) {
                return new String[0];
            }
            final String serialized = writeMessage(m);
            if (m instanceof AbstractEncodedMessage) {
                final AbstractEncodedMessage encoded = (AbstractEncodedMessage) m;
                return this.fragmenter.fragment(encoded.protocolVersion, encoded.senderTag.getValue(),
                        encoded.receiverTag.getValue(), serialized);
            }
            return new String[] {serialized};
        }
    }

    /**
     * Start a new OTR session by sending an OTR query message.
     * <p>
     * Consider using {@link OtrPolicy#viable()} to verify whether any version of the OTR protocol is allowed, such that
     * we can actually establish a private conversation.
     *
     * @throws OtrException Throws an error in case we failed to inject the
     *                      Query message into the host's transport channel.
     */
    @Override
    public void startSession() throws OtrException {
        synchronized (this.masterSession) {
            if (this.getSessionStatus() == ENCRYPTED) {
                this.logger.info("startSession was called, however an encrypted session is already established.");
                return;
            }
            this.logger.finest("Enquiring to start Authenticated Key Exchange, sending query message");
            final OtrPolicy policy = this.getSessionPolicy();
            final Set<Version> allowedVersions = allowedVersions(policy);
            if (allowedVersions.isEmpty()) {
                throw new OtrException("Current OTR policy declines all supported versions of OTR. There is no way to start an OTR session that complies with the policy.");
            }
            final QueryMessage queryMessage = new QueryMessage(allowedVersions);
            injectMessage(queryMessage);
        }
    }

    @Override
    @GuardedBy("masterSession")
    public void startAKE(final Set<Version> versions) throws OtrException {
        assert this.masterSession == this : "BUG: startAKE should only ever be called from the master session, as no instance tags are known.";
        this.logger.log(FINEST, "Starting AKE for versions {0}.", new Object[]{versions});
        final OtrPolicy policy = getSessionPolicy();
        if (versions.contains(Version.FOUR) && policy.isAllowV4()) {
            this.logger.finest("Start OTRv4 DAKE. Sending Identity Message.");
            respondAuth(FOUR, ZERO_TAG);
        } else if (versions.contains(Version.THREE) && policy.isAllowV3()) {
            this.logger.finest("Start OTR AKE for version 3. Sending D-H Commit Message.");
            respondAuth(THREE, ZERO_TAG);
        } else if (versions.contains(Version.TWO) && policy.isAllowV2()) {
            this.logger.finest("Start OTR AKE for version 2. Sending D-H Commit Message.");
            respondAuth(TWO, ZERO_TAG);
        } else {
            this.logger.info("Query message received, but none of the versions are acceptable. They are either excluded by policy or through lack of support.");
        }
    }

    /**
     * End message state.
     *
     * @throws OtrException Throw OTR exception in case of failure during
     *                      ending.
     */
    @Override
    public void endSession() throws OtrException {
        synchronized (this.masterSession) {
            if (this != this.outgoingSession) {
                this.outgoingSession.endSession();
                return;
            }
            this.sessionState.end(this);
        }
    }

    /**
     * Refresh an existing ENCRYPTED session by ending and restarting it. Before
     * ending the session we record the current protocol version of the active
     * session. Afterwards, in case we received a valid version, we restart by
     * immediately sending a DH-Commit messages, as we already negotiated a
     * protocol version before and then we ended up with acquired version. In
     * case we weren't able to acquire a valid protocol version, we start by
     * sending a Query message.
     *
     * @throws OtrException Throws exception in case of failed session ending,
     *                      failed full session start, or failed creation or injection of DH-Commit
     *                      message.
     */
    @Override
    public void refreshSession() throws OtrException {
        synchronized (this.masterSession) {
            if (this.outgoingSession != this) {
                this.outgoingSession.refreshSession();
                return;
            }
            final Version version = this.sessionState.getVersion();
            this.sessionState.end(this);
            if (version == Version.NONE) {
                startSession();
            } else {
                respondAuth(version, this.receiverTag);
            }
        }
    }

    @Override
    public void addOtrEngineListener(final OtrEngineListener l) {
        synchronized (this.masterSession) {
            if (!this.listeners.contains(l)) {
                this.listeners.add(l);
            }
        }
    }

    @Override
    public void removeOtrEngineListener(final OtrEngineListener l) {
        synchronized (this.masterSession) {
            this.listeners.remove(l);
        }
    }

    @Override
    @Nonnull
    public OtrPolicy getSessionPolicy() {
        synchronized (this.masterSession) {
            return this.host.getSessionPolicy(this.sessionID);
        }
    }

    @Override
    @Nonnull
    public InstanceTag getSenderInstanceTag() {
        return this.senderTag;
    }

    @Override
    @Nonnull
    public InstanceTag getReceiverInstanceTag() {
        return this.receiverTag;
    }

    /**
     * Get the current session's protocol version. That is, in case no OTR
     * session is established (yet) it will return 0. This protocol version is
     * different from the protocol version in the current AKE conversation which
     * may be ongoing simultaneously.
     *
     * @return Returns 0 for no session, or protocol version in case of
     * established OTR session.
     */
    @Nonnull
    @Override
    public Version getProtocolVersion() {
        synchronized (this.masterSession) {
            return this.sessionState.getVersion();
        }
    }

    /**
     * Get list of OTR session instances, i.e. sessions with different instance
     * tags. There is always at least 1 session, the master session or only
     * session in case of OTRv2.
     *
     * @return Returns list of session instances.
     */
    @Override
    @Nonnull
    public List<SessionImpl> getInstances() {
        synchronized (this.masterSession) {
            assert this == this.masterSession : "BUG: expected this method to be called from master session only.";
            final List<SessionImpl> result = new ArrayList<>();
            result.add(this);
            result.addAll(this.slaveSessions.values());
            return result;
        }
    }

    /**
     * Set the outgoing session to the session corresponding to the specified
     * Receiver instance tag. Setting the outgoing session is only allowed for
     * master sessions.
     */
    // TODO consider making the case for nonexistant instance tag a checked exception. 
    @Override
    public void setOutgoingSession(final InstanceTag tag) {
        synchronized (this.masterSession) {
            if (this.masterSession != this) {
                // Only master session can set the outgoing session.
                throw new UnsupportedOperationException("Only master session is allowed to set/change the outgoing session instance.");
            }
            if (tag.equals(this.receiverTag)) {
                this.outgoingSession = this;
                outgoingSessionChanged(duplicate(this.listeners), this.sessionID);
                return;
            }
            final SessionImpl newActiveSession = this.slaveSessions.get(tag);
            if (newActiveSession == null) {
                throw new IllegalArgumentException("No slave session exists with provided instance tag.");
            }
            this.outgoingSession = newActiveSession;
            outgoingSessionChanged(duplicate(this.listeners), this.sessionID);
        }
    }

    @Override
    @Nonnull
    public SessionStatus getSessionStatus(final InstanceTag tag) {
        synchronized (this.masterSession) {
            if (tag.equals(this.receiverTag)) {
                return this.sessionState.getStatus();
            }
            final SessionImpl slave = this.slaveSessions.get(tag);
            if (slave == null) {
                throw new IllegalArgumentException("Unknown instance tag specified: " + tag.getValue());
            }
            return slave.getSessionStatus();
        }
    }

    @Override
    @Nonnull
    public SessionStatus getSessionStatus() {
        synchronized (this.masterSession) {
            synchronized (this.outgoingSession.masterSession) {
                return this.outgoingSession.sessionState.getStatus();
            }
        }
    }

    /**
     * Get remote public key for specified session.
     *
     * @param tag Instance tag identifying session. In case of
     * {@link InstanceTag#ZERO_TAG} queries session status for OTRv2 session.
     * @return Returns remote (long-term) public key.
     * @throws IncorrectStateException Thrown in case session's message state is
     * not ENCRYPTED.
     */
    @Override
    @Nonnull
    public RemoteInfo getRemoteInfo(final InstanceTag tag) throws IncorrectStateException {
        synchronized (this.masterSession) {
            if (tag.equals(this.receiverTag)) {
                return this.sessionState.getRemoteInfo();
            }
            final SessionImpl slave = this.slaveSessions.get(tag);
            if (slave == null) {
                throw new IllegalArgumentException("Unknown tag specified: " + tag.getValue());
            }
            return slave.getRemoteInfo();
        }
    }

    @Override
    @Nonnull
    public RemoteInfo getRemoteInfo() throws IncorrectStateException {
        synchronized (this.masterSession) {
            if (this != this.outgoingSession) {
                return this.outgoingSession.getRemoteInfo();
            }
            return this.sessionState.getRemoteInfo();
        }
    }

    /**
     * Get the currently set outgoing instance. This instance is used for
     * outgoing traffic.
     *
     * @return Returns session instance, possibly a slave session.
     */
    @Override
    @Nonnull
    public SessionImpl getOutgoingSession() {
        synchronized (this.masterSession) {
            return this.outgoingSession;
        }
    }

    /**
     * Respond to AKE query message.
     *
     * @param version     OTR protocol version to use.
     * @param receiverTag The receiver tag to which to address the DH Commit
     *                    message. In case the receiver is not yet known (this is a valid use
     *                    case), specify {@link InstanceTag#ZERO_TAG}.
     * @throws OtrException In case of invalid/unsupported OTR protocol version.
     */
    @GuardedBy("masterSession")
    private void respondAuth(final Version version, final InstanceTag receiverTag) throws OtrException {
        if (!Version.SUPPORTED.contains(version)) {
            throw new OtrException("Unsupported OTR version encountered.");
        }
        // Ensure we initiate authentication state in master session, as we copy the master session's authentication
        // state upon receiving a DHKey message. This is caused by the fact that we may get multiple D-H Key responses
        // to a D-H Commit message without receiver instance tag. (This is due to the subtle workings of the
        // implementation.)
        this.logger.log(FINEST, "Responding to Query Message, acknowledging version {0}", version);
        synchronized (this.masterSession.masterSession) {
            this.masterSession.sessionState.initiateAKE(this.masterSession, version, receiverTag);
        }
    }

    /**
     * Initialize SMP negotiation.
     *
     * @param question The question, optional.
     * @param answer   The answer to be verified using ZK-proof.
     * @throws OtrException In case of failure to init SMP or transform to encoded message.
     */
    @Override
    public void initSmp(@Nullable final String question, final String answer) throws OtrException {
        synchronized (this.masterSession) {
            if (this != this.outgoingSession) {
                this.outgoingSession.initSmp(question, answer);
                return;
            }
            final State session = this.sessionState;
            if (!(session instanceof StateEncrypted)) {
                this.logger.log(INFO, "Not initiating SMP negotiation as we are currently not in an Encrypted messaging state.");
                return;
            }
            final StateEncrypted encrypted = (StateEncrypted) session;
            // First try, we may find that we get an SMP Abort response. A running SMP negotiation was aborted.
            final TLV tlv = encrypted.getSmpHandler().initiate(question == null ? "" : question, answer.getBytes(UTF_8));
            injectMessage(encrypted.transformSending(this, "", singletonList(tlv), FLAG_IGNORE_UNREADABLE));
            if (!encrypted.getSmpHandler().smpAbortedTLV(tlv)) {
                return;
            }
            // Second try, in case first try aborted an open negotiation. Initiations should be possible at any moment, even
            // if this aborts a running SMP negotiation.
            final TLV tlv2 = encrypted.getSmpHandler().initiate(question == null ? "" : question, answer.getBytes(UTF_8));
            injectMessage(encrypted.transformSending(this, "", singletonList(tlv2), FLAG_IGNORE_UNREADABLE));
        }
    }

    /**
     * Respond to SMP request.
     *
     * @param question The question to be sent with SMP response, may be null.
     * @param secret   The SMP secret that should be verified through ZK-proof.
     * @throws OtrException In case of failure to send, message state different
     *                      from ENCRYPTED, issues with SMP processing.
     */
    @Override
    public void respondSmp(@Nullable final String question, final String secret) throws OtrException {
        synchronized (this.masterSession) {
            if (this != this.outgoingSession) {
                this.outgoingSession.respondSmp(question, secret);
                return;
            }
            sendResponseSmp(question, secret);
        }
    }

    /**
     * Respond with SMP message for specified receiver tag.
     *
     * @param receiverTag The receiver instance tag.
     * @param question    The question, optional.
     * @param secret      The secret to be verified using ZK-proof.
     * @throws OtrException In case of failure.
     */
    @Override
    public void respondSmp(final InstanceTag receiverTag, @Nullable final String question, final String secret)
            throws OtrException {
        synchronized (this.masterSession) {
            final SessionImpl session = receiverTag.equals(this.receiverTag) ? this : this.slaveSessions.get(receiverTag);
            if (session == null) {
                throw new IllegalArgumentException("Unknown receiver instance tag: " + receiverTag.getValue());
            }
            synchronized (session.masterSession) {
                session.sendResponseSmp(question, secret);
            }
        }
    }

    /**
     * Send SMP response.
     *
     * @param question (Optional) question
     * @param answer   answer of which we verify common knowledge
     * @throws OtrException In case of failure to send, message state different from ENCRYPTED, issues with SMP
     *                      processing.
     */
    @GuardedBy("masterSession")
    private void sendResponseSmp(@Nullable final String question, final String answer) throws OtrException {
        final State session = this.sessionState;
        final TLV tlv = session.getSmpHandler().respond(question == null ? "" : question, answer.getBytes(UTF_8));
        final Message m = session.transformSending(this, "", singletonList(tlv), FLAG_IGNORE_UNREADABLE);
        if (m != null) {
            injectMessage(m);
        }
    }

    /**
     * Abort running SMP negotiation.
     *
     * @throws OtrException In case session is not in ENCRYPTED message state.
     */
    @Override
    public void abortSmp() throws OtrException {
        synchronized (this.masterSession) {
            if (this != this.outgoingSession) {
                this.outgoingSession.abortSmp();
                return;
            }
            final State session = this.sessionState;
            final TLV tlv = session.getSmpHandler().abort();
            final Message m = session.transformSending(this, "", singletonList(tlv), FLAG_IGNORE_UNREADABLE);
            if (m != null) {
                injectMessage(m);
            }
        }
    }

    /**
     * Check if SMP is in progress.
     *
     * @return Returns true if SMP is in progress, or false if not in progress.
     * Note that false will also be returned in case message state is not ENCRYPTED.
     */
    @Override
    public boolean isSmpInProgress() {
        synchronized (this.masterSession) {
            if (this != this.outgoingSession) {
                return this.outgoingSession.isSmpInProgress();
            }
            try {
                return this.sessionState.getSmpHandler().getStatus() == INPROGRESS;
            } catch (final IncorrectStateException e) {
                return false;
            }
        }
    }

    /**
     * Acquire the extra symmetric key that can be derived from the session's
     * shared secret.
     * <p>
     * This extra key can also be derived by your chat counterpart. This key
     * never needs to be communicated. TLV 8, that is described in otr v3 spec,
     * is used to inform your counterpart that he needs to start using the key.
     * He can derive the actual key for himself, so TLV 8 should NEVER contain
     * this symmetric key data.
     *
     * @return Returns the extra symmetric key.
     * @throws OtrException In case the message state is not ENCRYPTED, there
     *                      exists no extra symmetric key to return.
     */
    @Override
    @Nonnull
    public byte[] getExtraSymmetricKey() throws OtrException {
        synchronized (this.masterSession) {
            return this.sessionState.getExtraSymmetricKey();
        }
    }

    /**
     * Get the moment of last activity relevant to this session.
     *
     * @return timestamp of last activity according to monotonic time ({@link System#nanoTime()})
     * @throws IncorrectStateException In case the session's current state does not recognize a significant notion of
     *                                 "last activity".
     */
    long getLastActivityTimestamp() throws IncorrectStateException {
        return this.sessionState.getLastActivityTimestamp();
    }

    /**
     * Expire the session.
     *
     * @throws OtrException Thrown in case of failure to fully expire the session.
     */
    void expireSession() throws OtrException {
        synchronized (this.masterSession) {
            final State state = this.sessionState;
            try {
                state.expire(this);
            } finally {
                state.destroy();
                sessionStatusChanged(duplicate(this.listeners), this.sessionID, this.receiverTag);
            }
        }
    }

    /**
     * Get the timestamp of the last message sent.
     * <p>
     * Returns a monotonic timestamp of the moment when the most recent message was sent. The message sent is
     * specifically a DataMessage, i.e. a message sent when a private messaging session is established.
     *
     * @return Returns the monotonic timestamp ({@link System#nanoTime()} of most recently sent message.
     * @throws IncorrectStateException In case session is not in private messaging state.
     */
    long getLastMessageSentTimestamp() throws IncorrectStateException {
        return this.sessionState.getLastMessageSentTimestamp();
    }

    /**
     * Send heartbeat message.
     *
     * @throws OtrException In case of failure to inject the heartbeat message into the communication channel.
     */
    void sendHeartbeat() throws OtrException {
        synchronized (this.masterSession) {
            final State state = this.sessionState;
            if (!(state instanceof StateEncrypted)) {
                return;
            }
            final AbstractEncodedMessage heartbeat = ((StateEncrypted) state).transformSending(this, "",
                    Collections.emptyList(), FLAG_IGNORE_UNREADABLE);
            injectMessage(heartbeat);
        }
    }
}
