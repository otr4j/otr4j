/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */
package net.java.otr4j.api;

import com.google.errorprone.annotations.CheckReturnValue;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.Set;

/**
 * Instance is the "child" interface of a session, whenever a particular outgoing session instance is
 * selected.
 * <p>
 * The original (very early) design and structure were determined by the absence of instance tags at the time.
 * This was before OTR protocol version3 was specified. Consequently, there was only a single Session instance
 * for an account. With the introduction of instances, instance-tags, there became a need for state management
 * regarding the "default outgoing session instace". This state management itself is a source of issues, given
 * that this it has to be in sync with state management of the respective host applications. This interface
 * separates the general session-wide operations in {@link Session} from the instance-specific operations as
 * defined here, in {@link Instance}. (There will likely be further separation in the future.)
 */
public interface Instance {

    /**
     * Get current outgoing session's status.
     *
     * @return Returns session status.
     */
    @Nonnull
    SessionStatus getSessionStatus();

    /**
     * Get protocol version for active session.
     *
     * @return Returns protocol version or 0 in case of no session active.
     */
    @Nonnull
    Version getProtocolVersion();

    /**
     * Get sender instance tag.
     *
     * @return Returns sender instance tag.
     */
    @Nonnull
    InstanceTag getSenderInstanceTag();

    /**
     * Get receiver instance tag.
     *
     * @return Returns receiver instance tag or 0 in case of OTRv2 session /
     * OTRv3 master session instance.
     */
    @Nonnull
    InstanceTag getReceiverInstanceTag();

    /**
     * Get remote's long-term public key.
     *
     * @return Returns long-term public key.
     * @throws OtrException Thrown in case message state is not ENCRYPTED, hence
     * no long-term public key is known.
     */
    @Nonnull
    RemoteInfo getRemoteInfo() throws OtrException;

    /**
     * Start an AKE directly.
     *
     * @param versions allowed versions for AKE, higher versions get preference.
     * @throws OtrException in case of failure.
     */
    void startAKE(Set<Version> versions) throws OtrException;

    /**
     * Transform message text to prepare for sending which includes possible
     * OTR facilities. This method assumes no TLVs need to be sent.
     *
     * @param msgText plain message content
     * @return Returns OTR-processed (possibly ENCRYPTED) message content in
     * suitable fragments according to host information on the transport
     * fragmentation.
     * @throws OtrException Thrown in case of problems during transformation.
     */
    @Nonnull
    String[] transformSending(String msgText) throws OtrException;

    /**
     * Transform message text to prepare for sending which includes possible
     * OTR facilities.
     *
     * @param msgText plain message content
     * @param tlvs any TLV records to be packed with the other message contents.
     * @return Returns OTR-processed (possibly ENCRYPTED) message content in
     * suitable fragments according to host information on the transport
     * fragmentation.
     * @throws OtrException Thrown in case of problems during transformation.
     */
    @Nonnull
    String[] transformSending(String msgText, Iterable<TLV> tlvs) throws OtrException;

    /**
     * Get Extra Symmetric Key that is provided by OTRv3 based on the current Session Keys.
     *
     * @return Returns 256-bit (shared) secret that can be used to start an out-of-band confidential communication channel
     * @throws OtrException In case message status is not ENCRYPTED.
     */
    @Nonnull
    byte[] getExtraSymmetricKey() throws OtrException;

    /**
     * Refresh an existing OTR session, i.e. perform new AKE. If sufficient
     * information is available about the protocol capabilities of the other
     * party, then we will immediately send an D-H Commit message with the
     * receiver instance tag set to speed up the process and to avoid other
     * instances from being triggered to start AKE.
     *
     * @throws OtrException In case of failed refresh.
     */
    void refreshSession() throws OtrException;

    /**
     * End ENCRYPTED session.
     *
     * @throws OtrException in case of failure to inject OTR message to inform
     * counter party. (The transition to PLAINTEXT will
     * happen regardless.)
     */
    void endSession() throws OtrException;

    /**
     * Query if SMP is in progress.
     *
     * @return Returns true if in progress, or false otherwise.
     */
    @CheckReturnValue
    boolean isSmpInProgress();

    /**
     * Initiate a new SMP negotiation by providing an optional question and a secret.
     *
     * @param question The optional question, may be null.
     * @param secret The secret that we should verify the other side knows about.
     * @throws OtrException In case of failure during initiation.
     */
    void initSmp(@Nullable String question, String secret) throws OtrException;

    /**
     * Respond to an SMP request for a specific receiver instance tag.
     *
     * @param question The question
     * @param secret The secret
     * @throws OtrException In case of failure during response.
     */
    void respondSmp(@Nullable String question, String secret) throws OtrException;

    /**
     * Abort a running SMP negotiation.
     *
     * @throws OtrException In case session is not in ENCRYPTED message state.
     */
    void abortSmp() throws OtrException;
}
