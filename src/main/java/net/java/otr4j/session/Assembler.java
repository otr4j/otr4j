/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.session;

import net.java.otr4j.io.Fragment;

import javax.annotation.Nullable;
import java.net.ProtocolException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

import static net.java.otr4j.util.Arrays.containsEmpty;
import static net.java.otr4j.util.Strings.concat;

/**
 * Support for re-assembling fragmented OTR-encoded messages.
 */
final class Assembler {

    /**
     * Maximum messages in assembly in the out-of-order assembler. (Before clean-up of oldest entries initiates.)
     */
    private static final int MAX_MESSAGES_IN_ASSEMBLY = 100;
    private static final int MAX_MESSAGE_SIZE = 100 * 1024 * 1024;

    private final InOrderAssembler inOrder = new InOrderAssembler();
    private final OutOfOrderAssembler outOfOrder = new OutOfOrderAssembler();

    /**
     * Accumulate fragments into a full OTR-encoded message.
     * <p>
     * Note that the implementation assumes that fragments are already verified for consistency and sender and receiver
     * tag have been read and fragment is redirected to the appropriate slave session.
     *
     * @param fragment a message fragment
     * @return Returns completed OTR-encoded message, or null if more fragments are needed to complete the message.
     * @throws ProtocolException In case the fragment is rejected.
     */
    @Nullable
    String accumulate(final Fragment fragment) throws ProtocolException {
        switch (fragment.getVersion()) {
        case TWO:
        case THREE:
            return this.inOrder.accumulate(fragment);
        case FOUR:
            return this.outOfOrder.accumulate(fragment);
        default:
            throw new UnsupportedOperationException("Unsupported protocol version.");
        }
    }

    /**
     * In-order assembler, following OTRv2/OTRv3 specification.
     */
    // TODO false-positive in PMD.UnusedPrivateMethod (<https://github.com/pmd/pmd/issues/4016>)
    @SuppressWarnings({"PMD.AvoidStringBufferField", "PMD.UnusedPrivateMethod"})
    private static final class InOrderAssembler {

        private static final int INDEX_FIRST_FRAGMENT = 1;

        private final HashMap<Integer, Status> accumulations = new HashMap<>();

        /**
         * Appends a message fragment to the internal buffer and returns
         * the full message if msgText was no fragmented message or all
         * the fragments have been combined. Returns null, if there are
         * fragments pending or an invalid fragment was received.
         * <p>
         * A fragmented OTR message looks like this:
         * (V2) ?OTR,k,n,piece-k,
         * or
         * (V3) ?OTR|sender_instance|receiver_instance,k,n,piece-k,
         *
         * @param fragment The message fragment to process.
         * @return String with the accumulated message or
         * null if the message was incomplete or malformed
         * @throws ProtocolException Thrown in case the message is bad in some way
         *                           that breaks with the expectations of the OTR protocol.
         */
        @Nullable
        private String accumulate(final Fragment fragment) throws ProtocolException {
            final int id = fragment.getSenderTag().getValue();
            if (fragment.getIndex() == INDEX_FIRST_FRAGMENT) {
                // first fragment
                final Status status = new Status(fragment.getIndex(), fragment.getTotal(), fragment.getContent());
                this.accumulations.put(id, status);
            } else {
                // next fragment
                final Status status = this.accumulations.get(id);
                if (status == null) {
                    throw new ProtocolException("Rejecting fragment from unknown sender tag, for which we have not started collecting yet.");
                }
                if (fragment.getTotal() == status.total && fragment.getIndex() == status.current + 1) {
                    // consecutive fragment, in order
                    status.current++;
                    status.content.append(fragment.getContent());
                } else {
                    // out-of-order fragment
                    this.accumulations.remove(id);
                    throw new ProtocolException("Rejecting fragment that was received out-of-order.");
                }
            }

            if (fragment.getIndex() == fragment.getTotal()) {
                final Status status = this.accumulations.remove(id);
                return status.content.toString();
            }

            // Fragment did not result in completed message. Waiting for next fragment.
            return null;
        }

        /**
         * In-progress assembly status type.
         */
        private static final class Status {
            private int current;
            private final int total;
            private final StringBuilder content;

            public Status(final int index, final int total, final String content) {
                this.current = index;
                this.total = total;
                this.content = new StringBuilder(content);
            }
        }
    }

    /**
     * Out-of-order assembler, following OTRv4 specification.
     */
    // REMARK now that a maximum of `MAX_MESSAGES_IN_ASSEMBLY` is maintained, one can still interfere by sending bogus messages at such a rate that a valid message is cleaned up, i.e. between first and last fragment of a message, at least 100 bogus messages are sent.
    private static final class OutOfOrderAssembler {

        private static final Logger LOGGER = Logger.getLogger(OutOfOrderAssembler.class.getName());

        // TODO strictly speaking we're removing the eldest, not the least-active. We could possibly remove message fragments even though one of the fragments arrived very recently.
        private final LinkedHashMap<Integer, String[]> fragments = new LinkedHashMap<>() {
            @Override
            protected boolean removeEldestEntry(final Map.Entry<Integer, String[]> eldest) {
                return this.size() > MAX_MESSAGES_IN_ASSEMBLY;
            }
        };

        /**
         * Accumulate fragments.
         *
         * @param fragment the fragment to accumulate in the assembly
         * @return Returns null in case of incomplete message (more fragments needed) or reassembled message text in
         * case of complete reassembly.
         */
        @Nullable
        String accumulate(final Fragment fragment) throws ProtocolException {
            final String[] parts = this.fragments.computeIfAbsent(fragment.getIdentifier(), k -> new String[fragment.getTotal()]);
            if (fragment.getTotal() != parts.length) {
                LOGGER.log(Level.FINEST, "OTRv4 fragmentation of other party may be broken. Initial total is different from this message. Ignoring this fragment. (Original: {0}, current fragment: {1})",
                        new Object[]{parts.length, fragment.getTotal()});
                throw new ProtocolException("Rejecting fragment with different total value than other fragments of the same series.");
            }
            final int zeroBasedIndex = fragment.getIndex() - 1;
            if (parts[zeroBasedIndex] != null) {
                LOGGER.log(Level.FINEST, "Fragment with index {0} is already present. Ignoring this fragment.",
                        new Object[]{fragment.getIndex()});
                throw new ProtocolException("Rejecting fragment with index that is already present.");
            }
            parts[zeroBasedIndex] = fragment.getContent();
            if (containsEmpty(parts)) {
                final int usage = Arrays.stream(parts).filter(Objects::nonNull).map(String::length).reduce(0, Integer::sum);
                if (usage > MAX_MESSAGE_SIZE) {
                    LOGGER.warning("Fragments of incomplete message already exceed maximum message size. Evicting fragments of message.");
                    this.fragments.remove(fragment.getIdentifier());
                }
                // Not all message parts are present. Return null and wait for next message part before continuing.
                return null;
            }
            this.fragments.remove(fragment.getIdentifier());
            return concat(parts);
        }
    }
}
