/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.messages;

import net.java.otr4j.api.ClientProfile;
import net.java.otr4j.api.InstanceTag;
import net.java.otr4j.api.Session.Version;
import net.java.otr4j.crypto.DSAKeyPair;
import net.java.otr4j.crypto.DSAKeyPair.DSASignature;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.crypto.ed448.EdDSAKeyPair;
import net.java.otr4j.crypto.ed448.Point;
import net.java.otr4j.io.OtrEncodable;
import net.java.otr4j.io.OtrInputStream;
import net.java.otr4j.io.OtrInputStream.UnsupportedLengthException;
import net.java.otr4j.io.OtrOutputStream;
import net.java.otr4j.io.UnsupportedTypeException;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.math.BigInteger;
import java.net.ProtocolException;
import java.security.interfaces.DSAPublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static java.util.Objects.requireNonNull;
import static net.java.otr4j.api.InstanceTag.isValidInstanceTag;
import static net.java.otr4j.crypto.DSAKeyPair.verifySignature;
import static net.java.otr4j.crypto.OtrCryptoEngine4.verifyEdDSAPublicKey;
import static net.java.otr4j.io.MessageProcessor.encodeVersionString;
import static net.java.otr4j.messages.Validators.validateAtMost;
import static net.java.otr4j.messages.Validators.validateDateAfter;
import static net.java.otr4j.messages.Validators.validateExactly;
import static net.java.otr4j.util.ByteArrays.constantTimeEquals;
import static net.java.otr4j.util.Iterables.findByType;

/**
 * The client profile payload.
 * <p>
 * This is the client profile in a representation that is easily serializable and that is able to carry the signatures
 * corresponding to the client profile.
 * <p>
 * The client profile payload is the unverified container for the data received from other parties. {@link #validate()}
 * will validate on success convert the type to the actual {@link ClientProfile} data-type. This split ensures that
 * client profiles are validated before trusted use.
 */
@SuppressWarnings("PMD.AvoidLiteralsInIfCondition")
public final class ClientProfilePayload implements OtrEncodable {

    private static final Logger LOGGER = Logger.getLogger(ClientProfilePayload.class.getName());

    private static final String NUMBERINDEX = "0123456789";

    private final List<Field> fields;

    private final byte[] signature;

    /**
     * Constructor for payload remains private as we expect to create this only from one of 2 sources:
     * 1. A ClientProfile instances to be converted.
     * 2. An (untrusted) input source to be deserialized.
     *
     * @param fields    The fields that are part of the payload.
     * @param signature The signature by the long-term public key.
     */
    @SuppressWarnings("PMD.ArrayIsStoredDirectly")
    private ClientProfilePayload(final List<Field> fields, final byte[] signature) {
        this.fields = requireNonNull(fields);
        this.signature = requireNonNull(signature);
    }

    /**
     * Generates a client profile payload by converting the profile and signing with provided keys.
     *
     * @param profile                   The client profile to be converted.
     * @param expirationUnixTimeSeconds Expiration time of profile as unix timestamp in seconds.
     * @param dsaKeyPair                OTRv3 DSA key pair for signing. (Transitional signature)
     * @param eddsaKeyPair              EdDSA long-term key pair.
     * @return Returns a Client Profile payload that can be serialized to an OTR-encoded data stream.
     */
    @Nonnull
    public static ClientProfilePayload signClientProfile(final ClientProfile profile, final long expirationUnixTimeSeconds,
            @Nullable final DSAKeyPair dsaKeyPair, final EdDSAKeyPair eddsaKeyPair) {
        final ArrayList<Field> fields = new ArrayList<>();
        fields.add(new InstanceTagField(profile.getInstanceTag().getValue()));
        fields.add(new ED448PublicKeyField(profile.getLongTermPublicKey()));
        fields.add(new ED448ForgingKeyField(profile.getForgingKey()));
        fields.add(new VersionsField(new ArrayList<>(profile.getVersions())));
        fields.add(new ExpirationDateField(expirationUnixTimeSeconds));
        final DSAPublicKey dsaPublicKey = profile.getDsaPublicKey();
        if (dsaPublicKey != null) {
            if (dsaKeyPair == null) {
                throw new IllegalArgumentException("DSA public key provided, but private key is not provided.");
            }
            fields.add(new DSAPublicKeyField(dsaPublicKey));
        }
        final OtrOutputStream out = new OtrOutputStream();
        for (final Field field : fields) {
            out.write(field);
        }
        final byte[] partialM = out.toByteArray();
        final byte[] m;
        if (dsaKeyPair == null) {
            m = partialM;
        } else {
            final DSASignature transitionalSignature = dsaKeyPair.signRS(partialM);
            final TransitionalSignatureField transSigField = new TransitionalSignatureField(transitionalSignature);
            fields.add(transSigField);
            out.write(transSigField);
            m = out.toByteArray();
        }
        final byte[] signature = eddsaKeyPair.sign(m);
        // We assume that the internally generated client profiles are correct, however it is tested when assertions are
        // enabled.
        assert testValidate(fields, signature, Instant.now()) : "BUG: Internally constructed client profile payload fails validation. This should not happen.";
        return new ClientProfilePayload(fields, signature);
    }

    /**
     * Read Client Profile payload from OTR-encoded input stream.
     *
     * @param in The OTR-encoded input stream.
     * @return Returns ClientProfilePayload as read from input stream.
     * @throws ProtocolException   In case of failure to read the expected data from the input stream.
     * @throws OtrCryptoException  In case of failure to restore cryptographic components in the payload.
     * @throws ValidationException In case of failure to validate the client profile after reading. This indicates that
     *                             the various fields were valid but the composition of the profile is illegal.
     */
    @SuppressWarnings("SwitchStatementWithTooFewBranches")
    @Nonnull
    public static ClientProfilePayload readFrom(final OtrInputStream in) throws OtrCryptoException, ProtocolException,
            ValidationException {
        final int numFields = in.readInt();
        if (numFields <= 0) {
            throw new ProtocolException("Invalid number of fields: " + numFields);
        }
        final ArrayList<Field> fields = new ArrayList<>();
        for (int i = 0; i < numFields; i++) {
            final FieldType type = FieldType.findType(in.readShort());
            if (type == null) {
                throw new ProtocolException("Unknown field type encountered.");
            }
            switch (type) {
            case INSTANCE_TAG:
                fields.add(new InstanceTagField(in.readInt()));
                break;
            case LONG_TERM_EDDSA_PUBLIC_KEY:
                final int publicKeyType = in.readShort();
                switch (publicKeyType) {
                case ED448PublicKeyField.ED448_PUBLIC_KEY_TYPE:
                    final Point publicKey = in.readPoint();
                    fields.add(new ED448PublicKeyField(publicKey));
                    break;
                default:
                    throw new ProtocolException("Unsupported Ed448 public key type: " + publicKeyType);
                }
                break;
            case ED448_FORGING_PUBLIC_KEY:
                final int forgingKeyType = in.readShort();
                switch (forgingKeyType) {
                case ED448ForgingKeyField.ED448_FORGING_KEY_TYPE:
                    final Point publicKey = in.readPoint();
                    fields.add(new ED448ForgingKeyField(publicKey));
                    break;
                default:
                    throw new ProtocolException("Unsupported Ed448 forging key type: " + forgingKeyType);
                }
                break;
            case VERSIONS:
                try {
                    fields.add(new VersionsField(parseVersions(in.readData())));
                } catch (final UnsupportedLengthException e) {
                    throw new ProtocolException("Versions are not expected to be stored in an exceptionally large data field. This is not according to specification.");
                }
                break;
            case PROFILE_EXPIRATION:
                fields.add(new ExpirationDateField(in.readLong()));
                break;
            case TRANSITIONAL_SIGNATURE:
                final BigInteger r = in.readBigInt();
                final BigInteger s = in.readBigInt();
                fields.add(new TransitionalSignatureField(new DSASignature(r, s)));
                break;
            case TRANSITIONAL_DSA_PUBLIC_KEY:
                try {
                    fields.add(new DSAPublicKeyField(in.readPublicKey()));
                } catch (final UnsupportedTypeException e) {
                    throw new ProtocolException("Unsupported type of OTRv3 Public Key encountered.");
                }
                break;
            default:
                throw new ProtocolException("Unknown field type encountered: " + type);
            }
        }
        final byte[] signature = in.readEdDSASignature();
        validate(fields, signature, Instant.now());
        return new ClientProfilePayload(fields, signature);
    }

    @Nonnull
    private static ArrayList<Integer> parseVersions(@Nonnull final byte[] versiondata) throws ProtocolException {
        final ArrayList<Integer> versions = new ArrayList<>();
        for (final byte b : versiondata) {
            final int idx = NUMBERINDEX.indexOf(b);
            if (idx < 0) {
                throw new ProtocolException("Unknown or illegal version specifier found.");
            }
            versions.add(idx);
        }
        return versions;
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        final ClientProfilePayload that = (ClientProfilePayload) o;
        return Objects.equals(this.fields, that.fields) && constantTimeEquals(this.signature, that.signature);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(this.fields);
        result = 31 * result + Arrays.hashCode(this.signature);
        return result;
    }

    @Override
    public void writeTo(final OtrOutputStream out) {
        out.writeInt(this.fields.size());
        for (final Field field : this.fields) {
            out.write(field);
        }
        out.writeEdDSASignature(this.signature);
    }

    /**
     * Validate the Client Profile payload and return a corresponding Client Profile instance iff validation succeeds.
     *
     * @return Returns ClientProfile iff validation succeeds.
     * @throws ValidationException In case of validation failure.
     */
    @Nonnull
    public ClientProfile validate() throws ValidationException {
        validate(this.fields, this.signature, Instant.now());
        return reconstructClientProfile();
    }

    /**
     * Reconstruct client profile from fields and signatures stored in the payload.
     * <p>
     * This method is expected to succeed always. Validation MUST be performed prior to calling this method to ensure
     * that a valid composition of fields is available.
     *
     * @return Returns reconstructed client profile from fields and signatures stored inside the payload.
     */
    @Nonnull
    private ClientProfile reconstructClientProfile() {
        final InstanceTag instanceTag = new InstanceTag(findByType(this.fields, InstanceTagField.class).instanceTag);
        final Point longTermPublicKey = findByType(this.fields, ED448PublicKeyField.class).publicKey;
        final Point forgingKey = findByType(this.fields, ED448ForgingKeyField.class).publicKey;
        final List<Integer> versions = findByType(this.fields, VersionsField.class).versions;
        final DSAPublicKeyField dsaPublicKeyField = findByType(this.fields, DSAPublicKeyField.class, null);
        return new ClientProfile(instanceTag, longTermPublicKey, forgingKey, versions,
            dsaPublicKeyField == null ? null : dsaPublicKeyField.publicKey);
    }

    /**
     * Custom method to make {@link #validate()} suitable for assertions.
     *
     * @return true iff validated successfully
     */
    private static boolean testValidate(final List<Field> fields, final byte[] signature, final Instant now) {
        try {
            validate(fields, signature, now);
            return true;
        } catch (final ValidationException e) {
            LOGGER.log(Level.SEVERE, "Failed validation.", e);
            return false;
        }
    }

    /**
     * Verify consistency of fields list.
     *
     * @param fields    List of fields.
     * @param signature The OTRv4 signature for the fields contained in the client profile.
     * @throws ValidationException In case ClientProfilePayload contents are not inconsistent or signature is invalid.
     */
    // TODO consider reducing complexity.
    @SuppressWarnings("PMD.CognitiveComplexity")
    private static void validate(final List<Field> fields, final byte[] signature, final Instant now)
            throws ValidationException {
        final ArrayList<InstanceTagField> instanceTagFields = new ArrayList<>();
        final ArrayList<ED448PublicKeyField> publicKeyFields = new ArrayList<>();
        final ArrayList<ED448ForgingKeyField> forgingKeyFields = new ArrayList<>();
        final ArrayList<VersionsField> versionsFields = new ArrayList<>();
        final ArrayList<ExpirationDateField> expirationDateFields = new ArrayList<>();
        final ArrayList<DSAPublicKeyField> dsaPublicKeyFields = new ArrayList<>();
        final ArrayList<TransitionalSignatureField> transitionalSignatureFields = new ArrayList<>();
        final OtrOutputStream out = new OtrOutputStream();
        for (final Field field : fields) {
            if (field instanceof InstanceTagField) {
                instanceTagFields.add((InstanceTagField) field);
            } else if (field instanceof ED448PublicKeyField) {
                publicKeyFields.add((ED448PublicKeyField) field);
            } else if (field instanceof ED448ForgingKeyField) {
                forgingKeyFields.add((ED448ForgingKeyField) field);
            } else if (field instanceof VersionsField) {
                versionsFields.add((VersionsField) field);
            } else if (field instanceof ExpirationDateField) {
                expirationDateFields.add((ExpirationDateField) field);
            } else if (field instanceof DSAPublicKeyField) {
                dsaPublicKeyFields.add((DSAPublicKeyField) field);
            } else if (field instanceof TransitionalSignatureField) {
                transitionalSignatureFields.add((TransitionalSignatureField) field);
                // Note: we need to skip the step of writing the transitional signature to the output stream, because
                // the transitional signature needs to be verified first, which means excluding the transitional
                // signature itself.
                continue;
            } else {
                throw new UnsupportedOperationException("BUG: incomplete implementation: support for field type " + field.getClass() + " is not implemented yet.");
            }
            out.write(field);
        }
        validateExactly(1, instanceTagFields.size(), "Incorrect number of instance tag fields. Expected exactly 1.");
        if (!isValidInstanceTag(instanceTagFields.get(0).instanceTag) || instanceTagFields.get(0).instanceTag == 0) {
            throw new ValidationException("Illegal instance tag.");
        }
        validateExactly(1, publicKeyFields.size(), "Incorrect number of public key fields. Expected exactly 1.");
        final Point longTermPublicKey;
        try {
            verifyEdDSAPublicKey(publicKeyFields.get(0).publicKey);
            longTermPublicKey = publicKeyFields.get(0).publicKey;
        } catch (final OtrCryptoException e) {
            throw new ValidationException("Illegal EdDSA long-term public key.", e);
        }
        validateExactly(1, forgingKeyFields.size(), "Incorrect number of forging key fields. Expected exactly 1.");
        try {
            verifyEdDSAPublicKey(forgingKeyFields.get(0).publicKey);
        } catch (final OtrCryptoException e) {
            throw new ValidationException("Illegal Ed448 forging key.", e);
        }
        validateExactly(1, versionsFields.size(), "Incorrect number of versions fields. Expected exactly 1.");
        if (!versionsFields.get(0).versions.contains(Version.FOUR)) {
            throw new ValidationException("Expected at least OTR version 4 to be supported.");
        }
        validateExactly(1, expirationDateFields.size(), "Incorrect number of expiration date fields. Expected exactly 1.");
        validateAtMost(1, dsaPublicKeyFields.size(), "Expected either no or single DSA public key field. Found more than one.");
        if (dsaPublicKeyFields.size() == 1 && transitionalSignatureFields.isEmpty()) {
            throw new ValidationException("DSA public key encountered without corresponding transitional signature.");
        }
        validateDateAfter(now, Instant.ofEpochSecond(expirationDateFields.get(0).timestamp),
                "Client Profile has expired.");
        validateAtMost(1, transitionalSignatureFields.size(), "Expected at most one transitional signature, got more than one.");
        if (transitionalSignatureFields.size() == 1) {
            if (dsaPublicKeyFields.size() == 1) {
                // a DSA public key is available, hence we will validate the content with the transitional signature
                try {
                    final DSAPublicKey dsaPublicKey = dsaPublicKeyFields.get(0).publicKey;
                    final DSASignature transitionalSignature = transitionalSignatureFields.get(0).signature;
                    verifySignature(out.toByteArray(), dsaPublicKey, transitionalSignature.r, transitionalSignature.s);
                } catch (final OtrCryptoException e) {
                    throw new ValidationException("Failed transitional signature validation.", e);
                }
            }
            out.write(transitionalSignatureFields.get(0));
        }
        try {
            EdDSAKeyPair.verify(longTermPublicKey, out.toByteArray(), signature);
        } catch (final net.java.otr4j.crypto.ed448.ValidationException e) {
            throw new ValidationException("Verification of EdDSA signature failed.", e);
        }
    }

    /**
     * Type of fields.
     */
    private enum FieldType {
        /**
         * Client Profile owner instance tag (INT)
         */
        INSTANCE_TAG(0x0001),
        /**
         * Ed448 public key (ED448-PUBKEY)
         */
        LONG_TERM_EDDSA_PUBLIC_KEY(0x0002),
        /**
         * Ed448 forger public key (ED448-FORGER-PUBKEY)
         */
        ED448_FORGING_PUBLIC_KEY(0x0003),
        /**
         * Versions (DATA)
         * <p>
         * A string corresponding to supported OTR protocol versions.
         */
        VERSIONS(0x0004),
        /**
         * Client Profile Expiration (CLIENT-PROF-EXP)
         * <p>
         * The expiration date represented in standard Unix 64-bit timestamp format. (Seconds as of midnight Jan 1, 1970
         * UTC, ignoring leap seconds.)
         */
        PROFILE_EXPIRATION(0x0005),
        /**
         * OTRv3 public authentication DSA key (PUBKEY)
         */
        TRANSITIONAL_DSA_PUBLIC_KEY(0x0006),
        /**
         * Transitional Signature (CLIENT-SIG)
         * <p>
         * This signature is defined as a signature over fields 0x0001, 0x0002, 0x0003, 0x0004, 0x0005 and 0x006 only.
         */
        TRANSITIONAL_SIGNATURE(0x0007);

        private final int type;

        FieldType(final int type) {
            this.type = type;
        }

        /**
         * Find FieldType instance corresponding to the specified value.
         *
         * @param value The type value.
         * @return Returns the FieldType instance corresponding to the type value specified. Or null if type cannot be
         * found.
         */
        @Nullable
        private static FieldType findType(final int value) {
            for (final FieldType t : values()) {
                if (t.type == value) {
                    return t;
                }
            }
            return null;
        }
    }

    /**
     * Generic type for 'Field' type to express format in which various field types are implemented.
     */
    private interface Field extends OtrEncodable {
    }

    /**
     * Field for (owner) Instance Tag.
     */
    private static final class InstanceTagField implements Field {

        private static final FieldType TYPE = FieldType.INSTANCE_TAG;

        private final int instanceTag;

        private InstanceTagField(final int instanceTag) {
            this.instanceTag = instanceTag;
        }

        @Override
        public void writeTo(final OtrOutputStream out) {
            out.writeShort(TYPE.type);
            out.writeInt(this.instanceTag);
        }

        @Override
        public boolean equals(final Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            final InstanceTagField that = (InstanceTagField) o;
            return this.instanceTag == that.instanceTag;
        }

        @Override
        public int hashCode() {
            return Objects.hash(this.instanceTag);
        }
    }

    /**
     * Field for Ed448 public keys.
     */
    private static final class ED448PublicKeyField implements Field {

        private static final int ED448_PUBLIC_KEY_TYPE = 0x0010;
        private static final FieldType TYPE = FieldType.LONG_TERM_EDDSA_PUBLIC_KEY;

        private final Point publicKey;

        private ED448PublicKeyField(final Point publicKey) {
            this.publicKey = requireNonNull(publicKey);
        }

        @Override
        public void writeTo(final OtrOutputStream out) {
            out.writeShort(TYPE.type);
            out.writeShort(ED448_PUBLIC_KEY_TYPE);
            out.writePoint(this.publicKey);
        }

        @Override
        public boolean equals(final Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            final ED448PublicKeyField that = (ED448PublicKeyField) o;
            return Objects.equals(this.publicKey, that.publicKey);
        }

        @Override
        public int hashCode() {
            return Objects.hash(this.publicKey);
        }
    }

    /**
     * Field for Ed448 forging keys.
     */
    private static final class ED448ForgingKeyField implements Field {

        private static final int ED448_FORGING_KEY_TYPE = 0x0012;
        private static final FieldType TYPE = FieldType.ED448_FORGING_PUBLIC_KEY;

        private final Point publicKey;

        private ED448ForgingKeyField(final Point publicKey) {
            this.publicKey = requireNonNull(publicKey);
        }

        @Override
        public void writeTo(final OtrOutputStream out) {
            out.writeShort(TYPE.type);
            out.writeShort(ED448_FORGING_KEY_TYPE);
            out.writePoint(this.publicKey);
        }

        @Override
        public boolean equals(final Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            final ED448ForgingKeyField that = (ED448ForgingKeyField) o;
            return Objects.equals(this.publicKey, that.publicKey);
        }

        @Override
        public int hashCode() {
            return Objects.hash(this.publicKey);
        }
    }

    /**
     * Field for versions.
     */
    private static final class VersionsField implements Field {

        private static final FieldType TYPE = FieldType.VERSIONS;

        private final List<Integer> versions;

        private VersionsField(final List<Integer> versions) {
            this.versions = requireNonNull(versions);
        }

        @Override
        public void writeTo(final OtrOutputStream out) {
            out.writeShort(TYPE.type);
            out.writeData(encodeVersionString(this.versions).getBytes(US_ASCII));
        }

        @Override
        public boolean equals(final Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            final VersionsField that = (VersionsField) o;
            return Objects.equals(this.versions, that.versions);
        }

        @Override
        public int hashCode() {
            return Objects.hash(this.versions);
        }
    }

    /**
     * Field for expiration date.
     */
    private static final class ExpirationDateField implements Field {

        private static final FieldType TYPE = FieldType.PROFILE_EXPIRATION;

        private final long timestamp;

        /**
         * Expiration time as unix timestamp in seconds.
         *
         * @param timestamp expiration timestamp
         */
        private ExpirationDateField(final long timestamp) {
            this.timestamp = timestamp;
        }

        @Override
        public void writeTo(final OtrOutputStream out) {
            out.writeShort(TYPE.type);
            out.writeLong(this.timestamp);
        }

        @Override
        public boolean equals(final Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            final ExpirationDateField that = (ExpirationDateField) o;
            return this.timestamp == that.timestamp;
        }

        @Override
        public int hashCode() {
            return Objects.hash(this.timestamp);
        }
    }

    /**
     * Field for OTRv3 DSA public key.
     */
    private static final class DSAPublicKeyField implements Field {

        private static final FieldType TYPE = FieldType.TRANSITIONAL_DSA_PUBLIC_KEY;

        private final DSAPublicKey publicKey;

        private DSAPublicKeyField(final DSAPublicKey publicKey) {
            this.publicKey = requireNonNull(publicKey);
        }

        @Override
        public void writeTo(final OtrOutputStream out) {
            out.writeShort(TYPE.type);
            out.writePublicKey(this.publicKey);
        }

        @Override
        public boolean equals(final Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            final DSAPublicKeyField that = (DSAPublicKeyField) o;
            return Objects.equals(this.publicKey, that.publicKey);
        }

        @Override
        public int hashCode() {
            return Objects.hash(this.publicKey);
        }
    }

    /**
     * Field for transitional signature.
     */
    private static final class TransitionalSignatureField implements Field {

        private static final FieldType TYPE = FieldType.TRANSITIONAL_SIGNATURE;

        private final DSASignature signature;

        private TransitionalSignatureField(final DSASignature signature) {
            this.signature = requireNonNull(signature);
        }

        @Override
        public void writeTo(final OtrOutputStream out) {
            out.writeShort(TYPE.type);
            out.writeBigInt(this.signature.r);
            out.writeBigInt(this.signature.s);
        }

        @Override
        public boolean equals(final Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            final TransitionalSignatureField that = (TransitionalSignatureField) o;
            return Objects.equals(this.signature, that.signature);
        }

        @Override
        public int hashCode() {
            return Objects.hash(this.signature);
        }
    }
}
