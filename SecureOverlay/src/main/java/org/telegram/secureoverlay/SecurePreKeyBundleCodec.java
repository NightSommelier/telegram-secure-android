package org.telegram.secureoverlay;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.signal.libsignal.protocol.IdentityKey;
import org.signal.libsignal.protocol.IdentityKeyPair;
import org.signal.libsignal.protocol.ecc.ECPublicKey;
import org.signal.libsignal.protocol.kem.KEMPublicKey;
import org.signal.libsignal.protocol.state.PreKeyBundle;

/**
 * Canonical, bounded encoding of a public libsignal pre-key bundle.
 *
 * This carries no private state and is deliberately separate from encrypted message carriers.
 */
public final class SecurePreKeyBundleCodec {
    private static final int LEGACY_VERSION = 1;
    private static final int RECOVERY_VERSION = 2;
    private static final int PARTICIPANT_BOUND_VERSION = 3;
    private static final int MAX_FIELD_BYTES = 8 * 1024;
    private static final int MAX_BUNDLE_BYTES = 32 * 1024;
    private static final byte[] RECOVERY_SIGNATURE_DOMAIN =
            "Fork-Secure pairing offer v2\u0000".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] PARTICIPANT_BOUND_SIGNATURE_DOMAIN =
            "Fork-Secure pairing offer v3\u0000".getBytes(StandardCharsets.US_ASCII);
    private static final java.security.SecureRandom RANDOM = new java.security.SecureRandom();

    private SecurePreKeyBundleCodec() {}

    public static byte[] encode(KeystoreSignalProtocolStore store) {
        try {
            KeystoreSignalProtocolStore.LocalPreKeyMaterial local = store.ensureLocalPreKeyMaterial();
            return encode(new PublicBundle(
                    store.getLocalRegistrationId(),
                    local.preKeyId, local.preKey.getKeyPair().getPublicKey().serialize(),
                    local.signedPreKeyId, local.signedPreKey.getKeyPair().getPublicKey().serialize(),
                    local.signedPreKey.getSignature(), store.getIdentityKeyPair().getPublicKey().serialize(),
                    local.kyberPreKeyId, local.kyberPreKey.getKeyPair().getPublicKey().serialize(),
                    local.kyberPreKey.getSignature()));
        } catch (Exception e) {
            throw new IllegalStateException("cannot encode secure pre-key bundle", e);
        }
    }

    public static byte[] encode(PublicBundle bundle) {
        requireBundle(bundle);
        try {
            ByteArrayOutputStream sink = new ByteArrayOutputStream();
            DataOutputStream out = new DataOutputStream(sink);
            out.writeByte(LEGACY_VERSION);
            writeBundleFields(out, bundle);
            out.flush();
            byte[] result = sink.toByteArray();
            requireEncodedSize(result);
            return result;
        } catch (IOException impossible) {
            throw new AssertionError(impossible);
        }
    }

    /**
     * Encodes recovery and participant binding metadata (v3) and signs the complete canonical
     * pairing body with the identity private key.
     */
    public static byte[] encodeRecoveryOffer(
            KeystoreSignalProtocolStore store,
            SecureRecoveryGenerationStore.Record recovery,
            long ownerUserId,
            long recipientUserId) {
        if (store == null) {
            throw new IllegalArgumentException("signal store is required");
        }
        if (ownerUserId <= 0 || recipientUserId <= 0 || ownerUserId == recipientUserId) {
            throw new IllegalArgumentException("invalid v3 pairing offer binding metadata");
        }
        try {
            KeystoreSignalProtocolStore.LocalPreKeyMaterial local =
                    store.ensureLocalPreKeyMaterial();
            PublicBundle bundle = new PublicBundle(
                    store.getLocalRegistrationId(),
                    local.preKeyId,
                    local.preKey.getKeyPair().getPublicKey().serialize(),
                    local.signedPreKeyId,
                    local.signedPreKey.getKeyPair().getPublicKey().serialize(),
                    local.signedPreKey.getSignature(),
                    store.getIdentityKeyPair().getPublicKey().serialize(),
                    local.kyberPreKeyId,
                    local.kyberPreKey.getKeyPair().getPublicKey().serialize(),
                    local.kyberPreKey.getSignature());
            return encodeRecoveryOffer(
                    bundle,
                    recovery,
                    store.getIdentityKeyPair(),
                    ownerUserId,
                    recipientUserId,
                    System.currentTimeMillis() / 1000L,
                    randomNonZeroNonce());
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("cannot encode recovery pairing offer", e);
        }
    }

    static byte[] encodeRecoveryOffer(
            PublicBundle bundle,
            SecureRecoveryGenerationStore.Record recovery,
            IdentityKeyPair signer,
            long ownerUserId,
            long recipientUserId,
            long issuedAtEpochSeconds,
            long offerNonce) {
        requireBundle(bundle);
        if (recovery == null || signer == null
                || !Arrays.equals(signer.getPublicKey().serialize(), bundle.identityKey)) {
            throw new IllegalArgumentException("recovery offer signer does not match identity");
        }
        if (ownerUserId <= 0
                || recipientUserId <= 0
                || ownerUserId == recipientUserId
                || issuedAtEpochSeconds <= 0
                || offerNonce == 0) {
            throw new IllegalArgumentException("invalid v3 pairing offer binding metadata");
        }
        try {
            ByteArrayOutputStream bodySink = new ByteArrayOutputStream();
            DataOutputStream bodyOut = new DataOutputStream(bodySink);
            bodyOut.writeByte(PARTICIPANT_BOUND_VERSION);
            writeBundleFields(bodyOut, bundle);
            bodyOut.writeLong(recovery.generation);
            bodyOut.writeLong(recovery.recoveryId.getMostSignificantBits());
            bodyOut.writeLong(recovery.recoveryId.getLeastSignificantBits());
            bodyOut.writeLong(ownerUserId);
            bodyOut.writeLong(recipientUserId);
            bodyOut.writeLong(issuedAtEpochSeconds);
            bodyOut.writeLong(offerNonce);
            bodyOut.flush();
            byte[] body = bodySink.toByteArray();
            byte[] signature = signer.getPrivateKey().calculateSignature(
                    participantBoundSignatureInput(body));

            ByteArrayOutputStream resultSink = new ByteArrayOutputStream();
            resultSink.write(body);
            DataOutputStream resultOut = new DataOutputStream(resultSink);
            field(resultOut, signature);
            resultOut.flush();
            byte[] result = resultSink.toByteArray();
            requireEncodedSize(result);
            return result;
        } catch (IOException impossible) {
            throw new AssertionError(impossible);
        }
    }

    private static long randomNonZeroNonce() {
        long nonce;
        do {
            nonce = RANDOM.nextLong();
        } while (nonce == 0);
        return nonce;
    }

    public static PreKeyBundle decode(byte[] encoded) {
        return decodeOffer(encoded).preKeyBundle;
    }

    public static DecodedOffer decodeOffer(byte[] encoded) {
        if (encoded == null || encoded.length == 0 || encoded.length > MAX_BUNDLE_BYTES) {
            throw new IllegalArgumentException("invalid pre-key bundle size");
        }
        try {
            ByteArrayInputStream source = new ByteArrayInputStream(encoded);
            DataInputStream in = new DataInputStream(source);
            int version = in.readUnsignedByte();
            if (version != PARTICIPANT_BOUND_VERSION) {
                throw new IllegalArgumentException("unsupported pre-key bundle version");
            }
            int registrationId = positive(in.readInt(), "registration id");
            int preKeyId = nonNegative(in.readInt(), "pre-key id");
            ECPublicKey preKey = new ECPublicKey(field(in));
            int signedPreKeyId = nonNegative(in.readInt(), "signed pre-key id");
            ECPublicKey signedPreKey = new ECPublicKey(field(in));
            byte[] signature = field(in);
            IdentityKey identity = new IdentityKey(field(in));
            int kyberPreKeyId = nonNegative(in.readInt(), "Kyber pre-key id");
            KEMPublicKey kyberPreKey = new KEMPublicKey(field(in));
            byte[] kyberSignature = field(in);
            SecureRecoveryGenerationStore.Record recovery =
                    new SecureRecoveryGenerationStore.Record(
                            in.readLong(), new java.util.UUID(in.readLong(), in.readLong()));
            long ownerUserId = in.readLong();
            long recipientUserId = in.readLong();
            long issuedAtEpochSeconds = in.readLong();
            long offerNonce = in.readLong();
            if (ownerUserId <= 0
                    || recipientUserId <= 0
                    || ownerUserId == recipientUserId
                    || issuedAtEpochSeconds <= 0
                    || offerNonce == 0) {
                throw new IllegalArgumentException("invalid v3 pairing offer binding metadata");
            }
            int signedBodyBytes = encoded.length - source.available();
            byte[] signedBody = Arrays.copyOf(encoded, signedBodyBytes);
            byte[] offerSignature = field(in);
            if (in.available() != 0) throw new IllegalArgumentException("trailing pre-key bundle data");
            if (!identity.getPublicKey().verifySignature(signedPreKey.serialize(), signature)
                    || !identity.getPublicKey().verifySignature(kyberPreKey.serialize(), kyberSignature)) {
                throw new IllegalArgumentException("invalid pre-key bundle signature");
            }
            byte[] signatureInput = participantBoundSignatureInput(signedBody);
            if (!identity.getPublicKey().verifySignature(signatureInput, offerSignature)) {
                throw new IllegalArgumentException("invalid recovery pairing signature");
            }
            PreKeyBundle preKeyBundle = new PreKeyBundle(
                    registrationId,
                    1,
                    preKeyId,
                    preKey,
                    signedPreKeyId,
                    signedPreKey,
                    signature,
                    identity,
                    kyberPreKeyId,
                    kyberPreKey,
                    kyberSignature);
            return new DecodedOffer(
                    preKeyBundle,
                    recovery,
                    ownerUserId,
                    recipientUserId,
                    issuedAtEpochSeconds,
                    offerNonce);
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("malformed pre-key bundle", e);
        }
    }

    private static void writeBundleFields(DataOutputStream out, PublicBundle bundle)
            throws IOException {
        out.writeInt(bundle.registrationId);
        out.writeInt(bundle.preKeyId);
        field(out, bundle.preKey);
        out.writeInt(bundle.signedPreKeyId);
        field(out, bundle.signedPreKey);
        field(out, bundle.signedPreKeySignature);
        field(out, bundle.identityKey);
        out.writeInt(bundle.kyberPreKeyId);
        field(out, bundle.kyberPreKey);
        field(out, bundle.kyberPreKeySignature);
    }

    private static byte[] recoverySignatureInput(byte[] canonicalBody) {
        byte[] input = new byte[RECOVERY_SIGNATURE_DOMAIN.length + canonicalBody.length];
        System.arraycopy(
                RECOVERY_SIGNATURE_DOMAIN, 0, input, 0, RECOVERY_SIGNATURE_DOMAIN.length);
        System.arraycopy(
                canonicalBody,
                0,
                input,
                RECOVERY_SIGNATURE_DOMAIN.length,
                canonicalBody.length);
        return input;
    }

    private static byte[] participantBoundSignatureInput(byte[] canonicalBody) {
        byte[] input = new byte[PARTICIPANT_BOUND_SIGNATURE_DOMAIN.length + canonicalBody.length];
        System.arraycopy(
                PARTICIPANT_BOUND_SIGNATURE_DOMAIN,
                0,
                input,
                0,
                PARTICIPANT_BOUND_SIGNATURE_DOMAIN.length);
        System.arraycopy(
                canonicalBody,
                0,
                input,
                PARTICIPANT_BOUND_SIGNATURE_DOMAIN.length,
                canonicalBody.length);
        return input;
    }

    private static void requireBundle(PublicBundle bundle) {
        if (bundle == null || bundle.registrationId <= 0 || bundle.preKeyId < 0
                || bundle.signedPreKeyId < 0 || bundle.kyberPreKeyId < 0) {
            throw new IllegalArgumentException("invalid pre-key bundle ids");
        }
    }

    private static void requireEncodedSize(byte[] encoded) {
        if (encoded.length > MAX_BUNDLE_BYTES) {
            throw new IllegalArgumentException("pre-key bundle too large");
        }
    }

    private static void field(DataOutputStream out, byte[] value) throws IOException {
        if (value == null || value.length == 0 || value.length > MAX_FIELD_BYTES) throw new IllegalArgumentException("invalid pre-key bundle field");
        out.writeShort(value.length);
        out.write(value);
    }

    private static byte[] field(DataInputStream in) throws IOException {
        int length = in.readUnsignedShort();
        if (length == 0 || length > MAX_FIELD_BYTES || length > in.available()) throw new IllegalArgumentException("invalid pre-key bundle field");
        byte[] value = new byte[length];
        in.readFully(value);
        return value;
    }

    private static int positive(int value, String field) { if (value <= 0) throw new IllegalArgumentException("invalid " + field); return value; }
    private static int nonNegative(int value, String field) { if (value < 0) throw new IllegalArgumentException("invalid " + field); return value; }

    public static final class DecodedOffer {
        public final PreKeyBundle preKeyBundle;
        public final SecureRecoveryGenerationStore.Record recovery;
        public final long ownerUserId;
        public final long recipientUserId;
        public final long issuedAtEpochSeconds;
        public final long offerNonce;

        DecodedOffer(
                PreKeyBundle preKeyBundle,
                SecureRecoveryGenerationStore.Record recovery,
                long ownerUserId,
                long recipientUserId,
                long issuedAtEpochSeconds,
                long offerNonce) {
            this.preKeyBundle = preKeyBundle;
            this.recovery = recovery;
            this.ownerUserId = ownerUserId;
            this.recipientUserId = recipientUserId;
            this.issuedAtEpochSeconds = issuedAtEpochSeconds;
            this.offerNonce = offerNonce;
        }
    }

    public static final class PublicBundle {
        final int registrationId, preKeyId, signedPreKeyId, kyberPreKeyId;
        final byte[] preKey, signedPreKey, signedPreKeySignature, identityKey, kyberPreKey, kyberPreKeySignature;
        public PublicBundle(int registrationId, int preKeyId, byte[] preKey, int signedPreKeyId, byte[] signedPreKey,
                byte[] signedPreKeySignature, byte[] identityKey, int kyberPreKeyId, byte[] kyberPreKey, byte[] kyberPreKeySignature) {
            this.registrationId = registrationId; this.preKeyId = preKeyId; this.preKey = preKey;
            this.signedPreKeyId = signedPreKeyId; this.signedPreKey = signedPreKey; this.signedPreKeySignature = signedPreKeySignature;
            this.identityKey = identityKey; this.kyberPreKeyId = kyberPreKeyId; this.kyberPreKey = kyberPreKey; this.kyberPreKeySignature = kyberPreKeySignature;
        }
    }
}
