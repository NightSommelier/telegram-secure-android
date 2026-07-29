package org.telegram.secureoverlay;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import org.signal.libsignal.protocol.IdentityKey;
import org.signal.libsignal.protocol.ecc.ECPublicKey;
import org.signal.libsignal.protocol.kem.KEMPublicKey;
import org.signal.libsignal.protocol.state.PreKeyBundle;

/**
 * Canonical, bounded encoding of a public libsignal pre-key bundle.
 *
 * This carries no private state and is deliberately separate from encrypted message carriers.
 */
public final class SecurePreKeyBundleCodec {
    private static final int VERSION = 1;
    private static final int MAX_FIELD_BYTES = 8 * 1024;
    private static final int MAX_BUNDLE_BYTES = 32 * 1024;

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
        if (bundle == null || bundle.registrationId <= 0 || bundle.preKeyId < 0 || bundle.signedPreKeyId < 0 || bundle.kyberPreKeyId < 0) {
            throw new IllegalArgumentException("invalid pre-key bundle ids");
        }
        try {
            ByteArrayOutputStream sink = new ByteArrayOutputStream();
            DataOutputStream out = new DataOutputStream(sink);
            out.writeByte(VERSION);
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
            out.flush();
            byte[] result = sink.toByteArray();
            if (result.length > MAX_BUNDLE_BYTES) throw new IllegalArgumentException("pre-key bundle too large");
            return result;
        } catch (IOException impossible) {
            throw new AssertionError(impossible);
        }
    }

    public static PreKeyBundle decode(byte[] encoded) {
        if (encoded == null || encoded.length == 0 || encoded.length > MAX_BUNDLE_BYTES) {
            throw new IllegalArgumentException("invalid pre-key bundle size");
        }
        try {
            DataInputStream in = new DataInputStream(new ByteArrayInputStream(encoded));
            if (in.readUnsignedByte() != VERSION) throw new IllegalArgumentException("unsupported pre-key bundle version");
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
            if (in.available() != 0) throw new IllegalArgumentException("trailing pre-key bundle data");
            if (!identity.getPublicKey().verifySignature(signedPreKey.serialize(), signature)
                    || !identity.getPublicKey().verifySignature(kyberPreKey.serialize(), kyberSignature)) {
                throw new IllegalArgumentException("invalid pre-key bundle signature");
            }
            return new PreKeyBundle(registrationId, 1, preKeyId, preKey, signedPreKeyId,
                    signedPreKey, signature, identity, kyberPreKeyId, kyberPreKey, kyberSignature);
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("malformed pre-key bundle", e);
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
