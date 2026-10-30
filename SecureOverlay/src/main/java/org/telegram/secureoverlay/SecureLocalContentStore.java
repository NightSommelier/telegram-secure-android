package org.telegram.secureoverlay;

import android.content.Context;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/** Keystore-encrypted local cache for authenticated typed payload bytes. */
final class SecureLocalContentStore {
    static final String OUTGOING_PREFIX = "outgoing-content.v1.";
    static final String INCOMING_PREFIX = "incoming-content.v1.";

    static final byte MAGIC_1 = (byte) 0x7E;
    static final byte MAGIC_2 = (byte) 0x43; // ~C
    static final byte FORMAT_VERSION = 1;
    static final int HEADER_LENGTH = 2 + 1 + 8 + 32; // 43 bytes

    private final int account;
    private final long peerUserId;
    private final KeystoreEncryptedBlobStore blobs;
    private final byte[] nameMaskKey;

    SecureLocalContentStore(Context context, int account, long peerUserId) {
        if (account < 0 || peerUserId == 0) {
            throw new IllegalArgumentException("secure content requires an account and peer");
        }
        this.account = account;
        this.peerUserId = peerUserId;
        blobs = new KeystoreEncryptedBlobStore(context.getApplicationContext());
        nameMaskKey = SecureNameMask.getOrGenerateKey(blobs);
    }

    void rememberOutgoing(String carrier, byte[] content)
            throws KeystoreEncryptedBlobStore.StateStoreException {
        remember(OUTGOING_PREFIX, carrier, content);
    }

    void rememberIncoming(String carrier, byte[] content)
            throws KeystoreEncryptedBlobStore.StateStoreException {
        remember(INCOMING_PREFIX, carrier, content);
    }

    byte[] loadOutgoing(String carrier)
            throws KeystoreEncryptedBlobStore.StateStoreException {
        return load(OUTGOING_PREFIX, carrier);
    }

    byte[] loadIncoming(String carrier)
            throws KeystoreEncryptedBlobStore.StateStoreException {
        return load(INCOMING_PREFIX, carrier);
    }

    void forgetOutgoing(String carrier)
            throws KeystoreEncryptedBlobStore.StateStoreException {
        String storageKey = key(OUTGOING_PREFIX, account, peerUserId, carrier);
        String legacy = legacyKey(OUTGOING_PREFIX, account, peerUserId, carrier);
        blobs.deleteAll(storageKey, legacy);
    }

    private void remember(String prefix, String carrier, byte[] content)
            throws KeystoreEncryptedBlobStore.StateStoreException {
        requireEncryptedCarrier(carrier);
        if (content == null || content.length == 0) {
            throw new IllegalArgumentException("local secure content is empty");
        }
        // Parse before persistence so malformed typed content can never become trusted cache.
        SecureContentCodec.decode(content);
        byte[] digest = sha256Bytes(carrier);
        byte[] encoded = encodeRecord(peerUserId, digest, content);
        blobs.put(key(prefix, account, peerUserId, carrier), encoded);
    }

    private byte[] load(String prefix, String carrier)
            throws KeystoreEncryptedBlobStore.StateStoreException {
        if (!isEncryptedCarrier(carrier)) {
            return null;
        }
        String storageKey = key(prefix, account, peerUserId, carrier);
        byte[] data = blobs.get(storageKey);
        if (data == null) {
            String legacy = legacyKey(prefix, account, peerUserId, carrier);
            data = blobs.get(legacy);
            if (data != null) {
                byte[] payload = extractPayload(data);
                byte[] digest = sha256Bytes(carrier);
                blobs.put(storageKey, encodeRecord(peerUserId, digest, payload));
                blobs.delete(legacy);
                data = payload;
            } else {
                return null;
            }
        } else {
            data = extractPayload(data);
        }
        if (data != null) {
            SecureContentCodec.decode(data);
        }
        return data;
    }

    static boolean isEncodedRecord(byte[] data) {
        return data != null && data.length >= HEADER_LENGTH
                && data[0] == MAGIC_1 && data[1] == MAGIC_2 && data[2] == FORMAT_VERSION;
    }

    static byte[] encodeRecord(long peerUserId, byte[] carrierDigest, byte[] payload) {
        byte[] record = new byte[HEADER_LENGTH + payload.length];
        record[0] = MAGIC_1;
        record[1] = MAGIC_2;
        record[2] = FORMAT_VERSION;
        ByteBuffer.wrap(record, 3, 8).putLong(peerUserId);
        System.arraycopy(carrierDigest, 0, record, 11, 32);
        System.arraycopy(payload, 0, record, HEADER_LENGTH, payload.length);
        return record;
    }

    static byte[] extractPayload(byte[] record) {
        if (isEncodedRecord(record)) {
            byte[] payload = new byte[record.length - HEADER_LENGTH];
            System.arraycopy(record, HEADER_LENGTH, payload, 0, payload.length);
            return payload;
        }
        return record;
    }

    private static void requireEncryptedCarrier(String carrier) {
        if (!isEncryptedCarrier(carrier)) {
            throw new IllegalArgumentException("local content requires encrypted carrier");
        }
    }

    private static boolean isEncryptedCarrier(String carrier) {
        SecureCarrierCodec.Decoded decoded = SecureCarrierCodec.decode(carrier);
        return decoded != null && decoded.type != SecureCarrierCodec.TYPE_PREKEY_BUNDLE;
    }

    static String key(String prefix, int account, long peerUserId, String carrier) {
        return keyByDigest(prefix, account, peerUserId, sha256Hex(carrier));
    }

    static String keyByDigest(String prefix, int account, long peerUserId, String digestHex) {
        byte[] maskKey = SecureNameMask.getOrGenerateKey((Context) null);
        String peerMask = SecureNameMask.maskPeer(maskKey, account, peerUserId);
        String carrierMask = SecureNameMask.maskCarrier(maskKey, account, peerUserId, digestHex);
        return prefix + account + '.' + peerMask + '.' + carrierMask;
    }

    static String legacyKey(String prefix, int account, long peerUserId, String carrier) {
        return prefix + account + '.' + peerUserId + '.' + sha256Hex(carrier);
    }

    static String legacyKeyByDigest(String prefix, int account, long peerUserId, String digestHex) {
        return prefix + account + '.' + peerUserId + '.' + digestHex;
    }

    static byte[] sha256Bytes(String value) {
        try {
            return MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
    }

    static String sha256Hex(String value) {
        byte[] digest = sha256Bytes(value);
        StringBuilder result = new StringBuilder(digest.length * 2);
        for (byte item : digest) {
            result.append(Character.forDigit((item >>> 4) & 0x0f, 16));
            result.append(Character.forDigit(item & 0x0f, 16));
        }
        return result.toString();
    }
}
