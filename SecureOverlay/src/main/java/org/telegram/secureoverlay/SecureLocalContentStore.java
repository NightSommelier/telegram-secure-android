package org.telegram.secureoverlay;

import android.content.Context;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/** Keystore-encrypted local cache for authenticated typed payload bytes. */
final class SecureLocalContentStore {
    static final String OUTGOING_PREFIX = "outgoing-content.v1.";
    static final String INCOMING_PREFIX = "incoming-content.v1.";

    private final int account;
    private final long peerUserId;
    private final KeystoreEncryptedBlobStore blobs;

    SecureLocalContentStore(Context context, int account, long peerUserId) {
        this.account = account;
        this.peerUserId = peerUserId;
        blobs = new KeystoreEncryptedBlobStore(context.getApplicationContext());
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

    private void remember(String prefix, String carrier, byte[] content)
            throws KeystoreEncryptedBlobStore.StateStoreException {
        requireEncryptedCarrier(carrier);
        if (content == null || content.length == 0) {
            throw new IllegalArgumentException("local secure content is empty");
        }
        // Parse before persistence so malformed typed content can never become trusted cache.
        SecureContentCodec.decode(content);
        blobs.put(key(prefix, account, peerUserId, carrier), content);
    }

    private byte[] load(String prefix, String carrier)
            throws KeystoreEncryptedBlobStore.StateStoreException {
        if (!isEncryptedCarrier(carrier)) {
            return null;
        }
        byte[] content = blobs.get(key(prefix, account, peerUserId, carrier));
        if (content != null) {
            SecureContentCodec.decode(content);
        }
        return content;
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
        return prefix + account + '.' + peerUserId + '.' + sha256Hex(carrier);
    }

    private static String sha256Hex(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder result = new StringBuilder(digest.length * 2);
            for (byte item : digest) {
                result.append(Character.forDigit((item >>> 4) & 0x0f, 16));
                result.append(Character.forDigit(item & 0x0f, 16));
            }
            return result.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
    }
}
