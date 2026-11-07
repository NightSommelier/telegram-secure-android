package org.telegram.secureoverlay;

import android.content.Context;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Derives HMAC-based pseudorandom record names to protect metadata (peer IDs and carrier digests)
 * in local persistent storage.
 */
public final class SecureNameMask {
    private static final String HMAC_ALGO = "HmacSHA256";
    private static final String STORAGE_KEY = "internal/name_mask_key";
    private static final int KEY_LEN = 32;

    private static volatile byte[] cachedKey;
    private static final Object lock = new Object();

    private SecureNameMask() {
    }

    private static boolean shouldCacheKey(KeystoreSignalProtocolStore.EncryptedStateStorage storage) {
        return storage instanceof KeystoreEncryptedBlobStore
                && ((KeystoreEncryptedBlobStore) storage).isPersistent();
    }

    public static byte[] getOrGenerateKey(KeystoreSignalProtocolStore.EncryptedStateStorage storage) {
        if (storage == null) {
            throw new IllegalArgumentException("storage is required for name mask key");
        }
        boolean cacheable = shouldCacheKey(storage);
        if (cacheable) {
            byte[] k = cachedKey;
            if (k != null) {
                return k;
            }
        }
        synchronized (lock) {
            if (cacheable && cachedKey != null) {
                return cachedKey;
            }
            try {
                byte[] existing = storage.get(STORAGE_KEY);
                if (existing != null && existing.length == KEY_LEN) {
                    if (cacheable) {
                        cachedKey = existing.clone();
                    }
                    return existing.clone();
                }
                byte[] generated = new byte[KEY_LEN];
                new SecureRandom().nextBytes(generated);
                storage.put(STORAGE_KEY, generated);
                if (cacheable) {
                    cachedKey = generated.clone();
                }
                return generated.clone();
            } catch (Exception e) {
                throw new IllegalStateException("failed to get or generate name mask key", e);
            }
        }
    }

    public static byte[] getOrGenerateKey(Context context) {
        if (context == null) {
            throw new IllegalArgumentException("context is required for name mask key");
        }
        byte[] k = cachedKey;
        if (k != null) {
            return k;
        }
        Context app = context.getApplicationContext();
        return getOrGenerateKey(new KeystoreEncryptedBlobStore(app != null ? app : context));
    }

    static byte[] peekCachedKey() {
        return cachedKey;
    }

    static void clearCachedKey() {
        synchronized (lock) {
            cachedKey = null;
        }
    }

    static void setCachedKeyForTesting(byte[] key) {
        synchronized (lock) {
            cachedKey = key;
        }
    }

    public static String mask(byte[] key, String input) {
        if (key == null || key.length == 0) {
            throw new IllegalArgumentException("invalid name mask key");
        }
        try {
            Mac mac = Mac.getInstance(HMAC_ALGO);
            mac.init(new SecretKeySpec(key, HMAC_ALGO));
            byte[] hmac = mac.doFinal(input.getBytes(StandardCharsets.UTF_8));
            return hex(hmac);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("failed to compute name mask", e);
        }
    }

    public static String maskPeer(byte[] key, int account, long peerUserId) {
        return mask(key, "peer:" + account + ":" + peerUserId);
    }

    public static String maskCarrier(byte[] key, int account, long peerUserId, String carrierDigestHex) {
        return mask(key, "carrier:" + account + ":" + peerUserId + ":" + carrierDigestHex);
    }

    private static String hex(byte[] value) {
        StringBuilder result = new StringBuilder(value.length * 2);
        for (byte item : value) {
            result.append(Character.forDigit((item >>> 4) & 0x0f, 16));
            result.append(Character.forDigit(item & 0x0f, 16));
        }
        return result.toString();
    }
}
