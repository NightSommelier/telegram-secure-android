package org.telegram.secureoverlay;

import android.content.Context;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

/** Keystore-encrypted local cache for authenticated typed payload bytes. */
final class SecureLocalContentStore {
    static final String OUTGOING_PREFIX = "outgoing-content.v1.";
    static final String INCOMING_PREFIX = "incoming-content.v1.";
    private static final int CONTENT_CACHE_LIMIT = 1024;
    private static final byte[] NEGATIVE_SENTINEL = new byte[0];
    private static final LinkedHashMap<String, byte[]> contentCache =
            new LinkedHashMap<String, byte[]>(CONTENT_CACHE_LIMIT, 0.75f, true) {
                @Override
                protected boolean removeEldestEntry(Map.Entry<String, byte[]> eldest) {
                    return size() > CONTENT_CACHE_LIMIT;
                }
            };

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

    byte[] peekOutgoing(String carrier) {
        return peek(OUTGOING_PREFIX, carrier);
    }

    byte[] peekIncoming(String carrier) {
        return peek(INCOMING_PREFIX, carrier);
    }

    boolean hasCachedOutgoing(String carrier) {
        return hasPositiveCached(OUTGOING_PREFIX, carrier);
    }

    boolean hasCachedIncoming(String carrier) {
        return hasPositiveCached(INCOMING_PREFIX, carrier);
    }

    private byte[] peek(String prefix, String carrier) {
        if (!isEncryptedCarrier(carrier)) {
            return null;
        }
        String storageKey = key(nameMaskKey, prefix, account, peerUserId, carrier);
        synchronized (contentCache) {
            byte[] cached = contentCache.get(storageKey);
            if (cached == null || cached == NEGATIVE_SENTINEL) {
                return null;
            }
            return Arrays.copyOf(cached, cached.length);
        }
    }

    private boolean hasPositiveCached(String prefix, String carrier) {
        if (!isEncryptedCarrier(carrier)) {
            return false;
        }
        String storageKey = key(nameMaskKey, prefix, account, peerUserId, carrier);
        synchronized (contentCache) {
            byte[] cached = contentCache.get(storageKey);
            return cached != null && cached != NEGATIVE_SENTINEL;
        }
    }

    void forgetOutgoing(String carrier)
            throws KeystoreEncryptedBlobStore.StateStoreException {
        String storageKey = key(nameMaskKey, OUTGOING_PREFIX, account, peerUserId, carrier);
        String legacy = legacyKey(OUTGOING_PREFIX, account, peerUserId, carrier);
        blobs.deleteAll(storageKey, legacy);
        synchronized (contentCache) {
            contentCache.remove(storageKey);
            contentCache.remove(legacy);
        }
    }

    static void evictContentPrefixes(String... prefixes) {
        if (prefixes == null || prefixes.length == 0) {
            return;
        }
        synchronized (contentCache) {
            contentCache.keySet().removeIf(k -> {
                for (String prefix : prefixes) {
                    if (prefix != null && k.startsWith(prefix)) {
                        return true;
                    }
                }
                return false;
            });
        }
    }

    static void clearMemoryCache() {
        synchronized (contentCache) {
            contentCache.clear();
        }
    }

    private void remember(String prefix, String carrier, byte[] content)
            throws KeystoreEncryptedBlobStore.StateStoreException {
        requireEncryptedCarrier(carrier);
        if (content == null || content.length == 0) {
            throw new IllegalArgumentException("local secure content is empty");
        }
        // Parse before persistence so malformed typed content can never become trusted cache.
        SecureContentCodec.decode(content);
        String storageKey = key(nameMaskKey, prefix, account, peerUserId, carrier);
        byte[] digest = sha256Bytes(carrier);
        byte[] encoded = encodeRecord(peerUserId, digest, content);
        blobs.put(storageKey, encoded);
        synchronized (contentCache) {
            contentCache.put(storageKey, Arrays.copyOf(content, content.length));
        }
    }

    private byte[] load(String prefix, String carrier)
            throws KeystoreEncryptedBlobStore.StateStoreException {
        if (!isEncryptedCarrier(carrier)) {
            return null;
        }
        String storageKey = key(nameMaskKey, prefix, account, peerUserId, carrier);
        synchronized (contentCache) {
            byte[] cached = contentCache.get(storageKey);
            if (cached != null) {
                return cached == NEGATIVE_SENTINEL ? null : Arrays.copyOf(cached, cached.length);
            }
        }
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
                synchronized (contentCache) {
                    contentCache.put(storageKey, NEGATIVE_SENTINEL);
                }
                return null;
            }
        } else {
            data = extractPayload(data);
        }
        if (data != null) {
            SecureContentCodec.decode(data);
            synchronized (contentCache) {
                contentCache.put(storageKey, Arrays.copyOf(data, data.length));
            }
            return Arrays.copyOf(data, data.length);
        }
        return null;
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

    static String key(byte[] maskKey, String prefix, int account, long peerUserId, String carrier) {
        return keyByDigest(maskKey, prefix, account, peerUserId, sha256Hex(carrier));
    }

    static String keyByDigest(
            byte[] maskKey, String prefix, int account, long peerUserId, String digestHex) {
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
