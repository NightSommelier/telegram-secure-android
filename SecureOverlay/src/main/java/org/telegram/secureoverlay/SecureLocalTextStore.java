package org.telegram.secureoverlay;

import android.content.Context;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Device-local encrypted display copy of secure message text.
 *
 * <p>Telegram receives only the TGS1 carrier. The carrier hash and direction select an
 * AES-GCM-protected blob. Record names are HMAC-masked to protect peer IDs and carrier digests
 * from local storage leakage.</p>
 */
final class SecureLocalTextStore {
    static final String OUTGOING_PREFIX = "outgoing-text.v1.";
    static final String INCOMING_PREFIX = "incoming-text.v1.";
    private static final int DISPLAY_CACHE_LIMIT = 512;
    private static final LinkedHashMap<String, String> displayCache =
            new LinkedHashMap<String, String>(DISPLAY_CACHE_LIMIT, 0.75f, true) {
                @Override
                protected boolean removeEldestEntry(Map.Entry<String, String> eldest) {
                    return size() > DISPLAY_CACHE_LIMIT;
                }
            };

    static final byte MAGIC_1 = (byte) 0x7E;
    static final byte MAGIC_2 = (byte) 0x54; // ~T
    static final byte FORMAT_VERSION = 1;
    static final int HEADER_LENGTH = 2 + 1 + 8 + 32; // 43 bytes

    public static final class RecordHeader {
        public final long peerUserId;
        public final byte[] carrierDigest;
        public final byte[] payload;

        RecordHeader(long peerUserId, byte[] carrierDigest, byte[] payload) {
            this.peerUserId = peerUserId;
            this.carrierDigest = carrierDigest;
            this.payload = payload;
        }
    }

    private final int account;
    private final long peerUserId;
    private final KeystoreEncryptedBlobStore blobs;
    private final byte[] nameMaskKey;

    SecureLocalTextStore(Context context, int account, long peerUserId) {
        if (account < 0 || peerUserId == 0) {
            throw new IllegalArgumentException("outgoing secure text requires an account and peer");
        }
        this.account = account;
        this.peerUserId = peerUserId;
        blobs = new KeystoreEncryptedBlobStore(context.getApplicationContext());
        nameMaskKey = SecureNameMask.getOrGenerateKey(blobs);
    }

    void rememberOutgoing(String carrier, String plaintext)
            throws KeystoreEncryptedBlobStore.StateStoreException {
        remember(OUTGOING_PREFIX, carrier, plaintext);
    }

    void rememberIncoming(String carrier, String plaintext)
            throws KeystoreEncryptedBlobStore.StateStoreException {
        remember(INCOMING_PREFIX, carrier, plaintext);
    }

    String loadOutgoing(String carrier)
            throws KeystoreEncryptedBlobStore.StateStoreException, CharacterCodingException {
        return load(OUTGOING_PREFIX, carrier);
    }

    String loadIncoming(String carrier)
            throws KeystoreEncryptedBlobStore.StateStoreException, CharacterCodingException {
        return load(INCOMING_PREFIX, carrier);
    }

    void forgetOutgoing(String carrier)
            throws KeystoreEncryptedBlobStore.StateStoreException {
        String storageKey = key(OUTGOING_PREFIX, account, peerUserId, carrier);
        String legacy = legacyKey(OUTGOING_PREFIX, account, peerUserId, carrier);
        blobs.deleteAll(storageKey, legacy);
        evictDisplayCopies(storageKey, legacy);
    }

    private void remember(String prefix, String carrier, String plaintext)
            throws KeystoreEncryptedBlobStore.StateStoreException {
        SecureCarrierCodec.Decoded decoded = SecureCarrierCodec.decode(carrier);
        if (decoded == null || decoded.type == SecureCarrierCodec.TYPE_PREKEY_BUNDLE) {
            throw new IllegalArgumentException("local text requires an encrypted message carrier");
        }
        if (plaintext == null || plaintext.isEmpty()) {
            throw new IllegalArgumentException("local secure plaintext is empty");
        }
        String storageKey = key(prefix, account, peerUserId, carrier);
        byte[] payload = plaintext.getBytes(StandardCharsets.UTF_8);
        byte[] digest = sha256Bytes(carrier);
        byte[] encoded = encodeRecord(peerUserId, digest, payload);
        blobs.put(storageKey, encoded);
        synchronized (displayCache) {
            displayCache.put(storageKey, plaintext);
        }
    }

    private String load(String prefix, String carrier)
            throws KeystoreEncryptedBlobStore.StateStoreException, CharacterCodingException {
        SecureCarrierCodec.Decoded decoded = SecureCarrierCodec.decode(carrier);
        if (decoded == null || decoded.type == SecureCarrierCodec.TYPE_PREKEY_BUNDLE) {
            return null;
        }
        String storageKey = key(prefix, account, peerUserId, carrier);
        synchronized (displayCache) {
            String cached = displayCache.get(storageKey);
            if (cached != null) {
                return cached;
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
                return null;
            }
        } else {
            data = extractPayload(data);
        }

        CharBuffer chars = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(data));
        String displayText = chars.toString();
        synchronized (displayCache) {
            displayCache.put(storageKey, displayText);
        }
        return displayText;
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

    static RecordHeader decodeHeader(byte[] record) {
        if (!isEncodedRecord(record)) {
            throw new IllegalArgumentException("not an encoded secure text record");
        }
        long peerUserId = ByteBuffer.wrap(record, 3, 8).getLong();
        byte[] digest = new byte[32];
        System.arraycopy(record, 11, digest, 0, 32);
        byte[] payload = new byte[record.length - HEADER_LENGTH];
        System.arraycopy(record, HEADER_LENGTH, payload, 0, payload.length);
        return new RecordHeader(peerUserId, digest, payload);
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

    static void evictDisplayCopies(String... storageKeys) {
        synchronized (displayCache) {
            for (String storageKey : storageKeys) {
                displayCache.remove(storageKey);
            }
        }
    }

    static void evictDisplayPrefixes(String... prefixes) {
        synchronized (displayCache) {
            displayCache.keySet().removeIf(key -> {
                for (String prefix : prefixes) {
                    if (key.startsWith(prefix)) {
                        return true;
                    }
                }
                return false;
            });
        }
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
