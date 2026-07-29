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
 * AES-GCM-protected blob. Outbound copies avoid trying to decrypt our own ratchet message; inbound
 * copies avoid consuming the same ratchet message again when Telegram reloads chat history.</p>
 */
final class SecureLocalTextStore {
    private static final String OUTGOING_PREFIX = "outgoing-text.v1.";
    private static final String INCOMING_PREFIX = "incoming-text.v1.";
    private static final int DISPLAY_CACHE_LIMIT = 512;
    private static final LinkedHashMap<String, String> displayCache =
            new LinkedHashMap<String, String>(DISPLAY_CACHE_LIMIT, 0.75f, true) {
                @Override
                protected boolean removeEldestEntry(Map.Entry<String, String> eldest) {
                    return size() > DISPLAY_CACHE_LIMIT;
                }
            };

    private final int account;
    private final long peerUserId;
    private final KeystoreEncryptedBlobStore blobs;

    SecureLocalTextStore(Context context, int account, long peerUserId) {
        if (account < 0 || peerUserId <= 0) {
            throw new IllegalArgumentException("outgoing secure text requires an account and user peer");
        }
        this.account = account;
        this.peerUserId = peerUserId;
        blobs = new KeystoreEncryptedBlobStore(context.getApplicationContext());
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

    private void remember(String prefix, String carrier, String plaintext)
            throws KeystoreEncryptedBlobStore.StateStoreException {
        SecureCarrierCodec.Decoded decoded = SecureCarrierCodec.decode(carrier);
        if (decoded == null || decoded.type == SecureCarrierCodec.TYPE_PREKEY_BUNDLE) {
            throw new IllegalArgumentException("local text requires an encrypted message carrier");
        }
        if (plaintext == null || plaintext.isEmpty()) {
            throw new IllegalArgumentException("local secure plaintext is empty");
        }
        String storageKey = key(prefix, carrier);
        blobs.put(storageKey, plaintext.getBytes(StandardCharsets.UTF_8));
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
        String storageKey = key(prefix, carrier);
        synchronized (displayCache) {
            String cached = displayCache.get(storageKey);
            if (cached != null) {
                return cached;
            }
        }
        byte[] plaintext = blobs.get(storageKey);
        if (plaintext == null) {
            return null;
        }
        CharBuffer chars = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(plaintext));
        String displayText = chars.toString();
        synchronized (displayCache) {
            displayCache.put(storageKey, displayText);
        }
        return displayText;
    }

    private String key(String prefix, String carrier) {
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
