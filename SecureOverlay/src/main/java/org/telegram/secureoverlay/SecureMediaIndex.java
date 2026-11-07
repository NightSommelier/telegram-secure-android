package org.telegram.secureoverlay;

import android.content.Context;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Keystore-encrypted local classification index for authenticated Fork-Secure media.
 *
 * <p>The Telegram message remains the source of truth and contains only its opaque encrypted
 * transport. Entries are bound to the exact carrier digest so reusing a message id cannot attach
 * stale plaintext metadata to another carrier. Missing plaintext cache files intentionally do not
 * remove entries: the encrypted Telegram attachment can be downloaded and decrypted again.</p>
 */
public final class SecureMediaIndex {
    public static final int KIND_PHOTO = 1;
    public static final int KIND_VIDEO = 2;
    public static final int KIND_ROUND_VIDEO = 3;
    public static final int KIND_VOICE = 4;
    public static final int KIND_MUSIC = 5;
    public static final int KIND_FILE = 6;
    public static final int KIND_GIF = 7;

    private static final String PREFIX = "media-index.v1.";
    private static final int FORMAT_VERSION = 1;
    private static final int DIGEST_BYTES = 32;
    private static final int MAX_PATH_BYTES = 4096;
    private static final int MAX_NAME_BYTES = 1024;
    private static final int MAX_MIME_BYTES = 255;
    private static final int MAX_CAPTION_BYTES = 16 * 1024;

    private static final int MEMORY_CACHE_LIMIT = 512;
    private static final LinkedHashMap<String, SecureMediaIndex.Entry> memoryCache =
            new LinkedHashMap<String, SecureMediaIndex.Entry>(MEMORY_CACHE_LIMIT, 0.75f, true) {
                @Override
                protected boolean removeEldestEntry(Map.Entry<String, SecureMediaIndex.Entry> eldest) {
                    return size() > MEMORY_CACHE_LIMIT;
                }
            };
    private static final Entry NEGATIVE_ENTRY = new Entry(
            -1, 0, new byte[DIGEST_BYTES], KIND_FILE, "", "", "", "", 0, 0);

    private final int account;
    private final long peerUserId;
    private final String scopedPrefix;
    private final String legacyPrefix;
    private final KeystoreEncryptedBlobStore blobs;
    private final byte[] nameMaskKey;

    public SecureMediaIndex(Context context, int account, long peerUserId) {
        if (context == null || account < 0 || peerUserId == 0) {
            throw new IllegalArgumentException(
                    "secure media index requires an account and user peer");
        }
        this.account = account;
        this.peerUserId = peerUserId;
        blobs = new KeystoreEncryptedBlobStore(context.getApplicationContext());
        nameMaskKey = SecureNameMask.getOrGenerateKey(blobs);
        String peerMask = SecureNameMask.maskPeer(nameMaskKey, account, peerUserId);
        scopedPrefix = PREFIX + account + '.' + peerMask + '.';
        legacyPrefix = PREFIX + account + '.' + peerUserId + '.';
    }

    public static final class CachedLookup {
        public static final CachedLookup MISS = new CachedLookup(0, null);
        public static final CachedLookup NEGATIVE = new CachedLookup(1, null);

        private final int state;
        public final Entry entry;

        private CachedLookup(int state, Entry entry) {
            this.state = state;
            this.entry = entry;
        }

        public boolean isMiss() {
            return state == 0;
        }

        public boolean isNegative() {
            return state == 1;
        }

        public boolean isHit() {
            return state == 2 && entry != null;
        }

        static CachedLookup hit(Entry entry) {
            return new CachedLookup(2, entry);
        }
    }

    /**
     * Pure in-memory lookup safe for UI/scroll threads: performs zero SQLite queries and zero
     * Android Keystore IPC calls. Works for 1:1 chats, basic groups, and supergroups.
     */
    public static CachedLookup lookupCached(int account, long peerUserId, String carrier) {
        if (account < 0 || peerUserId == 0 || carrier == null || carrier.isEmpty()) {
            return CachedLookup.NEGATIVE;
        }
        byte[] maskKey = SecureNameMask.peekCachedKey();
        if (maskKey == null) {
            return CachedLookup.MISS;
        }
        byte[] carrierDigest = digest(carrier);
        String peerMask = SecureNameMask.maskPeer(maskKey, account, peerUserId);
        String carrierMask = SecureNameMask.maskCarrier(maskKey, account, peerUserId, hex(carrierDigest));
        String key = PREFIX + account + '.' + peerMask + '.' + carrierMask;
        synchronized (memoryCache) {
            Entry cached = memoryCache.get(key);
            if (cached == null) {
                return CachedLookup.MISS;
            }
            if (cached == NEGATIVE_ENTRY) {
                return CachedLookup.NEGATIVE;
            }
            return CachedLookup.hit(cached);
        }
    }

    public static void clearMemoryCache() {
        synchronized (memoryCache) {
            memoryCache.clear();
        }
    }

    public void put(Entry entry) {
        if (entry == null) {
            throw new IllegalArgumentException("secure media index entry is required");
        }
        String key = key(entry.carrierDigest);
        try {
            blobs.put(key, encode(entry));
            synchronized (memoryCache) {
                memoryCache.put(key, entry);
            }
        } catch (KeystoreEncryptedBlobStore.StateStoreException e) {
            throw new SecureMediaIndexException("cannot persist secure media index", e);
        }
    }

    public Entry find(int messageId, String carrier) {
        if (carrier == null || carrier.isEmpty()) {
            return null;
        }
        return findByDigest(messageId, digest(carrier));
    }

    public Entry findByDigest(int messageId, byte[] digest) {
        if (digest == null || digest.length != DIGEST_BYTES) {
            return null;
        }
        String key = key(digest);
        synchronized (memoryCache) {
            Entry cached = memoryCache.get(key);
            if (cached != null) {
                if (cached == NEGATIVE_ENTRY) {
                    return null;
                }
                if (messageId > 0 && cached.messageId != messageId) {
                    Entry updated = new Entry(
                            messageId,
                            cached.date,
                            cached.carrierDigest,
                            cached.kind,
                            cached.plaintextPath,
                            cached.fileName,
                            cached.mimeType,
                            cached.caption,
                            cached.width,
                            cached.height);
                    memoryCache.put(key, updated);
                    try {
                        blobs.put(key, encode(updated));
                    } catch (Exception ignore) {
                    }
                    return updated;
                }
                return cached;
            }
        }
        try {
            byte[] encoded = blobs.get(key);
            if (encoded == null) {
                String legacy = legacyKey(digest);
                encoded = blobs.get(legacy);
                if (encoded != null) {
                    blobs.put(key, encoded);
                    blobs.delete(legacy);
                }
            }
            if (encoded == null) {
                synchronized (memoryCache) {
                    memoryCache.put(key, NEGATIVE_ENTRY);
                }
                return null;
            }
            Entry entry = decode(encoded);
            if (!MessageDigest.isEqual(digest, entry.carrierDigest)) {
                synchronized (memoryCache) {
                    memoryCache.put(key, NEGATIVE_ENTRY);
                }
                return null;
            }
            entry = sanitizeEntry(key, entry);
            if (entry == null) {
                return null;
            }
            if (messageId > 0 && entry.messageId != messageId) {
                entry = new Entry(
                        messageId,
                        entry.date,
                        entry.carrierDigest,
                        entry.kind,
                        entry.plaintextPath,
                        entry.fileName,
                        entry.mimeType,
                        entry.caption,
                        entry.width,
                        entry.height);
                try {
                    blobs.put(key, encode(entry));
                } catch (Exception ignore) {
                }
            }
            synchronized (memoryCache) {
                memoryCache.put(key, entry);
            }
            return entry;
        } catch (KeystoreEncryptedBlobStore.StateStoreException e) {
            throw new SecureMediaIndexException("cannot load secure media index", e);
        }
    }

    public List<Entry> list(int kind) {
        requireKind(kind);
        try {
            Map<String, byte[]> records = blobs.snapshotPrefixes(scopedPrefix);
            Map<String, byte[]> legacyRecords = blobs.snapshotPrefixes(legacyPrefix);
            if (!legacyRecords.isEmpty()) {
                for (Map.Entry<String, byte[]> leg : legacyRecords.entrySet()) {
                    try {
                        Entry e = decode(leg.getValue());
                        blobs.put(key(e.carrierDigest), leg.getValue());
                        blobs.delete(leg.getKey());
                        records.put(key(e.carrierDigest), leg.getValue());
                    } catch (Exception ignore) {
                    }
                }
            }
            ArrayList<Entry> result = new ArrayList<>();
            for (Map.Entry<String, byte[]> item : records.entrySet()) {
                Entry entry = sanitizeEntry(item.getKey(), decode(item.getValue()));
                if (entry == null) {
                    continue;
                }
                synchronized (memoryCache) {
                    memoryCache.put(item.getKey(), entry);
                }
                if (entry.kind == kind) {
                    result.add(entry);
                }
            }
            result.sort(Comparator
                    .comparingInt((Entry entry) -> entry.date).reversed()
                    .thenComparing(
                            Comparator.comparingInt(
                                    (Entry entry) -> entry.messageId).reversed()));
            return result;
        } catch (KeystoreEncryptedBlobStore.StateStoreException e) {
            throw new SecureMediaIndexException("cannot list secure media index", e);
        }
    }

    public List<Entry> listAll() {
        try {
            Map<String, byte[]> records = blobs.snapshotPrefixes(scopedPrefix);
            Map<String, byte[]> legacyRecords = blobs.snapshotPrefixes(legacyPrefix);
            if (!legacyRecords.isEmpty()) {
                for (Map.Entry<String, byte[]> leg : legacyRecords.entrySet()) {
                    try {
                        Entry e = decode(leg.getValue());
                        blobs.put(key(e.carrierDigest), leg.getValue());
                        blobs.delete(leg.getKey());
                        records.put(key(e.carrierDigest), leg.getValue());
                    } catch (Exception ignore) {
                    }
                }
            }
            ArrayList<Entry> result = new ArrayList<>();
            for (Map.Entry<String, byte[]> item : records.entrySet()) {
                Entry entry = sanitizeEntry(item.getKey(), decode(item.getValue()));
                if (entry == null) {
                    continue;
                }
                synchronized (memoryCache) {
                    memoryCache.put(item.getKey(), entry);
                }
                result.add(entry);
            }
            return result;
        } catch (KeystoreEncryptedBlobStore.StateStoreException e) {
            throw new SecureMediaIndexException("cannot list secure media index", e);
        }
    }

    public int count(int kind) {
        return list(kind).size();
    }

    public int[] countByKind() {
        int[] counts = new int[KIND_GIF + 1];
        try {
            Map<String, byte[]> records = blobs.snapshotPrefixes(scopedPrefix);
            Map<String, byte[]> legacyRecords = blobs.snapshotPrefixes(legacyPrefix);
            if (!legacyRecords.isEmpty()) {
                for (Map.Entry<String, byte[]> leg : legacyRecords.entrySet()) {
                    try {
                        Entry e = decode(leg.getValue());
                        blobs.put(key(e.carrierDigest), leg.getValue());
                        blobs.delete(leg.getKey());
                        records.put(key(e.carrierDigest), leg.getValue());
                    } catch (Exception ignore) {
                    }
                }
            }
            for (Map.Entry<String, byte[]> item : records.entrySet()) {
                Entry entry = sanitizeEntry(item.getKey(), decode(item.getValue()));
                if (entry == null) {
                    continue;
                }
                synchronized (memoryCache) {
                    memoryCache.put(item.getKey(), entry);
                }
                if (entry.kind >= KIND_PHOTO && entry.kind <= KIND_GIF) {
                    counts[entry.kind]++;
                }
            }
        } catch (KeystoreEncryptedBlobStore.StateStoreException e) {
            throw new SecureMediaIndexException("cannot count secure media index", e);
        }
        return counts;
    }

    public boolean removeIndexOnly(byte[] digest) {
        if (digest == null || digest.length != DIGEST_BYTES) {
            return false;
        }
        String key = key(digest);
        String legacyKey = legacyKey(digest);
        synchronized (memoryCache) {
            memoryCache.put(key, NEGATIVE_ENTRY);
            memoryCache.remove(legacyKey);
        }
        try {
            blobs.deleteAll(key, legacyKey);
            return true;
        } catch (KeystoreEncryptedBlobStore.StateStoreException e) {
            return false;
        }
    }

    private Entry sanitizeEntry(String storageKey, Entry entry) {
        if (entry == null) {
            return null;
        }
        String path = entry.plaintextPath != null ? entry.plaintextPath : "";
        String name = entry.fileName != null
                ? entry.fileName.toLowerCase(java.util.Locale.ROOT)
                : "";
        String mime = entry.mimeType != null
                ? entry.mimeType.toLowerCase(java.util.Locale.ROOT)
                : "";
        // Stickers, control/event artifacts, and orphaned test entries must never appear in
        // shared media / profile files. Remove only the index record so cached sticker files
        // in fork-secure-media-in remain usable in chat bubbles.
        if (path.contains("fork-secure-media-in")
                || path.contains("fork-secure-stickers")
                || mime.contains("tgsticker")
                || name.endsWith(".tgse")
                || name.endsWith(".tgs")
                || name.equals("file.bin")
                || name.matches("^[$#]?[0-9a-f]{32}\\.bin$")
                || (entry.messageId <= 0 && name.startsWith("fork-secure-photo-"))) {
            try {
                blobs.delete(storageKey);
            } catch (Exception ignore) {
            }
            synchronized (memoryCache) {
                memoryCache.put(storageKey, NEGATIVE_ENTRY);
            }
            return null;
        }
        if (entry.kind == KIND_FILE) {
            int resolvedKind = entry.kind;
            try {
                String digestHex = hex(entry.carrierDigest);
                byte[] contentRecord = blobs.get(
                        SecureLocalContentStore.keyByDigest(
                                nameMaskKey,
                                SecureLocalContentStore.OUTGOING_PREFIX,
                                account,
                                peerUserId,
                                digestHex));
                if (contentRecord == null) {
                    contentRecord = blobs.get(
                            SecureLocalContentStore.keyByDigest(
                                    nameMaskKey,
                                    SecureLocalContentStore.INCOMING_PREFIX,
                                    account,
                                    peerUserId,
                                    digestHex));
                }
                if (contentRecord != null) {
                    byte[] payload = SecureLocalContentStore.extractPayload(contentRecord);
                    SecureContentCodec.Decoded decoded = SecureContentCodec.decode(payload);
                    if (decoded.type == SecureContentCodec.TYPE_PHOTO
                            || (decoded.type == SecureContentCodec.TYPE_FILE
                                    && decoded.attachment != null
                                    && decoded.attachment.photo)) {
                        resolvedKind = KIND_PHOTO;
                    } else if (decoded.type != SecureContentCodec.TYPE_FILE) {
                        blobs.delete(storageKey);
                        synchronized (memoryCache) {
                            memoryCache.put(storageKey, NEGATIVE_ENTRY);
                        }
                        return null;
                    }
                }
            } catch (Exception ignore) {
            }
            if (resolvedKind == KIND_FILE
                    && mime.startsWith("image/")
                    && !mime.equals("image/gif")
                    && !mime.equals("image/webp")
                    && (name.matches("^-?\\d{10,}(_\\d+)?\\.(jpe?g|png|heic|heif)$")
                            || name.startsWith("fork-secure-")
                            || name.startsWith("fscreenshot_")
                            || name.startsWith("screenshot_")
                            || name.matches("^img[_0-9-]+\\.(jpe?g|heic|heif)$")
                            || path.contains("fork-secure-attachments-out"))) {
                resolvedKind = KIND_PHOTO;
            }
            if (resolvedKind != entry.kind) {
                entry = new Entry(
                        entry.messageId,
                        entry.date,
                        entry.carrierDigest,
                        resolvedKind,
                        entry.plaintextPath,
                        entry.fileName,
                        entry.mimeType,
                        entry.caption,
                        entry.width,
                        entry.height);
                try {
                    blobs.put(storageKey, encode(entry));
                } catch (Exception ignore) {
                }
            }
        }
        return entry;
    }

    public boolean forget(String carrier) {
        return forgetByDigest(digest(carrier));
    }

    public boolean forgetByDigest(byte[] digest) {
        if (digest == null || digest.length != DIGEST_BYTES) {
            return false;
        }
        String key = key(digest);
        String legacyKey = legacyKey(digest);
        synchronized (memoryCache) {
            memoryCache.remove(key);
            memoryCache.remove(legacyKey);
        }
        try {
            byte[] encoded = blobs.get(key);
            if (encoded == null) {
                encoded = blobs.get(legacyKey);
            }
            if (encoded == null) {
                return false;
            }
            try {
                Entry entry = decode(encoded);
                if (entry != null && entry.plaintextPath != null && !entry.plaintextPath.isEmpty()) {
                    new java.io.File(entry.plaintextPath).delete();
                }
            } catch (Exception ignore) {
            }
            blobs.deleteAll(key, legacyKey);
            return true;
        } catch (KeystoreEncryptedBlobStore.StateStoreException e) {
            throw new SecureMediaIndexException("cannot remove secure media index", e);
        }
    }

    public void forgetPeer() {
        synchronized (memoryCache) {
            memoryCache.keySet().removeIf(k -> k.startsWith(scopedPrefix) || k.startsWith(legacyPrefix));
        }
        try {
            Map<String, byte[]> records = blobs.snapshotPrefixes(scopedPrefix);
            records.putAll(blobs.snapshotPrefixes(legacyPrefix));
            for (byte[] encoded : records.values()) {
                try {
                    Entry entry = decode(encoded);
                    if (entry != null && entry.plaintextPath != null && !entry.plaintextPath.isEmpty()) {
                        new java.io.File(entry.plaintextPath).delete();
                    }
                } catch (Exception ignore) {
                }
            }
            blobs.deletePrefixes(scopedPrefix, legacyPrefix);
        } catch (KeystoreEncryptedBlobStore.StateStoreException e) {
            throw new SecureMediaIndexException("cannot clear secure media index", e);
        }
    }

    public static List<Entry> listAllForAccount(Context context, int account) {
        if (context == null || account < 0) {
            return Collections.emptyList();
        }
        String prefix = PREFIX + account + '.';
        try {
            KeystoreEncryptedBlobStore store = new KeystoreEncryptedBlobStore(context.getApplicationContext());
            Map<String, byte[]> records = store.snapshotPrefixes(prefix);
            ArrayList<Entry> result = new ArrayList<>();
            for (byte[] encoded : records.values()) {
                try {
                    Entry entry = decode(encoded);
                    if (entry != null) {
                        result.add(entry);
                    }
                } catch (Exception ignore) {
                }
            }
            return result;
        } catch (Throwable e) {
            return Collections.emptyList();
        }
    }

    private String key(byte[] digest) {
        String carrierMask = SecureNameMask.maskCarrier(nameMaskKey, account, peerUserId, hex(digest));
        return scopedPrefix + carrierMask;
    }

    private String legacyKey(byte[] digest) {
        return legacyPrefix + hex(digest);
    }

    private static byte[] encode(Entry entry) {
        validate(entry);
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            DataOutputStream output = new DataOutputStream(bytes);
            output.writeByte(FORMAT_VERSION);
            output.writeInt(entry.messageId);
            output.writeInt(entry.date);
            output.writeByte(entry.kind);
            output.write(entry.carrierDigest);
            writeString(output, entry.plaintextPath, MAX_PATH_BYTES);
            writeString(output, entry.fileName, MAX_NAME_BYTES);
            writeString(output, entry.mimeType, MAX_MIME_BYTES);
            writeString(output, entry.caption, MAX_CAPTION_BYTES);
            output.writeInt(entry.width);
            output.writeInt(entry.height);
            output.flush();
            return bytes.toByteArray();
        } catch (IOException impossible) {
            throw new AssertionError(impossible);
        }
    }

    private static Entry decode(byte[] encoded) {
        if (encoded == null) {
            throw new SecureMediaIndexException("secure media index record is missing", null);
        }
        try {
            DataInputStream input = new DataInputStream(new ByteArrayInputStream(encoded));
            if (input.readUnsignedByte() != FORMAT_VERSION) {
                throw new IOException("unsupported secure media index version");
            }
            int messageId = input.readInt();
            int date = input.readInt();
            int kind = input.readUnsignedByte();
            byte[] carrierDigest = new byte[DIGEST_BYTES];
            input.readFully(carrierDigest);
            String path = readString(input, MAX_PATH_BYTES);
            String name = readString(input, MAX_NAME_BYTES);
            String mime = readString(input, MAX_MIME_BYTES);
            String caption = readString(input, MAX_CAPTION_BYTES);
            int width = input.readInt();
            int height = input.readInt();
            if (input.available() != 0) {
                throw new IOException("trailing secure media index data");
            }
            Entry result = new Entry(
                    messageId, date, carrierDigest, kind,
                    path, name, mime, caption, width, height);
            validate(result);
            return result;
        } catch (EOFException e) {
            throw new SecureMediaIndexException("truncated secure media index record", e);
        } catch (IOException | IllegalArgumentException e) {
            throw new SecureMediaIndexException("invalid secure media index record", e);
        }
    }

    private static void validate(Entry entry) {
        if (entry.messageId == 0 || entry.date < 0
                || entry.carrierDigest == null
                || entry.carrierDigest.length != DIGEST_BYTES
                || entry.width < 0 || entry.height < 0) {
            throw new IllegalArgumentException("invalid secure media index entry");
        }
        requireKind(entry.kind);
        requireString(entry.plaintextPath, MAX_PATH_BYTES, false);
        requireString(entry.fileName, MAX_NAME_BYTES, true);
        requireString(entry.mimeType, MAX_MIME_BYTES, true);
        requireString(entry.caption, MAX_CAPTION_BYTES, true);
    }

    private static void requireKind(int kind) {
        if (kind < KIND_PHOTO || kind > KIND_GIF) {
            throw new IllegalArgumentException("invalid secure media kind");
        }
    }

    private static void writeString(
            DataOutputStream output, String value, int maximum) throws IOException {
        byte[] encoded = value == null
                ? new byte[0] : value.getBytes(StandardCharsets.UTF_8);
        if (encoded.length > maximum) {
            throw new IllegalArgumentException("secure media metadata is too long");
        }
        output.writeInt(encoded.length);
        output.write(encoded);
    }

    private static String readString(DataInputStream input, int maximum) throws IOException {
        int length = input.readInt();
        if (length < 0 || length > maximum || length > input.available()) {
            throw new IOException("invalid secure media metadata length");
        }
        byte[] encoded = new byte[length];
        input.readFully(encoded);
        return new String(encoded, StandardCharsets.UTF_8);
    }

    private static void requireString(String value, int maximum, boolean emptyAllowed) {
        if (value == null || !emptyAllowed && value.isEmpty()
                || value.getBytes(StandardCharsets.UTF_8).length > maximum) {
            throw new IllegalArgumentException("invalid secure media metadata");
        }
    }

    public static byte[] digest(String carrier) {
        if (carrier == null || carrier.isEmpty()) {
            throw new IllegalArgumentException("secure media carrier is required");
        }
        try {
            return MessageDigest.getInstance("SHA-256")
                    .digest(carrier.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
    }

    private static String hex(byte[] value) {
        StringBuilder result = new StringBuilder(value.length * 2);
        for (byte item : value) {
            result.append(Character.forDigit((item >>> 4) & 0x0f, 16));
            result.append(Character.forDigit(item & 0x0f, 16));
        }
        return result.toString();
    }

    public static final class Entry {
        public final int messageId;
        public final int date;
        public final int kind;
        public final String plaintextPath;
        public final String fileName;
        public final String mimeType;
        public final String caption;
        public final int width;
        public final int height;
        private final byte[] carrierDigest;

        public Entry(
                int messageId,
                int date,
                String carrier,
                int kind,
                String plaintextPath,
                String fileName,
                String mimeType,
                String caption,
                int width,
                int height) {
            this(
                    messageId, date, digest(carrier), kind,
                    plaintextPath, fileName, mimeType, caption, width, height);
        }

        public Entry(
                int messageId,
                int date,
                byte[] carrierDigest,
                int kind,
                String plaintextPath,
                String fileName,
                String mimeType,
                String caption,
                int width,
                int height) {
            this.messageId = messageId;
            this.date = date;
            this.carrierDigest = carrierDigest.clone();
            this.kind = kind;
            this.plaintextPath = plaintextPath;
            this.fileName = fileName == null ? "" : fileName;
            this.mimeType = mimeType == null ? "" : mimeType;
            this.caption = caption == null ? "" : caption;
            this.width = width;
            this.height = height;
        }

        public byte[] carrierDigest() {
            return carrierDigest.clone();
        }
    }

    public static final class SecureMediaIndexException extends RuntimeException {
        SecureMediaIndexException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
