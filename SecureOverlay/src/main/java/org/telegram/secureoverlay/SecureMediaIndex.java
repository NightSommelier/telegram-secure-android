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
import java.util.Comparator;
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

    private final String scopedPrefix;
    private final KeystoreEncryptedBlobStore blobs;

    public SecureMediaIndex(Context context, int account, long peerUserId) {
        if (context == null || account < 0 || peerUserId <= 0) {
            throw new IllegalArgumentException(
                    "secure media index requires an account and user peer");
        }
        scopedPrefix = PREFIX + account + '.' + peerUserId + '.';
        blobs = new KeystoreEncryptedBlobStore(context.getApplicationContext());
    }

    public void put(Entry entry) {
        if (entry == null) {
            throw new IllegalArgumentException("secure media index entry is required");
        }
        try {
            blobs.put(key(entry.carrierDigest), encode(entry));
        } catch (KeystoreEncryptedBlobStore.StateStoreException e) {
            throw new SecureMediaIndexException("cannot persist secure media index", e);
        }
    }

    public Entry find(int messageId, String carrier) {
        byte[] digest = digest(carrier);
        try {
            byte[] encoded = blobs.get(key(digest));
            if (encoded == null) {
                return null;
            }
            Entry entry = decode(encoded);
            return entry.messageId == messageId
                    && MessageDigest.isEqual(digest, entry.carrierDigest)
                    ? entry : null;
        } catch (KeystoreEncryptedBlobStore.StateStoreException e) {
            throw new SecureMediaIndexException("cannot load secure media index", e);
        }
    }

    public List<Entry> list(int kind) {
        requireKind(kind);
        try {
            Map<String, byte[]> records = blobs.snapshotPrefixes(scopedPrefix);
            ArrayList<Entry> result = new ArrayList<>();
            for (byte[] encoded : records.values()) {
                Entry entry = decode(encoded);
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

    public int count(int kind) {
        return list(kind).size();
    }

    public boolean forget(String carrier) {
        String key = key(digest(carrier));
        try {
            if (blobs.get(key) == null) {
                return false;
            }
            blobs.delete(key);
            return true;
        } catch (KeystoreEncryptedBlobStore.StateStoreException e) {
            throw new SecureMediaIndexException("cannot remove secure media index", e);
        }
    }

    public void forgetPeer() {
        try {
            blobs.deletePrefixes(scopedPrefix);
        } catch (KeystoreEncryptedBlobStore.StateStoreException e) {
            throw new SecureMediaIndexException("cannot clear secure media index", e);
        }
    }

    private String key(byte[] digest) {
        return scopedPrefix + hex(digest);
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

    private static byte[] digest(String carrier) {
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

        private Entry(
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
    }

    public static final class SecureMediaIndexException extends RuntimeException {
        SecureMediaIndexException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
