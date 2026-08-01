package org.telegram.secureoverlay;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.UUID;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.signal.libsignal.protocol.IdentityKeyPair;

/**
 * Password-protected recovery archive for identity and historical local display records.
 *
 * <p>Live libsignal sessions and peer trust are deliberately excluded. Restoring a ratchet
 * snapshot would roll its send state backwards and could reuse message keys. The restored chat
 * roster is therefore paused until every peer is paired and verified again.</p>
 */
public final class SecureHistoryBackupCodec {
    static final int KIND_OUTGOING_TEXT = 1;
    static final int KIND_INCOMING_TEXT = 2;
    static final int KIND_OUTGOING_CONTENT = 3;
    static final int KIND_INCOMING_CONTENT = 4;
    static final int KIND_SAVED_MESSAGES_KEY = 5;

    private static final byte[] CONTAINER_MAGIC = new byte[] {'F', 'S', 'R', 'K'};
    private static final byte[] PLAINTEXT_MAGIC = new byte[] {'F', 'S', 'R', 'P'};
    private static final int FORMAT_VERSION = 1;
    private static final int KDF_PBKDF2_HMAC_SHA256 = 2;
    private static final int AEAD_AES_256_GCM = 1;
    private static final int FLAG_NO_PASSWORD = 1;
    private static final int PBKDF2_ITERATIONS = 600_000;
    private static final int SALT_BYTES = 16;
    private static final int NONCE_BYTES = 12;
    private static final int TAG_BYTES = 16;
    private static final int KEY_BYTES = 32;
    private static final int FIXED_HEADER_BYTES = 26;
    private static final int MAX_ARCHIVE_PLAINTEXT_BYTES = 32 * 1024 * 1024;
    private static final int MAX_RECORD_BYTES = 64 * 1024;
    private static final int MAX_RECORDS = 100_000;
    private static final int MAX_PEERS = 20_000;
    private static final int MAX_PASSWORD_BYTES = 512;
    private static final int MAX_IDENTITY_BYTES = 512;
    private static final byte[] NO_PASSWORD_KDF_INPUT =
            "Fork-Secure unprotected history backup v1"
                    .getBytes(StandardCharsets.US_ASCII);
    private static final SecureRandom RANDOM = new SecureRandom();

    private SecureHistoryBackupCodec() {
    }

    public static final class CacheRecord {
        public final int kind;
        public final long peerUserId;
        public final byte[] carrierDigest;
        public final byte[] value;

        public CacheRecord(int kind, long peerUserId, byte[] carrierDigest, byte[] value) {
            requireKind(kind);
            if (peerUserId <= 0
                    || carrierDigest == null
                    || carrierDigest.length != 32
                    || value == null
                    || value.length == 0
                    || value.length > MAX_RECORD_BYTES) {
                throw new IllegalArgumentException("invalid secure history cache record");
            }
            this.kind = kind;
            this.peerUserId = peerUserId;
            this.carrierDigest = carrierDigest.clone();
            this.value = value.clone();
            validateCacheValue(kind, this.value);
        }
    }

    public static final class PeerRecord {
        public final long peerUserId;
        public final int lastPairingMessageId;

        public PeerRecord(long peerUserId, int lastPairingMessageId) {
            if (peerUserId <= 0 || lastPairingMessageId < 0) {
                throw new IllegalArgumentException("invalid secure history peer record");
            }
            this.peerUserId = peerUserId;
            this.lastPairingMessageId = lastPairingMessageId;
        }
    }

    public static final class Payload {
        public final UUID archiveId;
        public final long ownerUserId;
        public final long generation;
        public final long exportedAtUnixSeconds;
        public final int registrationId;
        public final byte[] serializedIdentity;
        public final List<CacheRecord> cacheRecords;
        public final List<PeerRecord> peers;

        public Payload(
                UUID archiveId,
                long ownerUserId,
                long generation,
                long exportedAtUnixSeconds,
                int registrationId,
                byte[] serializedIdentity,
                List<CacheRecord> cacheRecords,
                List<PeerRecord> peers) {
            if (archiveId == null
                    || (archiveId.getMostSignificantBits() == 0
                    && archiveId.getLeastSignificantBits() == 0)
                    || ownerUserId <= 0
                    || generation <= 0
                    || exportedAtUnixSeconds <= 0
                    || registrationId <= 0
                    || registrationId > 16_380
                    || serializedIdentity == null
                    || serializedIdentity.length < 16
                    || serializedIdentity.length > MAX_IDENTITY_BYTES
                    || cacheRecords == null
                    || cacheRecords.size() > MAX_RECORDS
                    || peers == null
                    || peers.size() > MAX_PEERS) {
                throw new IllegalArgumentException("invalid secure history backup metadata");
            }
            validateIdentity(serializedIdentity);
            this.archiveId = archiveId;
            this.ownerUserId = ownerUserId;
            this.generation = generation;
            this.exportedAtUnixSeconds = exportedAtUnixSeconds;
            this.registrationId = registrationId;
            this.serializedIdentity = serializedIdentity.clone();
            this.cacheRecords = canonicalCacheRecords(cacheRecords);
            this.peers = canonicalPeers(peers);
        }
    }

    public static byte[] encrypt(Payload payload, char[] password) {
        return encrypt(payload, password, randomBytes(SALT_BYTES), randomBytes(NONCE_BYTES));
    }

    static byte[] encrypt(Payload payload, char[] password, byte[] salt, byte[] nonce) {
        if (payload == null
                || salt == null
                || salt.length != SALT_BYTES
                || nonce == null
                || nonce.length != NONCE_BYTES) {
            throw new IllegalArgumentException("invalid secure history encryption input");
        }
        byte[] plaintext = encodePlaintext(payload);
        boolean noPassword = password != null && password.length == 0;
        byte[] passwordBytes = encodePassword(password, noPassword);
        byte[] key = null;
        try {
            byte[] header = encodeHeader(
                    plaintext.length,
                    salt,
                    nonce,
                    noPassword ? FLAG_NO_PASSWORD : 0);
            key = pbkdf2HmacSha256(passwordBytes, salt);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(
                    Cipher.ENCRYPT_MODE,
                    new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(TAG_BYTES * 8, nonce));
            cipher.updateAAD(header);
            byte[] ciphertext = cipher.doFinal(plaintext);
            ByteArrayOutputStream output =
                    new ByteArrayOutputStream(header.length + ciphertext.length);
            output.write(header, 0, header.length);
            output.write(ciphertext, 0, ciphertext.length);
            return output.toByteArray();
        } catch (GeneralSecurityException error) {
            throw new IllegalStateException("cannot encrypt secure history backup", error);
        } finally {
            Arrays.fill(plaintext, (byte) 0);
            Arrays.fill(passwordBytes, (byte) 0);
            if (key != null) {
                Arrays.fill(key, (byte) 0);
            }
        }
    }

    public static Payload decrypt(byte[] archive, char[] password) {
        ParsedContainer parsed = parseContainer(archive);
        byte[] passwordBytes = encodePassword(password, parsed.noPassword);
        byte[] key = null;
        byte[] plaintext = null;
        try {
            key = pbkdf2HmacSha256(passwordBytes, parsed.salt);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(
                    Cipher.DECRYPT_MODE,
                    new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(TAG_BYTES * 8, parsed.nonce));
            cipher.updateAAD(parsed.header);
            plaintext = cipher.doFinal(parsed.ciphertext);
            if (plaintext.length != parsed.plaintextLength) {
                throw new IllegalArgumentException(
                        "secure history backup plaintext length mismatch");
            }
            return decodePlaintext(plaintext);
        } catch (AEADBadTagException error) {
            throw new SecurityException(
                    "wrong password or modified secure history backup", error);
        } catch (GeneralSecurityException error) {
            throw new IllegalStateException("cannot decrypt secure history backup", error);
        } finally {
            Arrays.fill(passwordBytes, (byte) 0);
            if (key != null) {
                Arrays.fill(key, (byte) 0);
            }
            if (plaintext != null) {
                Arrays.fill(plaintext, (byte) 0);
            }
        }
    }

    public static boolean requiresPassword(byte[] archive) {
        return !parseContainer(archive).noPassword;
    }

    static byte[] encodePlaintext(Payload payload) {
        if (payload == null) {
            throw new IllegalArgumentException("secure history payload is required");
        }
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            DataOutputStream output = new DataOutputStream(bytes);
            output.write(PLAINTEXT_MAGIC);
            output.writeShort(FORMAT_VERSION);
            output.writeLong(payload.archiveId.getMostSignificantBits());
            output.writeLong(payload.archiveId.getLeastSignificantBits());
            output.writeLong(payload.ownerUserId);
            output.writeLong(payload.generation);
            output.writeLong(payload.exportedAtUnixSeconds);
            output.writeInt(payload.registrationId);
            output.writeShort(payload.serializedIdentity.length);
            output.write(payload.serializedIdentity);
            output.writeInt(payload.cacheRecords.size());
            for (CacheRecord record : payload.cacheRecords) {
                output.writeByte(record.kind);
                output.writeLong(record.peerUserId);
                output.write(record.carrierDigest);
                output.writeInt(record.value.length);
                output.write(record.value);
            }
            output.writeInt(payload.peers.size());
            for (PeerRecord peer : payload.peers) {
                output.writeLong(peer.peerUserId);
                output.writeInt(peer.lastPairingMessageId);
            }
            output.flush();
            byte[] encoded = bytes.toByteArray();
            if (encoded.length == 0 || encoded.length > MAX_ARCHIVE_PLAINTEXT_BYTES) {
                throw new IllegalArgumentException("secure history backup is too large");
            }
            return encoded;
        } catch (java.io.IOException impossible) {
            throw new AssertionError(impossible);
        }
    }

    static Payload decodePlaintext(byte[] plaintext) {
        if (plaintext == null
                || plaintext.length == 0
                || plaintext.length > MAX_ARCHIVE_PLAINTEXT_BYTES) {
            throw new IllegalArgumentException("invalid secure history plaintext length");
        }
        try {
            DataInputStream input = new DataInputStream(new ByteArrayInputStream(plaintext));
            byte[] magic = new byte[PLAINTEXT_MAGIC.length];
            input.readFully(magic);
            int version = input.readUnsignedShort();
            if (!Arrays.equals(magic, PLAINTEXT_MAGIC) || version != FORMAT_VERSION) {
                throw new IllegalArgumentException("unsupported secure history plaintext");
            }
            UUID archiveId = new UUID(input.readLong(), input.readLong());
            long ownerUserId = input.readLong();
            long generation = input.readLong();
            long exportedAt = input.readLong();
            int registrationId = input.readInt();
            int identityLength = input.readUnsignedShort();
            if (identityLength < 16
                    || identityLength > MAX_IDENTITY_BYTES
                    || identityLength > input.available()) {
                throw new IllegalArgumentException("invalid secure history identity length");
            }
            byte[] identity = new byte[identityLength];
            input.readFully(identity);
            int cacheCount = input.readInt();
            if (cacheCount < 0 || cacheCount > MAX_RECORDS) {
                throw new IllegalArgumentException("invalid secure history record count");
            }
            List<CacheRecord> records = new ArrayList<>(cacheCount);
            CacheRecord previous = null;
            for (int i = 0; i < cacheCount; i++) {
                int kind = input.readUnsignedByte();
                long peerUserId = input.readLong();
                byte[] digest = new byte[32];
                input.readFully(digest);
                int valueLength = input.readInt();
                if (valueLength <= 0
                        || valueLength > MAX_RECORD_BYTES
                        || valueLength > input.available()) {
                    throw new IllegalArgumentException(
                            "invalid secure history record length");
                }
                byte[] value = new byte[valueLength];
                input.readFully(value);
                CacheRecord current = new CacheRecord(kind, peerUserId, digest, value);
                if (previous != null && CACHE_ORDER.compare(previous, current) >= 0) {
                    throw new IllegalArgumentException(
                            "non-canonical secure history record order");
                }
                records.add(current);
                previous = current;
            }
            int peerCount = input.readInt();
            if (peerCount < 0 || peerCount > MAX_PEERS) {
                throw new IllegalArgumentException("invalid secure history peer count");
            }
            List<PeerRecord> peers = new ArrayList<>(peerCount);
            long previousPeer = 0;
            for (int i = 0; i < peerCount; i++) {
                PeerRecord peer = new PeerRecord(input.readLong(), input.readInt());
                if (peer.peerUserId <= previousPeer) {
                    throw new IllegalArgumentException(
                            "non-canonical secure history peer order");
                }
                peers.add(peer);
                previousPeer = peer.peerUserId;
            }
            if (input.available() != 0) {
                throw new IllegalArgumentException("secure history backup has trailing bytes");
            }
            return new Payload(
                    archiveId,
                    ownerUserId,
                    generation,
                    exportedAt,
                    registrationId,
                    identity,
                    records,
                    peers);
        } catch (java.io.EOFException error) {
            throw new IllegalArgumentException("truncated secure history backup", error);
        } catch (java.io.IOException impossible) {
            throw new AssertionError(impossible);
        }
    }

    private static final Comparator<CacheRecord> CACHE_ORDER = (left, right) -> {
        int result = Integer.compare(left.kind, right.kind);
        if (result != 0) {
            return result;
        }
        result = Long.compare(left.peerUserId, right.peerUserId);
        if (result != 0) {
            return result;
        }
        for (int i = 0; i < left.carrierDigest.length; i++) {
            result = Integer.compare(
                    left.carrierDigest[i] & 0xff,
                    right.carrierDigest[i] & 0xff);
            if (result != 0) {
                return result;
            }
        }
        return 0;
    };

    private static List<CacheRecord> canonicalCacheRecords(List<CacheRecord> source) {
        List<CacheRecord> copy = new ArrayList<>(source.size());
        for (CacheRecord record : source) {
            if (record == null) {
                throw new IllegalArgumentException("secure history record is missing");
            }
            copy.add(new CacheRecord(
                    record.kind,
                    record.peerUserId,
                    record.carrierDigest,
                    record.value));
        }
        copy.sort(CACHE_ORDER);
        for (int i = 1; i < copy.size(); i++) {
            if (CACHE_ORDER.compare(copy.get(i - 1), copy.get(i)) == 0) {
                throw new IllegalArgumentException("duplicate secure history record");
            }
        }
        return copy;
    }

    private static List<PeerRecord> canonicalPeers(List<PeerRecord> source) {
        List<PeerRecord> copy = new ArrayList<>(source.size());
        for (PeerRecord peer : source) {
            if (peer == null) {
                throw new IllegalArgumentException("secure history peer is missing");
            }
            copy.add(new PeerRecord(peer.peerUserId, peer.lastPairingMessageId));
        }
        copy.sort(Comparator.comparingLong(peer -> peer.peerUserId));
        for (int i = 1; i < copy.size(); i++) {
            if (copy.get(i - 1).peerUserId == copy.get(i).peerUserId) {
                throw new IllegalArgumentException("duplicate secure history peer");
            }
        }
        return copy;
    }

    private static void validateCacheValue(int kind, byte[] value) {
        if (kind == KIND_SAVED_MESSAGES_KEY) {
            if (value.length != 36) {
                throw new IllegalArgumentException("invalid Saved Messages backup key");
            }
            return;
        }
        if (kind == KIND_OUTGOING_CONTENT || kind == KIND_INCOMING_CONTENT) {
            SecureContentCodec.decode(value);
            return;
        }
        try {
            StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(value));
        } catch (CharacterCodingException error) {
            throw new IllegalArgumentException("invalid secure history text", error);
        }
    }

    private static void requireKind(int kind) {
        if (kind < KIND_OUTGOING_TEXT || kind > KIND_SAVED_MESSAGES_KEY) {
            throw new IllegalArgumentException("unknown secure history record kind");
        }
    }

    private static ParsedContainer parseContainer(byte[] archive) {
        if (archive == null
                || archive.length < FIXED_HEADER_BYTES + SALT_BYTES + NONCE_BYTES + TAG_BYTES + 1
                || archive.length > MAX_ARCHIVE_PLAINTEXT_BYTES
                        + FIXED_HEADER_BYTES + SALT_BYTES + NONCE_BYTES + TAG_BYTES) {
            throw new IllegalArgumentException("secure history backup is truncated or too large");
        }
        try {
            DataInputStream input = new DataInputStream(new ByteArrayInputStream(archive));
            byte[] magic = new byte[CONTAINER_MAGIC.length];
            input.readFully(magic);
            int version = input.readUnsignedShort();
            int kdf = input.readUnsignedByte();
            int aead = input.readUnsignedByte();
            int flags = input.readUnsignedShort();
            int iterations = input.readInt();
            int reservedKdf = input.readInt();
            int parallelism = input.readUnsignedByte();
            int saltLength = input.readUnsignedByte();
            int nonceLength = input.readUnsignedByte();
            int reserved = input.readUnsignedByte();
            int plaintextLength = input.readInt();
            if (!Arrays.equals(magic, CONTAINER_MAGIC)
                    || version != FORMAT_VERSION
                    || kdf != KDF_PBKDF2_HMAC_SHA256
                    || aead != AEAD_AES_256_GCM
                    || (flags != 0 && flags != FLAG_NO_PASSWORD)
                    || iterations != PBKDF2_ITERATIONS
                    || reservedKdf != 0
                    || parallelism != 1
                    || saltLength != SALT_BYTES
                    || nonceLength != NONCE_BYTES
                    || reserved != 0
                    || plaintextLength <= 0
                    || plaintextLength > MAX_ARCHIVE_PLAINTEXT_BYTES) {
                throw new IllegalArgumentException("unsupported secure history header");
            }
            long expectedLength = (long) FIXED_HEADER_BYTES
                    + saltLength
                    + nonceLength
                    + plaintextLength
                    + TAG_BYTES;
            if (expectedLength != archive.length) {
                throw new IllegalArgumentException(
                        "invalid secure history backup resource length");
            }
            byte[] salt = new byte[saltLength];
            byte[] nonce = new byte[nonceLength];
            input.readFully(salt);
            input.readFully(nonce);
            byte[] header = Arrays.copyOf(
                    archive, FIXED_HEADER_BYTES + saltLength + nonceLength);
            byte[] ciphertext = new byte[plaintextLength + TAG_BYTES];
            input.readFully(ciphertext);
            return new ParsedContainer(
                    plaintextLength,
                    salt,
                    nonce,
                    header,
                    ciphertext,
                    flags == FLAG_NO_PASSWORD);
        } catch (java.io.EOFException error) {
            throw new IllegalArgumentException("truncated secure history backup", error);
        } catch (java.io.IOException impossible) {
            throw new AssertionError(impossible);
        }
    }

    private static byte[] encodeHeader(
            int plaintextLength, byte[] salt, byte[] nonce, int flags) {
        try {
            ByteArrayOutputStream bytes =
                    new ByteArrayOutputStream(FIXED_HEADER_BYTES + salt.length + nonce.length);
            DataOutputStream output = new DataOutputStream(bytes);
            output.write(CONTAINER_MAGIC);
            output.writeShort(FORMAT_VERSION);
            output.writeByte(KDF_PBKDF2_HMAC_SHA256);
            output.writeByte(AEAD_AES_256_GCM);
            output.writeShort(flags);
            output.writeInt(PBKDF2_ITERATIONS);
            output.writeInt(0);
            output.writeByte(1);
            output.writeByte(salt.length);
            output.writeByte(nonce.length);
            output.writeByte(0);
            output.writeInt(plaintextLength);
            output.write(salt);
            output.write(nonce);
            output.flush();
            return bytes.toByteArray();
        } catch (java.io.IOException impossible) {
            throw new AssertionError(impossible);
        }
    }

    private static byte[] encodePassword(char[] password, boolean noPassword) {
        if (password == null) {
            throw new IllegalArgumentException("secure history password is required");
        }
        if (noPassword) {
            if (password.length != 0) {
                throw new SecurityException(
                        "unprotected secure history backup requires an empty password");
            }
            return NO_PASSWORD_KDF_INPUT.clone();
        }
        if (password.length == 0) {
            throw new IllegalArgumentException("secure history password is required");
        }
        try {
            ByteBuffer encoded = StandardCharsets.UTF_8.newEncoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .encode(CharBuffer.wrap(password));
            if (encoded.remaining() == 0 || encoded.remaining() > MAX_PASSWORD_BYTES) {
                throw new IllegalArgumentException("secure history password is too long");
            }
            byte[] copy = new byte[encoded.remaining()];
            encoded.get(copy);
            if (encoded.hasArray()) {
                Arrays.fill(encoded.array(), (byte) 0);
            }
            return copy;
        } catch (CharacterCodingException error) {
            throw new IllegalArgumentException(
                    "secure history password is invalid UTF-16", error);
        }
    }

    private static byte[] pbkdf2HmacSha256(byte[] password, byte[] salt) {
        byte[] block = new byte[salt.length + 4];
        System.arraycopy(salt, 0, block, 0, salt.length);
        block[block.length - 1] = 1;
        byte[] u = null;
        byte[] result = null;
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(password, "HmacSHA256"));
            u = mac.doFinal(block);
            result = u.clone();
            for (int i = 1; i < PBKDF2_ITERATIONS; i++) {
                byte[] next = mac.doFinal(u);
                Arrays.fill(u, (byte) 0);
                u = next;
                for (int j = 0; j < result.length; j++) {
                    result[j] ^= u[j];
                }
            }
            return result;
        } catch (GeneralSecurityException error) {
            if (result != null) {
                Arrays.fill(result, (byte) 0);
            }
            throw new IllegalStateException("PBKDF2-HMAC-SHA-256 is unavailable", error);
        } finally {
            Arrays.fill(block, (byte) 0);
            if (u != null) {
                Arrays.fill(u, (byte) 0);
            }
        }
    }

    private static void validateIdentity(byte[] serializedIdentity) {
        try {
            new IdentityKeyPair(serializedIdentity);
        } catch (Exception error) {
            throw new IllegalArgumentException("invalid secure history identity", error);
        }
    }

    private static byte[] randomBytes(int length) {
        byte[] value = new byte[length];
        RANDOM.nextBytes(value);
        return value;
    }

    private static final class ParsedContainer {
        final int plaintextLength;
        final byte[] salt;
        final byte[] nonce;
        final byte[] header;
        final byte[] ciphertext;
        final boolean noPassword;

        ParsedContainer(
                int plaintextLength,
                byte[] salt,
                byte[] nonce,
                byte[] header,
                byte[] ciphertext,
                boolean noPassword) {
            this.plaintextLength = plaintextLength;
            this.salt = salt;
            this.nonce = nonce;
            this.header = header;
            this.ciphertext = ciphertext;
            this.noPassword = noPassword;
        }
    }
}
