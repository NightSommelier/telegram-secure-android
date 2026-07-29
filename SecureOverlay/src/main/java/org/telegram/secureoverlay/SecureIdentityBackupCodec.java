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
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.UUID;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.signal.libsignal.protocol.IdentityKeyPair;

/**
 * Canonical password-protected archive for one Fork-Secure identity.
 *
 * <p>Version 1 intentionally contains no sessions, peer trust, message plaintext, Telegram
 * credentials, or media. KDF and AEAD identifiers are explicit so a future Argon2id container can
 * be added without reinterpreting existing archives.</p>
 */
public final class SecureIdentityBackupCodec {
    private static final byte[] CONTAINER_MAGIC =
            new byte[] {'F', 'S', 'B', 'K'};
    private static final byte[] PLAINTEXT_MAGIC =
            new byte[] {'F', 'S', 'B', 'P'};
    private static final int FORMAT_VERSION = 1;
    private static final int KDF_PBKDF2_HMAC_SHA256 = 2;
    private static final int AEAD_AES_256_GCM = 1;
    private static final int PBKDF2_ITERATIONS = 600_000;
    private static final int SALT_BYTES = 16;
    private static final int NONCE_BYTES = 12;
    private static final int TAG_BYTES = 16;
    private static final int KEY_BYTES = 32;
    private static final int FIXED_HEADER_BYTES = 26;
    private static final int MAX_PLAINTEXT_BYTES = 4096;
    private static final int MAX_PASSWORD_BYTES = 512;
    private static final int MAX_IDENTITY_BYTES = 512;
    private static final int MAX_REGISTRATION_ID = 16_380;
    private static final SecureRandom RANDOM = new SecureRandom();

    private SecureIdentityBackupCodec() {
    }

    public static final class Payload {
        public final UUID archiveId;
        public final long ownerUserId;
        public final long generation;
        public final long exportedAtUnixSeconds;
        public final int registrationId;
        public final byte[] serializedIdentity;

        public Payload(
                UUID archiveId,
                long ownerUserId,
                long generation,
                long exportedAtUnixSeconds,
                int registrationId,
                byte[] serializedIdentity) {
            if (archiveId == null
                    || (archiveId.getMostSignificantBits() == 0
                    && archiveId.getLeastSignificantBits() == 0)) {
                throw new IllegalArgumentException("archive id must be non-zero");
            }
            if (ownerUserId <= 0 || generation <= 0 || exportedAtUnixSeconds <= 0) {
                throw new IllegalArgumentException("invalid identity backup metadata");
            }
            if (registrationId <= 0 || registrationId > MAX_REGISTRATION_ID) {
                throw new IllegalArgumentException("invalid libsignal registration id");
            }
            if (serializedIdentity == null
                    || serializedIdentity.length < 16
                    || serializedIdentity.length > MAX_IDENTITY_BYTES) {
                throw new IllegalArgumentException("invalid serialized identity length");
            }
            validateIdentity(serializedIdentity);
            this.archiveId = archiveId;
            this.ownerUserId = ownerUserId;
            this.generation = generation;
            this.exportedAtUnixSeconds = exportedAtUnixSeconds;
            this.registrationId = registrationId;
            this.serializedIdentity = serializedIdentity.clone();
        }
    }

    public static byte[] encrypt(Payload payload, char[] password) {
        byte[] salt = randomBytes(SALT_BYTES);
        byte[] nonce = randomBytes(NONCE_BYTES);
        return encrypt(payload, password, salt, nonce);
    }

    static byte[] encrypt(Payload payload, char[] password, byte[] salt, byte[] nonce) {
        if (payload == null || salt == null || salt.length != SALT_BYTES
                || nonce == null || nonce.length != NONCE_BYTES) {
            throw new IllegalArgumentException("invalid identity backup encryption input");
        }
        byte[] plaintext = encodePlaintext(payload);
        byte[] passwordBytes = encodePassword(password);
        byte[] key = null;
        try {
            byte[] header = encodeHeader(plaintext.length, salt, nonce);
            key = pbkdf2HmacSha256(passwordBytes, salt, PBKDF2_ITERATIONS);
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
            throw new IllegalStateException("cannot encrypt identity backup", error);
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
        byte[] passwordBytes = encodePassword(password);
        byte[] key = null;
        byte[] plaintext = null;
        try {
            key = pbkdf2HmacSha256(
                    passwordBytes, parsed.salt, PBKDF2_ITERATIONS);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(
                    Cipher.DECRYPT_MODE,
                    new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(TAG_BYTES * 8, parsed.nonce));
            cipher.updateAAD(parsed.header);
            plaintext = cipher.doFinal(parsed.ciphertext);
            if (plaintext.length != parsed.plaintextLength) {
                throw new IllegalArgumentException("identity backup plaintext length mismatch");
            }
            return decodePlaintext(plaintext);
        } catch (AEADBadTagException error) {
            throw new SecurityException("wrong password or modified identity backup", error);
        } catch (GeneralSecurityException error) {
            throw new IllegalStateException("cannot decrypt identity backup", error);
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

    static byte[] encodePlaintext(Payload payload) {
        if (payload == null) {
            throw new IllegalArgumentException("identity backup payload is required");
        }
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            DataOutputStream output = new DataOutputStream(bytes);
            output.write(PLAINTEXT_MAGIC);
            output.writeShort(FORMAT_VERSION);
            field(output, 1, uuidBytes(payload.archiveId));
            field(output, 2, ByteBuffer.allocate(8).putLong(payload.ownerUserId).array());
            field(output, 3, ByteBuffer.allocate(8).putLong(payload.generation).array());
            field(output, 4, ByteBuffer.allocate(8).putLong(payload.exportedAtUnixSeconds).array());
            field(output, 5, ByteBuffer.allocate(4).putInt(payload.registrationId).array());
            field(output, 6, payload.serializedIdentity);
            field(output, 7, identityDigest(payload.serializedIdentity));
            field(output, 8, new byte[] {1});
            output.flush();
            byte[] encoded = bytes.toByteArray();
            if (encoded.length == 0 || encoded.length > MAX_PLAINTEXT_BYTES) {
                throw new IllegalArgumentException("identity backup plaintext is too large");
            }
            return encoded;
        } catch (java.io.IOException impossible) {
            throw new AssertionError(impossible);
        }
    }

    static Payload decodePlaintext(byte[] plaintext) {
        if (plaintext == null || plaintext.length == 0
                || plaintext.length > MAX_PLAINTEXT_BYTES) {
            throw new IllegalArgumentException("invalid identity backup plaintext length");
        }
        try {
            DataInputStream input = new DataInputStream(new ByteArrayInputStream(plaintext));
            byte[] magic = new byte[PLAINTEXT_MAGIC.length];
            input.readFully(magic);
            if (!Arrays.equals(magic, PLAINTEXT_MAGIC)
                    || input.readUnsignedShort() != FORMAT_VERSION) {
                throw new IllegalArgumentException("unsupported identity backup plaintext");
            }
            byte[][] fields = new byte[9][];
            int expectedTag = 1;
            while (input.available() > 0) {
                int tag = input.readUnsignedByte();
                int length = input.readUnsignedShort();
                if (tag != expectedTag || tag > 8 || length > input.available()) {
                    throw new IllegalArgumentException("non-canonical identity backup field");
                }
                byte[] value = new byte[length];
                input.readFully(value);
                fields[tag] = value;
                expectedTag++;
            }
            if (expectedTag != 9) {
                throw new IllegalArgumentException("incomplete identity backup plaintext");
            }
            requireLength(fields[1], 16, "archive id");
            requireLength(fields[2], 8, "owner id");
            requireLength(fields[3], 8, "generation");
            requireLength(fields[4], 8, "export time");
            requireLength(fields[5], 4, "registration");
            if (fields[6].length < 16 || fields[6].length > MAX_IDENTITY_BYTES) {
                throw new IllegalArgumentException("invalid identity backup key length");
            }
            requireLength(fields[7], 32, "identity digest");
            requireLength(fields[8], 1, "recovery policy");
            if (fields[8][0] != 1
                    || !MessageDigest.isEqual(fields[7], identityDigest(fields[6]))) {
                throw new IllegalArgumentException("identity backup key validation failed");
            }
            return new Payload(
                    uuid(fields[1]),
                    ByteBuffer.wrap(fields[2]).getLong(),
                    ByteBuffer.wrap(fields[3]).getLong(),
                    ByteBuffer.wrap(fields[4]).getLong(),
                    ByteBuffer.wrap(fields[5]).getInt(),
                    fields[6]);
        } catch (java.io.EOFException error) {
            throw new IllegalArgumentException("truncated identity backup plaintext", error);
        } catch (java.io.IOException impossible) {
            throw new AssertionError(impossible);
        }
    }

    static byte[] pbkdf2HmacSha256(byte[] password, byte[] salt, int iterations) {
        if (password == null || salt == null || salt.length < 16
                || iterations != PBKDF2_ITERATIONS) {
            throw new IllegalArgumentException("invalid identity backup KDF input");
        }
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
            for (int i = 1; i < iterations; i++) {
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

    private static ParsedContainer parseContainer(byte[] archive) {
        if (archive == null || archive.length < FIXED_HEADER_BYTES + SALT_BYTES
                + NONCE_BYTES + TAG_BYTES + 1) {
            throw new IllegalArgumentException("identity backup is truncated");
        }
        try {
            DataInputStream input = new DataInputStream(new ByteArrayInputStream(archive));
            byte[] magic = new byte[CONTAINER_MAGIC.length];
            input.readFully(magic);
            int version = input.readUnsignedShort();
            int kdf = input.readUnsignedByte();
            int aead = input.readUnsignedByte();
            int flags = input.readUnsignedShort();
            int kdfParameter1 = input.readInt();
            int kdfParameter2 = input.readInt();
            int parallelism = input.readUnsignedByte();
            int saltLength = input.readUnsignedByte();
            int nonceLength = input.readUnsignedByte();
            int reserved = input.readUnsignedByte();
            int plaintextLength = input.readInt();
            if (!Arrays.equals(magic, CONTAINER_MAGIC)
                    || version != FORMAT_VERSION
                    || kdf != KDF_PBKDF2_HMAC_SHA256
                    || aead != AEAD_AES_256_GCM
                    || flags != 0
                    || kdfParameter1 != PBKDF2_ITERATIONS
                    || kdfParameter2 != 0
                    || parallelism != 1
                    || saltLength != SALT_BYTES
                    || nonceLength != NONCE_BYTES
                    || reserved != 0
                    || plaintextLength <= 0
                    || plaintextLength > MAX_PLAINTEXT_BYTES) {
                throw new IllegalArgumentException("unsupported identity backup header");
            }
            long expectedLength = (long) FIXED_HEADER_BYTES + saltLength + nonceLength
                    + plaintextLength + TAG_BYTES;
            if (expectedLength != archive.length) {
                throw new IllegalArgumentException("invalid identity backup resource length");
            }
            byte[] salt = new byte[saltLength];
            byte[] nonce = new byte[nonceLength];
            input.readFully(salt);
            input.readFully(nonce);
            int headerLength = FIXED_HEADER_BYTES + saltLength + nonceLength;
            byte[] header = Arrays.copyOf(archive, headerLength);
            byte[] ciphertext = new byte[plaintextLength + TAG_BYTES];
            input.readFully(ciphertext);
            if (input.available() != 0) {
                throw new IllegalArgumentException("identity backup has trailing bytes");
            }
            return new ParsedContainer(
                    plaintextLength, salt, nonce, header, ciphertext);
        } catch (java.io.EOFException error) {
            throw new IllegalArgumentException("identity backup is truncated", error);
        } catch (java.io.IOException impossible) {
            throw new AssertionError(impossible);
        }
    }

    private static byte[] encodeHeader(int plaintextLength, byte[] salt, byte[] nonce) {
        try {
            ByteArrayOutputStream bytes =
                    new ByteArrayOutputStream(FIXED_HEADER_BYTES + salt.length + nonce.length);
            DataOutputStream output = new DataOutputStream(bytes);
            output.write(CONTAINER_MAGIC);
            output.writeShort(FORMAT_VERSION);
            output.writeByte(KDF_PBKDF2_HMAC_SHA256);
            output.writeByte(AEAD_AES_256_GCM);
            output.writeShort(0);
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

    private static byte[] encodePassword(char[] password) {
        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("identity backup password is required");
        }
        try {
            ByteBuffer encoded = StandardCharsets.UTF_8.newEncoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .encode(CharBuffer.wrap(password));
            if (encoded.remaining() == 0 || encoded.remaining() > MAX_PASSWORD_BYTES) {
                throw new IllegalArgumentException("identity backup password is too long");
            }
            byte[] copy = new byte[encoded.remaining()];
            encoded.get(copy);
            if (encoded.hasArray()) {
                Arrays.fill(encoded.array(), (byte) 0);
            }
            return copy;
        } catch (CharacterCodingException error) {
            throw new IllegalArgumentException("identity backup password is invalid UTF-16", error);
        }
    }

    private static byte[] identityDigest(byte[] serializedIdentity) {
        try {
            IdentityKeyPair pair = new IdentityKeyPair(serializedIdentity);
            return MessageDigest.getInstance("SHA-256")
                    .digest(pair.getPublicKey().serialize());
        } catch (Exception error) {
            throw new IllegalArgumentException("invalid libsignal identity", error);
        }
    }

    private static void validateIdentity(byte[] serializedIdentity) {
        identityDigest(serializedIdentity);
    }

    private static void field(DataOutputStream output, int tag, byte[] value)
            throws java.io.IOException {
        if (tag <= 0 || tag > 255 || value == null || value.length > 0xffff) {
            throw new IllegalArgumentException("invalid identity backup field");
        }
        output.writeByte(tag);
        output.writeShort(value.length);
        output.write(value);
    }

    private static void requireLength(byte[] value, int expected, String name) {
        if (value == null || value.length != expected) {
            throw new IllegalArgumentException("invalid identity backup " + name);
        }
    }

    private static byte[] uuidBytes(UUID value) {
        return ByteBuffer.allocate(16)
                .putLong(value.getMostSignificantBits())
                .putLong(value.getLeastSignificantBits())
                .array();
    }

    private static UUID uuid(byte[] value) {
        ByteBuffer input = ByteBuffer.wrap(value);
        return new UUID(input.getLong(), input.getLong());
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

        ParsedContainer(
                int plaintextLength,
                byte[] salt,
                byte[] nonce,
                byte[] header,
                byte[] ciphertext) {
            this.plaintextLength = plaintextLength;
            this.salt = salt;
            this.nonce = nonce;
            this.header = header;
            this.ciphertext = ciphertext;
        }
    }
}
