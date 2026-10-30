package org.telegram.secureoverlay;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/** Small authenticated record codec for Saved Messages text; Telegram adapters are separate. */
public final class SecureSavedMessageCrypto {
    private static final byte[] MAGIC = new byte[] {'F', 'S', 'M', '1'};
    private static final byte[] MAGIC_V2 = new byte[] {'F', 'S', 'M', '2'};
    private static final int NONCE_BYTES = 12;
    private static final int TAG_BYTES = 16;
    private static final int MAX_TEXT_BYTES = 16 * 1024;
    private static final java.security.SecureRandom RANDOM = new java.security.SecureRandom();

    private SecureSavedMessageCrypto() {
    }

    public static int extractGeneration(byte[] record) {
        if (record == null || record.length < 8) {
            return -1;
        }
        return ByteBuffer.wrap(record).order(ByteOrder.BIG_ENDIAN).getInt(4);
    }

    public static byte[] buildAad(byte[] magic, int generation, byte kind, int account, long recordId) {
        ByteBuffer buf = ByteBuffer.allocate(magic.length + 4 + 1 + 4 + 8)
                .order(ByteOrder.BIG_ENDIAN);
        buf.put(magic);
        buf.putInt(generation);
        buf.put(kind);
        buf.putInt(account);
        buf.putLong(recordId);
        return buf.array();
    }

    public static byte[] encryptText(String text, SecureSavedMessagesKeyStore.KeyMaterial key) {
        if (text == null || text.isEmpty() || key == null) {
            throw new IllegalArgumentException("Saved Messages text and key are required");
        }
        byte[] plaintext = text.getBytes(StandardCharsets.UTF_8);
        if (plaintext.length > MAX_TEXT_BYTES) {
            throw new IllegalArgumentException("Saved Messages text is too large");
        }
        return encryptRecord(plaintext, key, SecureSavedMessagesPolicy.ContentKind.TEXT);
    }

    /** Encrypts an encoded text/media record for the account's own Saved Messages. */
    public static byte[] encryptRecord(byte[] plaintext, SecureSavedMessagesKeyStore.KeyMaterial key) {
        SecureSavedMessagesPolicy.ContentKind kind = SecureSavedMessagesPolicy.ContentKind.PHOTO;
        try {
            SecureContentCodec.Decoded decoded = SecureContentCodec.decode(plaintext);
            if (decoded.type == SecureContentCodec.TYPE_TEXT) {
                kind = SecureSavedMessagesPolicy.ContentKind.TEXT;
            }
        } catch (Exception ignored) {
        }
        return encryptRecord(plaintext, key, kind);
    }

    public static byte[] encryptRecord(byte[] plaintext, SecureSavedMessagesKeyStore.KeyMaterial key,
            SecureSavedMessagesPolicy.ContentKind kind) {
        return encryptRecord(plaintext, key, kind, RANDOM.nextLong());
    }

    public static byte[] encryptRecord(byte[] plaintext, SecureSavedMessagesKeyStore.KeyMaterial key,
            SecureSavedMessagesPolicy.ContentKind kind, long recordId) {
        if (plaintext == null || plaintext.length == 0 || key == null) {
            throw new IllegalArgumentException("Saved Messages plaintext and key are required");
        }
        if (plaintext.length > MAX_TEXT_BYTES) {
            throw new IllegalArgumentException("Saved Messages record is too large");
        }
        byte[] nonce = new byte[NONCE_BYTES];
        RANDOM.nextBytes(nonce);
        byte kindByte = (byte) kind.ordinal();
        byte[] aad = buildAad(MAGIC_V2, key.generation, kindByte, key.account, recordId);
        byte[] ciphertext = crypt(javax.crypto.Cipher.ENCRYPT_MODE, plaintext, nonce, key.key, aad);

        ByteBuffer out = ByteBuffer.allocate(MAGIC_V2.length + 4 + 1 + 4 + 8 + NONCE_BYTES + ciphertext.length)
                .order(ByteOrder.BIG_ENDIAN);
        out.put(MAGIC_V2)
           .putInt(key.generation)
           .put(kindByte)
           .putInt(key.account)
           .putLong(recordId)
           .put(nonce)
           .put(ciphertext);
        return out.array();
    }

    public static String decryptText(byte[] record, SecureSavedMessagesKeyStore.KeyMaterial key) {
        byte[] plaintext = decryptRecordInternal(record, key, true);
        return new String(plaintext, StandardCharsets.UTF_8);
    }

    public static byte[] decryptRecord(byte[] record, SecureSavedMessagesKeyStore.KeyMaterial key) {
        return decryptRecordInternal(record, key, false);
    }

    private static byte[] decryptRecordInternal(byte[] record, SecureSavedMessagesKeyStore.KeyMaterial key,
            boolean isText) {
        if (record == null || key == null || record.length < MAGIC.length + 4 + 1 + NONCE_BYTES + TAG_BYTES) {
            throw new IllegalArgumentException("Saved Messages record is truncated");
        }
        ByteBuffer in = ByteBuffer.wrap(record).order(ByteOrder.BIG_ENDIAN);
        byte[] magic = new byte[4];
        in.get(magic);
        int generation = in.getInt();
        if (generation != key.generation) {
            throw new IllegalArgumentException("Saved Messages record generation mismatch");
        }
        int kind = in.get() & 0xff;

        byte[] nonce = new byte[NONCE_BYTES];
        byte[] aad;

        if (Arrays.equals(MAGIC_V2, magic)) {
            if (record.length < MAGIC_V2.length + 4 + 1 + 4 + 8 + NONCE_BYTES + TAG_BYTES) {
                throw new IllegalArgumentException("Saved Messages v2 record is truncated");
            }
            int account = in.getInt();
            if (key.account > 0 && account != 0 && key.account != account) {
                throw new IllegalArgumentException("Saved Messages record account mismatch");
            }
            long recordId = in.getLong();
            in.get(nonce);
            aad = buildAad(MAGIC_V2, generation, (byte) kind, account, recordId);
        } else if (Arrays.equals(MAGIC, magic)) {
            in.get(nonce);
            aad = legacyAad(generation);
        } else {
            throw new IllegalArgumentException("invalid Saved Messages magic");
        }

        if (isText) {
            if (kind != SecureSavedMessagesPolicy.ContentKind.TEXT.ordinal()
                    && kind != SecureSavedMessagesPolicy.ContentKind.PHOTO.ordinal()) {
                throw new IllegalArgumentException("Saved Messages text record kind mismatch");
            }
        } else {
            if (kind == SecureSavedMessagesPolicy.ContentKind.TEXT.ordinal()) {
                throw new IllegalArgumentException("Saved Messages media record mismatch");
            }
        }

        byte[] ciphertext = new byte[in.remaining()];
        in.get(ciphertext);

        byte[] plaintext = crypt(javax.crypto.Cipher.DECRYPT_MODE, ciphertext, nonce, key.key, aad);
        if (plaintext.length == 0 || plaintext.length > MAX_TEXT_BYTES) {
            throw new IllegalArgumentException("Saved Messages plaintext is invalid");
        }
        return plaintext;
    }

    public static String encryptTextCarrier(
            String text, SecureSavedMessagesKeyStore.KeyMaterial key) {
        return SecureCarrierCodec.encode(
                SecureCarrierCodec.TYPE_SAVED_MESSAGE, encryptText(text, key));
    }

    public static String decryptTextCarrier(
            String carrier, SecureSavedMessagesKeyStore.KeyMaterial key) {
        SecureCarrierCodec.Decoded decoded = SecureCarrierCodec.decode(carrier);
        if (decoded == null || decoded.type != SecureCarrierCodec.TYPE_SAVED_MESSAGE) {
            throw new IllegalArgumentException("not a Saved Messages carrier");
        }
        return decryptText(decoded.payload, key);
    }

    private static byte[] crypt(int mode, byte[] input, byte[] nonce, byte[] rawKey, byte[] aad) {
        try {
            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(mode, new javax.crypto.spec.SecretKeySpec(rawKey, "AES"),
                    new javax.crypto.spec.GCMParameterSpec(TAG_BYTES * 8, nonce));
            cipher.updateAAD(aad);
            return cipher.doFinal(input);
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("Saved Messages authentication failed", e);
        }
    }

    private static byte[] legacyAad(int generation) {
        return ("Fork-Secure/Saved-Messages/v1/" + generation).getBytes(StandardCharsets.US_ASCII);
    }
}
