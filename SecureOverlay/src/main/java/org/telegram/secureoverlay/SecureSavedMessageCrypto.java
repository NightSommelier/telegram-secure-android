package org.telegram.secureoverlay;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/** Small authenticated record codec for Saved Messages text; Telegram adapters are separate. */
public final class SecureSavedMessageCrypto {
    private static final byte[] MAGIC = new byte[] {'F', 'S', 'M', '1'};
    private static final int NONCE_BYTES = 12;
    private static final int TAG_BYTES = 16;
    private static final int MAX_TEXT_BYTES = 16 * 1024;

    private SecureSavedMessageCrypto() {
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
        return encryptRecord(plaintext, key, SecureSavedMessagesPolicy.ContentKind.PHOTO);
    }

    private static byte[] encryptRecord(byte[] plaintext, SecureSavedMessagesKeyStore.KeyMaterial key,
            SecureSavedMessagesPolicy.ContentKind kind) {
        if (plaintext == null || plaintext.length == 0 || key == null) {
            throw new IllegalArgumentException("Saved Messages plaintext and key are required");
        }
        if (plaintext.length > MAX_TEXT_BYTES) {
            throw new IllegalArgumentException("Saved Messages record is too large");
        }
        byte[] nonce = new byte[NONCE_BYTES];
        new java.security.SecureRandom().nextBytes(nonce);
        byte[] ciphertext = crypt(javax.crypto.Cipher.ENCRYPT_MODE, plaintext, nonce, key, key.generation);
        ByteBuffer out = ByteBuffer.allocate(MAGIC.length + 4 + 1 + NONCE_BYTES + ciphertext.length)
                .order(ByteOrder.BIG_ENDIAN);
        out.put(MAGIC).putInt(key.generation).put((byte) kind.ordinal()).put(nonce).put(ciphertext);
        return out.array();
    }

    public static String decryptText(byte[] record, SecureSavedMessagesKeyStore.KeyMaterial key) {
        if (record == null || key == null || record.length < MAGIC.length + 4 + 1 + NONCE_BYTES + TAG_BYTES) {
            throw new IllegalArgumentException("Saved Messages record is truncated");
        }
        ByteBuffer in = ByteBuffer.wrap(record).order(ByteOrder.BIG_ENDIAN);
        byte[] magic = new byte[MAGIC.length];
        in.get(magic);
        int generation = in.getInt();
        int kind = in.get() & 0xff;
        byte[] nonce = new byte[NONCE_BYTES];
        in.get(nonce);
        byte[] ciphertext = new byte[in.remaining()];
        in.get(ciphertext);
        if (!Arrays.equals(MAGIC, magic) || generation != key.generation
                || (kind != SecureSavedMessagesPolicy.ContentKind.TEXT.ordinal()
                && kind != SecureSavedMessagesPolicy.ContentKind.PHOTO.ordinal())) {
            throw new IllegalArgumentException("Saved Messages record generation or kind mismatch");
        }
        byte[] plaintext = crypt(javax.crypto.Cipher.DECRYPT_MODE, ciphertext, nonce, key, generation);
        if (plaintext.length == 0 || plaintext.length > MAX_TEXT_BYTES) {
            throw new IllegalArgumentException("Saved Messages plaintext is invalid");
        }
        return new String(plaintext, StandardCharsets.UTF_8);
    }

    public static byte[] decryptRecord(byte[] record, SecureSavedMessagesKeyStore.KeyMaterial key) {
        if (record == null || key == null || record.length < MAGIC.length + 4 + 1 + NONCE_BYTES + TAG_BYTES) {
            throw new IllegalArgumentException("Saved Messages record is truncated");
        }
        ByteBuffer in = ByteBuffer.wrap(record).order(ByteOrder.BIG_ENDIAN);
        byte[] magic = new byte[MAGIC.length];
        in.get(magic);
        int generation = in.getInt();
        int kind = in.get() & 0xff;
        byte[] nonce = new byte[NONCE_BYTES];
        in.get(nonce);
        byte[] ciphertext = new byte[in.remaining()];
        in.get(ciphertext);
        if (!Arrays.equals(MAGIC, magic) || generation != key.generation
                || kind == SecureSavedMessagesPolicy.ContentKind.TEXT.ordinal()) {
            throw new IllegalArgumentException("Saved Messages media record mismatch");
        }
        return crypt(javax.crypto.Cipher.DECRYPT_MODE, ciphertext, nonce, key, generation);
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

    private static byte[] crypt(int mode, byte[] input, byte[] nonce,
            SecureSavedMessagesKeyStore.KeyMaterial key, int generation) {
        try {
            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(mode, new javax.crypto.spec.SecretKeySpec(key.key, "AES"),
                    new javax.crypto.spec.GCMParameterSpec(TAG_BYTES * 8, nonce));
            cipher.updateAAD(aad(generation));
            return cipher.doFinal(input);
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("Saved Messages authentication failed", e);
        }
    }

    private static byte[] aad(int generation) {
        return ("Fork-Secure/Saved-Messages/v1/" + generation).getBytes(StandardCharsets.US_ASCII);
    }
}
