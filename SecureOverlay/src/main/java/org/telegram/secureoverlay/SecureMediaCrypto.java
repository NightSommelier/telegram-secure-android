package org.telegram.secureoverlay;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** Per-file authenticated encryption used before media bytes enter Telegram transport. */
public final class SecureMediaCrypto {
    public static final int MAX_STATIC_STICKER_BYTES = 1024 * 1024;
    /** Streaming attachment ceiling for the local MVP (Telegram documents can be much larger). */
    public static final int MAX_ATTACHMENT_BYTES = 512 * 1024 * 1024;
    public static final int GCM_TAG_BYTES = 16;
    private static final int KEY_BYTES = 32;
    private static final int NONCE_BYTES = 12;
    private static final byte[] STICKER_AAD_PREFIX =
            new byte[] {'F', 'S', 'C', '1', 'S', 'T', 'I', 'C', 'K', 'E', 'R'};
    private static final byte[] ATTACHMENT_AAD_PREFIX =
            new byte[] {'F', 'S', 'C', '1', 'A', 'T', 'T', 'A', 'C', 'H'};

    private SecureMediaCrypto() {}

    public static EncryptedStaticSticker encryptStaticSticker(
            byte[] webp, int width, int height, String emoji) {
        return encryptSticker(
                webp,
                width,
                height,
                emoji,
                SecureContentCodec.STICKER_FORMAT_WEBP);
    }

    public static EncryptedStaticSticker encryptSticker(
            byte[] plaintext, int width, int height, String emoji, int format) {
        if (!matchesStickerFormat(plaintext, format)
                || plaintext.length > MAX_STATIC_STICKER_BYTES) {
            throw new IllegalArgumentException("secure sticker bytes do not match their format");
        }
        byte[] mediaId = randomBytes(16);
        byte[] key = randomBytes(KEY_BYTES);
        byte[] nonce = randomBytes(NONCE_BYTES);
        byte[] ciphertext = crypt(Cipher.ENCRYPT_MODE, plaintext, key, nonce, format);
        SecureContentCodec.StaticSticker manifest = new SecureContentCodec.StaticSticker(
                mediaId,
                key,
                nonce,
                sha256(ciphertext),
                plaintext.length,
                ciphertext.length,
                width,
                height,
                emoji,
                format);
        // Validate all caller-provided dimensions and metadata before returning ciphertext.
        SecureContentCodec.encodeSticker(manifest);
        return new EncryptedStaticSticker(ciphertext, manifest);
    }

    public static SecureContentCodec.StaticSticker encryptStaticStickerFile(
            File source, File destination, int width, int height, String emoji) {
        return encryptStickerFile(
                source,
                destination,
                width,
                height,
                emoji,
                SecureContentCodec.STICKER_FORMAT_WEBP);
    }

    public static SecureContentCodec.StaticSticker encryptStickerFile(
            File source,
            File destination,
            int width,
            int height,
            String emoji,
            int format) {
        if (source == null || destination == null || !source.isFile()) {
            throw new IllegalArgumentException("secure sticker source is unavailable");
        }
        byte[] plaintext = readBounded(source, MAX_STATIC_STICKER_BYTES);
        EncryptedStaticSticker encrypted =
                encryptSticker(plaintext, width, height, emoji, format);
        File parent = destination.getParentFile();
        if (parent == null || (!parent.isDirectory() && !parent.mkdirs())) {
            throw new SecureMediaException("cannot create secure media directory", null);
        }
        File temporary = new File(destination.getAbsolutePath() + ".tmp");
        try (FileOutputStream output = new FileOutputStream(temporary, false)) {
            output.write(encrypted.ciphertext);
            output.getFD().sync();
        } catch (IOException e) {
            temporary.delete();
            throw new SecureMediaException("cannot persist encrypted secure media", e);
        }
        if (!temporary.renameTo(destination)) {
            temporary.delete();
            throw new SecureMediaException("cannot finalize encrypted secure media", null);
        }
        return encrypted.manifest;
    }

    public static byte[] decryptStaticSticker(
            byte[] ciphertext, SecureContentCodec.StaticSticker manifest) {
        if (ciphertext == null
                || manifest == null
                || ciphertext.length != manifest.ciphertextSize
                || !MessageDigest.isEqual(sha256(ciphertext), manifest.ciphertextSha256)) {
            throw new IllegalArgumentException("secure sticker ciphertext does not match manifest");
        }
        final byte[] plaintext;
        try {
            plaintext = crypt(
                    Cipher.DECRYPT_MODE,
                    ciphertext,
                    manifest.key,
                    manifest.nonce,
                    manifest.format);
        } catch (SecureMediaException e) {
            if (e.getCause() instanceof AEADBadTagException) {
                throw new IllegalArgumentException("secure sticker authentication failed", e);
            }
            throw e;
        }
        if (plaintext.length != manifest.plaintextSize
                || !matchesStickerFormat(plaintext, manifest.format)) {
            throw new IllegalArgumentException("secure sticker plaintext is invalid");
        }
        return plaintext;
    }

    public static void decryptStickerFile(
            File ciphertextFile,
            File destination,
            SecureContentCodec.StaticSticker manifest) {
        if (ciphertextFile == null || destination == null || !ciphertextFile.isFile()) {
            throw new IllegalArgumentException("secure sticker ciphertext is unavailable");
        }
        byte[] ciphertext = readBounded(
                ciphertextFile, MAX_STATIC_STICKER_BYTES + GCM_TAG_BYTES);
        byte[] plaintext = decryptStaticSticker(ciphertext, manifest);
        File parent = destination.getParentFile();
        if (parent == null || (!parent.isDirectory() && !parent.mkdirs())) {
            throw new SecureMediaException("cannot create decrypted media directory", null);
        }
        File temporary = new File(destination.getAbsolutePath() + ".tmp");
        try (FileOutputStream output = new FileOutputStream(temporary, false)) {
            output.write(plaintext);
            output.getFD().sync();
        } catch (IOException e) {
            temporary.delete();
            throw new SecureMediaException("cannot persist decrypted secure media", e);
        }
        if (destination.exists() && !destination.delete()) {
            temporary.delete();
            throw new SecureMediaException("cannot replace decrypted secure media", null);
        }
        if (!temporary.renameTo(destination)) {
            temporary.delete();
            throw new SecureMediaException("cannot finalize decrypted secure media", null);
        }
    }

    public static SecureContentCodec.Attachment encryptAttachmentFile(
            File source,
            File destination,
            String fileName,
            String mimeType,
            String caption,
            int width,
            int height,
            boolean photo) {
        return encryptAttachmentFile(
                source,
                destination,
                fileName,
                mimeType,
                caption,
                width,
                height,
                photo,
                photo
                        ? SecureContentCodec.ATTACHMENT_PRESENTATION_FILE
                        : mimeType != null && mimeType.startsWith("video/")
                                ? SecureContentCodec.ATTACHMENT_PRESENTATION_VIDEO
                                : mimeType != null && mimeType.startsWith("audio/")
                                        ? SecureContentCodec.ATTACHMENT_PRESENTATION_AUDIO
                                        : SecureContentCodec.ATTACHMENT_PRESENTATION_FILE,
                0,
                "",
                "");
    }

    public static SecureContentCodec.Attachment encryptAttachmentFile(
            File source,
            File destination,
            String fileName,
            String mimeType,
            String caption,
            int width,
            int height,
            boolean photo,
            int presentation,
            int durationSeconds,
            String title,
            String performer) {
        if (source == null || destination == null || !source.isFile()) {
            throw new IllegalArgumentException("secure attachment source is unavailable");
        }
        long sourceSize = source.length();
        if (sourceSize <= 0 || sourceSize > MAX_ATTACHMENT_BYTES) {
            throw new IllegalArgumentException("secure attachment size is invalid");
        }
        byte[] mediaId = randomBytes(16);
        byte[] key = randomBytes(KEY_BYTES);
        byte[] nonce = randomBytes(NONCE_BYTES);
        SecureContentCodec.encodeAttachment(new SecureContentCodec.Attachment(
                mediaId,
                key,
                nonce,
                new byte[32],
                (int) sourceSize,
                (int) sourceSize + GCM_TAG_BYTES,
                fileName,
                mimeType,
                caption,
                width,
                height,
                photo,
                presentation,
                durationSeconds,
                title,
                performer));
        File parent = destination.getParentFile();
        if (parent == null || (!parent.isDirectory() && !parent.mkdirs())) {
            throw new SecureMediaException("cannot create secure attachment directory", null);
        }
        File temporary = new File(destination.getAbsolutePath() + ".tmp");
        MessageDigest digest = newSha256();
        long plaintextBytes = 0;
        long ciphertextBytes = 0;
        try (FileInputStream input = new FileInputStream(source);
                FileOutputStream output = new FileOutputStream(temporary, false)) {
            Cipher cipher = createAttachmentCipher(
                    Cipher.ENCRYPT_MODE, key, nonce, photo);
            byte[] buffer = new byte[64 * 1024];
            int count;
            while ((count = input.read(buffer)) != -1) {
                plaintextBytes += count;
                if (plaintextBytes > MAX_ATTACHMENT_BYTES) {
                    throw new IllegalArgumentException(
                            "secure attachment exceeds size limit");
                }
                byte[] encrypted = cipher.update(buffer, 0, count);
                if (encrypted != null && encrypted.length != 0) {
                    output.write(encrypted);
                    digest.update(encrypted);
                    ciphertextBytes += encrypted.length;
                }
            }
            byte[] finalBytes = cipher.doFinal();
            output.write(finalBytes);
            digest.update(finalBytes);
            ciphertextBytes += finalBytes.length;
            output.getFD().sync();
        } catch (IllegalArgumentException e) {
            temporary.delete();
            throw e;
        } catch (IOException | GeneralSecurityException e) {
            temporary.delete();
            throw new SecureMediaException("cannot encrypt secure attachment", e);
        }
        if (plaintextBytes != sourceSize
                || ciphertextBytes != plaintextBytes + GCM_TAG_BYTES
                || plaintextBytes > Integer.MAX_VALUE
                || ciphertextBytes > Integer.MAX_VALUE) {
            temporary.delete();
            throw new SecureMediaException("secure attachment size changed while reading", null);
        }
        if (!temporary.renameTo(destination)) {
            temporary.delete();
            throw new SecureMediaException("cannot finalize encrypted attachment", null);
        }
        SecureContentCodec.Attachment manifest = new SecureContentCodec.Attachment(
                mediaId,
                key,
                nonce,
                digest.digest(),
                (int) plaintextBytes,
                (int) ciphertextBytes,
                fileName,
                mimeType,
                caption,
                width,
                height,
                photo,
                presentation,
                durationSeconds,
                title,
                performer);
        // Validate all metadata before a carrier can be produced.
        SecureContentCodec.encodeAttachment(manifest);
        return manifest;
    }

    public static void decryptAttachmentFile(
            File ciphertextFile,
            File destination,
            SecureContentCodec.Attachment manifest) {
        if (ciphertextFile == null
                || destination == null
                || manifest == null
                || !ciphertextFile.isFile()
                || ciphertextFile.length() != manifest.ciphertextSize
                || !MessageDigest.isEqual(
                        sha256File(
                                ciphertextFile,
                                MAX_ATTACHMENT_BYTES + GCM_TAG_BYTES),
                        manifest.ciphertextSha256)) {
            throw new IllegalArgumentException(
                    "secure attachment ciphertext does not match manifest");
        }
        File parent = destination.getParentFile();
        if (parent == null || (!parent.isDirectory() && !parent.mkdirs())) {
            throw new SecureMediaException("cannot create decrypted attachment directory", null);
        }
        File temporary = new File(destination.getAbsolutePath() + ".tmp");
        long plaintextBytes = 0;
        try (FileInputStream input = new FileInputStream(ciphertextFile);
                FileOutputStream output = new FileOutputStream(temporary, false)) {
            Cipher cipher = createAttachmentCipher(
                    Cipher.DECRYPT_MODE, manifest.key, manifest.nonce, manifest.photo);
            byte[] buffer = new byte[64 * 1024];
            int count;
            while ((count = input.read(buffer)) != -1) {
                byte[] decrypted = cipher.update(buffer, 0, count);
                if (decrypted != null && decrypted.length != 0) {
                    output.write(decrypted);
                    plaintextBytes += decrypted.length;
                    if (plaintextBytes > manifest.plaintextSize) {
                        throw new IllegalArgumentException(
                                "secure attachment plaintext exceeds manifest");
                    }
                }
            }
            byte[] finalBytes = cipher.doFinal();
            output.write(finalBytes);
            plaintextBytes += finalBytes.length;
            output.getFD().sync();
        } catch (AEADBadTagException e) {
            temporary.delete();
            throw new IllegalArgumentException(
                    "secure attachment authentication failed", e);
        } catch (IllegalArgumentException e) {
            temporary.delete();
            throw e;
        } catch (IOException | GeneralSecurityException e) {
            temporary.delete();
            throw new SecureMediaException("cannot decrypt secure attachment", e);
        }
        if (plaintextBytes != manifest.plaintextSize) {
            temporary.delete();
            throw new IllegalArgumentException("secure attachment plaintext size is invalid");
        }
        if (destination.exists() && !destination.delete()) {
            temporary.delete();
            throw new SecureMediaException("cannot replace decrypted attachment", null);
        }
        if (!temporary.renameTo(destination)) {
            temporary.delete();
            throw new SecureMediaException("cannot finalize decrypted attachment", null);
        }
    }

    private static byte[] crypt(
            int mode, byte[] input, byte[] key, byte[] nonce, int format) {
        if (key == null || key.length != KEY_BYTES || nonce == null || nonce.length != NONCE_BYTES) {
            throw new IllegalArgumentException("invalid secure media key material");
        }
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(mode, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
            cipher.updateAAD(STICKER_AAD_PREFIX);
            cipher.updateAAD(new byte[] {(byte) format});
            return cipher.doFinal(input);
        } catch (GeneralSecurityException e) {
            throw new SecureMediaException("secure media cryptography failed", e);
        }
    }

    private static Cipher createAttachmentCipher(
            int mode, byte[] key, byte[] nonce, boolean photo)
            throws GeneralSecurityException {
        if (key == null || key.length != KEY_BYTES || nonce == null || nonce.length != NONCE_BYTES) {
            throw new IllegalArgumentException("invalid secure attachment key material");
        }
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(mode, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        cipher.updateAAD(ATTACHMENT_AAD_PREFIX);
        cipher.updateAAD(new byte[] {(byte) (photo ? 1 : 0)});
        return cipher;
    }

    private static boolean isStaticWebp(byte[] value) {
        return value != null
                && value.length >= 12
                && value[0] == 'R'
                && value[1] == 'I'
                && value[2] == 'F'
                && value[3] == 'F'
                && value[8] == 'W'
                && value[9] == 'E'
                && value[10] == 'B'
                && value[11] == 'P';
    }

    private static boolean isAnimatedTgs(byte[] value) {
        return value != null
                && value.length >= 2
                && (value[0] & 0xff) == 0x1f
                && (value[1] & 0xff) == 0x8b;
    }

    private static boolean isVideoWebm(byte[] value) {
        return value != null
                && value.length >= 4
                && (value[0] & 0xff) == 0x1a
                && (value[1] & 0xff) == 0x45
                && (value[2] & 0xff) == 0xdf
                && (value[3] & 0xff) == 0xa3;
    }

    private static boolean matchesStickerFormat(byte[] value, int format) {
        if (format == SecureContentCodec.STICKER_FORMAT_WEBP) {
            return isStaticWebp(value);
        }
        if (format == SecureContentCodec.STICKER_FORMAT_TGS) {
            return isAnimatedTgs(value);
        }
        if (format == SecureContentCodec.STICKER_FORMAT_WEBM) {
            return isVideoWebm(value);
        }
        return false;
    }

    private static byte[] randomBytes(int count) {
        byte[] value = new byte[count];
        new SecureRandom().nextBytes(value);
        return value;
    }

    private static byte[] readBounded(File source, int maximum) {
        long size = source.length();
        if (size <= 0 || size > maximum) {
            throw new IllegalArgumentException("secure media size is invalid");
        }
        try (FileInputStream input = new FileInputStream(source);
                ByteArrayOutputStream output = new ByteArrayOutputStream((int) size)) {
            byte[] buffer = new byte[16 * 1024];
            int count;
            while ((count = input.read(buffer)) != -1) {
                if (output.size() + count > maximum) {
                    throw new IllegalArgumentException("secure media exceeds size limit");
                }
                output.write(buffer, 0, count);
            }
            return output.toByteArray();
        } catch (IOException e) {
            throw new SecureMediaException("cannot read secure media", e);
        }
    }

    private static byte[] sha256(byte[] value) {
        return newSha256().digest(value);
    }

    private static byte[] sha256File(File source, int maximum) {
        long size = source.length();
        if (size <= 0 || size > maximum) {
            throw new IllegalArgumentException("secure media size is invalid");
        }
        MessageDigest digest = newSha256();
        try (FileInputStream input = new FileInputStream(source)) {
            byte[] buffer = new byte[64 * 1024];
            int count;
            long total = 0;
            while ((count = input.read(buffer)) != -1) {
                total += count;
                if (total > maximum) {
                    throw new IllegalArgumentException("secure media exceeds size limit");
                }
                digest.update(buffer, 0, count);
            }
            return digest.digest();
        } catch (IOException e) {
            throw new SecureMediaException("cannot hash secure media", e);
        }
    }

    private static MessageDigest newSha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
    }

    public static final class EncryptedStaticSticker {
        public final byte[] ciphertext;
        public final SecureContentCodec.StaticSticker manifest;

        private EncryptedStaticSticker(
                byte[] ciphertext, SecureContentCodec.StaticSticker manifest) {
            this.ciphertext = Arrays.copyOf(ciphertext, ciphertext.length);
            this.manifest = manifest;
        }
    }

    public static final class SecureMediaException extends RuntimeException {
        SecureMediaException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
