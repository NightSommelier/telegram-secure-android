package org.telegram.secureoverlay;

import java.io.File;
import java.nio.ByteBuffer;
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
    /**
     * Animated and video stickers legitimately exceed one MiB. Keep a bounded ceiling while
     * processing files in fixed-size chunks so a sticker-panel tap cannot duplicate the whole
     * file in the application heap.
     */
    public static final int MAX_STATIC_STICKER_BYTES = 8 * 1024 * 1024;
    /** Streaming attachment ceiling for the local MVP (Telegram documents can be much larger). */
    public static final int MAX_ATTACHMENT_BYTES = 512 * 1024 * 1024;
    public static final int SEGMENT_SIZE = 64 * 1024;
    public static final int GCM_TAG_BYTES = 16;
    public static final int MAX_ATTACHMENT_CIPHERTEXT_BYTES =
            MAX_ATTACHMENT_BYTES + (MAX_ATTACHMENT_BYTES / SEGMENT_SIZE + 1) * GCM_TAG_BYTES;
    private static final int KEY_BYTES = 32;
    private static final int NONCE_BYTES = 12;
    private static final byte[] STICKER_AAD_PREFIX =
            new byte[] {'F', 'S', 'C', '1', 'S', 'T', 'I', 'C', 'K', 'E', 'R'};
    private static final byte[] ATTACHMENT_AAD_PREFIX =
            new byte[] {'F', 'S', 'C', '1', 'A', 'T', 'T', 'A', 'C', 'H'};

    private SecureMediaCrypto() {}

    /**
     * Computes the padded length using the Padmé (PURB) padding algorithm.
     * Hides exact payload lengths with at most 12% space overhead for small payloads,
     * dropping below 6% for larger files.
     */
    public static int padmeSize(int length) {
        if (length <= 0) {
            throw new IllegalArgumentException("invalid length: " + length);
        }
        final int minSize = 256;
        if (length <= minSize) {
            return minSize;
        }
        int e = 31 - Integer.numberOfLeadingZeros(length);
        int s = 31 - Integer.numberOfLeadingZeros(e) + 1;
        int lastBits = e - s;
        long mask = (1L << lastBits) - 1L;
        long padded = ((long) length + mask) & ~mask;
        if (padded > Integer.MAX_VALUE) {
            throw new IllegalArgumentException("padded size exceeds integer max");
        }
        return (int) padded;
    }

    public static int calculateSegmentedCiphertextSize(long plaintextSize) {
        if (plaintextSize <= 0 || plaintextSize > MAX_ATTACHMENT_BYTES) {
            throw new IllegalArgumentException("invalid plaintext size: " + plaintextSize);
        }
        int targetPaddedPlaintextSize = padmeSize((int) plaintextSize);
        int numSegments = (targetPaddedPlaintextSize + SEGMENT_SIZE - 1) / SEGMENT_SIZE;
        if (numSegments <= 0) {
            numSegments = 1;
        }
        long totalCiphertext = (long) targetPaddedPlaintextSize + ((long) numSegments * GCM_TAG_BYTES);
        if (totalCiphertext > Integer.MAX_VALUE) {
            throw new IllegalArgumentException("ciphertext size exceeds integer max");
        }
        return (int) totalCiphertext;
    }

    private static byte[] deriveSegmentNonce(byte[] baseNonce, int segmentIndex, boolean isLast) {
        ByteBuffer nonceBuf = ByteBuffer.allocate(NONCE_BYTES);
        nonceBuf.put(baseNonce, 0, 7);
        nonceBuf.putInt(segmentIndex);
        nonceBuf.put((byte) (isLast ? 1 : 0));
        return nonceBuf.array();
    }

    private static byte[] deriveSegmentAad(boolean photo, int segmentIndex, boolean isLast) {
        ByteBuffer aadBuf = ByteBuffer.allocate(ATTACHMENT_AAD_PREFIX.length + 1 + 4 + 1);
        aadBuf.put(ATTACHMENT_AAD_PREFIX);
        aadBuf.put((byte) (photo ? 1 : 0));
        aadBuf.putInt(segmentIndex);
        aadBuf.put((byte) (isLast ? 1 : 0));
        return aadBuf.array();
    }

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
        source = requireSafeFile(source, "source");
        destination = requireSafeFile(destination, "destination");
        if (!source.isFile()) {
            throw new IllegalArgumentException("secure sticker source is unavailable");
        }
        long sourceSize = source.length();
        if (sourceSize <= 0 || sourceSize > MAX_STATIC_STICKER_BYTES
                || !matchesStickerFormat(source, format)) {
            throw new IllegalArgumentException("secure sticker bytes do not match their format");
        }
        byte[] mediaId = randomBytes(16);
        byte[] key = randomBytes(KEY_BYTES);
        byte[] nonce = randomBytes(NONCE_BYTES);
        // Validate caller-supplied dimensions and metadata before writing any encrypted bytes.
        SecureContentCodec.encodeSticker(new SecureContentCodec.StaticSticker(
                mediaId,
                key,
                nonce,
                new byte[32],
                (int) sourceSize,
                (int) sourceSize + GCM_TAG_BYTES,
                width,
                height,
                emoji,
                format));
        File temporary = createSafeTemporaryFile(destination);
        MessageDigest digest = newSha256();
        long plaintextBytes = 0;
        long ciphertextBytes = 0;
        try (FileInputStream input = new FileInputStream(source);
                FileOutputStream output = new FileOutputStream(temporary, false)) {
            Cipher cipher = createStickerCipher(Cipher.ENCRYPT_MODE, key, nonce, format);
            byte[] buffer = new byte[64 * 1024];
            int count;
            while ((count = input.read(buffer)) != -1) {
                plaintextBytes += count;
                if (plaintextBytes > MAX_STATIC_STICKER_BYTES) {
                    throw new IllegalArgumentException("secure sticker exceeds size limit");
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
            throw new SecureMediaException("cannot encrypt secure sticker", e);
        }
        if (plaintextBytes != sourceSize
                || ciphertextBytes != plaintextBytes + GCM_TAG_BYTES) {
            temporary.delete();
            throw new SecureMediaException("secure sticker size changed while reading", null);
        }
        if (!temporary.renameTo(destination)) {
            temporary.delete();
            throw new SecureMediaException("cannot finalize encrypted secure media", null);
        }
        SecureContentCodec.StaticSticker manifest = new SecureContentCodec.StaticSticker(
                mediaId,
                key,
                nonce,
                digest.digest(),
                (int) plaintextBytes,
                (int) ciphertextBytes,
                width,
                height,
                emoji,
                format);
        SecureContentCodec.encodeSticker(manifest);
        return manifest;
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
        ciphertextFile = requireSafeFile(ciphertextFile, "ciphertextFile");
        destination = requireSafeFile(destination, "destination");
        if (!ciphertextFile.isFile()) {
            throw new IllegalArgumentException("secure sticker ciphertext is unavailable");
        }
        if (manifest == null
                || ciphertextFile.length() != manifest.ciphertextSize
                || !MessageDigest.isEqual(
                        sha256File(ciphertextFile, MAX_STATIC_STICKER_BYTES + GCM_TAG_BYTES),
                        manifest.ciphertextSha256)) {
            throw new IllegalArgumentException("secure sticker ciphertext does not match manifest");
        }
        File temporary = createSafeTemporaryFile(destination);
        long plaintextBytes = 0;
        try (FileInputStream input = new FileInputStream(ciphertextFile);
                FileOutputStream output = new FileOutputStream(temporary, false)) {
            Cipher cipher = createStickerCipher(
                    Cipher.DECRYPT_MODE, manifest.key, manifest.nonce, manifest.format);
            byte[] buffer = new byte[64 * 1024];
            int count;
            while ((count = input.read(buffer)) != -1) {
                byte[] decrypted = cipher.update(buffer, 0, count);
                if (decrypted != null && decrypted.length != 0) {
                    output.write(decrypted);
                    plaintextBytes += decrypted.length;
                    if (plaintextBytes > manifest.plaintextSize) {
                        throw new IllegalArgumentException(
                                "secure sticker plaintext exceeds manifest");
                    }
                }
            }
            byte[] finalBytes = cipher.doFinal();
            output.write(finalBytes);
            plaintextBytes += finalBytes.length;
            output.getFD().sync();
        } catch (AEADBadTagException e) {
            temporary.delete();
            throw new IllegalArgumentException("secure sticker authentication failed", e);
        } catch (IllegalArgumentException e) {
            temporary.delete();
            throw e;
        } catch (IOException | GeneralSecurityException e) {
            temporary.delete();
            throw new SecureMediaException("cannot decrypt secure sticker", e);
        }
        if (plaintextBytes != manifest.plaintextSize
                || !matchesStickerFormat(temporary, manifest.format)) {
            temporary.delete();
            throw new IllegalArgumentException("secure sticker plaintext is invalid");
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
        return encryptAttachmentFile(
                source,
                destination,
                fileName,
                mimeType,
                caption,
                width,
                height,
                photo,
                presentation,
                durationSeconds,
                title,
                performer,
                null);
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
            String performer,
            byte[] waveform) {
        return encryptAttachmentFile(
                source,
                destination,
                fileName,
                mimeType,
                caption,
                width,
                height,
                photo,
                presentation,
                durationSeconds,
                0,
                title,
                performer,
                waveform);
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
            int ttlSeconds,
            String title,
            String performer,
            byte[] waveform) {
        source = requireSafeFile(source, "source");
        destination = requireSafeFile(destination, "destination");
        if (!source.isFile()) {
            throw new IllegalArgumentException("secure attachment source is unavailable");
        }
        long sourceSize = source.length();
        if (sourceSize <= 0 || sourceSize > MAX_ATTACHMENT_BYTES) {
            throw new IllegalArgumentException("secure attachment size is invalid");
        }
        int targetPaddedPlaintextSize = padmeSize((int) sourceSize);
        int expectedCiphertextSize = calculateSegmentedCiphertextSize(sourceSize);
        byte[] mediaId = randomBytes(16);
        byte[] key = randomBytes(KEY_BYTES);
        byte[] nonce = randomBytes(NONCE_BYTES);
        SecureContentCodec.encodeAttachment(new SecureContentCodec.Attachment(
                mediaId,
                key,
                nonce,
                new byte[32],
                (int) sourceSize,
                expectedCiphertextSize,
                fileName,
                mimeType,
                caption,
                width,
                height,
                photo,
                presentation,
                durationSeconds,
                ttlSeconds,
                title,
                performer,
                waveform));
        File temporary = createSafeTemporaryFile(destination);
        MessageDigest digest = newSha256();
        long plaintextBytes = 0;
        long ciphertextBytes = 0;
        int numSegments = (targetPaddedPlaintextSize + SEGMENT_SIZE - 1) / SEGMENT_SIZE;
        if (numSegments <= 0) {
            numSegments = 1;
        }
        try (FileInputStream input = new FileInputStream(source);
                FileOutputStream output = new FileOutputStream(temporary, false)) {
            byte[] segmentBuffer = new byte[SEGMENT_SIZE];
            SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
            int segmentIndex = 0;
            long remainingPaddedPlaintext = targetPaddedPlaintextSize;
            long remainingFilePlaintext = sourceSize;

            while (segmentIndex < numSegments) {
                boolean isLast = (segmentIndex == numSegments - 1);
                int segmentTargetLen = isLast
                        ? (int) remainingPaddedPlaintext
                        : SEGMENT_SIZE;
                int bytesReadFromSource = 0;
                while (bytesReadFromSource < segmentTargetLen && remainingFilePlaintext > 0) {
                    int toRead = (int) Math.min((long) (segmentTargetLen - bytesReadFromSource), remainingFilePlaintext);
                    int r = input.read(segmentBuffer, bytesReadFromSource, toRead);
                    if (r == -1) {
                        break;
                    }
                    bytesReadFromSource += r;
                    remainingFilePlaintext -= r;
                    plaintextBytes += r;
                }
                if (bytesReadFromSource < segmentTargetLen) {
                    Arrays.fill(segmentBuffer, bytesReadFromSource, segmentTargetLen, (byte) 0);
                }
                byte[] segmentNonce = deriveSegmentNonce(nonce, segmentIndex, isLast);
                byte[] segmentAad = deriveSegmentAad(photo, segmentIndex, isLast);
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(128, segmentNonce));
                cipher.updateAAD(segmentAad);
                byte[] encryptedSegment = cipher.doFinal(segmentBuffer, 0, segmentTargetLen);

                output.write(encryptedSegment);
                digest.update(encryptedSegment);
                ciphertextBytes += encryptedSegment.length;
                remainingPaddedPlaintext -= segmentTargetLen;
                segmentIndex++;
            }
            output.getFD().sync();
        } catch (IllegalArgumentException e) {
            temporary.delete();
            throw e;
        } catch (IOException | GeneralSecurityException e) {
            temporary.delete();
            throw new SecureMediaException("cannot encrypt secure attachment", e);
        }
        if (plaintextBytes != sourceSize
                || ciphertextBytes != expectedCiphertextSize
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
                ttlSeconds,
                title,
                performer,
                waveform);
        SecureContentCodec.encodeAttachment(manifest);
        return manifest;
    }

    public static void decryptAttachmentFile(
            File ciphertextFile,
            File destination,
            SecureContentCodec.Attachment manifest) {
        ciphertextFile = requireSafeFile(ciphertextFile, "ciphertextFile");
        destination = requireSafeFile(destination, "destination");
        if (manifest == null
                || manifest.plaintextSize <= 0
                || manifest.plaintextSize > MAX_ATTACHMENT_BYTES
                || manifest.ciphertextSize < manifest.plaintextSize + GCM_TAG_BYTES
                || !ciphertextFile.isFile()
                || ciphertextFile.length() != manifest.ciphertextSize
                || !MessageDigest.isEqual(
                        sha256File(
                                ciphertextFile,
                                MAX_ATTACHMENT_CIPHERTEXT_BYTES),
                        manifest.ciphertextSha256)) {
            throw new IllegalArgumentException(
                    "secure attachment ciphertext does not match manifest");
        }
        int targetPaddedPlaintextSize = padmeSize(manifest.plaintextSize);
        int expectedSegmentedCiphertextSize = calculateSegmentedCiphertextSize(manifest.plaintextSize);
        int legacyPaddedCiphertextSize = targetPaddedPlaintextSize + GCM_TAG_BYTES;
        int legacyUnpaddedCiphertextSize = manifest.plaintextSize + GCM_TAG_BYTES;

        boolean isSegmented = (manifest.ciphertextSize == expectedSegmentedCiphertextSize);
        boolean isLegacy = (manifest.ciphertextSize == legacyPaddedCiphertextSize
                || manifest.ciphertextSize == legacyUnpaddedCiphertextSize);
        if (!isSegmented && !isLegacy) {
            throw new IllegalArgumentException("invalid secure attachment ciphertext size");
        }

        File temporary = createSafeTemporaryFile(destination);
        if (isSegmented) {
            decryptSegmented(ciphertextFile, temporary, destination, manifest, targetPaddedPlaintextSize);
        } else {
            decryptLegacy(ciphertextFile, temporary, destination, manifest);
        }
    }

    private static void decryptSegmented(
            File ciphertextFile,
            File temporary,
            File destination,
            SecureContentCodec.Attachment manifest,
            int targetPaddedPlaintextSize) {
        long writtenPlaintextBytes = 0;
        long totalDecryptedBytes = 0;
        int numSegments = (targetPaddedPlaintextSize + SEGMENT_SIZE - 1) / SEGMENT_SIZE;
        if (numSegments <= 0) {
            numSegments = 1;
        }
        try (FileInputStream input = new FileInputStream(ciphertextFile);
                FileOutputStream output = new FileOutputStream(temporary, false)) {
            SecretKeySpec secretKey = new SecretKeySpec(manifest.key, "AES");
            int segmentIndex = 0;
            long remainingPaddedPlaintext = targetPaddedPlaintextSize;
            while (segmentIndex < numSegments) {
                boolean isLast = (segmentIndex == numSegments - 1);
                int segmentPlaintextLen = isLast
                        ? (int) remainingPaddedPlaintext
                        : SEGMENT_SIZE;
                int segmentCiphertextLen = segmentPlaintextLen + GCM_TAG_BYTES;
                byte[] segmentCiphertext = new byte[segmentCiphertextLen];
                int totalRead = 0;
                while (totalRead < segmentCiphertextLen) {
                    int r = input.read(segmentCiphertext, totalRead, segmentCiphertextLen - totalRead);
                    if (r == -1) {
                        break;
                    }
                    totalRead += r;
                }
                if (totalRead != segmentCiphertextLen) {
                    throw new IllegalArgumentException("truncated segmented attachment ciphertext");
                }
                byte[] segmentNonce = deriveSegmentNonce(manifest.nonce, segmentIndex, isLast);
                byte[] segmentAad = deriveSegmentAad(manifest.photo, segmentIndex, isLast);
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(128, segmentNonce));
                cipher.updateAAD(segmentAad);
                byte[] decrypted = cipher.doFinal(segmentCiphertext);
                if (decrypted.length != segmentPlaintextLen) {
                    throw new IllegalArgumentException("unexpected decrypted segment size");
                }
                processDecryptedChunk(decrypted, output, manifest.plaintextSize, writtenPlaintextBytes);
                totalDecryptedBytes += decrypted.length;
                writtenPlaintextBytes = Math.min(totalDecryptedBytes, manifest.plaintextSize);
                remainingPaddedPlaintext -= segmentPlaintextLen;
                segmentIndex++;
            }
            output.getFD().sync();
        } catch (AEADBadTagException e) {
            temporary.delete();
            throw new IllegalArgumentException("secure attachment authentication failed", e);
        } catch (IllegalArgumentException e) {
            temporary.delete();
            throw e;
        } catch (IOException | GeneralSecurityException e) {
            temporary.delete();
            throw new SecureMediaException("cannot decrypt secure attachment", e);
        }
        if (writtenPlaintextBytes != manifest.plaintextSize
                || totalDecryptedBytes != targetPaddedPlaintextSize) {
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

    private static void decryptLegacy(
            File ciphertextFile,
            File temporary,
            File destination,
            SecureContentCodec.Attachment manifest) {
        int paddedPlaintextSize = manifest.ciphertextSize - GCM_TAG_BYTES;
        long writtenPlaintextBytes = 0;
        long totalDecryptedBytes = 0;
        try (FileInputStream input = new FileInputStream(ciphertextFile);
                FileOutputStream output = new FileOutputStream(temporary, false)) {
            Cipher cipher = createAttachmentCipher(
                    Cipher.DECRYPT_MODE, manifest.key, manifest.nonce, manifest.photo);
            byte[] buffer = new byte[64 * 1024];
            int count;
            while ((count = input.read(buffer)) != -1) {
                byte[] decrypted = cipher.update(buffer, 0, count);
                if (decrypted != null && decrypted.length != 0) {
                    processDecryptedChunk(
                            decrypted,
                            output,
                            manifest.plaintextSize,
                            writtenPlaintextBytes);
                    totalDecryptedBytes += decrypted.length;
                    writtenPlaintextBytes = Math.min(totalDecryptedBytes, manifest.plaintextSize);
                }
            }
            byte[] finalBytes = cipher.doFinal();
            if (finalBytes != null && finalBytes.length != 0) {
                processDecryptedChunk(
                        finalBytes,
                        output,
                        manifest.plaintextSize,
                        writtenPlaintextBytes);
                totalDecryptedBytes += finalBytes.length;
                writtenPlaintextBytes = Math.min(totalDecryptedBytes, manifest.plaintextSize);
            }
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
        if (writtenPlaintextBytes != manifest.plaintextSize
                || totalDecryptedBytes != paddedPlaintextSize) {
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

    private static void processDecryptedChunk(
            byte[] chunk,
            FileOutputStream output,
            int maxPlaintextSize,
            long currentWritten) throws IOException {
        long payloadBytesLeft = maxPlaintextSize - currentWritten;
        if (payloadBytesLeft > 0) {
            int toWrite = (int) Math.min((long) chunk.length, payloadBytesLeft);
            output.write(chunk, 0, toWrite);
            for (int i = toWrite; i < chunk.length; i++) {
                if (chunk[i] != 0) {
                    throw new IllegalArgumentException("invalid secure attachment padding byte");
                }
            }
        } else {
            for (int i = 0; i < chunk.length; i++) {
                if (chunk[i] != 0) {
                    throw new IllegalArgumentException("invalid secure attachment padding byte");
                }
            }
        }
    }

    public static File requireSafeFile(File file, File allowedRoot, String label) {
        if (file == null) {
            throw new IllegalArgumentException(label + " is null");
        }
        try {
            File canonical = file.getCanonicalFile();
            String name = canonical.getName();
            if (name.contains("..") || name.contains("/") || name.contains("\\")) {
                throw new IllegalArgumentException(label + " contains path traversal sequences");
            }
            if (allowedRoot != null) {
                File rootCanonical = allowedRoot.getCanonicalFile();
                String rootPath = rootCanonical.getPath();
                String canonicalPath = canonical.getPath();
                if (!canonicalPath.startsWith(rootPath + File.separator)
                        && !canonicalPath.equals(rootPath)) {
                    throw new IllegalArgumentException(label + " escapes allowed root directory");
                }
            } else {
                File parent = canonical.getParentFile();
                if (parent != null) {
                    String parentCanonicalPath = parent.getCanonicalPath();
                    String canonicalPath = canonical.getPath();
                    if (!canonicalPath.startsWith(parentCanonicalPath + File.separator)
                            && !canonicalPath.equals(parentCanonicalPath)) {
                        throw new IllegalArgumentException(label + " escapes parent directory");
                    }
                }
            }
            return canonical;
        } catch (IOException e) {
            throw new IllegalArgumentException("cannot resolve safe path for " + label, e);
        }
    }

    public static File requireSafeFile(File file, String label) {
        return requireSafeFile(file, null, label);
    }

    public static void purgeTemporaryFiles(File directory) {
        if (directory == null || !directory.isDirectory()) {
            return;
        }
        File[] files = directory.listFiles();
        if (files == null) {
            return;
        }
        for (File file : files) {
            if (file == null) {
                continue;
            }
            if (file.isDirectory()) {
                purgeTemporaryFiles(file);
            } else if (file.getName().endsWith(".tmp")) {
                file.delete();
            }
        }
    }

    private static File createSafeTemporaryFile(File destination) {
        File safeDestination = requireSafeFile(destination, "destination");
        File parent = safeDestination.getParentFile();
        if (parent == null || (!parent.isDirectory() && !parent.mkdirs())) {
            throw new SecureMediaException("cannot create media directory", null);
        }
        return requireSafeFile(new File(parent, safeDestination.getName() + ".tmp"), "temporary");
    }

    private static byte[] crypt(
            int mode, byte[] input, byte[] key, byte[] nonce, int format) {
        try {
            Cipher cipher = createStickerCipher(mode, key, nonce, format);
            return cipher.doFinal(input);
        } catch (GeneralSecurityException e) {
            throw new SecureMediaException("secure media cryptography failed", e);
        }
    }

    private static Cipher createStickerCipher(int mode, byte[] key, byte[] nonce, int format)
            throws GeneralSecurityException {
        if (key == null || key.length != KEY_BYTES || nonce == null || nonce.length != NONCE_BYTES) {
            throw new IllegalArgumentException("invalid secure media key material");
        }
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(mode, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        cipher.updateAAD(STICKER_AAD_PREFIX);
        cipher.updateAAD(new byte[] {(byte) format});
        return cipher;
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

    private static boolean matchesStickerFormat(File source, int format) {
        source = requireSafeFile(source, "source");
        int headerSize = format == SecureContentCodec.STICKER_FORMAT_WEBP ? 12
                : format == SecureContentCodec.STICKER_FORMAT_TGS ? 2
                : format == SecureContentCodec.STICKER_FORMAT_WEBM ? 4 : 0;
        if (headerSize == 0) {
            return false;
        }
        byte[] header = new byte[headerSize];
        try (FileInputStream input = new FileInputStream(source)) {
            int offset = 0;
            while (offset < header.length) {
                int count = input.read(header, offset, header.length - offset);
                if (count == -1) {
                    return false;
                }
                offset += count;
            }
            return matchesStickerFormat(header, format);
        } catch (IOException e) {
            throw new SecureMediaException("cannot read secure sticker header", e);
        }
    }

    private static byte[] randomBytes(int count) {
        byte[] value = new byte[count];
        new SecureRandom().nextBytes(value);
        return value;
    }

    private static byte[] sha256(byte[] value) {
        return newSha256().digest(value);
    }

    private static byte[] sha256File(File source, int maximum) {
        source = requireSafeFile(source, "source");
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
