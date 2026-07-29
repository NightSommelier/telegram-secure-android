package org.telegram.secureoverlay;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import android.content.Context;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Arrays;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
public final class SecureMediaCryptoTest {
    @Test
    public void staticWebpEncryptsAuthenticatesAndRoundTrips() {
        byte[] webp = fakeWebp();

        SecureMediaCrypto.EncryptedStaticSticker encrypted =
                SecureMediaCrypto.encryptStaticSticker(webp, 512, 384, "🙂");
        byte[] encodedManifest =
                SecureContentCodec.encodeStaticSticker(encrypted.manifest);
        SecureContentCodec.Decoded decoded = SecureContentCodec.decode(encodedManifest);

        assertEquals(SecureContentCodec.TYPE_STATIC_STICKER, decoded.type);
        assertEquals(webp.length + SecureMediaCrypto.GCM_TAG_BYTES,
                encrypted.ciphertext.length);
        assertEquals(512, decoded.staticSticker.width);
        assertEquals(384, decoded.staticSticker.height);
        assertEquals("🙂", decoded.staticSticker.emoji);
        assertArrayEquals(
                webp,
                SecureMediaCrypto.decryptStaticSticker(
                        encrypted.ciphertext, decoded.staticSticker));
    }

    @Test
    public void tamperingNeverReturnsStickerBytes() {
        SecureMediaCrypto.EncryptedStaticSticker encrypted =
                SecureMediaCrypto.encryptStaticSticker(fakeWebp(), 512, 512, "");
        byte[] tampered = Arrays.copyOf(encrypted.ciphertext, encrypted.ciphertext.length);
        tampered[tampered.length - 1] ^= 1;

        try {
            SecureMediaCrypto.decryptStaticSticker(tampered, encrypted.manifest);
            fail("expected tampered sticker rejection");
        } catch (IllegalArgumentException expected) {
            // Digest/tag mismatch fails closed.
        }
    }

    @Test
    public void nonWebpInputIsRejected() {
        try {
            SecureMediaCrypto.encryptStaticSticker(new byte[32], 512, 512, "");
            fail("expected non-WebP rejection");
        } catch (IllegalArgumentException expected) {
            // No fallback to uploading unencrypted bytes.
        }
    }

    @Test
    public void animatedTgsAndVideoWebmRoundTripWithDistinctAuthenticatedFormats() {
        assertStickerFormatRoundTrip(
                new byte[] {(byte) 0x1f, (byte) 0x8b, 8, 0, 1, 2, 3, 4},
                SecureContentCodec.STICKER_FORMAT_TGS,
                SecureContentCodec.TYPE_ANIMATED_STICKER);
        assertStickerFormatRoundTrip(
                new byte[] {
                        0x1a, 0x45, (byte) 0xdf, (byte) 0xa3, 1, 2, 3, 4
                },
                SecureContentCodec.STICKER_FORMAT_WEBM,
                SecureContentCodec.TYPE_VIDEO_STICKER);
    }

    @Test
    public void manifestFormatCannotBeChangedWithoutAuthenticationFailure() {
        SecureMediaCrypto.EncryptedStaticSticker encrypted =
                SecureMediaCrypto.encryptSticker(
                        new byte[] {(byte) 0x1f, (byte) 0x8b, 8, 0, 1, 2},
                        512,
                        512,
                        "",
                        SecureContentCodec.STICKER_FORMAT_TGS);
        SecureContentCodec.StaticSticker wrongFormat =
                new SecureContentCodec.StaticSticker(
                        encrypted.manifest.mediaId,
                        encrypted.manifest.key,
                        encrypted.manifest.nonce,
                        encrypted.manifest.ciphertextSha256,
                        encrypted.manifest.plaintextSize,
                        encrypted.manifest.ciphertextSize,
                        encrypted.manifest.width,
                        encrypted.manifest.height,
                        encrypted.manifest.emoji,
                        SecureContentCodec.STICKER_FORMAT_WEBP);
        try {
            SecureMediaCrypto.decryptStaticSticker(encrypted.ciphertext, wrongFormat);
            fail("expected authenticated format mismatch");
        } catch (IllegalArgumentException expected) {
            // The format is part of both Signal manifest and file AEAD associated data.
        }
    }

    @Test
    public void mediaCacheKeepsActiveFileAndPrunesOldestSiblings() throws IOException {
        Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
        File directory = new File(context.getCacheDir(), "secure-media-cache-test");
        directory.mkdirs();
        File oldest = writeCacheFile(directory, "oldest.bin", 4, 1);
        File middle = writeCacheFile(directory, "middle.bin", 4, 2);
        File active = writeCacheFile(directory, "active.bin", 4, 3);

        SecureMediaCache.touchAndPrune(active, 2, 8);

        assertFalse(oldest.exists());
        assertTrue(middle.exists());
        assertTrue(active.exists());
        middle.delete();
        active.delete();
        directory.delete();
    }

    @Test
    public void attachmentFileEncryptsStreamsAndRoundTrips() throws IOException {
        Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
        File directory = new File(context.getCacheDir(), "secure-attachment-crypto-test");
        directory.mkdirs();
        File source = new File(directory, "source.jpg");
        byte[] plaintext = new byte[192 * 1024 + 7];
        for (int i = 0; i < plaintext.length; i++) {
            plaintext[i] = (byte) (i * 31);
        }
        try (FileOutputStream output = new FileOutputStream(source, false)) {
            output.write(plaintext);
        }
        File encrypted = new File(directory, "opaque.bin");
        File decrypted = new File(directory, "decrypted.jpg");

        SecureContentCodec.Attachment manifest =
                SecureMediaCrypto.encryptAttachmentFile(
                        source,
                        encrypted,
                        "holiday.jpg",
                        "image/jpeg",
                        "private caption",
                        1600,
                        900,
                        true);
        SecureContentCodec.Decoded decoded = SecureContentCodec.decode(
                SecureContentCodec.encodeAttachment(manifest));
        SecureMediaCrypto.decryptAttachmentFile(
                encrypted, decrypted, decoded.attachment);

        assertEquals(plaintext.length + SecureMediaCrypto.GCM_TAG_BYTES,
                encrypted.length());
        assertArrayEquals(plaintext, readFile(decrypted));
        source.delete();
        encrypted.delete();
        decrypted.delete();
        directory.delete();
    }

    @Test
    public void tamperedAttachmentLeavesNoPlaintextFile() throws IOException {
        Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
        File directory = new File(context.getCacheDir(), "secure-attachment-tamper-test");
        directory.mkdirs();
        File source = writeCacheFile(directory, "source.txt", 128, 1);
        File encrypted = new File(directory, "opaque.bin");
        File destination = new File(directory, "result.txt");
        SecureContentCodec.Attachment manifest =
                SecureMediaCrypto.encryptAttachmentFile(
                        source,
                        encrypted,
                        "notes.txt",
                        "text/plain",
                        "",
                        0,
                        0,
                        false);
        try (java.io.RandomAccessFile file =
                new java.io.RandomAccessFile(encrypted, "rw")) {
            long last = encrypted.length() - 1;
            file.seek(last);
            int value = file.read();
            file.seek(last);
            file.write(value ^ 1);
        }

        try {
            SecureMediaCrypto.decryptAttachmentFile(
                    encrypted, destination, manifest);
            fail("expected tampered attachment rejection");
        } catch (IllegalArgumentException expected) {
            assertFalse(destination.exists());
        }
        source.delete();
        encrypted.delete();
        destination.delete();
        directory.delete();
    }

    @Test
    public void attachmentKindIsAuthenticated() throws IOException {
        Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
        File directory = new File(context.getCacheDir(), "secure-attachment-kind-test");
        directory.mkdirs();
        File source = writeCacheFile(directory, "source.bin", 128, 1);
        File encrypted = new File(directory, "opaque.bin");
        File destination = new File(directory, "result.bin");
        SecureContentCodec.Attachment fileManifest =
                SecureMediaCrypto.encryptAttachmentFile(
                        source,
                        encrypted,
                        "data.bin",
                        "application/octet-stream",
                        "",
                        0,
                        0,
                        false);
        SecureContentCodec.Attachment forgedPhoto =
                new SecureContentCodec.Attachment(
                        fileManifest.mediaId,
                        fileManifest.key,
                        fileManifest.nonce,
                        fileManifest.ciphertextSha256,
                        fileManifest.plaintextSize,
                        fileManifest.ciphertextSize,
                        "data.jpg",
                        "image/jpeg",
                        "",
                        1,
                        1,
                        true);

        try {
            SecureMediaCrypto.decryptAttachmentFile(
                    encrypted, destination, forgedPhoto);
            fail("expected attachment kind authentication failure");
        } catch (IllegalArgumentException expected) {
            assertFalse(destination.exists());
        }
        source.delete();
        encrypted.delete();
        destination.delete();
        directory.delete();
    }

    private static byte[] fakeWebp() {
        return new byte[] {
                'R', 'I', 'F', 'F', 4, 0, 0, 0,
                'W', 'E', 'B', 'P', 'V', 'P', '8', ' '
        };
    }

    private static File writeCacheFile(
            File directory, String name, int size, long modified) throws IOException {
        File file = new File(directory, name);
        try (FileOutputStream output = new FileOutputStream(file, false)) {
            output.write(new byte[size]);
        }
        file.setLastModified(modified);
        return file;
    }

    private static byte[] readFile(File file) throws IOException {
        try (java.io.FileInputStream input = new java.io.FileInputStream(file);
                java.io.ByteArrayOutputStream output = new java.io.ByteArrayOutputStream()) {
            byte[] buffer = new byte[16 * 1024];
            int count;
            while ((count = input.read(buffer)) != -1) {
                output.write(buffer, 0, count);
            }
            return output.toByteArray();
        }
    }

    private static void assertStickerFormatRoundTrip(
            byte[] plaintext, int format, int expectedType) {
        SecureMediaCrypto.EncryptedStaticSticker encrypted =
                SecureMediaCrypto.encryptSticker(plaintext, 512, 512, "", format);
        SecureContentCodec.Decoded decoded = SecureContentCodec.decode(
                SecureContentCodec.encodeSticker(encrypted.manifest));
        assertEquals(expectedType, decoded.type);
        assertEquals(format, decoded.staticSticker.format);
        assertArrayEquals(
                plaintext,
                SecureMediaCrypto.decryptStaticSticker(
                        encrypted.ciphertext, decoded.staticSticker));
    }
}
