package org.telegram.secureoverlay;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
public final class SecureContentCodecTest {
    @Test
    public void textRoundTripsWithDeterministicEncoding() {
        String value = "Привіт, secure text";

        byte[] encoded = SecureContentCodec.encodeText(value);
        SecureContentCodec.Decoded decoded = SecureContentCodec.decode(encoded);

        assertTrue(SecureContentCodec.isVersioned(encoded));
        assertEquals(SecureContentCodec.TYPE_TEXT, decoded.type);
        assertEquals(value, decoded.text);
        assertNull(decoded.staticSticker);
        assertNull(decoded.attachment);
        assertArrayEquals(
                new byte[] {'F', 'S', 'C', '1', 1, 0, 0, 0, 25},
                java.util.Arrays.copyOf(encoded, 9));
    }

    @Test
    public void attachmentMetadataRoundTripsInsideTypedContent() {
        SecureContentCodec.Attachment attachment = new SecureContentCodec.Attachment(
                new byte[16],
                new byte[32],
                new byte[12],
                new byte[32],
                123,
                123 + SecureMediaCrypto.GCM_TAG_BYTES,
                "знімок.jpg",
                "image/jpeg",
                "Приватний підпис",
                1920,
                1080,
                true);

        SecureContentCodec.Decoded decoded = SecureContentCodec.decode(
                SecureContentCodec.encodeAttachment(attachment));

        assertEquals(SecureContentCodec.TYPE_PHOTO, decoded.type);
        assertEquals("знімок.jpg", decoded.attachment.fileName);
        assertEquals("image/jpeg", decoded.attachment.mimeType);
        assertEquals("Приватний підпис", decoded.attachment.caption);
        assertEquals(1920, decoded.attachment.width);
        assertEquals(1080, decoded.attachment.height);
        assertTrue(decoded.attachment.photo);
    }

    @Test
    public void videoAttachmentMetadataRoundTripsWithDimensions() {
        SecureContentCodec.Attachment attachment = new SecureContentCodec.Attachment(
                new byte[16],
                new byte[32],
                new byte[12],
                new byte[32],
                123,
                123 + SecureMediaCrypto.GCM_TAG_BYTES,
                "clip.mp4",
                "video/mp4",
                "",
                1920,
                1080,
                false);

        SecureContentCodec.Decoded decoded = SecureContentCodec.decode(
                SecureContentCodec.encodeAttachment(attachment));

        assertEquals(SecureContentCodec.TYPE_FILE, decoded.type);
        assertEquals("video/mp4", decoded.attachment.mimeType);
        assertEquals(1920, decoded.attachment.width);
        assertEquals(1080, decoded.attachment.height);
        assertFalse(decoded.attachment.photo);
    }

    @Test
    public void webmVideoManifestIsSupported() {
        SecureContentCodec.Attachment attachment = new SecureContentCodec.Attachment(
                new byte[16],
                new byte[32],
                new byte[12],
                new byte[32],
                123,
                123 + SecureMediaCrypto.GCM_TAG_BYTES,
                "clip.webm",
                "video/webm",
                "",
                1280,
                720,
                false);

        SecureContentCodec.Decoded decoded = SecureContentCodec.decode(
                SecureContentCodec.encodeAttachment(attachment));

        assertEquals(SecureContentCodec.TYPE_FILE, decoded.type);
        assertEquals("video/webm", decoded.attachment.mimeType);
        assertEquals(1280, decoded.attachment.width);
        assertEquals(720, decoded.attachment.height);
    }

    @Test
    public void genericFileCannotClaimVisualDimensions() {
        SecureContentCodec.Attachment attachment = new SecureContentCodec.Attachment(
                new byte[16],
                new byte[32],
                new byte[12],
                new byte[32],
                123,
                123 + SecureMediaCrypto.GCM_TAG_BYTES,
                "data.bin",
                "application/octet-stream",
                "",
                1920,
                1080,
                false);
        try {
            SecureContentCodec.encodeAttachment(attachment);
            fail("expected generic file dimensions rejection");
        } catch (IllegalArgumentException expected) {
            // Dimensions are reserved for photos and authenticated video manifests.
        }
    }

    @Test
    public void legacyVideoWithoutDimensionsRemainsReadable() {
        SecureContentCodec.Attachment attachment = new SecureContentCodec.Attachment(
                new byte[16],
                new byte[32],
                new byte[12],
                new byte[32],
                123,
                123 + SecureMediaCrypto.GCM_TAG_BYTES,
                "legacy.mp4",
                "video/mp4",
                "",
                0,
                0,
                false);

        SecureContentCodec.Decoded decoded = SecureContentCodec.decode(
                SecureContentCodec.encodeAttachment(attachment));

        assertEquals(SecureContentCodec.TYPE_FILE, decoded.type);
        assertEquals(0, decoded.attachment.width);
        assertEquals(0, decoded.attachment.height);
    }

    @Test
    public void encryptedCaptionCarriesAlbumIdWithoutChangingDisplayedCaption() {
        String albumId = "00112233445566778899aabbccddeeff";
        String encoded = SecureContentCodec.encodeCaption("опис", true, albumId);

        assertTrue(SecureContentCodec.isCaptionAbove(encoded));
        assertEquals(albumId, SecureContentCodec.albumId(encoded));
        assertEquals("опис", SecureContentCodec.displayCaption(encoded));
        assertEquals("опис", SecureContentCodec.displayCaption("опис"));
        assertEquals("", SecureContentCodec.albumId("опис"));
    }

    @Test
    public void editedCaptionPreservesAttachmentIdentityAndAlbum() {
        String albumId = "00112233445566778899aabbccddeeff";
        SecureContentCodec.Attachment original = new SecureContentCodec.Attachment(
                new byte[16],
                new byte[32],
                new byte[12],
                new byte[32],
                123,
                123 + SecureMediaCrypto.GCM_TAG_BYTES,
                "photo.jpg",
                "image/jpeg",
                SecureContentCodec.encodeCaption("старий опис", false, albumId),
                1920,
                1080,
                true);

        SecureContentCodec.Attachment edited = SecureContentCodec.withCaption(
                original, "новий опис", true);

        assertArrayEquals(original.mediaId, edited.mediaId);
        assertArrayEquals(original.key, edited.key);
        assertArrayEquals(original.nonce, edited.nonce);
        assertArrayEquals(original.ciphertextSha256, edited.ciphertextSha256);
        assertEquals(original.ciphertextSize, edited.ciphertextSize);
        assertEquals("новий опис", SecureContentCodec.displayCaption(edited.caption));
        assertEquals(albumId, SecureContentCodec.albumId(edited.caption));
        assertTrue(SecureContentCodec.isCaptionAbove(edited.caption));
    }

    @Test
    public void unsafeAttachmentNameIsRejected() {
        SecureContentCodec.Attachment attachment = new SecureContentCodec.Attachment(
                new byte[16],
                new byte[32],
                new byte[12],
                new byte[32],
                1,
                1 + SecureMediaCrypto.GCM_TAG_BYTES,
                "../secret.txt",
                "text/plain",
                "",
                0,
                0,
                false);
        try {
            SecureContentCodec.encodeAttachment(attachment);
            fail("expected unsafe attachment name rejection");
        } catch (IllegalArgumentException expected) {
            // Decrypted metadata must never become a path traversal.
        }
    }

    @Test
    public void legacyPlaintextIsNotMisclassified() {
        assertFalse(SecureContentCodec.isVersioned(
                "old encrypted beta text".getBytes(StandardCharsets.UTF_8)));
        assertFalse(SecureContentCodec.isVersioned(null));
    }

    @Test
    public void rejectsMalformedTypedContent() {
        assertMalformed(new byte[] {'F', 'S', 'C', '1'});

        ByteBuffer unknownType = ByteBuffer.allocate(10).order(ByteOrder.BIG_ENDIAN);
        unknownType.put(new byte[] {'F', 'S', 'C', '1'});
        unknownType.put((byte) 99);
        unknownType.putInt(1);
        unknownType.put((byte) 1);
        assertMalformed(unknownType.array());

        byte[] invalidUtf8 = new byte[] {
                'F', 'S', 'C', '1', 1, 0, 0, 0, 2, (byte) 0xc3, 0x28
        };
        assertMalformed(invalidUtf8);

        byte[] trailing = SecureContentCodec.encodeText("ok");
        assertMalformed(java.util.Arrays.copyOf(trailing, trailing.length + 1));
    }

    private static void assertMalformed(byte[] value) {
        try {
            SecureContentCodec.decode(value);
            fail("expected malformed secure content");
        } catch (IllegalArgumentException expected) {
            // Recognized typed plaintext must fail closed.
        }
    }
}
