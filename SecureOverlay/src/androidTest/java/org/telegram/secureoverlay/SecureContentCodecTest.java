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
