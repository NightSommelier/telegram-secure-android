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
    public void withCaptionPreservesPresentationMetadataAndWaveform() {
        byte[] waveform = new byte[] {1, 2, 3, 4, 5};
        SecureContentCodec.Attachment original = new SecureContentCodec.Attachment(
                new byte[16],
                new byte[32],
                new byte[12],
                new byte[32],
                123,
                123 + SecureMediaCrypto.GCM_TAG_BYTES,
                "audio.ogg",
                "audio/ogg",
                "старий опис",
                0,
                0,
                false,
                SecureContentCodec.ATTACHMENT_PRESENTATION_AUDIO,
                42,
                "Трек",
                "Виконавець",
                waveform);

        SecureContentCodec.Attachment edited = SecureContentCodec.withCaption(
                original, "новий опис", false);

        assertEquals(SecureContentCodec.ATTACHMENT_PRESENTATION_AUDIO, edited.presentation);
        assertEquals(42, edited.durationSeconds);
        assertEquals("Трек", edited.title);
        assertEquals("Виконавець", edited.performer);
        assertArrayEquals(waveform, edited.waveform);
        assertEquals("новий опис", SecureContentCodec.displayCaption(edited.caption));
    }

    @Test
    public void voiceAttachmentPresentationRoundTripsInsideAuthenticatedManifest() {
        SecureContentCodec.Attachment attachment = new SecureContentCodec.Attachment(
                new byte[16],
                new byte[32],
                new byte[12],
                new byte[32],
                123,
                123 + SecureMediaCrypto.GCM_TAG_BYTES,
                "voice.ogg",
                "audio/ogg",
                "",
                0,
                0,
                false,
                SecureContentCodec.ATTACHMENT_PRESENTATION_VOICE,
                37,
                "",
                "");

        SecureContentCodec.Decoded decoded = SecureContentCodec.decode(
                SecureContentCodec.encodeAttachment(attachment));

        assertEquals(SecureContentCodec.ATTACHMENT_PRESENTATION_VOICE,
                decoded.attachment.presentation);
        assertEquals(37, decoded.attachment.durationSeconds);
        assertEquals("", decoded.attachment.title);
        assertEquals("", decoded.attachment.performer);
        assertNull(decoded.attachment.waveform);
    }

    @Test
    public void voiceAttachmentPresentationWithWaveformRoundTripsInsideAuthenticatedManifest() {
        byte[] waveform = new byte[] {0, 4, 17, -50, -93, 86, -103, -45, -12, -26, 63, -25, -3};
        SecureContentCodec.Attachment attachment = new SecureContentCodec.Attachment(
                new byte[16],
                new byte[32],
                new byte[12],
                new byte[32],
                123,
                123 + SecureMediaCrypto.GCM_TAG_BYTES,
                "voice.ogg",
                "audio/ogg",
                "",
                0,
                0,
                false,
                SecureContentCodec.ATTACHMENT_PRESENTATION_VOICE,
                37,
                "",
                "",
                waveform);

        byte[] encoded = SecureContentCodec.encodeAttachment(attachment);
        SecureContentCodec.Decoded decoded = SecureContentCodec.decode(encoded);

        assertEquals(SecureContentCodec.ATTACHMENT_PRESENTATION_VOICE,
                decoded.attachment.presentation);
        assertEquals(37, decoded.attachment.durationSeconds);
        assertEquals("", decoded.attachment.title);
        assertEquals("", decoded.attachment.performer);
        assertArrayEquals(waveform, decoded.attachment.waveform);
    }

    @Test
    public void oversizedWaveformFailsClosed() {
        byte[] oversizedWaveform = new byte[SecureContentCodec.MAX_WAVEFORM_BYTES + 1];
        SecureContentCodec.Attachment attachment = new SecureContentCodec.Attachment(
                new byte[16],
                new byte[32],
                new byte[12],
                new byte[32],
                123,
                123 + SecureMediaCrypto.GCM_TAG_BYTES,
                "voice.ogg",
                "audio/ogg",
                "",
                0,
                0,
                false,
                SecureContentCodec.ATTACHMENT_PRESENTATION_VOICE,
                37,
                "",
                "",
                oversizedWaveform);
        try {
            SecureContentCodec.encodeAttachment(attachment);
            fail("oversized waveform must be rejected");
        } catch (IllegalArgumentException expected) {
            // Success
        }
    }

    @Test
    public void waveformOnNonAudioPresentationFailsClosed() {
        byte[] waveform = new byte[] {1, 2, 3};
        SecureContentCodec.Attachment attachment = new SecureContentCodec.Attachment(
                new byte[16],
                new byte[32],
                new byte[12],
                new byte[32],
                123,
                123 + SecureMediaCrypto.GCM_TAG_BYTES,
                "photo.jpg",
                "image/jpeg",
                "",
                100,
                100,
                true,
                SecureContentCodec.ATTACHMENT_PRESENTATION_FILE,
                0,
                "",
                "",
                waveform);
        try {
            SecureContentCodec.encodeAttachment(attachment);
            fail("waveform on photo must be rejected");
        } catch (IllegalArgumentException expected) {
            // Success
        }
    }

    @Test
    public void legacyAttachmentWithoutPresentationExtensionRemainsReadable() {
        SecureContentCodec.Attachment attachment = new SecureContentCodec.Attachment(
                new byte[16], new byte[32], new byte[12], new byte[32],
                123, 123 + SecureMediaCrypto.GCM_TAG_BYTES,
                "audio.ogg", "audio/ogg", "", 0, 0, false);
        byte[] current = SecureContentCodec.encodeAttachment(attachment);
        // FSM1 has a 13-byte header and no title/performer for this legacy-compatible value.
        byte[] legacy = java.util.Arrays.copyOf(current, current.length - 13);
        ByteBuffer.wrap(legacy).order(ByteOrder.BIG_ENDIAN).putInt(5, legacy.length - 9);

        SecureContentCodec.Decoded decoded = SecureContentCodec.decode(legacy);

        assertEquals(SecureContentCodec.ATTACHMENT_PRESENTATION_AUDIO,
                decoded.attachment.presentation);
        assertEquals(0, decoded.attachment.durationSeconds);
    }

    @Test
    public void animationPresentationRoundTripsCleanly() {
        SecureContentCodec.Attachment attachment = new SecureContentCodec.Attachment(
                new byte[16], new byte[32], new byte[12], new byte[32],
                123, 123 + SecureMediaCrypto.GCM_TAG_BYTES,
                "animation.gif", "image/gif", "", 320, 240, false,
                SecureContentCodec.ATTACHMENT_PRESENTATION_ANIMATION, 0, "", "");
        byte[] encoded = SecureContentCodec.encodeAttachment(attachment);

        SecureContentCodec.Decoded decoded = SecureContentCodec.decode(encoded);

        assertEquals(SecureContentCodec.ATTACHMENT_PRESENTATION_ANIMATION,
                decoded.attachment.presentation);
        assertEquals(320, decoded.attachment.width);
        assertEquals(240, decoded.attachment.height);
        assertEquals("image/gif", decoded.attachment.mimeType);
    }

    @Test
    public void malformedAttachmentPresentationFailsClosed() {
        SecureContentCodec.Attachment attachment = new SecureContentCodec.Attachment(
                new byte[16], new byte[32], new byte[12], new byte[32],
                123, 123 + SecureMediaCrypto.GCM_TAG_BYTES,
                "voice.ogg", "audio/ogg", "", 0, 0, false,
                SecureContentCodec.ATTACHMENT_PRESENTATION_VOICE, 1, "", "");
        byte[] malformed = SecureContentCodec.encodeAttachment(attachment);
        malformed[malformed.length - 13] ^= 1;

        assertMalformed(malformed);
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

    @Test
    public void deleteControlRoundTripsAndValidates() {
        byte[] digest1 = new byte[32];
        java.util.Arrays.fill(digest1, (byte) 0x11);
        byte[] digest2 = new byte[32];
        java.util.Arrays.fill(digest2, (byte) 0x22);

        java.util.List<byte[]> digests = java.util.Arrays.asList(digest1, digest2);
        byte[] encoded = SecureContentCodec.encodeDeleteControl(digests);

        assertTrue(SecureContentCodec.isVersioned(encoded));
        SecureContentCodec.Decoded decoded = SecureContentCodec.decode(encoded);

        assertEquals(SecureContentCodec.TYPE_CONTROL, decoded.type);
        assertNotNull(decoded.control);
        assertEquals(SecureContentCodec.CONTROL_ACTION_DELETE, decoded.control.action);
        assertEquals(2, decoded.control.carrierDigests.size());
        assertArrayEquals(digest1, decoded.control.carrierDigests.get(0));
        assertArrayEquals(digest2, decoded.control.carrierDigests.get(1));

        // Truncation fails closed
        assertMalformed(java.util.Arrays.copyOf(encoded, encoded.length - 1));
    }

    @Test
    public void contactRoundTripsAndValidates() {
        SecureContentCodec.Contact contact = new SecureContentCodec.Contact(
                "+380501234567",
                "Тарас",
                "Шевченко",
                "BEGIN:VCARD\nVERSION:3.0\nFN:Тарас Шевченко\nTEL:+380501234567\nEND:VCARD");

        byte[] encoded = SecureContentCodec.encodeContact(contact);
        assertTrue(SecureContentCodec.isVersioned(encoded));

        SecureContentCodec.Decoded decoded = SecureContentCodec.decode(encoded);
        assertEquals(SecureContentCodec.TYPE_CONTACT, decoded.type);
        assertNotNull(decoded.contact);
        assertEquals("+380501234567", decoded.contact.phoneNumber);
        assertEquals("Тарас", decoded.contact.firstName);
        assertEquals("Шевченко", decoded.contact.lastName);
        assertEquals(contact.vcard, decoded.contact.vcard);

        // Truncation fails closed
        assertMalformed(java.util.Arrays.copyOf(encoded, encoded.length - 1));
    }

    @Test
    public void geoLocationRoundTripsAndValidates() {
        SecureContentCodec.GeoLocation location = new SecureContentCodec.GeoLocation(
                50.4501, 30.5234, 15, 3600);

        byte[] encoded = SecureContentCodec.encodeLocation(location);
        assertTrue(SecureContentCodec.isVersioned(encoded));

        SecureContentCodec.Decoded decoded = SecureContentCodec.decode(encoded);
        assertEquals(SecureContentCodec.TYPE_GEO_LOCATION, decoded.type);
        assertNotNull(decoded.location);
        assertEquals(50.4501, decoded.location.latitude, 0.000001);
        assertEquals(30.5234, decoded.location.longitude, 0.000001);
        assertEquals(15, decoded.location.accuracy);
        assertEquals(3600, decoded.location.period);

        // Bounds checking
        try {
            new SecureContentCodec.GeoLocation(91.0, 0, 0, 0);
            fail("expected invalid latitude");
        } catch (IllegalArgumentException expected) {
        }
        try {
            new SecureContentCodec.GeoLocation(0, 181.0, 0, 0);
            fail("expected invalid longitude");
        } catch (IllegalArgumentException expected) {
        }

        // Truncation fails closed
        assertMalformed(java.util.Arrays.copyOf(encoded, encoded.length - 1));
    }

    private static void assertNotNull(Object value) {
        assertTrue(value != null);
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
