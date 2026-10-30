package org.telegram.secureoverlay;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Collections;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public final class SecureTrafficPaddingJvmTest {

    @Rule
    public TemporaryFolder temporaryFolder = new TemporaryFolder();

    @Test
    public void fsc1PayloadsArePaddedToMultiplesOf160() {
        int[] textLengths = {1, 5, 20, 50, 100, 150, 151, 160, 200, 319, 320, 500};
        for (int len : textLengths) {
            byte[] raw = new byte[len];
            Arrays.fill(raw, (byte) 'A');
            String text = new String(raw, StandardCharsets.UTF_8);

            byte[] encoded = SecureContentCodec.encodeText(text);
            assertEquals("Encoded text must be a multiple of 160 bytes for len=" + len,
                    0, encoded.length % 160);
            assertTrue("Encoded text must be >= unpadded length + 1",
                    encoded.length >= 9 + len + 1);

            SecureContentCodec.Decoded decoded = SecureContentCodec.decode(encoded);
            assertEquals(SecureContentCodec.TYPE_TEXT, decoded.type);
            assertEquals(text, decoded.text);
        }

        // Control message padding
        byte[] digest = new byte[32];
        Arrays.fill(digest, (byte) 7);
        byte[] encodedControl = SecureContentCodec.encodeDeleteControl(
                Collections.singletonList(digest));
        assertEquals(0, encodedControl.length % 160);
        SecureContentCodec.Decoded decodedControl = SecureContentCodec.decode(encodedControl);
        assertEquals(SecureContentCodec.TYPE_CONTROL, decodedControl.type);
        assertArrayEquals(digest, decodedControl.control.carrierDigests.get(0));

        // Location message padding
        SecureContentCodec.GeoLocation location = new SecureContentCodec.GeoLocation(
                50.4501, 30.5234, 10, 3600);
        byte[] encodedLocation = SecureContentCodec.encodeLocation(location);
        assertEquals(0, encodedLocation.length % 160);
        SecureContentCodec.Decoded decodedLocation = SecureContentCodec.decode(encodedLocation);
        assertEquals(SecureContentCodec.TYPE_GEO_LOCATION, decodedLocation.type);
        assertEquals(50.4501, decodedLocation.location.latitude, 0.0001);

        // Contact message padding
        SecureContentCodec.Contact contact = new SecureContentCodec.Contact(
                "+380501112233", "Ivan", "Franko", "VCARD");
        byte[] encodedContact = SecureContentCodec.encodeContact(contact);
        assertEquals(0, encodedContact.length % 160);
        SecureContentCodec.Decoded decodedContact = SecureContentCodec.decode(encodedContact);
        assertEquals(SecureContentCodec.TYPE_CONTACT, decodedContact.type);
        assertEquals("+380501112233", decodedContact.contact.phoneNumber);
    }

    @Test
    public void fsc1PaddingCorruptionFailsClosed() {
        byte[] encoded = SecureContentCodec.encodeText("Hello, secure world!");
        assertTrue(encoded.length % 160 == 0);

        // Corrupt delimiter byte (located right after header + payload)
        // Header is 9 bytes. Payload "Hello, secure world!" is 20 bytes UTF-8.
        int delimiterIndex = 9 + 20;
        assertEquals((byte) 0x80, encoded[delimiterIndex]);

        byte[] corruptedDelimiter = encoded.clone();
        corruptedDelimiter[delimiterIndex] = (byte) 0x81;
        try {
            SecureContentCodec.decode(corruptedDelimiter);
            fail("expected invalid delimiter rejection");
        } catch (IllegalArgumentException expected) {
            // Success
        }

        corruptedDelimiter[delimiterIndex] = 0x00;
        try {
            SecureContentCodec.decode(corruptedDelimiter);
            fail("expected zero delimiter rejection");
        } catch (IllegalArgumentException expected) {
            // Success
        }

        // Corrupt trailing padding zero
        byte[] corruptedPadding = encoded.clone();
        corruptedPadding[encoded.length - 1] = 0x01;
        try {
            SecureContentCodec.decode(corruptedPadding);
            fail("expected non-zero padding byte rejection");
        } catch (IllegalArgumentException expected) {
            // Success
        }

        // Truncate 1 byte
        byte[] truncatedOne = Arrays.copyOf(encoded, encoded.length - 1);
        try {
            SecureContentCodec.decode(truncatedOne);
            fail("expected truncated padding length rejection");
        } catch (IllegalArgumentException expected) {
            // Success
        }
    }

    @Test
    public void fsc1LegacyUnpaddedDecodesCleanly() {
        // Construct legacy unpadded message directly without trailing padding
        byte[] payload = "Legacy unpadded message".getBytes(StandardCharsets.UTF_8);
        ByteBuffer buffer = ByteBuffer.allocate(9 + payload.length).order(ByteOrder.BIG_ENDIAN);
        buffer.put(new byte[] {'F', 'S', 'C', '1'});
        buffer.put((byte) SecureContentCodec.TYPE_TEXT);
        buffer.putInt(payload.length);
        buffer.put(payload);
        byte[] legacy = buffer.array();

        // Legacy message length is NOT a multiple of 160 (9 + 23 = 32 bytes)
        assertEquals(32, legacy.length);
        SecureContentCodec.Decoded decoded = SecureContentCodec.decode(legacy);
        assertEquals(SecureContentCodec.TYPE_TEXT, decoded.type);
        assertEquals("Legacy unpadded message", decoded.text);
    }

    @Test
    public void padmeSizeCalculationsMatchSpecification() {
        try {
            SecureMediaCrypto.padmeSize(0);
            fail("expected non-positive length rejection");
        } catch (IllegalArgumentException expected) {
            // Success
        }

        try {
            SecureMediaCrypto.padmeSize(-10);
            fail("expected negative length rejection");
        } catch (IllegalArgumentException expected) {
            // Success
        }

        // Minimum floor is 256 bytes
        assertEquals(256, SecureMediaCrypto.padmeSize(1));
        assertEquals(256, SecureMediaCrypto.padmeSize(50));
        assertEquals(256, SecureMediaCrypto.padmeSize(256));

        // Stepping past 256
        assertEquals(272, SecureMediaCrypto.padmeSize(257));
        assertEquals(272, SecureMediaCrypto.padmeSize(272));
        assertEquals(288, SecureMediaCrypto.padmeSize(273));

        // Power-of-two boundaries
        assertEquals(512, SecureMediaCrypto.padmeSize(512));
        assertEquals(544, SecureMediaCrypto.padmeSize(513));

        assertEquals(1024, SecureMediaCrypto.padmeSize(1024));
        assertEquals(1088, SecureMediaCrypto.padmeSize(1025));

        // Bounded space overhead <= 12% for any length
        for (int l = 256; l <= 65536; l += 37) {
            int padded = SecureMediaCrypto.padmeSize(l);
            assertTrue("Padded must be >= length: l=" + l, padded >= l);
            double overhead = (padded - l) / (double) l;
            assertTrue("Overhead must be <= 12% for l=" + l + " but was " + overhead, overhead <= 0.125);
        }

        // Maximum attachment ceiling
        assertEquals(SecureMediaCrypto.MAX_ATTACHMENT_BYTES,
                SecureMediaCrypto.padmeSize(SecureMediaCrypto.MAX_ATTACHMENT_BYTES));
    }

    @Test
    public void attachmentEncryptionAppliesPadmeAndRoundTrips() throws IOException {
        File dir = temporaryFolder.newFolder("attachment-test");
        File source = new File(dir, "photo.jpg");
        byte[] content = new byte[123];
        for (int i = 0; i < content.length; i++) {
            content[i] = (byte) (i ^ 42);
        }
        try (FileOutputStream out = new FileOutputStream(source)) {
            out.write(content);
        }

        File encrypted = new File(dir, "encrypted.bin");
        File destination = new File(dir, "decrypted.jpg");

        SecureContentCodec.Attachment manifest = SecureMediaCrypto.encryptAttachmentFile(
                source,
                encrypted,
                "photo.jpg",
                "image/jpeg",
                "caption",
                800,
                600,
                true);

        assertEquals(123, manifest.plaintextSize);
        int expectedPaddedPlaintext = SecureMediaCrypto.padmeSize(123);
        assertEquals(256, expectedPaddedPlaintext);
        int expectedCiphertext = SecureMediaCrypto.calculateSegmentedCiphertextSize(123);
        assertEquals(expectedCiphertext, manifest.ciphertextSize);
        assertEquals(expectedCiphertext, encrypted.length());

        // Decrypt
        SecureMediaCrypto.decryptAttachmentFile(encrypted, destination, manifest);
        assertTrue(destination.isFile());
        assertEquals(123, destination.length());

        byte[] decryptedBytes = new byte[(int) destination.length()];
        try (FileInputStream in = new FileInputStream(destination)) {
            assertEquals(123, in.read(decryptedBytes));
        }
        assertArrayEquals(content, decryptedBytes);
    }

    @Test
    public void attachmentDecryptionRejectsCorruptedPadding() throws Exception {
        File dir = temporaryFolder.newFolder("attachment-corrupt-test");
        File source = new File(dir, "sample.bin");
        byte[] content = new byte[100];
        Arrays.fill(content, (byte) 0x42);
        try (FileOutputStream out = new FileOutputStream(source)) {
            out.write(content);
        }

        File encrypted = new File(dir, "enc.bin");
        File destination = new File(dir, "dec.bin");

        SecureContentCodec.Attachment manifest = SecureMediaCrypto.encryptAttachmentFile(
                source,
                encrypted,
                "sample.bin",
                "application/octet-stream",
                "",
                0,
                0,
                false);

        // Tampering with the ciphertext file directly fails GCM authentication
        byte[] encBytes = new byte[(int) encrypted.length()];
        try (FileInputStream in = new FileInputStream(encrypted)) {
            in.read(encBytes);
        }
        encBytes[110] ^= 0x01; // Tamper in padding region of ciphertext
        try (FileOutputStream out = new FileOutputStream(encrypted)) {
            out.write(encBytes);
        }

        try {
            SecureMediaCrypto.decryptAttachmentFile(encrypted, destination, manifest);
            fail("expected GCM authentication failure on tampered padding");
        } catch (IllegalArgumentException expected) {
            assertFalse("Destination must not exist on failure", destination.exists());
        }
    }

    @Test
    public void attachmentLegacyUnpaddedDecryptionSucceeds() throws Exception {
        File dir = temporaryFolder.newFolder("attachment-legacy-test");
        byte[] content = new byte[120];
        Arrays.fill(content, (byte) 0x55);

        // Encrypt manually with AES-GCM without Padme padding (legacy style)
        byte[] key = new byte[32];
        Arrays.fill(key, (byte) 1);
        byte[] nonce = new byte[12];
        Arrays.fill(nonce, (byte) 2);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        cipher.updateAAD(new byte[] {'F', 'S', 'C', '1', 'A', 'T', 'T', 'A', 'C', 'H'});
        cipher.updateAAD(new byte[] {0}); // photo = false
        byte[] ciphertext = cipher.doFinal(content);
        assertEquals(content.length + 16, ciphertext.length);

        File encrypted = new File(dir, "legacy_enc.bin");
        try (FileOutputStream out = new FileOutputStream(encrypted)) {
            out.write(ciphertext);
        }

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] ciphertextSha256 = digest.digest(ciphertext);

        byte[] mediaId = new byte[16];
        Arrays.fill(mediaId, (byte) 9);
        SecureContentCodec.Attachment legacyManifest = new SecureContentCodec.Attachment(
                mediaId,
                key,
                nonce,
                ciphertextSha256,
                content.length,
                ciphertext.length, // Unpadded ciphertextSize!
                "legacy.bin",
                "application/octet-stream",
                "",
                0,
                0,
                false);

        File destination = new File(dir, "legacy_dec.bin");
        SecureMediaCrypto.decryptAttachmentFile(encrypted, destination, legacyManifest);

        assertTrue(destination.isFile());
        assertEquals(content.length, destination.length());
        byte[] decrypted = new byte[content.length];
        try (FileInputStream in = new FileInputStream(destination)) {
            in.read(decrypted);
        }
        assertArrayEquals(content, decrypted);
    }
}
