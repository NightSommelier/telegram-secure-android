package org.telegram.secureoverlay;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public final class SecureArchitecturePhase4JvmTest {

    @Rule
    public TemporaryFolder temporaryFolder = new TemporaryFolder();

    @Test
    public void sa16TransactionalStoreOperations() throws Exception {
        KeystoreEncryptedBlobStore store = new KeystoreEncryptedBlobStore(null);

        // put & get
        String key1 = "test/record1";
        byte[] val1 = "value 1".getBytes(StandardCharsets.UTF_8);
        store.put(key1, val1);
        assertArrayEquals(val1, store.get(key1));
        assertTrue(store.has(key1));

        // putAll
        Map<String, byte[]> map = new LinkedHashMap<>();
        map.put("root/a", new byte[] {1, 2});
        map.put("root/b", new byte[] {3, 4});
        map.put("other/c", new byte[] {5, 6});
        store.putAll(map);
        assertTrue(store.has("root/a"));
        assertTrue(store.has("root/b"));
        assertTrue(store.has("other/c"));

        // replaceRoots: replaces root/ while leaving other/ intact
        Map<String, byte[]> replacements = new LinkedHashMap<>();
        replacements.put("root/new", new byte[] {7, 8});
        store.replaceRoots(replacements, "root");
        assertNull(store.get("root/a"));
        assertNull(store.get("root/b"));
        assertArrayEquals(new byte[] {7, 8}, store.get("root/new"));
        assertArrayEquals(new byte[] {5, 6}, store.get("other/c"));

        // deleteRoots
        store.deleteRoots("root");
        assertNull(store.get("root/new"));
        assertTrue(store.has("other/c"));

        // deletePrefixes
        store.deletePrefixes("other/");
        assertNull(store.get("other/c"));
        assertFalse(store.has("other/c"));
    }

    @Test
    public void sa17SegmentedStreamingCiphertextSizeCalculations() {
        // Minimum size is 256 bytes (Padmé floor)
        int size100 = SecureMediaCrypto.calculateSegmentedCiphertextSize(100);
        // 1 segment of 256 bytes + 16-byte tag = 272
        assertEquals(272, size100);

        // 64 KiB = 65,536 bytes (1 segment)
        int size64k = SecureMediaCrypto.calculateSegmentedCiphertextSize(64 * 1024);
        int padded64k = SecureMediaCrypto.padmeSize(64 * 1024);
        assertEquals(padded64k + 16, size64k);

        // Multi-segment file: 150 KiB (3 segments of 64 KiB, 64 KiB, ~22 KiB)
        int raw150k = 150 * 1024;
        int padded150k = SecureMediaCrypto.padmeSize(raw150k);
        int numSegments = (padded150k + SecureMediaCrypto.SEGMENT_SIZE - 1) / SecureMediaCrypto.SEGMENT_SIZE;
        assertTrue(numSegments >= 3);
        int expectedCiphertextSize = padded150k + (numSegments * SecureMediaCrypto.GCM_TAG_BYTES);
        assertEquals(expectedCiphertextSize,
                SecureMediaCrypto.calculateSegmentedCiphertextSize(raw150k));
    }

    @Test
    public void sa17SegmentedStreamingEncryptAndDecryptRoundTrip() throws Exception {
        File dir = temporaryFolder.newFolder("segmented-media-test");
        File source = new File(dir, "large_video.mp4");

        // 150 KiB file spans 3 64-KiB segments
        int plaintextSize = 150 * 1024 + 17;
        byte[] content = new byte[plaintextSize];
        for (int i = 0; i < content.length; i++) {
            content[i] = (byte) ((i * 37) ^ 0x5a);
        }
        try (FileOutputStream out = new FileOutputStream(source)) {
            out.write(content);
        }

        File encrypted = new File(dir, "encrypted.bin");
        File decrypted = new File(dir, "decrypted.mp4");

        SecureContentCodec.Attachment manifest = SecureMediaCrypto.encryptAttachmentFile(
                source,
                encrypted,
                "video.mp4",
                "video/mp4",
                "sample caption",
                1280,
                720,
                false);

        assertEquals(plaintextSize, manifest.plaintextSize);
        int expectedCiphertextSize = SecureMediaCrypto.calculateSegmentedCiphertextSize(plaintextSize);
        assertEquals(expectedCiphertextSize, manifest.ciphertextSize);
        assertEquals(expectedCiphertextSize, encrypted.length());

        // Decrypt using segmented streaming AEAD
        SecureMediaCrypto.decryptAttachmentFile(encrypted, decrypted, manifest);
        assertTrue(decrypted.isFile());
        assertEquals(plaintextSize, decrypted.length());

        byte[] decryptedBytes = new byte[plaintextSize];
        try (FileInputStream in = new FileInputStream(decrypted)) {
            int read = in.read(decryptedBytes);
            assertEquals(plaintextSize, read);
        }
        assertArrayEquals(content, decryptedBytes);
    }

    @Test
    public void sa17SegmentedDecryptionRejectsCorruptedSegment() throws Exception {
        File dir = temporaryFolder.newFolder("segmented-corrupt-test");
        File source = new File(dir, "data.bin");

        // Multi-segment file (130 KiB)
        int size = 130 * 1024;
        byte[] content = new byte[size];
        Arrays.fill(content, (byte) 0x77);
        try (FileOutputStream out = new FileOutputStream(source)) {
            out.write(content);
        }

        File encrypted = new File(dir, "enc.bin");
        File decrypted = new File(dir, "dec.bin");

        SecureContentCodec.Attachment manifest = SecureMediaCrypto.encryptAttachmentFile(
                source,
                encrypted,
                "data.bin",
                "application/octet-stream",
                "",
                0,
                0,
                false);

        // Corrupt a byte in the second segment (after first 64 KiB + 16 bytes tag)
        byte[] encBytes = new byte[(int) encrypted.length()];
        try (FileInputStream in = new FileInputStream(encrypted)) {
            in.read(encBytes);
        }
        int secondSegmentByte = 64 * 1024 + 16 + 50;
        encBytes[secondSegmentByte] ^= 0x42;
        try (FileOutputStream out = new FileOutputStream(encrypted)) {
            out.write(encBytes);
        }

        try {
            SecureMediaCrypto.decryptAttachmentFile(encrypted, decrypted, manifest);
            fail("expected authentication failure on corrupted segment");
        } catch (IllegalArgumentException expected) {
            assertFalse(decrypted.exists());
        }
    }

    @Test
    public void sa19SecureSessionManagerLifecycleAndGroupGuard() {
        SecureSessionManager.resetAll();
        assertFalse(SecureSessionManager.GROUPS_ENABLED);

        // Group peer dialog IDs (< 0) must be rejected when GROUPS_ENABLED is false
        long groupChatId = -100123456789L;
        try {
            SecureSessionManager.getInstance(null, 0).getEngineForPeer(groupChatId);
            fail("expected disabled groups rejection");
        } catch (SecureChatEngine.SecureChatException expected) {
            assertTrue(expected.getMessage().contains("groups are disabled"));
        }

        // Enable groups flag
        SecureSessionManager.GROUPS_ENABLED = true;
        try {
            // When enabled, it does not throw the feature flag exception
            // (May fail on initialization or peer binding, but not the flag)
            assertNotNull(SecureSessionManager.getInstance(null, 0));
        } finally {
            SecureSessionManager.GROUPS_ENABLED = false;
        }
    }
}
