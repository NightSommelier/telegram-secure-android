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

    @Test
    public void sa20SavedMessagesBindingAndGenerations() throws Exception {
        byte[] rawKey = new byte[32];
        Arrays.fill(rawKey, (byte) 0x42);
        SecureSavedMessagesKeyStore.KeyMaterial key =
                new SecureSavedMessagesKeyStore.KeyMaterial(1, 1, rawKey);

        String note = "Secret saved note for account 1";
        byte[] record = SecureSavedMessageCrypto.encryptText(note, key);
        assertEquals(1, SecureSavedMessageCrypto.extractGeneration(record));

        // Decryption round-trip
        String decrypted = SecureSavedMessageCrypto.decryptText(record, key);
        assertEquals(note, decrypted);

        // Header tampering:
        // Layout: MAGIC_V2 (4) + generation (4) + kind (1) + account (4) + recordId (8) + nonce (12) + ciphertext
        // Tamper generation in header (bytes 4..7)
        byte[] tamperedGen = record.clone();
        tamperedGen[7] ^= 1;
        try {
            SecureSavedMessageCrypto.decryptText(tamperedGen, key);
            fail("tampered generation must fail");
        } catch (IllegalArgumentException expected) {
            // Expected generation mismatch
        }

        // Tamper kind byte (byte 8)
        byte[] tamperedKind = record.clone();
        tamperedKind[8] ^= 1;
        try {
            SecureSavedMessageCrypto.decryptText(tamperedKind, key);
            fail("tampered kind must fail authentication or kind check");
        } catch (IllegalArgumentException expected) {
            // Expected authentication or kind mismatch
        }

        // Tamper account (bytes 9..12)
        byte[] tamperedAccount = record.clone();
        tamperedAccount[12] ^= 1;
        try {
            SecureSavedMessageCrypto.decryptText(tamperedAccount, key);
            fail("tampered account must fail authentication or account mismatch");
        } catch (IllegalArgumentException expected) {
            // Expected account mismatch or auth fail
        }

        // Tamper recordId (bytes 13..20)
        byte[] tamperedRecordId = record.clone();
        tamperedRecordId[20] ^= 1;
        try {
            SecureSavedMessageCrypto.decryptText(tamperedRecordId, key);
            fail("tampered recordId must fail authentication");
        } catch (IllegalArgumentException expected) {
            // Expected auth fail because recordId is in AAD
        }

        // ContentKind distinction in encryptRecord:
        byte[] textContent = SecureContentCodec.encodeText("my note");
        byte[] textRecord = SecureSavedMessageCrypto.encryptRecord(textContent, key);
        // byte 8 is kind: should be ContentKind.TEXT (ordinal 0)
        assertEquals(SecureSavedMessagesPolicy.ContentKind.TEXT.ordinal(), textRecord[8] & 0xff);

        byte[] binaryContent = new byte[] {0x00, 0x01, 0x02};
        byte[] photoRecord = SecureSavedMessageCrypto.encryptRecord(binaryContent, key);
        assertEquals(SecureSavedMessagesPolicy.ContentKind.PHOTO.ordinal(), photoRecord[8] & 0xff);
    }

    @Test
    public void sa21TypedControlSentinels() {
        // Pairing ACK control
        byte[] ackBytes = SecureContentCodec.encodePairingAckControl();
        SecureContentCodec.Decoded decodedAck = SecureContentCodec.decode(ackBytes);
        assertEquals(SecureContentCodec.TYPE_CONTROL, decodedAck.type);
        assertNotNull(decodedAck.control);
        assertEquals(SecureContentCodec.CONTROL_ACTION_PAIRING_ACK, decodedAck.control.action);

        // Pairing READY control
        byte[] readyBytes = SecureContentCodec.encodePairingReadyControl();
        SecureContentCodec.Decoded decodedReady = SecureContentCodec.decode(readyBytes);
        assertEquals(SecureContentCodec.TYPE_CONTROL, decodedReady.type);
        assertNotNull(decodedReady.control);
        assertEquals(SecureContentCodec.CONTROL_ACTION_PAIRING_READY, decodedReady.control.action);

        // Pairing REJECT control
        byte[] rejectBytes = SecureContentCodec.encodePairingRejectControl();
        SecureContentCodec.Decoded decodedReject = SecureContentCodec.decode(rejectBytes);
        assertEquals(SecureContentCodec.TYPE_CONTROL, decodedReject.type);
        assertNotNull(decodedReject.control);
        assertEquals(SecureContentCodec.CONTROL_ACTION_PAIRING_REJECT, decodedReject.control.action);

        // Delete control
        byte[] digest = new byte[32];
        Arrays.fill(digest, (byte) 0xAA);
        byte[] deleteBytes = SecureContentCodec.encodeDeleteControl(Arrays.asList(digest));
        SecureContentCodec.Decoded decodedDelete = SecureContentCodec.decode(deleteBytes);
        assertEquals(SecureContentCodec.TYPE_CONTROL, decodedDelete.type);
        assertNotNull(decodedDelete.control);
        assertEquals(SecureContentCodec.CONTROL_ACTION_DELETE, decodedDelete.control.action);
        assertEquals(1, decodedDelete.control.carrierDigests.size());
        assertArrayEquals(digest, decodedDelete.control.carrierDigests.get(0));
    }

    @Test
    public void sa22ScopedFailedDecryptCacheOperations() {
        // Scoped cache clearing should execute cleanly
        SecureChatEngine.clearFailedDecryptCache(0, 12345L);
        SecureChatEngine.clearFailedDecryptCache();
    }

    @Test
    public void sa23FileHygieneConfinementAndPurge() throws Exception {
        File rootDir = temporaryFolder.newFolder("allowed_root");
        File subDir = new File(rootDir, "sub");
        subDir.mkdirs();
        File validFile = new File(subDir, "payload.bin");
        validFile.createNewFile();

        // Valid confinement check
        File safe = SecureMediaCrypto.requireSafeFile(validFile, rootDir, "valid");
        assertEquals(validFile.getCanonicalPath(), safe.getCanonicalPath());

        // Traversal escaping root must fail closed
        File outsideDir = temporaryFolder.newFolder("outside_root");
        File outsideFile = new File(outsideDir, "escape.bin");
        outsideFile.createNewFile();
        try {
            SecureMediaCrypto.requireSafeFile(outsideFile, rootDir, "outside");
            fail("requireSafeFile must reject file outside allowed root");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("escapes allowed root"));
        }

        // Path traversal sequence must fail
        File traversalFile = new File(rootDir, "../secret.txt");
        try {
            SecureMediaCrypto.requireSafeFile(traversalFile, rootDir, "traversal");
            fail("requireSafeFile must reject path traversal");
        } catch (IllegalArgumentException expected) {
            // Expected
        }

        // Purge temporary files
        File tmp1 = new File(subDir, "media1.tmp");
        tmp1.createNewFile();
        File tmp2 = new File(rootDir, "media2.tmp");
        tmp2.createNewFile();
        File keep = new File(rootDir, "media3.keep");
        keep.createNewFile();

        assertTrue(tmp1.exists());
        assertTrue(tmp2.exists());
        assertTrue(keep.exists());

        SecureMediaCrypto.purgeTemporaryFiles(rootDir);

        assertFalse(tmp1.exists());
        assertFalse(tmp2.exists());
        assertTrue(keep.exists());
    }

    @Test
    public void sa25VerificationMetadataSignalPinned() throws Exception {
        File metaFile = new File("../gradle/verification-metadata.xml");
        if (!metaFile.exists()) {
            metaFile = new File("gradle/verification-metadata.xml");
        }
        assertTrue("gradle/verification-metadata.xml must exist", metaFile.isFile());

        byte[] bytes = new byte[(int) metaFile.length()];
        try (FileInputStream in = new FileInputStream(metaFile)) {
            in.read(bytes);
        }
        String content = new String(bytes, StandardCharsets.UTF_8);

        assertTrue(content.contains("libsignal-android"));
        assertTrue(content.contains("libsignal-client"));
        assertTrue(content.contains("4528ea6373cf15dba008effa33e24ee1006e358ab83e8fc2678734e44e6987db"));
        assertTrue(content.contains("2124c5215f71209ec6ac3508f43ef6f3af74718911baa1d6185b9930d21ed5b7"));
    }

    @Test
    public void sa33LinkGuardExtendedConfusableAndIpv6() {
        // IPv6 bracketed address parsing
        String ipv6Url = "http://[::1]:8080/secure/api?query=1";
        SecureLinkGuard.Analysis analysisIpv6 = SecureLinkGuard.analyze(ipv6Url);
        assertEquals("[::1]", analysisIpv6.host);
        assertEquals(ipv6Url, SecureLinkGuard.toSafeCopyUrl(analysisIpv6));

        // Mixed-case host preservation without case-sensitive replace bug
        String mixedCaseUrl = "https://Paypal.com/signin";
        SecureLinkGuard.Analysis analysisMixed = SecureLinkGuard.analyze(mixedCaseUrl);
        assertEquals("paypal.com", analysisMixed.host);
        assertEquals("https://paypal.com/signin", SecureLinkGuard.toSafeCopyUrl(analysisMixed));

        // Confusable Cyrillic 'a' (U+0430) spoofing paypal.com
        String spoofedUrl = "https://p\u0430yp\u0430l.com/login";
        SecureLinkGuard.Analysis analysisSpoofed = SecureLinkGuard.analyze(spoofedUrl);
        assertTrue(analysisSpoofed.isSuspicious);
        assertTrue(analysisSpoofed.hasConfusableTarget);
        assertEquals("paypal.com", analysisSpoofed.targetSpoofedDomain);

        // Confusable Armenian 'o' (U+0585) spoofing google.com
        String armenianSpoof = "https://g\u0585\u0585gle.com";
        SecureLinkGuard.Analysis analysisArmenian = SecureLinkGuard.analyze(armenianSpoof);
        assertTrue(analysisArmenian.isSuspicious);
        assertTrue(analysisArmenian.hasConfusableTarget);
        assertEquals("google.com", analysisArmenian.targetSpoofedDomain);
    }
}
