package org.telegram.secureoverlay;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.signal.libsignal.protocol.IdentityKeyPair;

public final class SecureWave2AndAsyncIndexJvmTest {

    @Rule
    public final TemporaryFolder tempFolder = new TemporaryFolder();

    @Test
    public void sa38_constructorIsPackagePrivateAndTMessagesProjUsesManager() throws Exception {
        for (Constructor<?> ctor : SecureChatEngine.class.getDeclaredConstructors()) {
            assertFalse(
                    "SecureChatEngine constructor must not be public (SA-38)",
                    Modifier.isPublic(ctor.getModifiers()));
        }

        Path uiRoot = Paths.get("../TMessagesProj/src/main/java");
        if (!Files.isDirectory(uiRoot)) {
            uiRoot = Paths.get("TMessagesProj/src/main/java");
        }
        assertTrue("TMessagesProj source tree must exist", Files.isDirectory(uiRoot));

        try (Stream<Path> walk = Files.walk(uiRoot)) {
            List<Path> javaFiles = walk
                    .filter(p -> p.toString().endsWith(".java"))
                    .collect(Collectors.toList());
            for (Path file : javaFiles) {
                String source = new String(Files.readAllBytes(file), StandardCharsets.UTF_8);
                assertFalse(
                        "Direct new SecureChatEngine(...) found in " + file,
                        source.contains("new SecureChatEngine(")
                                || source.contains("new org.telegram.secureoverlay.SecureChatEngine("));
            }
        }
    }

    @Test
    public void sa43AndSa28_exportRejectsWeakRepeatPatternsWhileImportRestoresLegacyArchives()
            throws Exception {
        assertFalse(SecureIdentityBackupCodec.isStrongPassword("123412341234".toCharArray()));
        assertFalse(SecureIdentityBackupCodec.isStrongPassword("abcdabcdabcd".toCharArray()));
        assertTrue(SecureIdentityBackupCodec.isStrongPassword("StrongPass#1".toCharArray()));

        IdentityKeyPair identity = IdentityKeyPair.generate();
        SecureIdentityBackupCodec.Payload payload = new SecureIdentityBackupCodec.Payload(
                UUID.fromString("00112233-4455-6677-8899-aabbccddeeff"),
                777001L,
                2L,
                1_700_000_500L,
                4096,
                identity.serialize());

        // Simulate a legacy archive encrypted with a 6-character password ("short6")
        byte[] salt = new byte[16];
        byte[] nonce = new byte[12];
        for (int i = 0; i < salt.length; i++) {
            salt[i] = (byte) (i + 1);
        }
        for (int i = 0; i < nonce.length; i++) {
            nonce[i] = (byte) (i + 21);
        }
        byte[] plaintext = SecureIdentityBackupCodec.encodePlaintext(payload);
        Method pbkdf2 = SecureIdentityBackupCodec.class.getDeclaredMethod(
                "pbkdf2HmacSha256", byte[].class, byte[].class, int.class);
        pbkdf2.setAccessible(true);

        byte[] shortPwdKey = (byte[]) pbkdf2.invoke(
                null, "short6".getBytes(StandardCharsets.UTF_8), salt, 600_000);
        byte[] headerWithPwd = buildIdentityHeader(plaintext.length, salt, nonce, 0);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(
                Cipher.ENCRYPT_MODE,
                new SecretKeySpec(shortPwdKey, "AES"),
                new GCMParameterSpec(128, nonce));
        cipher.updateAAD(headerWithPwd);
        byte[] ctWithPwd = cipher.doFinal(plaintext);
        ByteArrayOutputStream legacyShortArchive = new ByteArrayOutputStream();
        legacyShortArchive.write(headerWithPwd);
        legacyShortArchive.write(ctWithPwd);

        SecureIdentityBackupCodec.Payload restoredShort =
                SecureIdentityBackupCodec.decrypt(
                        legacyShortArchive.toByteArray(), "short6".toCharArray());
        assertArrayEquals(payload.serializedIdentity, restoredShort.serializedIdentity);

        // Simulate a legacy FLAG_NO_PASSWORD archive (flags = 1)
        byte[] noPwdKey = (byte[]) pbkdf2.invoke(
                null,
                "Fork-Secure unprotected identity backup v1".getBytes(StandardCharsets.US_ASCII),
                salt,
                600_000);
        byte[] headerNoPwd = buildIdentityHeader(plaintext.length, salt, nonce, 1);
        Cipher cipherNoPwd = Cipher.getInstance("AES/GCM/NoPadding");
        cipherNoPwd.init(
                Cipher.ENCRYPT_MODE,
                new SecretKeySpec(noPwdKey, "AES"),
                new GCMParameterSpec(128, nonce));
        cipherNoPwd.updateAAD(headerNoPwd);
        byte[] ctNoPwd = cipherNoPwd.doFinal(plaintext);
        ByteArrayOutputStream legacyNoPwdArchive = new ByteArrayOutputStream();
        legacyNoPwdArchive.write(headerNoPwd);
        legacyNoPwdArchive.write(ctNoPwd);

        assertFalse(SecureIdentityBackupCodec.requiresPassword(legacyNoPwdArchive.toByteArray()));
        SecureIdentityBackupCodec.Payload restoredNoPwd =
                SecureIdentityBackupCodec.decrypt(legacyNoPwdArchive.toByteArray(), new char[0]);
        assertArrayEquals(payload.serializedIdentity, restoredNoPwd.serializedIdentity);
    }

    @Test
    public void sa44_singleSegmentLegacyPaddedAttachmentDecryptsViaFallback() throws Exception {
        byte[] samplePlaintext = "Legacy single-shot padded attachment <= 64KiB".getBytes(StandardCharsets.UTF_8);
        Method padmeMethod = SecureMediaCrypto.class.getDeclaredMethod("padmeSize", int.class);
        padmeMethod.setAccessible(true);
        int paddedLen = (Integer) padmeMethod.invoke(null, samplePlaintext.length);
        byte[] paddedPlaintext = new byte[paddedLen];
        System.arraycopy(samplePlaintext, 0, paddedPlaintext, 0, samplePlaintext.length);

        byte[] mediaId = new byte[16];
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        for (int i = 0; i < 16; i++) {
            mediaId[i] = (byte) (0x10 + i);
        }
        for (int i = 0; i < 32; i++) {
            key[i] = (byte) (0x30 + i);
        }
        for (int i = 0; i < 12; i++) {
            nonce[i] = (byte) (0x60 + i);
        }

        Method legacyCipherMethod = SecureMediaCrypto.class.getDeclaredMethod(
                "createAttachmentCipher", int.class, byte[].class, byte[].class, boolean.class);
        legacyCipherMethod.setAccessible(true);
        Cipher legacyEnc = (Cipher) legacyCipherMethod.invoke(
                null, Cipher.ENCRYPT_MODE, key, nonce, false);
        byte[] legacyCiphertext = legacyEnc.doFinal(paddedPlaintext);

        // Confirm ciphertext size collides with segmented single-segment ciphertext size (SA-44)
        assertEquals(
                SecureMediaCrypto.calculateSegmentedCiphertextSize(samplePlaintext.length),
                legacyCiphertext.length);

        byte[] sha256 = MessageDigest.getInstance("SHA-256").digest(legacyCiphertext);
        File dir = tempFolder.newFolder("sa44");
        File cipherFile = new File(dir, "legacy.bin");
        try (FileOutputStream out = new FileOutputStream(cipherFile)) {
            out.write(legacyCiphertext);
        }
        File destFile = new File(dir, "decrypted.txt");

        SecureContentCodec.Attachment manifest = new SecureContentCodec.Attachment(
                mediaId,
                key,
                nonce,
                sha256,
                samplePlaintext.length,
                legacyCiphertext.length,
                "note.txt",
                "text/plain",
                "",
                0,
                0,
                false);

        SecureMediaCrypto.decryptAttachmentFile(cipherFile, destFile, dir, manifest);
        byte[] decrypted = Files.readAllBytes(destFile.toPath());
        assertArrayEquals(samplePlaintext, decrypted);
    }

    @Test
    public void sa23_requireSafeFileBlocksTraversalOutsideAllowedRootAndParent() throws Exception {
        File root = tempFolder.newFolder("allowed-root");
        File outside = new File(tempFolder.getRoot(), "outside.bin");
        try {
            SecureMediaCrypto.requireSafeFile(new File(root, "../outside.bin"), root, "destination");
            fail("Traversal outside allowedRoot must be rejected");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("escapes"));
        }
        try {
            SecureMediaCrypto.requireSafeFile(new File(root, "../" + outside.getName()), "destination");
            fail("Traversal escaping uncanonicalized parent must be rejected");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("escapes"));
        }
    }

    @Test
    public void asyncMediaIndex_lookupCachedSupportsOneToOneGroupsAndSupergroupsWithoutDiskIo() {
        byte[] testMaskKey = new byte[32];
        for (int i = 0; i < testMaskKey.length; i++) {
            testMaskKey[i] = (byte) (i + 7);
        }
        SecureNameMask.setCachedKeyForTesting(testMaskKey);
        SecureMediaIndex.clearMemoryCache();
        try {
            assertTrue(SecureMediaIndex.lookupCached(0, 100500L, "TGS1:user").isMiss());
            assertTrue(SecureMediaIndex.lookupCached(0, -555666L, "TGS1:basicGroup").isMiss());
            assertTrue(SecureMediaIndex.lookupCached(0, -1001999888777L, "TGS1:supergroup").isMiss());
            assertTrue(SecureMediaIndex.lookupCached(0, 0L, "TGS1:invalid").isNegative());
        } finally {
            SecureNameMask.clearCachedKey();
            SecureMediaIndex.clearMemoryCache();
        }
    }

    private static byte[] buildIdentityHeader(
            int plaintextLength, byte[] salt, byte[] nonce, int flags) throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        DataOutputStream out = new DataOutputStream(bytes);
        out.write(new byte[] {'F', 'S', 'B', 'K'});
        out.writeShort(1);
        out.writeByte(2);
        out.writeByte(1);
        out.writeShort(flags);
        out.writeInt(600_000);
        out.writeInt(0);
        out.writeByte(1);
        out.writeByte(salt.length);
        out.writeByte(nonce.length);
        out.writeByte(0);
        out.writeInt(plaintextLength);
        out.write(salt);
        out.write(nonce);
        out.flush();
        return bytes.toByteArray();
    }
}
