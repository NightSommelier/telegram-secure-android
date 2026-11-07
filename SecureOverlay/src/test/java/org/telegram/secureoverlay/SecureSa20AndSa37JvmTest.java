package org.telegram.secureoverlay;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.Before;
import org.junit.Test;
import org.signal.libsignal.protocol.IdentityKeyPair;
import org.signal.libsignal.protocol.ecc.ECKeyPair;
import org.signal.libsignal.protocol.kem.KEMKeyPair;
import org.signal.libsignal.protocol.kem.KEMKeyType;

public final class SecureSa20AndSa37JvmTest {
    @Before
    public void resetMaskKey() {
        SecureNameMask.clearCachedKey();
    }

    @Test
    public void sa20MonotonicRecordIdsAndPinStoreBlockDuplicationSpliceAndEditRollback() {
        KeystoreEncryptedBlobStore storage = KeystoreEncryptedBlobStore.createInMemoryForTesting();
        SecureSavedMessagesPinStore pinStore = new SecureSavedMessagesPinStore(storage);

        byte[] rawKey = new byte[32];
        Arrays.fill(rawKey, (byte) 0x5A);
        SecureSavedMessagesKeyStore.KeyMaterial key =
                new SecureSavedMessagesKeyStore.KeyMaterial(1, 1, rawKey);

        byte[] r1 = SecureSavedMessageCrypto.encryptText("original note", key);
        byte[] r2 = SecureSavedMessageCrypto.encryptText("another new note", key);
        Long id1 = SecureSavedMessageCrypto.extractRecordId(r1);
        Long id2 = SecureSavedMessageCrypto.extractRecordId(r2);
        assertNotNull(id1);
        assertNotNull(id2);
        assertTrue("Expected strictly increasing recordId", id2 > id1);

        // Unsent negative local messageId decrypts without pinning a positive server ID
        assertEquals(
                "original note",
                SecureSavedMessageCrypto.decryptTextBound(r1, key, pinStore, -200001));

        // Server assigns messageId = 101: pins r1 <-> 101; idempotent re-reads succeed
        assertEquals(
                "original note",
                SecureSavedMessageCrypto.decryptTextBound(r1, key, pinStore, 101));
        assertEquals(
                "original note",
                SecureSavedMessageCrypto.decryptTextBound(r1, key, pinStore, 101));

        // Attack 1: Server duplicates r1 onto messageId = 102 -> rejected fail-closed
        try {
            SecureSavedMessageCrypto.decryptTextBound(r1, key, pinStore, 102);
            fail("Expected duplicated Saved Messages record on different messageId to fail");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("duplicated"));
        }

        // Attack 2: Server splices unedited new-message record r2 onto pinned message 101 -> rejected
        try {
            SecureSavedMessageCrypto.decryptTextBound(r2, key, pinStore, 101);
            fail("Expected unedited FSM2 record spliced onto existing message 101 to fail");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("unedited record cannot overwrite"));
        }

        // r2 was rejected on 101 without mutating state, so r2 still binds cleanly to its real message 102
        assertEquals(
                "another new note",
                SecureSavedMessageCrypto.decryptTextBound(r2, key, pinStore, 102));

        // Legitimate edit #1 on message 101 (FSM3 bound to targetMessageId = 101)
        byte[] edit1 = SecureSavedMessageCrypto.encryptTextForEdit("edited v1", key, 101);
        assertEquals(
                "edited v1",
                SecureSavedMessageCrypto.decryptTextBound(edit1, key, pinStore, 101));
        assertEquals(
                "edited v1",
                SecureSavedMessageCrypto.decryptTextBound(edit1, key, pinStore, 101));

        // Attack 3: Server rolls message 101 back to original r1 -> rejected
        try {
            SecureSavedMessageCrypto.decryptTextBound(r1, key, pinStore, 101);
            fail("Expected rollback to original FSM2 record to fail");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("rollback"));
        }

        // Legitimate edit #2 on message 101
        byte[] edit2 = SecureSavedMessageCrypto.encryptTextForEdit("edited v2", key, 101);
        assertEquals(
                "edited v2",
                SecureSavedMessageCrypto.decryptTextBound(edit2, key, pinStore, 101));

        // Attack 4: Server rolls message 101 back to edit1 -> rejected
        try {
            SecureSavedMessageCrypto.decryptTextBound(edit1, key, pinStore, 101);
            fail("Expected rollback to older FSM3 edit to fail");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("rollback"));
        }

        // Attack 5: Tampered ciphertext / AAD targetMessageId never mutates pinStore
        byte[] tamperedTarget = edit2.clone();
        tamperedTarget[24] ^= 1; // targetMessageId LSB in FSM3 header (bytes 21..24)
        try {
            SecureSavedMessageCrypto.decryptTextBound(tamperedTarget, key, pinStore, 999);
            fail("Expected tampered FSM3 targetMessageId to fail GCM authentication");
        } catch (IllegalArgumentException expected) {
            // Expected GCM auth failure
        }

        // Attack 6: Stateless FSM3 targetMessageId binding blocks cross-message replay even on fresh store
        SecureSavedMessagesPinStore freshAfterRestore =
                new SecureSavedMessagesPinStore(KeystoreEncryptedBlobStore.createInMemoryForTesting());
        try {
            SecureSavedMessageCrypto.decryptTextBound(edit2, key, freshAfterRestore, 202);
            fail("Expected FSM3 edit bound to 101 to fail on message 202 even with empty pinStore");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("different message ID"));
        }
        // On fresh store, legitimate message 101 decrypts edit2 and still blocks older edit1 rollback!
        assertEquals(
                "edited v2",
                SecureSavedMessageCrypto.decryptTextBound(edit2, key, freshAfterRestore, 101));
        try {
            SecureSavedMessageCrypto.decryptTextBound(edit1, key, freshAfterRestore, 101);
            fail("Expected monotonic recordId check to block rollback to edit1 on fresh store");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("rollback"));
        }
    }

    @Test
    public void sa20AccountScopedPinClearDoesNotAffectOtherAccount() {
        KeystoreEncryptedBlobStore storage = KeystoreEncryptedBlobStore.createInMemoryForTesting();
        SecureSavedMessagesPinStore pinStore = new SecureSavedMessagesPinStore(storage);

        byte[] raw = new byte[32];
        Arrays.fill(raw, (byte) 0x33);
        SecureSavedMessagesKeyStore.KeyMaterial keyAcct0 =
                new SecureSavedMessagesKeyStore.KeyMaterial(0, 1, raw);
        SecureSavedMessagesKeyStore.KeyMaterial keyAcct1 =
                new SecureSavedMessagesKeyStore.KeyMaterial(1, 1, raw);

        byte[] rec0 = SecureSavedMessageCrypto.encryptText("acct0", keyAcct0);
        byte[] rec1 = SecureSavedMessageCrypto.encryptText("acct1", keyAcct1);

        assertEquals("acct0", SecureSavedMessageCrypto.decryptTextBound(rec0, keyAcct0, pinStore, 10));
        assertEquals("acct1", SecureSavedMessageCrypto.decryptTextBound(rec1, keyAcct1, pinStore, 10));

        pinStore.clearForAccount(0);

        // Account 1 pin remains intact (duplicating rec1 to message 11 still fails)
        try {
            SecureSavedMessageCrypto.decryptTextBound(rec1, keyAcct1, pinStore, 11);
            fail("Expected account 1 pin to remain active after clearing account 0");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("duplicated"));
        }
    }

    @Test
    public void sa37RejectsSignedV2UnboundOffersAndZeroParticipantIds() throws Exception {
        IdentityKeyPair identity = IdentityKeyPair.generate();
        ECKeyPair preKey = ECKeyPair.generate();
        ECKeyPair signedPreKey = ECKeyPair.generate();
        byte[] signedSig = identity.getPrivateKey()
                .calculateSignature(signedPreKey.getPublicKey().serialize());
        KEMKeyPair kyber = KEMKeyPair.generate(KEMKeyType.KYBER_1024);
        byte[] kyberSig = identity.getPrivateKey()
                .calculateSignature(kyber.getPublicKey().serialize());
        SecurePreKeyBundleCodec.PublicBundle bundle =
                new SecurePreKeyBundleCodec.PublicBundle(
                        1234,
                        1,
                        preKey.getPublicKey().serialize(),
                        2,
                        signedPreKey.getPublicKey().serialize(),
                        signedSig,
                        identity.getPublicKey().serialize(),
                        3,
                        kyber.getPublicKey().serialize(),
                        kyberSig);
        SecureRecoveryGenerationStore.Record recovery =
                new SecureRecoveryGenerationStore.Record(1, UUID.randomUUID());

        // Craft a genuinely signed legacy v2 (unbound) offer and assert decodeOffer rejects it
        ByteArrayOutputStream bodySink = new ByteArrayOutputStream();
        DataOutputStream bodyOut = new DataOutputStream(bodySink);
        bodyOut.writeByte(2); // RECOVERY_VERSION (v2)
        bodyOut.writeInt(1234);
        bodyOut.writeInt(1);
        writeField(bodyOut, preKey.getPublicKey().serialize());
        bodyOut.writeInt(2);
        writeField(bodyOut, signedPreKey.getPublicKey().serialize());
        writeField(bodyOut, signedSig);
        writeField(bodyOut, identity.getPublicKey().serialize());
        bodyOut.writeInt(3);
        writeField(bodyOut, kyber.getPublicKey().serialize());
        writeField(bodyOut, kyberSig);
        bodyOut.writeLong(recovery.generation);
        bodyOut.writeLong(recovery.recoveryId.getMostSignificantBits());
        bodyOut.writeLong(recovery.recoveryId.getLeastSignificantBits());
        bodyOut.flush();
        byte[] v2Body = bodySink.toByteArray();
        byte[] domain = "Fork-Secure pairing offer v2\u0000".getBytes(StandardCharsets.US_ASCII);
        byte[] sigInput = new byte[domain.length + v2Body.length];
        System.arraycopy(domain, 0, sigInput, 0, domain.length);
        System.arraycopy(v2Body, 0, sigInput, domain.length, v2Body.length);
        byte[] v2Sig = identity.getPrivateKey().calculateSignature(sigInput);
        ByteArrayOutputStream fullV2 = new ByteArrayOutputStream();
        fullV2.write(v2Body);
        writeField(new DataOutputStream(fullV2), v2Sig);

        try {
            SecurePreKeyBundleCodec.decodeOffer(fullV2.toByteArray());
            fail("Expected signed v2 unbound offer to be rejected");
        } catch (IllegalArgumentException expected) {
            assertEquals("unsupported pre-key bundle version", expected.getMessage());
        }

        // Reject zero ownerUserId or zero recipientUserId at encode time
        try {
            SecurePreKeyBundleCodec.encodeRecoveryOffer(
                    bundle, recovery, identity, 0L, 2002L, 1700000000L, 12345L);
            fail("Expected ownerUserId=0 to be rejected");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("invalid v3"));
        }

        // Valid v3 offer still fails requireValidOfferBinding if senderUserId=0 or localUserId=0
        byte[] validV3 = SecurePreKeyBundleCodec.encodeRecoveryOffer(
                bundle, recovery, identity, 1001L, 2002L, 1700000000L, 12345L);
        SecurePreKeyBundleCodec.DecodedOffer decoded =
                SecurePreKeyBundleCodec.decodeOffer(validV3);

        try {
            SecureChatEngine.requireValidOfferBinding(1001L, 0L, 2002L, decoded);
            fail("Expected senderUserId=0 to fail offer binding");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("positive sender user ID"));
        }
        try {
            SecureChatEngine.requireValidOfferBinding(1001L, 1001L, 0L, decoded);
            fail("Expected localUserId=0 to fail offer binding");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("positive local user ID"));
        }
    }

    @Test
    public void sa37RequireValidInboundSenderAndRemovedOverloadsAndSourceLint() throws Exception {
        // 1:1 chat with senderUserId=0 must fail closed
        try {
            SecureChatEngine.requireValidInboundSender(1001L, 0L);
            fail("Expected senderUserId=0 in 1:1 chat to fail closed");
        } catch (SecureChatEngine.SecureChatException expected) {
            assertTrue(expected.getMessage().contains("positive sender user ID"));
        }
        // Group chat with senderUserId=0 must fail closed
        try {
            SecureChatEngine.requireValidInboundSender(-5001L, 0L);
            fail("Expected senderUserId=0 in group chat to fail closed");
        } catch (SecureChatEngine.SecureChatException expected) {
            assertTrue(expected.getMessage().contains("positive sender user ID"));
        }
        // Matching 1:1 and positive group sender succeed
        SecureChatEngine.requireValidInboundSender(1001L, 1001L);
        SecureChatEngine.requireValidInboundSender(-5001L, 1001L);

        // Reflection guard: senderless / unbound overloads must not exist on SecureChatEngine
        assertNoDeclaredMethod(SecureChatEngine.class, "createPairingOffer");
        assertNoDeclaredMethod(SecureChatEngine.class, "receivePairingOffer", String.class, int.class);
        assertNoDeclaredMethod(SecureChatEngine.class, "decryptText", String.class);
        assertNoDeclaredMethod(SecureChatEngine.class, "decryptAttachmentManifest", String.class);
        assertNoDeclaredMethod(SecureChatEngine.class, "decryptStaticStickerManifest", String.class);
        assertNoDeclaredMethod(SecureChatEngine.class, "resolveDialogPreview", String.class, boolean.class);
        assertNoDeclaredMethod(
                SecurePreKeyBundleCodec.class,
                "encodeRecoveryOffer",
                KeystoreSignalProtocolStore.class,
                SecureRecoveryGenerationStore.Record.class);

        // Source lint guard across TMessagesProj/src/main/java: no 1-arg decryptText(carrier) calls
        File appSrcRoot = new File("../TMessagesProj/src/main/java");
        if (!appSrcRoot.isDirectory()) {
            appSrcRoot = new File("TMessagesProj/src/main/java");
        }
        assertTrue("Expected TMessagesProj/src/main/java directory to exist", appSrcRoot.isDirectory());

        Pattern oneArgDecrypt = Pattern.compile(
                "\\.(?:decryptText|decryptForkSecureText|decryptAttachmentManifest|decryptStaticStickerManifest)\\s*\\([^,;)\\n]+\\)");
        Pattern zeroArgOffer = Pattern.compile("\\.createPairingOffer\\s*\\(\\s*\\)");

        try (Stream<Path> paths = Files.walk(appSrcRoot.toPath())) {
            paths.filter(p -> p.toString().endsWith(".java")).forEach(path -> {
                try {
                    String content = new String(Files.readAllBytes(path), StandardCharsets.UTF_8);
                    Matcher m1 = oneArgDecrypt.matcher(content);
                    if (m1.find()) {
                        fail("Found forbidden senderless decrypt call in " + path + ": " + m1.group());
                    }
                    Matcher m2 = zeroArgOffer.matcher(content);
                    if (m2.find()) {
                        fail("Found forbidden unbound createPairingOffer() call in " + path);
                    }
                } catch (java.io.IOException e) {
                    throw new RuntimeException(e);
                }
            });
        }
    }

    private static void assertNoDeclaredMethod(Class<?> clazz, String name, Class<?>... params) {
        try {
            Method m = clazz.getDeclaredMethod(name, params);
            fail("Forbidden senderless/unbound overload still exists: " + m);
        } catch (NoSuchMethodException expected) {
            // Expected: overload removed
        }
    }

    private static void writeField(DataOutputStream out, byte[] value) throws Exception {
        out.writeShort(value.length);
        out.write(value);
    }
}
