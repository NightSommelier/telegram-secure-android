package org.telegram.secureoverlay;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.Test;

public final class SecureTrustStateAndMediaDbJvmTest {

    private static final class InMemoryEncryptedStorage
            implements KeystoreSignalProtocolStore.EncryptedStateStorage {
        private final Map<String, byte[]> map = new LinkedHashMap<>();

        @Override
        public synchronized byte[] get(String name) {
            byte[] val = map.get(name);
            return val != null ? val.clone() : null;
        }

        @Override
        public synchronized void put(String name, byte[] data) {
            map.put(name, data != null ? data.clone() : null);
        }

        @Override
        public synchronized void delete(String name) {
            map.remove(name);
        }

        @Override
        public synchronized void deleteRoots(String... roots) {
            List<String> toRemove = new ArrayList<>();
            for (String k : map.keySet()) {
                for (String root : roots) {
                    if (k.equals(root) || k.startsWith(root + "/") || k.startsWith(root + ".")) {
                        toRemove.add(k);
                        break;
                    }
                }
            }
            for (String k : toRemove) {
                map.remove(k);
            }
        }

        @Override
        public synchronized void replaceRoots(Map<String, byte[]> replacements, String... roots) {
            deleteRoots(roots);
            if (replacements != null) {
                for (Map.Entry<String, byte[]> entry : replacements.entrySet()) {
                    put(entry.getKey(), entry.getValue());
                }
            }
        }

        @Override
        public synchronized boolean hasNameStartingWith(String... prefixes) {
            for (String k : map.keySet()) {
                for (String p : prefixes) {
                    if (k.startsWith(p)) {
                        return true;
                    }
                }
            }
            return false;
        }

        @Override
        public synchronized Map<String, byte[]> snapshotPrefixes(String... prefixes) {
            Map<String, byte[]> result = new LinkedHashMap<>();
            for (Map.Entry<String, byte[]> entry : map.entrySet()) {
                for (String p : prefixes) {
                    if (entry.getKey().startsWith(p)) {
                        result.put(entry.getKey(), entry.getValue() != null ? entry.getValue().clone() : null);
                        break;
                    }
                }
            }
            return result;
        }

        public Map<String, byte[]> rawMap() {
            return map;
        }
    }

    @Test
    public void secureChatStateStoresEncryptedStateAndMasksRecordNames() {
        InMemoryEncryptedStorage storage = new InMemoryEncryptedStorage();
        SecureChatState state = SecureChatState.forTest(storage);

        long peerId = 9876543210L;
        int account = 1;

        assertFalse(state.isPaired(account, peerId));
        assertFalse(state.isWaiting(account, peerId));
        assertFalse(state.isPaused(account, peerId));
        assertFalse(state.hasStateForPeer(account, peerId));

        state.markWaiting(account, peerId);
        assertTrue(state.isWaiting(account, peerId));
        assertFalse(state.isPaired(account, peerId));
        assertTrue(state.hasStateForPeer(account, peerId));

        state.markPaired(account, peerId);
        assertTrue(state.isPaired(account, peerId));
        assertFalse(state.isWaiting(account, peerId));

        state.pause(account, peerId);
        assertTrue(state.isPaused(account, peerId));
        assertFalse(state.isPaired(account, peerId));

        state.markIdentityPending(
                account,
                peerId,
                "TGS1:carrier-bundle-xyz",
                42,
                SecureChatState.PendingKind.RECOVERY_ADVANCE);
        assertTrue(state.isIdentityPending(account, peerId));
        assertEquals("TGS1:carrier-bundle-xyz", state.getPendingCarrier(account, peerId));
        assertEquals(42, state.getPendingMessageId(account, peerId));
        assertEquals(SecureChatState.PendingKind.RECOVERY_ADVANCE, state.getPendingKind(account, peerId));

        // Verify storage keys do NOT expose peerId or carrier bundle in plaintext
        boolean foundStateKey = false;
        for (String key : storage.rawMap().keySet()) {
            assertFalse("Storage key must not expose peer ID in plaintext: " + key,
                    key.contains(String.valueOf(peerId)));
            assertFalse("Storage key must not expose carrier in plaintext: " + key,
                    key.contains("carrier-bundle-xyz"));
            if (key.startsWith("chat-state.v1." + account + ".")) {
                foundStateKey = true;
            }
        }
        assertTrue("Expected HMAC-derived storage key for peer", foundStateKey);

        // Approve pending identity
        state.approvePendingIdentity(account, peerId);
        assertTrue(state.isPaired(account, peerId));
        assertFalse(state.isIdentityPending(account, peerId));
        assertNull(state.getPendingCarrier(account, peerId));
        assertEquals(42, state.getLastPairingMessageId(account, peerId));

        // Verify summary
        SecureChatState.Summary summary = state.getSummary(account);
        assertEquals(1, summary.paired);
        assertEquals(0, summary.waiting);
        assertEquals(0, summary.paused);
        assertEquals(0, summary.identityPending);
        assertEquals(1, summary.total());

        // Other account summary is empty
        assertEquals(0, state.getSummary(0).total());
    }

    @Test
    public void secureNameMaskDerivesPseudorandomHmacs() {
        InMemoryEncryptedStorage storage = new InMemoryEncryptedStorage();
        byte[] key = SecureNameMask.getOrGenerateKey(storage);
        assertNotNull(key);
        assertEquals(32, key.length);

        String peerHmac1 = SecureNameMask.maskPeer(key, 0, 1111);
        String peerHmac2 = SecureNameMask.maskPeer(key, 0, 1111);
        String peerHmac3 = SecureNameMask.maskPeer(key, 0, 2222);
        String peerHmacAccount1 = SecureNameMask.maskPeer(key, 1, 1111);

        assertEquals("Same input must derive identical HMAC", peerHmac1, peerHmac2);
        assertFalse("Different peers must derive different HMAC", peerHmac1.equals(peerHmac3));
        assertFalse("Different accounts must derive different HMAC", peerHmac1.equals(peerHmacAccount1));

        assertFalse(peerHmac1.contains("1111"));
        assertEquals(64, peerHmac1.length()); // 256 bits in hex
    }

    @Test
    public void secureLocalTextAndContentStoreEncodingAndMasking() {
        long peerUserId = 77778888L;
        byte[] carrierDigest = new byte[32];
        carrierDigest[0] = 0x12;
        carrierDigest[31] = 0x34;
        byte[] payload = "Hello secure encrypted text".getBytes(StandardCharsets.UTF_8);

        byte[] encodedText = SecureLocalTextStore.encodeRecord(peerUserId, carrierDigest, payload);
        assertTrue(SecureLocalTextStore.isEncodedRecord(encodedText));

        SecureLocalTextStore.RecordHeader header = SecureLocalTextStore.decodeHeader(encodedText);
        assertEquals(peerUserId, header.peerUserId);
        assertEquals(0x12, header.carrierDigest[0]);
        assertEquals(0x34, header.carrierDigest[31]);
        assertEquals("Hello secure encrypted text", new String(header.payload, StandardCharsets.UTF_8));

        byte[] extracted = SecureLocalTextStore.extractPayload(encodedText);
        assertEquals("Hello secure encrypted text", new String(extracted, StandardCharsets.UTF_8));

        // Content store header
        byte[] encodedContent = SecureLocalContentStore.encodeRecord(peerUserId, carrierDigest, payload);
        assertTrue(SecureLocalContentStore.isEncodedRecord(encodedContent));
        byte[] extractedContent = SecureLocalContentStore.extractPayload(encodedContent);
        assertEquals("Hello secure encrypted text", new String(extractedContent, StandardCharsets.UTF_8));

        // Key mask checks
        byte[] maskKey = SecureNameMask.getOrGenerateKey(KeystoreEncryptedBlobStore.createInMemoryForTesting());
        String key = SecureLocalTextStore.key(
                maskKey, SecureLocalTextStore.INCOMING_PREFIX, 0, peerUserId, "TGS1:some-carrier-message");
        assertFalse("Record name must not embed peer ID: " + key, key.contains(String.valueOf(peerUserId)));
        assertTrue("Record name must start with prefix: " + key, key.startsWith(SecureLocalTextStore.INCOMING_PREFIX));

        String contentKey = SecureLocalContentStore.key(
                maskKey, SecureLocalContentStore.INCOMING_PREFIX, 0, peerUserId, "TGS1:some-carrier-message");
        assertFalse("Content record name must not embed peer ID: " + contentKey, contentKey.contains(String.valueOf(peerUserId)));
        assertTrue("Content record name must start with prefix: " + contentKey, contentKey.startsWith(SecureLocalContentStore.INCOMING_PREFIX));
    }
}
