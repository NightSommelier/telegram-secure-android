package org.telegram.secureoverlay;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.Test;
import org.signal.libsignal.protocol.InvalidKeyIdException;
import org.signal.libsignal.protocol.state.KyberPreKeyRecord;
import org.signal.libsignal.protocol.state.PreKeyRecord;
import org.signal.libsignal.protocol.state.SignedPreKeyRecord;

public final class SecurePreKeyRotationJvmTest {

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
                    if (k.equals(root) || k.startsWith(root + "/")) {
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
    }

    @Test
    public void initialMaterialGeneratesValidSignedAndKyberKeys() throws Exception {
        InMemoryEncryptedStorage storage = new InMemoryEncryptedStorage();
        KeystoreSignalProtocolStore store = new KeystoreSignalProtocolStore(null, storage);

        KeystoreSignalProtocolStore.LocalPreKeyMaterial material =
                store.ensureLocalPreKeyMaterial();

        assertEquals(2, material.signedPreKeyId);
        assertEquals(3, material.kyberPreKeyId);
        assertNotNull(material.preKey);
        assertNotNull(material.signedPreKey);
        assertNotNull(material.kyberPreKey);

        // Verify signatures
        assertTrue(
                store.getIdentityKeyPair()
                        .getPublicKey()
                        .getPublicKey()
                        .verifySignature(
                                material.signedPreKey.getKeyPair().getPublicKey().serialize(),
                                material.signedPreKey.getSignature()));

        assertTrue(
                store.getIdentityKeyPair()
                        .getPublicKey()
                        .getPublicKey()
                        .verifySignature(
                                material.kyberPreKey.getKeyPair().getPublicKey().serialize(),
                                material.kyberPreKey.getSignature()));
    }

    @Test
    public void oneTimePreKeysAreConsumableAndNeverReusedAcrossOffers() throws Exception {
        InMemoryEncryptedStorage storage = new InMemoryEncryptedStorage();
        KeystoreSignalProtocolStore store = new KeystoreSignalProtocolStore(null, storage);

        Set<Integer> dispensedIds = new HashSet<>();
        final int count = 25;

        for (int i = 0; i < count; i++) {
            KeystoreSignalProtocolStore.LocalPreKeyMaterial material =
                    store.ensureLocalPreKeyMaterial();
            int id = material.preKeyId;

            // Every dispensed ID must be unique
            assertFalse("PreKey ID " + id + " was re-used!", dispensedIds.contains(id));
            dispensedIds.add(id);

            // Dispensed prekey must exist in local storage for inbound session decryption
            assertTrue(store.containsPreKey(id));
            PreKeyRecord loaded = store.loadPreKey(id);
            assertEquals(id, loaded.getId());
        }

        assertEquals(count, dispensedIds.size());
    }

    @Test
    public void signedAndKyberPreKeysRotateAfterSevenDaysWithSunsetPreservation()
            throws Exception {
        InMemoryEncryptedStorage storage = new InMemoryEncryptedStorage();
        KeystoreSignalProtocolStore store = new KeystoreSignalProtocolStore(null, storage);

        long t0 = 1_700_000_000_000L;
        store.rotateKeysIfNeeded(t0);

        int initialSignedId = store.getActiveSignedPreKeyId();
        int initialKyberId = store.getActiveKyberPreKeyId();
        assertEquals(2, initialSignedId);
        assertEquals(3, initialKyberId);

        SignedPreKeyRecord signed0 = store.loadSignedPreKey(initialSignedId);
        KyberPreKeyRecord kyber0 = store.loadKyberPreKey(initialKyberId);
        assertEquals(t0, signed0.getTimestamp());
        assertEquals(t0, kyber0.getTimestamp());

        // At day 5: no rotation should happen
        long t5Days = t0 + (5L * 24 * 60 * 60 * 1000L);
        boolean rotatedAt5 = store.rotateKeysIfNeeded(t5Days);
        assertFalse(rotatedAt5);
        assertEquals(initialSignedId, store.getActiveSignedPreKeyId());
        assertEquals(initialKyberId, store.getActiveKyberPreKeyId());

        // At day 7 + 1 hour: rotation must occur
        long t7Days = t0 + (7L * 24 * 60 * 60 * 1000L) + (3600 * 1000L);
        boolean rotatedAt7 = store.rotateKeysIfNeeded(t7Days);
        assertTrue(rotatedAt7);

        int rotatedSignedId = store.getActiveSignedPreKeyId();
        int rotatedKyberId = store.getActiveKyberPreKeyId();
        assertNotEquals(initialSignedId, rotatedSignedId);
        assertNotEquals(initialKyberId, rotatedKyberId);

        SignedPreKeyRecord signed1 = store.loadSignedPreKey(rotatedSignedId);
        KyberPreKeyRecord kyber1 = store.loadKyberPreKey(rotatedKyberId);
        assertEquals(t7Days, signed1.getTimestamp());
        assertEquals(t7Days, kyber1.getTimestamp());

        // Grace period check: old keys must STILL be loadable
        assertTrue(store.containsSignedPreKey(initialSignedId));
        assertTrue(store.containsKyberPreKey(initialKyberId));
        assertNotNull(store.loadSignedPreKey(initialSignedId));
        assertNotNull(store.loadKyberPreKey(initialKyberId));

        // Signatures of new keys must be valid
        assertTrue(
                store.getIdentityKeyPair()
                        .getPublicKey()
                        .getPublicKey()
                        .verifySignature(
                                signed1.getKeyPair().getPublicKey().serialize(),
                                signed1.getSignature()));
        assertTrue(
                store.getIdentityKeyPair()
                        .getPublicKey()
                        .getPublicKey()
                        .verifySignature(
                                kyber1.getKeyPair().getPublicKey().serialize(),
                                kyber1.getSignature()));

        // Beyond 30 days (e.g. day 32): old keys (t0) should be pruned, while day 7 keys remain
        long t32Days = t0 + (32L * 24 * 60 * 60 * 1000L);
        store.rotateKeysIfNeeded(t32Days);

        // Initial keys from t0 are >30 days old and not active: must be pruned
        assertFalse(
                "Expired signed prekey should be pruned",
                store.containsSignedPreKey(initialSignedId));
        assertFalse(
                "Expired Kyber prekey should be pruned",
                store.containsKyberPreKey(initialKyberId));

        try {
            store.loadSignedPreKey(initialSignedId);
            fail("Expected InvalidKeyIdException for pruned signed prekey");
        } catch (InvalidKeyIdException expected) {
            // Success
        }

        try {
            store.loadKyberPreKey(initialKyberId);
            fail("Expected InvalidKeyIdException for pruned Kyber prekey");
        } catch (InvalidKeyIdException expected) {
            // Success
        }

        // Active keys must remain available
        int activeSigned = store.getActiveSignedPreKeyId();
        int activeKyber = store.getActiveKyberPreKeyId();
        assertTrue(store.containsSignedPreKey(activeSigned));
        assertTrue(store.containsKyberPreKey(activeKyber));
    }
}
