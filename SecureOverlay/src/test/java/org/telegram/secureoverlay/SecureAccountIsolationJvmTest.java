package org.telegram.secureoverlay;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.Test;
import org.signal.libsignal.protocol.SignalProtocolAddress;
import org.signal.libsignal.protocol.state.SessionRecord;

public final class SecureAccountIsolationJvmTest {

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

        public synchronized void deletePrefixes(String... prefixes) {
            List<String> toRemove = new ArrayList<>();
            for (String k : map.keySet()) {
                for (String p : prefixes) {
                    if (k.startsWith(p)) {
                        toRemove.add(k);
                        break;
                    }
                }
            }
            for (String k : toRemove) {
                map.remove(k);
            }
        }

        public synchronized Map<String, byte[]> getAll() {
            return new LinkedHashMap<>(map);
        }
    }

    @Test
    public void differentAccountsHaveIsolatedCryptographicIdentitiesAndPreKeys()
            throws Exception {
        InMemoryEncryptedStorage storage = new InMemoryEncryptedStorage();

        KeystoreSignalProtocolStore account0 =
                new KeystoreSignalProtocolStore(null, 0, storage);
        KeystoreSignalProtocolStore account1 =
                new KeystoreSignalProtocolStore(null, 1, storage);

        assertEquals(0, account0.getAccount());
        assertEquals(1, account1.getAccount());

        // Identities must be completely different
        byte[] pub0 = account0.getIdentityKeyPair().getPublicKey().serialize();
        byte[] pub1 = account1.getIdentityKeyPair().getPublicKey().serialize();
        assertFalse(java.util.Arrays.equals(pub0, pub1));

        // Generating prekey material for both accounts
        KeystoreSignalProtocolStore.LocalPreKeyMaterial mat0 =
                account0.ensureLocalPreKeyMaterial();
        KeystoreSignalProtocolStore.LocalPreKeyMaterial mat1 =
                account1.ensureLocalPreKeyMaterial();

        // Account 0 signatures verify ONLY under account 0 identity key
        assertTrue(
                account0.getIdentityKeyPair()
                        .getPublicKey()
                        .getPublicKey()
                        .verifySignature(
                                mat0.signedPreKey.getKeyPair().getPublicKey().serialize(),
                                mat0.signedPreKey.getSignature()));

        assertFalse(
                account1.getIdentityKeyPair()
                        .getPublicKey()
                        .getPublicKey()
                        .verifySignature(
                                mat0.signedPreKey.getKeyPair().getPublicKey().serialize(),
                                mat0.signedPreKey.getSignature()));

        // Account 1 signatures verify ONLY under account 1 identity key
        assertTrue(
                account1.getIdentityKeyPair()
                        .getPublicKey()
                        .getPublicKey()
                        .verifySignature(
                                mat1.signedPreKey.getKeyPair().getPublicKey().serialize(),
                                mat1.signedPreKey.getSignature()));

        assertFalse(
                account0.getIdentityKeyPair()
                        .getPublicKey()
                        .getPublicKey()
                        .verifySignature(
                                mat1.signedPreKey.getKeyPair().getPublicKey().serialize(),
                                mat1.signedPreKey.getSignature()));

        // Storage keys must be properly prefixed by account/
        for (String key : storage.getAll().keySet()) {
            assertTrue(
                    "Key " + key + " is not scoped to an account!",
                    key.startsWith("account/0/") || key.startsWith("account/1/"));
        }
    }

    @Test
    public void sessionStateIsCompletelyIsolatedBetweenAccounts() throws Exception {
        InMemoryEncryptedStorage storage = new InMemoryEncryptedStorage();

        KeystoreSignalProtocolStore account0 =
                new KeystoreSignalProtocolStore(null, 0, storage);
        KeystoreSignalProtocolStore account1 =
                new KeystoreSignalProtocolStore(null, 1, storage);

        SignalProtocolAddress peerAddr =
                new SignalProtocolAddress("telegram-user-4242", 1);

        SessionRecord record = new SessionRecord();
        account0.storeSession(peerAddr, record);

        assertTrue(account0.containsSession(peerAddr));
        assertNotNull(account0.loadSession(peerAddr));

        // Account 1 must NOT see Account 0's session
        assertFalse(account1.containsSession(peerAddr));

        // Deleting session in Account 0 does not affect Account 1
        account0.deleteSession(peerAddr);
        assertFalse(account0.containsSession(peerAddr));
    }

    @Test
    public void accountResetDoesNotDestroyOtherAccountState() throws Exception {
        InMemoryEncryptedStorage storage = new InMemoryEncryptedStorage();

        KeystoreSignalProtocolStore account0 =
                new KeystoreSignalProtocolStore(null, 0, storage);
        KeystoreSignalProtocolStore account1 =
                new KeystoreSignalProtocolStore(null, 1, storage);

        SignalProtocolAddress peerAddr =
                new SignalProtocolAddress("telegram-user-5555", 1);
        account1.storeSession(peerAddr, new SessionRecord());

        byte[] account1PubKey =
                account1.getIdentityKeyPair().getPublicKey().serialize();

        // Reset account 0 by deleting account/0/ prefix
        storage.deletePrefixes("account/0/");

        // Account 1's identity and sessions must remain 100% intact
        assertTrue(account1.containsSession(peerAddr));
        byte[] account1ReloadedPubKey =
                new KeystoreSignalProtocolStore(null, 1, storage)
                        .getIdentityKeyPair()
                        .getPublicKey()
                        .serialize();
        org.junit.Assert.assertArrayEquals(account1PubKey, account1ReloadedPubKey);
    }
}
