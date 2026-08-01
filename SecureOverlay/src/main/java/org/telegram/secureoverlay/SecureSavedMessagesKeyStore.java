package org.telegram.secureoverlay;

import android.content.Context;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;

/** Account-scoped self-key storage for Saved Messages. Peer sessions never use this key. */
public final class SecureSavedMessagesKeyStore {
    private static final String PREFIX = "saved-messages/v1/account/";
    private static final int KEY_BYTES = 32;
    private static final SecureRandom RANDOM = new SecureRandom();

    private final KeystoreEncryptedBlobStore blobs;

    public SecureSavedMessagesKeyStore(Context context) {
        blobs = new KeystoreEncryptedBlobStore(context.getApplicationContext());
    }

    public synchronized KeyMaterial getOrCreate(int account)
            throws KeystoreEncryptedBlobStore.StateStoreException {
        requireAccount(account);
        String name = name(account);
        byte[] encoded = blobs.get(name);
        if (encoded == null) {
            encoded = encode(1, randomKey());
            blobs.put(name, encoded);
        }
        return decode(encoded);
    }

    /** Rotates only the Saved Messages self-key; existing generations remain undecryptable here. */
    public synchronized KeyMaterial rotate(int account)
            throws KeystoreEncryptedBlobStore.StateStoreException {
        requireAccount(account);
        KeyMaterial current = getOrCreate(account);
        KeyMaterial next = new KeyMaterial(current.generation + 1, randomKey());
        blobs.put(name(account), encode(next.generation, next.key));
        return next;
    }

    static byte[] encodeForBackup(KeyMaterial key) {
        if (key == null) {
            throw new IllegalArgumentException("Saved Messages key is required");
        }
        return encode(key.generation, key.key);
    }

    synchronized void restoreEncoded(int account, byte[] encoded)
            throws KeystoreEncryptedBlobStore.StateStoreException {
        requireAccount(account);
        KeyMaterial key = decode(encoded);
        blobs.put(name(account), encode(key.generation, key.key));
    }

    void clearForTests(int account) throws KeystoreEncryptedBlobStore.StateStoreException {
        blobs.delete(name(account));
    }

    private static byte[] encode(int generation, byte[] key) {
        ByteBuffer buffer = ByteBuffer.allocate(4 + KEY_BYTES);
        buffer.putInt(generation).put(key);
        return buffer.array();
    }

    private static KeyMaterial decode(byte[] encoded) {
        if (encoded == null || encoded.length != 4 + KEY_BYTES) {
            throw new IllegalStateException("invalid Saved Messages self-key record");
        }
        ByteBuffer buffer = ByteBuffer.wrap(encoded);
        int generation = buffer.getInt();
        byte[] key = new byte[KEY_BYTES];
        buffer.get(key);
        if (generation < 1) {
            throw new IllegalStateException("invalid Saved Messages key generation");
        }
        return new KeyMaterial(generation, key);
    }

    private static byte[] randomKey() {
        byte[] key = new byte[KEY_BYTES];
        RANDOM.nextBytes(key);
        return key;
    }

    private static String name(int account) {
        return PREFIX + account + "/self-key";
    }

    private static void requireAccount(int account) {
        if (account < 0) {
            throw new IllegalArgumentException("account must be non-negative");
        }
    }

    public static final class KeyMaterial {
        public final int generation;
        public final byte[] key;

        private KeyMaterial(int generation, byte[] key) {
            this.generation = generation;
            this.key = key.clone();
        }

        @Override
        public boolean equals(Object other) {
            if (!(other instanceof KeyMaterial)) {
                return false;
            }
            KeyMaterial value = (KeyMaterial) other;
            return generation == value.generation && Arrays.equals(key, value.key);
        }

        @Override
        public int hashCode() {
            return 31 * generation + Arrays.hashCode(key);
        }
    }
}
