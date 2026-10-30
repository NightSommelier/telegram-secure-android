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
            blobs.put(generationName(account, 1), encoded);
        }
        return decode(account, encoded);
    }

    /** Rotates Saved Messages self-key, preserving past generations for backward decryption. */
    public synchronized KeyMaterial rotate(int account)
            throws KeystoreEncryptedBlobStore.StateStoreException {
        requireAccount(account);
        KeyMaterial current = getOrCreate(account);
        KeyMaterial next = new KeyMaterial(account, current.generation + 1, randomKey());
        blobs.put(generationName(account, current.generation), encode(current.generation, current.key));
        blobs.put(name(account), encode(next.generation, next.key));
        blobs.put(generationName(account, next.generation), encode(next.generation, next.key));
        return next;
    }

    public synchronized KeyMaterial getKeyForGeneration(int account, int generation)
            throws KeystoreEncryptedBlobStore.StateStoreException {
        requireAccount(account);
        KeyMaterial current = getOrCreate(account);
        if (current.generation == generation) {
            return current;
        }
        byte[] encoded = blobs.get(generationName(account, generation));
        if (encoded != null) {
            return decode(account, encoded);
        }
        return null;
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
        KeyMaterial key = decode(account, encoded);
        blobs.put(name(account), encode(key.generation, key.key));
        blobs.put(generationName(account, key.generation), encode(key.generation, key.key));
    }

    void clearForTests(int account) throws KeystoreEncryptedBlobStore.StateStoreException {
        blobs.delete(name(account));
        blobs.deletePrefixes(PREFIX + account + "/generation/");
    }

    private static byte[] encode(int generation, byte[] key) {
        ByteBuffer buffer = ByteBuffer.allocate(4 + KEY_BYTES);
        buffer.putInt(generation).put(key);
        return buffer.array();
    }

    private static KeyMaterial decode(byte[] encoded) {
        return decode(0, encoded);
    }

    private static KeyMaterial decode(int account, byte[] encoded) {
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
        return new KeyMaterial(account, generation, key);
    }

    private static byte[] randomKey() {
        byte[] key = new byte[KEY_BYTES];
        RANDOM.nextBytes(key);
        return key;
    }

    private static String name(int account) {
        return PREFIX + account + "/self-key";
    }

    private static String generationName(int account, int generation) {
        return PREFIX + account + "/generation/" + generation;
    }

    private static void requireAccount(int account) {
        if (account < 0) {
            throw new IllegalArgumentException("account must be non-negative");
        }
    }

    public static final class KeyMaterial {
        public final int account;
        public final int generation;
        public final byte[] key;

        public KeyMaterial(int account, int generation, byte[] key) {
            this.account = account;
            this.generation = generation;
            this.key = key.clone();
        }

        public KeyMaterial(int generation, byte[] key) {
            this(0, generation, key);
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
