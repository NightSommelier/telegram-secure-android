package org.telegram.secureoverlay;

import android.content.Context;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.concurrent.ConcurrentHashMap;

/** Account-scoped self-key storage for Saved Messages. Peer sessions never use this key. */
public final class SecureSavedMessagesKeyStore {
    private static final String PREFIX = "saved-messages/v1/account/";
    private static final int KEY_BYTES = 32;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final ConcurrentHashMap<Integer, KeyMaterial> CURRENT_KEY_CACHE =
            new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, KeyMaterial> GENERATION_KEY_CACHE =
            new ConcurrentHashMap<>();

    private final KeystoreEncryptedBlobStore blobs;

    public SecureSavedMessagesKeyStore(Context context) {
        blobs = new KeystoreEncryptedBlobStore(context.getApplicationContext());
    }

    public static KeyMaterial peekCurrent(int account) {
        if (account < 0) {
            return null;
        }
        KeyMaterial cached = CURRENT_KEY_CACHE.get(account);
        return cached != null ? new KeyMaterial(cached.account, cached.generation, cached.key) : null;
    }

    public static void clearMemoryCache() {
        CURRENT_KEY_CACHE.clear();
        GENERATION_KEY_CACHE.clear();
    }

    static void evictAccountFromCache(int account) {
        CURRENT_KEY_CACHE.remove(account);
        String prefix = account + ":";
        GENERATION_KEY_CACHE.keySet().removeIf(k -> k.startsWith(prefix));
    }

    public synchronized KeyMaterial getOrCreate(int account)
            throws KeystoreEncryptedBlobStore.StateStoreException {
        requireAccount(account);
        if (blobs.isPersistent()) {
            KeyMaterial cached = CURRENT_KEY_CACHE.get(account);
            if (cached != null) {
                return new KeyMaterial(cached.account, cached.generation, cached.key);
            }
        }
        String name = name(account);
        byte[] encoded = blobs.get(name);
        if (encoded == null) {
            encoded = encode(1, randomKey());
            blobs.put(name, encoded);
            blobs.put(generationName(account, 1), encoded);
        }
        KeyMaterial loaded = decode(account, encoded);
        if (blobs.isPersistent()) {
            CURRENT_KEY_CACHE.put(account, loaded);
            GENERATION_KEY_CACHE.put(account + ":" + loaded.generation, loaded);
        }
        return new KeyMaterial(loaded.account, loaded.generation, loaded.key);
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
        if (blobs.isPersistent()) {
            GENERATION_KEY_CACHE.put(account + ":" + current.generation, current);
            CURRENT_KEY_CACHE.put(account, next);
            GENERATION_KEY_CACHE.put(account + ":" + next.generation, next);
        }
        return new KeyMaterial(next.account, next.generation, next.key);
    }

    public synchronized KeyMaterial getKeyForGeneration(int account, int generation)
            throws KeystoreEncryptedBlobStore.StateStoreException {
        requireAccount(account);
        if (blobs.isPersistent()) {
            KeyMaterial cachedGen = GENERATION_KEY_CACHE.get(account + ":" + generation);
            if (cachedGen != null) {
                return new KeyMaterial(cachedGen.account, cachedGen.generation, cachedGen.key);
            }
        }
        KeyMaterial current = getOrCreate(account);
        if (current.generation == generation) {
            return current;
        }
        byte[] encoded = blobs.get(generationName(account, generation));
        if (encoded != null) {
            KeyMaterial loaded = decode(account, encoded);
            if (blobs.isPersistent()) {
                GENERATION_KEY_CACHE.put(account + ":" + generation, loaded);
            }
            return new KeyMaterial(loaded.account, loaded.generation, loaded.key);
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
        if (blobs.isPersistent()) {
            evictAccountFromCache(account);
            CURRENT_KEY_CACHE.put(account, key);
            GENERATION_KEY_CACHE.put(account + ":" + key.generation, key);
        }
    }

    void clearForTests(int account) throws KeystoreEncryptedBlobStore.StateStoreException {
        evictAccountFromCache(account);
        SecureSavedMessagesPinStore.evictAccountFromCache(account);
        blobs.delete(name(account));
        blobs.deletePrefixes(PREFIX + account + "/generation/");
        blobs.deleteRoots(SecureSavedMessagesPinStore.accountRoot(account));
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
