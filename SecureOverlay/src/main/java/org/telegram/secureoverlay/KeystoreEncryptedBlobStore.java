package org.telegram.secureoverlay;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * Private encrypted blob storage for future libsignal state records.
 *
 * <p>Each stored value is AES-256-GCM encrypted with a non-exportable Android
 * Keystore key. The blob name is authenticated as associated data, so a value
 * cannot be moved to a different logical record. Writes use {@link
 * SharedPreferences.Editor#commit()} and report failure synchronously.</p>
 */
public final class KeystoreEncryptedBlobStore {
    private static final String KEYSTORE = "AndroidKeyStore";
    private static final String PREFS = "telegram_secure_overlay_state_v1";
    private static final String KEY_ALIAS = "telegram_secure_overlay_state_key_v1";
    private static final int NONCE_BYTES = 12;
    private static final int TAG_BITS = 128;
    private static final int FORMAT_VERSION = 1;
    private static final Object keyHandleLock = new Object();
    private static volatile SecretKey cachedKeyHandle;

    private final SharedPreferences preferences;

    public KeystoreEncryptedBlobStore(Context context) {
        preferences = context.getApplicationContext().getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    public synchronized void put(String name, byte[] plaintext) throws StateStoreException {
        requireName(name);
        if (plaintext == null) {
            throw new IllegalArgumentException("plaintext is required");
        }
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            // Android Keystore requires randomized encryption and therefore generates the GCM IV.
            // Supplying a caller-generated IV is rejected by modern Keystore implementations.
            cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey());
            byte[] nonce = cipher.getIV();
            if (nonce == null || nonce.length != NONCE_BYTES) {
                throw new StateStoreException("invalid Keystore GCM nonce");
            }
            cipher.updateAAD(name.getBytes(StandardCharsets.UTF_8));
            byte[] ciphertext = cipher.doFinal(plaintext);
            byte[] encoded = new byte[1 + nonce.length + ciphertext.length];
            encoded[0] = FORMAT_VERSION;
            System.arraycopy(nonce, 0, encoded, 1, nonce.length);
            System.arraycopy(ciphertext, 0, encoded, 1 + nonce.length, ciphertext.length);
            if (!preferences.edit().putString(name, Base64.encodeToString(encoded, Base64.NO_WRAP)).commit()) {
                throw new StateStoreException("failed to commit encrypted state");
            }
        } catch (GeneralSecurityException | IOException e) {
            throw new StateStoreException("failed to encrypt secure state", e);
        }
    }

    public synchronized byte[] get(String name) throws StateStoreException {
        requireName(name);
        String stored = preferences.getString(name, null);
        if (stored == null) {
            return null;
        }
        try {
            byte[] encoded = Base64.decode(stored, Base64.NO_WRAP);
            if (encoded.length <= 1 + NONCE_BYTES || encoded[0] != FORMAT_VERSION) {
                throw new StateStoreException("invalid encrypted state format");
            }
            byte[] nonce = new byte[NONCE_BYTES];
            System.arraycopy(encoded, 1, nonce, 0, nonce.length);
            byte[] ciphertext = new byte[encoded.length - 1 - nonce.length];
            System.arraycopy(encoded, 1 + nonce.length, ciphertext, 0, ciphertext.length);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, getOrCreateKey(), new GCMParameterSpec(TAG_BITS, nonce));
            cipher.updateAAD(name.getBytes(StandardCharsets.UTF_8));
            return cipher.doFinal(ciphertext);
        } catch (IllegalArgumentException | GeneralSecurityException | IOException e) {
            throw new StateStoreException("failed to decrypt secure state", e);
        }
    }

    public synchronized void delete(String name) throws StateStoreException {
        requireName(name);
        if (!preferences.edit().remove(name).commit()) {
            throw new StateStoreException("failed to delete encrypted state");
        }
    }

    /**
     * Deletes exact logical roots and all of their slash-delimited children in one commit.
     *
     * <p>This is used by identity reset to remove protocol keys and sessions while preserving
     * separately prefixed local message-display copies.</p>
     */
    public synchronized void deleteRoots(String... roots) throws StateStoreException {
        if (roots == null || roots.length == 0) {
            throw new IllegalArgumentException("secure state roots are required");
        }
        for (String root : roots) {
            requireName(root);
        }
        SharedPreferences.Editor editor = preferences.edit();
        boolean changed = false;
        for (Map.Entry<String, ?> entry : preferences.getAll().entrySet()) {
            String name = entry.getKey();
            for (String root : roots) {
                if (name.equals(root) || name.startsWith(root + "/")) {
                    editor.remove(name);
                    changed = true;
                    break;
                }
            }
        }
        if (changed && !editor.commit()) {
            throw new StateStoreException("failed to delete secure state roots");
        }
    }

    private static void requireName(String name) {
        if (name == null || name.isEmpty() || name.length() > 160) {
            throw new IllegalArgumentException("invalid secure state name");
        }
    }

    private static SecretKey getOrCreateKey() throws GeneralSecurityException, IOException {
        SecretKey cached = cachedKeyHandle;
        if (cached != null) {
            return cached;
        }
        synchronized (keyHandleLock) {
            cached = cachedKeyHandle;
            if (cached != null) {
                return cached;
            }
            KeyStore keyStore = KeyStore.getInstance(KEYSTORE);
            keyStore.load(null);
            SecretKey existing = (SecretKey) keyStore.getKey(KEY_ALIAS, null);
            if (existing != null) {
                cachedKeyHandle = existing;
                return existing;
            }
            KeyGenerator generator =
                    KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE);
            KeyGenParameterSpec.Builder spec = new KeyGenParameterSpec.Builder(
                    KEY_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                spec.setUnlockedDeviceRequired(true);
            }
            generator.init(spec.build());
            SecretKey generated = generator.generateKey();
            cachedKeyHandle = generated;
            return generated;
        }
    }

    public static final class StateStoreException extends Exception {
        StateStoreException(String message) {
            super(message);
        }

        StateStoreException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
