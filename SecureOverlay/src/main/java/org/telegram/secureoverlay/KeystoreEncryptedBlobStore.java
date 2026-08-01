package org.telegram.secureoverlay;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.LinkedHashMap;
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
    private static final String INSTALLATION_SENTINEL =
            "telegram_secure_overlay_installation_v1";
    private static final Object keyHandleLock = new Object();
    private static final Object installationLock = new Object();
    private static volatile SecretKey cachedKeyHandle;
    private static volatile boolean installationChecked;

    private final SharedPreferences preferences;

    public KeystoreEncryptedBlobStore(Context context) {
        Context appContext = context.getApplicationContext();
        preferences = appContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        ensureInstallationState(appContext, preferences);
    }

    public synchronized void put(String name, byte[] plaintext) throws StateStoreException {
        requireName(name);
        if (plaintext == null) {
            throw new IllegalArgumentException("plaintext is required");
        }
        Map<String, byte[]> values = new LinkedHashMap<>();
        values.put(name, plaintext);
        putAll(values);
    }

    /** Encrypts and stores all supplied records in one synchronous preferences transaction. */
    public synchronized void putAll(Map<String, byte[]> values) throws StateStoreException {
        Map<String, String> encrypted = encryptAll(values);
        SharedPreferences.Editor editor = preferences.edit();
        for (Map.Entry<String, String> entry : encrypted.entrySet()) {
            editor.putString(entry.getKey(), entry.getValue());
        }
        if (!editor.commit()) {
            throw new StateStoreException("failed to commit encrypted state");
        }
    }

    /**
     * Deletes logical roots and writes replacements in one synchronous preferences transaction.
     *
     * <p>All replacement values are encrypted before the editor is created, so a crypto failure
     * cannot leave a partially deleted protocol store.</p>
     */
    public synchronized void replaceRoots(
            Map<String, byte[]> replacements, String... roots) throws StateStoreException {
        if (roots == null || roots.length == 0) {
            throw new IllegalArgumentException("secure state roots are required");
        }
        for (String root : roots) {
            requireName(root);
        }
        Map<String, String> encrypted = encryptAll(replacements);
        SharedPreferences.Editor editor = preferences.edit();
        for (String name : preferences.getAll().keySet()) {
            for (String root : roots) {
                if (name.equals(root) || name.startsWith(root + "/")) {
                    editor.remove(name);
                    break;
                }
            }
        }
        for (Map.Entry<String, String> entry : encrypted.entrySet()) {
            editor.putString(entry.getKey(), entry.getValue());
        }
        if (!editor.commit()) {
            throw new StateStoreException("failed to replace encrypted state roots");
        }
    }

    /** Replaces every record under exact prefixes in one synchronous transaction. */
    synchronized void replacePrefixes(
            Map<String, byte[]> replacements, String... prefixes) throws StateStoreException {
        if (prefixes == null || prefixes.length == 0) {
            throw new IllegalArgumentException("secure state prefixes are required");
        }
        for (String prefix : prefixes) {
            requireName(prefix);
        }
        if (replacements == null) {
            throw new IllegalArgumentException("secure state replacements are required");
        }
        for (String name : replacements.keySet()) {
            requireName(name);
            if (!startsWithAny(name, prefixes)) {
                throw new IllegalArgumentException(
                        "replacement is outside secure state prefixes");
            }
        }
        Map<String, String> encrypted = replacements.isEmpty()
                ? new LinkedHashMap<>()
                : encryptAll(replacements);
        SharedPreferences.Editor editor = preferences.edit();
        for (String name : preferences.getAll().keySet()) {
            if (startsWithAny(name, prefixes)) {
                editor.remove(name);
            }
        }
        for (Map.Entry<String, String> entry : encrypted.entrySet()) {
            editor.putString(entry.getKey(), entry.getValue());
        }
        if (!editor.commit()) {
            throw new StateStoreException("failed to replace encrypted state prefixes");
        }
    }

    /**
     * Replaces slash-delimited roots and literal prefixes while atomically writing transaction
     * records outside those selectors.
     */
    synchronized void replaceSelected(
            Map<String, byte[]> replacements,
            String[] roots,
            String[] prefixes,
            String... transactionNames) throws StateStoreException {
        if (replacements == null || roots == null || prefixes == null
                || transactionNames == null) {
            throw new IllegalArgumentException("secure replacement selection is required");
        }
        for (String root : roots) {
            requireName(root);
        }
        for (String prefix : prefixes) {
            requireName(prefix);
        }
        for (String transactionName : transactionNames) {
            requireName(transactionName);
        }
        for (String name : replacements.keySet()) {
            requireName(name);
            if (!matchesRoot(name, roots)
                    && !startsWithAny(name, prefixes)
                    && !contains(transactionNames, name)) {
                throw new IllegalArgumentException(
                        "replacement is outside secure state selection");
            }
        }
        Map<String, String> encrypted = replacements.isEmpty()
                ? new LinkedHashMap<>()
                : encryptAll(replacements);
        SharedPreferences.Editor editor = preferences.edit();
        for (String name : preferences.getAll().keySet()) {
            if (matchesRoot(name, roots) || startsWithAny(name, prefixes)) {
                editor.remove(name);
            }
        }
        for (Map.Entry<String, String> entry : encrypted.entrySet()) {
            editor.putString(entry.getKey(), entry.getValue());
        }
        if (!editor.commit()) {
            throw new StateStoreException("failed to replace selected encrypted state");
        }
    }

    public synchronized boolean hasNameStartingWith(String... prefixes) {
        if (prefixes == null || prefixes.length == 0) {
            throw new IllegalArgumentException("secure state prefixes are required");
        }
        for (String prefix : prefixes) {
            requireName(prefix);
        }
        for (String name : preferences.getAll().keySet()) {
            for (String prefix : prefixes) {
                if (name.startsWith(prefix)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Decrypts a logical snapshot selected by exact prefixes.
     *
     * <p>Callers must use account-scoped prefixes and immediately place the result inside an
     * authenticated recovery archive.</p>
     */
    synchronized Map<String, byte[]> snapshotPrefixes(String... prefixes)
            throws StateStoreException {
        if (prefixes == null || prefixes.length == 0) {
            throw new IllegalArgumentException("secure snapshot prefixes are required");
        }
        for (String prefix : prefixes) {
            requireName(prefix);
        }
        Map<String, byte[]> snapshot = new LinkedHashMap<>();
        for (String name : preferences.getAll().keySet()) {
            if (startsWithAny(name, prefixes)) {
                snapshot.put(name, get(name));
            }
        }
        return snapshot;
    }

    private static Map<String, String> encryptAll(
            Map<String, byte[]> values) throws StateStoreException {
        if (values == null || values.isEmpty()) {
            throw new IllegalArgumentException("secure state values are required");
        }
        Map<String, String> encrypted = new LinkedHashMap<>();
        for (Map.Entry<String, byte[]> entry : values.entrySet()) {
            String name = entry.getKey();
            byte[] plaintext = entry.getValue();
            requireName(name);
            if (plaintext == null) {
                throw new IllegalArgumentException("plaintext is required");
            }
            encrypted.put(name, encrypt(name, plaintext));
        }
        return encrypted;
    }

    private static String encrypt(String name, byte[] plaintext) throws StateStoreException {
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
            return Base64.encodeToString(encoded, Base64.NO_WRAP);
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
        deleteAll(name);
    }

    /** Deletes exact logical records in one synchronous transaction. */
    public synchronized void deleteAll(String... names) throws StateStoreException {
        if (names == null || names.length == 0) {
            throw new IllegalArgumentException("secure state names are required");
        }
        SharedPreferences.Editor editor = preferences.edit();
        for (String name : names) {
            requireName(name);
            editor.remove(name);
        }
        if (!editor.commit()) {
            throw new StateStoreException("failed to delete encrypted state");
        }
    }

    /** Deletes every logical record whose name starts with one of the supplied prefixes. */
    public synchronized void deletePrefixes(String... prefixes) throws StateStoreException {
        if (prefixes == null || prefixes.length == 0) {
            throw new IllegalArgumentException("secure state prefixes are required");
        }
        for (String prefix : prefixes) {
            requireName(prefix);
        }
        SharedPreferences.Editor editor = preferences.edit();
        boolean changed = false;
        for (String name : preferences.getAll().keySet()) {
            for (String prefix : prefixes) {
                if (name.startsWith(prefix)) {
                    editor.remove(name);
                    changed = true;
                    break;
                }
            }
        }
        if (changed && !editor.commit()) {
            throw new StateStoreException("failed to delete encrypted state prefixes");
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

    private static boolean startsWithAny(String name, String... prefixes) {
        for (String prefix : prefixes) {
            if (name.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    private static boolean matchesRoot(String name, String... roots) {
        for (String root : roots) {
            if (name.equals(root) || name.startsWith(root + "/")) {
                return true;
            }
        }
        return false;
    }

    private static boolean contains(String[] values, String expected) {
        for (String value : values) {
            if (value.equals(expected)) {
                return true;
            }
        }
        return false;
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

    /**
     * Drops ciphertext restored without its non-exportable Keystore key.
     *
     * <p>The sentinel lives in {@code noBackupFilesDir}. An application update from an older
     * build has no sentinel but retains the Keystore key, so its valid state is preserved. A
     * reinstall or OEM restore may return SharedPreferences without that key; retaining such
     * ciphertext would permanently block both recovery import and new pairing.</p>
     */
    private static void ensureInstallationState(
            Context context, SharedPreferences encryptedPreferences) {
        if (installationChecked) {
            return;
        }
        synchronized (installationLock) {
            if (installationChecked) {
                return;
            }
            File sentinel = new File(
                    context.getNoBackupFilesDir(), INSTALLATION_SENTINEL);
            boolean keyPresent = hasKeystoreKey();
            boolean hasOrphanedState = !encryptedPreferences.getAll().isEmpty()
                    || SecureChatState.hasStoredState(context);
            if (hasOrphanedState && !keyPresent) {
                if (!encryptedPreferences.edit().clear().commit()) {
                    throw new IllegalStateException(
                            "failed to clear orphaned secure encrypted state");
                }
                SecureChatState.clearForMissingKeystore(context);
                cachedKeyHandle = null;
            }
            if (!sentinel.isFile()) {
                try {
                    File parent = sentinel.getParentFile();
                    if (parent == null
                            || (!parent.isDirectory() && !parent.mkdirs())
                            || (!sentinel.createNewFile() && !sentinel.isFile())) {
                        throw new IOException(
                                "cannot create Fork-Secure installation sentinel");
                    }
                } catch (IOException error) {
                    throw new IllegalStateException(
                            "cannot establish Fork-Secure installation state", error);
                }
            }
            installationChecked = true;
        }
    }

    private static boolean hasKeystoreKey() {
        try {
            KeyStore keyStore = KeyStore.getInstance(KEYSTORE);
            keyStore.load(null);
            return keyStore.containsAlias(KEY_ALIAS);
        } catch (GeneralSecurityException | IOException error) {
            throw new IllegalStateException(
                    "cannot inspect Fork-Secure Keystore state", error);
        }
    }

    static void resetInstallationCheckForTests() {
        synchronized (installationLock) {
            installationChecked = false;
            cachedKeyHandle = null;
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
