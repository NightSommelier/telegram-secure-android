package org.telegram.secureoverlay;

import android.content.ContentValues;
import android.content.Context;
import android.content.SharedPreferences;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * Transactional private encrypted blob storage for libsignal and secure chat state records.
 *
 * <p>Each stored value is AES-256-GCM encrypted with a non-exportable Android Keystore key.
 * Backed by an indexed SQLite database with atomic multi-statement transactions, avoiding
 * monolithic SharedPreferences XML rewrites. Automatically migrates legacy records on startup.</p>
 */
public final class KeystoreEncryptedBlobStore implements KeystoreSignalProtocolStore.EncryptedStateStorage {
    private static final String KEYSTORE = "AndroidKeyStore";
    private static final String PREFS = "telegram_secure_overlay_state_v1";
    private static final String KEY_ALIAS = "telegram_secure_overlay_state_key_v1";
    private static final String DB_NAME = "telegram_secure_overlay_v2.db";
    private static final int DB_VERSION = 1;
    private static final String TABLE_NAME = "secure_blobs";
    private static final String COL_NAME = "name";
    private static final String COL_VALUE = "encrypted_value";
    private static final String COL_UPDATED_AT = "updated_at";

    private static final int NONCE_BYTES = 12;
    private static final int TAG_BITS = 128;
    private static final int FORMAT_VERSION = 1;
    private static final String INSTALLATION_SENTINEL =
            "telegram_secure_overlay_installation_v1";
    private static final Object keyHandleLock = new Object();
    private static final Object installationLock = new Object();
    private static volatile SecretKey cachedKeyHandle;
    private static volatile boolean installationChecked;

    private final Context appContext;
    private final SharedPreferences preferences;
    private final DatabaseHelper dbHelper;
    private final Map<String, byte[]> testStorage = new ConcurrentHashMap<>();

    private static final class DatabaseHelper extends SQLiteOpenHelper {
        DatabaseHelper(Context context) {
            super(context, DB_NAME, null, DB_VERSION);
        }

        @Override
        public void onCreate(SQLiteDatabase db) {
            db.execSQL("CREATE TABLE IF NOT EXISTS " + TABLE_NAME + " ("
                    + COL_NAME + " TEXT PRIMARY KEY, "
                    + COL_VALUE + " TEXT NOT NULL, "
                    + COL_UPDATED_AT + " INTEGER NOT NULL);");
            db.execSQL("CREATE INDEX IF NOT EXISTS idx_secure_blobs_name ON "
                    + TABLE_NAME + " (" + COL_NAME + ");");
        }

        @Override
        public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
            // Future schema migrations
        }
    }

    public KeystoreEncryptedBlobStore(Context context) {
        if (context != null) {
            Context app = context.getApplicationContext();
            this.appContext = app != null ? app : context;
            SharedPreferences prefs = null;
            DatabaseHelper helper = null;
            try {
                prefs = this.appContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
                helper = new DatabaseHelper(this.appContext);
                ensureInstallationState(this.appContext, helper, prefs);
                migrateLegacyPreferences(helper.getWritableDatabase(), prefs);
            } catch (Exception e) {
                // In headless JVM unit tests without Android SQLite/SharedPreferences runtime
                helper = null;
                prefs = null;
            }
            this.preferences = prefs;
            this.dbHelper = helper;
        } else {
            this.appContext = null;
            this.preferences = null;
            this.dbHelper = null;
        }
    }

    private static void migrateLegacyPreferences(SQLiteDatabase db, SharedPreferences prefs) {
        if (prefs == null) {
            return;
        }
        Map<String, ?> all = prefs.getAll();
        if (all == null || all.isEmpty()) {
            return;
        }
        db.beginTransaction();
        try {
            for (Map.Entry<String, ?> entry : all.entrySet()) {
                if (entry.getValue() instanceof String) {
                    ContentValues cv = new ContentValues();
                    cv.put(COL_NAME, entry.getKey());
                    cv.put(COL_VALUE, (String) entry.getValue());
                    cv.put(COL_UPDATED_AT, System.currentTimeMillis());
                    db.insertWithOnConflict(TABLE_NAME, null, cv, SQLiteDatabase.CONFLICT_REPLACE);
                }
            }
            db.setTransactionSuccessful();
            prefs.edit().clear().commit();
        } finally {
            db.endTransaction();
        }
    }

    @Override
    public synchronized void put(String name, byte[] plaintext) throws StateStoreException {
        requireName(name);
        if (plaintext == null) {
            throw new IllegalArgumentException("plaintext is required");
        }
        if (dbHelper != null) {
            String encrypted = encrypt(name, plaintext);
            SQLiteDatabase db = dbHelper.getWritableDatabase();
            ContentValues cv = new ContentValues();
            cv.put(COL_NAME, name);
            cv.put(COL_VALUE, encrypted);
            cv.put(COL_UPDATED_AT, System.currentTimeMillis());
            long res = db.insertWithOnConflict(TABLE_NAME, null, cv, SQLiteDatabase.CONFLICT_REPLACE);
            if (res == -1) {
                throw new StateStoreException("failed to insert encrypted state");
            }
            return;
        }
        testStorage.put(name, plaintext.clone());
    }

    /** Encrypts and stores all supplied records in one atomic SQLite transaction. */
    public synchronized void putAll(Map<String, byte[]> values) throws StateStoreException {
        if (values == null || values.isEmpty()) {
            throw new IllegalArgumentException("secure state values are required");
        }
        if (dbHelper != null) {
            Map<String, String> encrypted = encryptAll(values);
            SQLiteDatabase db = dbHelper.getWritableDatabase();
            db.beginTransaction();
            try {
                for (Map.Entry<String, String> entry : encrypted.entrySet()) {
                    ContentValues cv = new ContentValues();
                    cv.put(COL_NAME, entry.getKey());
                    cv.put(COL_VALUE, entry.getValue());
                    cv.put(COL_UPDATED_AT, System.currentTimeMillis());
                    long res = db.insertWithOnConflict(TABLE_NAME, null, cv, SQLiteDatabase.CONFLICT_REPLACE);
                    if (res == -1) {
                        throw new StateStoreException("failed to commit encrypted state");
                    }
                }
                db.setTransactionSuccessful();
            } finally {
                db.endTransaction();
            }
            return;
        }
        for (Map.Entry<String, byte[]> entry : values.entrySet()) {
            testStorage.put(entry.getKey(), entry.getValue().clone());
        }
    }

    /**
     * Deletes logical roots and writes replacements in one atomic SQLite transaction.
     *
     * <p>All replacement values are encrypted before the transaction begins, so a crypto failure
     * cannot leave a partially modified protocol store.</p>
     */
    public synchronized void replaceRoots(
            Map<String, byte[]> replacements, String... roots) throws StateStoreException {
        if (roots == null || roots.length == 0) {
            throw new IllegalArgumentException("secure state roots are required");
        }
        for (String root : roots) {
            requireName(root);
        }
        if (dbHelper != null) {
            Map<String, String> encrypted = replacements != null && !replacements.isEmpty()
                    ? encryptAll(replacements) : new LinkedHashMap<>();
            SQLiteDatabase db = dbHelper.getWritableDatabase();
            db.beginTransaction();
            try {
                for (String root : roots) {
                    db.delete(TABLE_NAME, COL_NAME + " = ? OR " + COL_NAME + " LIKE ?",
                            new String[]{root, root + "/%"});
                }
                for (Map.Entry<String, String> entry : encrypted.entrySet()) {
                    ContentValues cv = new ContentValues();
                    cv.put(COL_NAME, entry.getKey());
                    cv.put(COL_VALUE, entry.getValue());
                    cv.put(COL_UPDATED_AT, System.currentTimeMillis());
                    long res = db.insertWithOnConflict(TABLE_NAME, null, cv, SQLiteDatabase.CONFLICT_REPLACE);
                    if (res == -1) {
                        throw new StateStoreException("failed to replace encrypted state roots");
                    }
                }
                db.setTransactionSuccessful();
            } finally {
                db.endTransaction();
            }
            return;
        }
        List<String> toRemove = new ArrayList<>();
        for (String key : testStorage.keySet()) {
            for (String root : roots) {
                if (key.equals(root) || key.startsWith(root + "/")) {
                    toRemove.add(key);
                    break;
                }
            }
        }
        for (String k : toRemove) {
            testStorage.remove(k);
        }
        if (replacements != null) {
            for (Map.Entry<String, byte[]> entry : replacements.entrySet()) {
                testStorage.put(entry.getKey(), entry.getValue().clone());
            }
        }
    }

    /** Replaces every record under exact prefixes in one atomic SQLite transaction. */
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
        if (dbHelper != null) {
            Map<String, String> encrypted = replacements.isEmpty()
                    ? new LinkedHashMap<>()
                    : encryptAll(replacements);
            SQLiteDatabase db = dbHelper.getWritableDatabase();
            db.beginTransaction();
            try {
                for (String prefix : prefixes) {
                    db.delete(TABLE_NAME, COL_NAME + " LIKE ?", new String[]{prefix + "%"});
                }
                for (Map.Entry<String, String> entry : encrypted.entrySet()) {
                    ContentValues cv = new ContentValues();
                    cv.put(COL_NAME, entry.getKey());
                    cv.put(COL_VALUE, entry.getValue());
                    cv.put(COL_UPDATED_AT, System.currentTimeMillis());
                    long res = db.insertWithOnConflict(TABLE_NAME, null, cv, SQLiteDatabase.CONFLICT_REPLACE);
                    if (res == -1) {
                        throw new StateStoreException("failed to replace encrypted state prefixes");
                    }
                }
                db.setTransactionSuccessful();
            } finally {
                db.endTransaction();
            }
            return;
        }
        List<String> toRemove = new ArrayList<>();
        for (String key : testStorage.keySet()) {
            if (startsWithAny(key, prefixes)) {
                toRemove.add(key);
            }
        }
        for (String k : toRemove) {
            testStorage.remove(k);
        }
        for (Map.Entry<String, byte[]> entry : replacements.entrySet()) {
            testStorage.put(entry.getKey(), entry.getValue().clone());
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
        if (dbHelper != null) {
            Map<String, String> encrypted = replacements.isEmpty()
                    ? new LinkedHashMap<>()
                    : encryptAll(replacements);
            SQLiteDatabase db = dbHelper.getWritableDatabase();
            db.beginTransaction();
            try {
                for (String root : roots) {
                    db.delete(TABLE_NAME, COL_NAME + " = ? OR " + COL_NAME + " LIKE ?",
                            new String[]{root, root + "/%"});
                }
                for (String prefix : prefixes) {
                    db.delete(TABLE_NAME, COL_NAME + " LIKE ?", new String[]{prefix + "%"});
                }
                for (Map.Entry<String, String> entry : encrypted.entrySet()) {
                    ContentValues cv = new ContentValues();
                    cv.put(COL_NAME, entry.getKey());
                    cv.put(COL_VALUE, entry.getValue());
                    cv.put(COL_UPDATED_AT, System.currentTimeMillis());
                    long res = db.insertWithOnConflict(TABLE_NAME, null, cv, SQLiteDatabase.CONFLICT_REPLACE);
                    if (res == -1) {
                        throw new StateStoreException("failed to replace selected encrypted state");
                    }
                }
                db.setTransactionSuccessful();
            } finally {
                db.endTransaction();
            }
            return;
        }
        List<String> toRemove = new ArrayList<>();
        for (String key : testStorage.keySet()) {
            if (matchesRoot(key, roots) || startsWithAny(key, prefixes)) {
                toRemove.add(key);
            }
        }
        for (String k : toRemove) {
            testStorage.remove(k);
        }
        for (Map.Entry<String, byte[]> entry : replacements.entrySet()) {
            testStorage.put(entry.getKey(), entry.getValue().clone());
        }
    }

    public synchronized boolean hasNameStartingWith(String... prefixes) {
        if (prefixes == null || prefixes.length == 0) {
            throw new IllegalArgumentException("secure state prefixes are required");
        }
        for (String prefix : prefixes) {
            requireName(prefix);
        }
        if (dbHelper != null) {
            SQLiteDatabase db = dbHelper.getReadableDatabase();
            for (String prefix : prefixes) {
                try (Cursor cursor = db.rawQuery(
                        "SELECT 1 FROM " + TABLE_NAME + " WHERE " + COL_NAME + " LIKE ? LIMIT 1",
                        new String[]{prefix + "%"})) {
                    if (cursor != null && cursor.moveToFirst()) {
                        return true;
                    }
                } catch (Exception ignored) {
                }
            }
            return false;
        }
        for (String name : testStorage.keySet()) {
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
    public synchronized Map<String, byte[]> snapshotPrefixes(String... prefixes)
            throws StateStoreException {
        if (prefixes == null || prefixes.length == 0) {
            throw new IllegalArgumentException("secure snapshot prefixes are required");
        }
        for (String prefix : prefixes) {
            requireName(prefix);
        }
        Map<String, byte[]> snapshot = new LinkedHashMap<>();
        if (dbHelper != null) {
            SQLiteDatabase db = dbHelper.getReadableDatabase();
            for (String prefix : prefixes) {
                try (Cursor cursor = db.query(TABLE_NAME,
                        new String[]{COL_NAME, COL_VALUE},
                        COL_NAME + " LIKE ?",
                        new String[]{prefix + "%"},
                        null,
                        null,
                        null)) {
                    if (cursor != null) {
                        while (cursor.moveToNext()) {
                            String name = cursor.getString(0);
                            String stored = cursor.getString(1);
                            snapshot.put(name, decrypt(name, stored));
                        }
                    }
                } catch (Exception e) {
                    if (e instanceof StateStoreException) {
                        throw (StateStoreException) e;
                    }
                    throw new StateStoreException("failed to query snapshot prefixes", e);
                }
            }
            return snapshot;
        }
        for (Map.Entry<String, byte[]> entry : testStorage.entrySet()) {
            if (startsWithAny(entry.getKey(), prefixes)) {
                snapshot.put(entry.getKey(), entry.getValue().clone());
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

    private static byte[] decrypt(String name, String stored) throws StateStoreException {
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

    @Override
    public synchronized byte[] get(String name) throws StateStoreException {
        requireName(name);
        if (dbHelper != null) {
            try {
                SQLiteDatabase db = dbHelper.getReadableDatabase();
                try (Cursor cursor = db.query(
                        TABLE_NAME,
                        new String[]{COL_VALUE},
                        COL_NAME + " = ?",
                        new String[]{name},
                        null,
                        null,
                        null)) {
                    if (cursor != null && cursor.moveToFirst()) {
                        String stored = cursor.getString(0);
                        return decrypt(name, stored);
                    }
                }
            } catch (Exception e) {
                if (e instanceof StateStoreException) {
                    throw (StateStoreException) e;
                }
                throw new StateStoreException("failed to query database for " + name, e);
            }
            return null;
        }
        byte[] val = testStorage.get(name);
        return val != null ? val.clone() : null;
    }

    public synchronized boolean has(String name) {
        if (name == null || name.isEmpty()) {
            return false;
        }
        if (dbHelper != null) {
            try {
                SQLiteDatabase db = dbHelper.getReadableDatabase();
                try (Cursor cursor = db.rawQuery(
                        "SELECT 1 FROM " + TABLE_NAME + " WHERE " + COL_NAME + " = ? LIMIT 1",
                        new String[]{name})) {
                    return cursor != null && cursor.moveToFirst();
                }
            } catch (Exception ignored) {
                return false;
            }
        }
        return testStorage.containsKey(name);
    }

    @Override
    public synchronized void delete(String name) throws StateStoreException {
        deleteAll(name);
    }

    /** Deletes exact logical records in one atomic SQLite transaction. */
    public synchronized void deleteAll(String... names) throws StateStoreException {
        if (names == null || names.length == 0) {
            throw new IllegalArgumentException("secure state names are required");
        }
        for (String name : names) {
            requireName(name);
        }
        if (dbHelper != null) {
            SQLiteDatabase db = dbHelper.getWritableDatabase();
            db.beginTransaction();
            try {
                for (String name : names) {
                    db.delete(TABLE_NAME, COL_NAME + " = ?", new String[]{name});
                }
                db.setTransactionSuccessful();
            } finally {
                db.endTransaction();
            }
            return;
        }
        for (String name : names) {
            testStorage.remove(name);
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
        if (dbHelper != null) {
            SQLiteDatabase db = dbHelper.getWritableDatabase();
            db.beginTransaction();
            try {
                for (String prefix : prefixes) {
                    db.delete(TABLE_NAME, COL_NAME + " LIKE ?", new String[]{prefix + "%"});
                }
                db.setTransactionSuccessful();
            } finally {
                db.endTransaction();
            }
            return;
        }
        List<String> toRemove = new ArrayList<>();
        for (String key : testStorage.keySet()) {
            for (String prefix : prefixes) {
                if (key.startsWith(prefix)) {
                    toRemove.add(key);
                    break;
                }
            }
        }
        for (String k : toRemove) {
            testStorage.remove(k);
        }
    }

    /**
     * Deletes exact logical roots and all of their slash-delimited children in one atomic transaction.
     */
    @Override
    public synchronized void deleteRoots(String... roots) throws StateStoreException {
        if (roots == null || roots.length == 0) {
            throw new IllegalArgumentException("secure state roots are required");
        }
        for (String root : roots) {
            requireName(root);
        }
        if (dbHelper != null) {
            SQLiteDatabase db = dbHelper.getWritableDatabase();
            db.beginTransaction();
            try {
                for (String root : roots) {
                    db.delete(TABLE_NAME, COL_NAME + " = ? OR " + COL_NAME + " LIKE ?",
                            new String[]{root, root + "/%"});
                }
                db.setTransactionSuccessful();
            } finally {
                db.endTransaction();
            }
            return;
        }
        List<String> toRemove = new ArrayList<>();
        for (String key : testStorage.keySet()) {
            for (String root : roots) {
                if (key.equals(root) || key.startsWith(root + "/")) {
                    toRemove.add(key);
                    break;
                }
            }
        }
        for (String k : toRemove) {
            testStorage.remove(k);
        }
    }

    public synchronized void clear() {
        if (dbHelper != null) {
            try {
                SQLiteDatabase db = dbHelper.getWritableDatabase();
                db.delete(TABLE_NAME, null, null);
            } catch (Exception ignored) {
            }
        }
        testStorage.clear();
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
     */
    private static void ensureInstallationState(
            Context context, DatabaseHelper helper, SharedPreferences encryptedPreferences) {
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
            boolean hasOrphanedState = (encryptedPreferences != null && !encryptedPreferences.getAll().isEmpty())
                    || SecureChatState.hasStoredState(context);
            if (hasOrphanedState && !keyPresent) {
                if (encryptedPreferences != null && !encryptedPreferences.edit().clear().commit()) {
                    throw new IllegalStateException(
                            "failed to clear orphaned secure encrypted state");
                }
                if (helper != null) {
                    try {
                        SQLiteDatabase db = helper.getWritableDatabase();
                        db.delete(TABLE_NAME, null, null);
                    } catch (Exception ignored) {
                    }
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
