package org.telegram.secureoverlay;

import android.content.Context;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.signal.libsignal.protocol.IdentityKey;
import org.signal.libsignal.protocol.IdentityKeyPair;
import org.signal.libsignal.protocol.InvalidKeyIdException;
import org.signal.libsignal.protocol.InvalidMessageException;
import org.signal.libsignal.protocol.NoSessionException;
import org.signal.libsignal.protocol.ReusedBaseKeyException;
import org.signal.libsignal.protocol.SignalProtocolAddress;
import org.signal.libsignal.protocol.ecc.ECKeyPair;
import org.signal.libsignal.protocol.ecc.ECPublicKey;
import org.signal.libsignal.protocol.kem.KEMKeyPair;
import org.signal.libsignal.protocol.kem.KEMKeyType;
import org.signal.libsignal.protocol.groups.state.SenderKeyRecord;
import org.signal.libsignal.protocol.groups.state.SenderKeyStore;
import org.signal.libsignal.protocol.state.IdentityKeyStore;
import org.signal.libsignal.protocol.state.KyberPreKeyRecord;
import org.signal.libsignal.protocol.state.KyberPreKeyStore;
import org.signal.libsignal.protocol.state.PreKeyRecord;
import org.signal.libsignal.protocol.state.PreKeyStore;
import org.signal.libsignal.protocol.state.SessionRecord;
import org.signal.libsignal.protocol.state.SessionStore;
import org.signal.libsignal.protocol.state.SignalProtocolStore;
import org.signal.libsignal.protocol.state.SignedPreKeyRecord;
import org.signal.libsignal.protocol.state.SignedPreKeyStore;
import org.signal.libsignal.protocol.util.KeyHelper;

/** Durable, single-device libsignal state backed by {@link KeystoreEncryptedBlobStore}. */
public final class KeystoreSignalProtocolStore implements SignalProtocolStore {
    static final Object PROTOCOL_STATE_LOCK = new Object();
    private static final int ONLY_DEVICE_ID = 1;
    private static final String IDENTITY = "identity";
    private static final String REGISTRATION = "registration";
    private final Context appContext;
    private final EncryptedStateStorage blobs;
    private final int account;
    private final String prefix;
    private final IdentityKeyPair identity;
    private final int registrationId;

    public int getAccount() { return account; }
    private String k(String name) { return prefix + name; }

    interface EncryptedStateStorage {
        byte[] get(String name) throws Exception;
        void put(String name, byte[] data) throws Exception;
        void delete(String name) throws Exception;
        void deleteRoots(String... roots) throws Exception;
        void replaceRoots(Map<String, byte[]> replacements, String... roots) throws Exception;
        boolean hasNameStartingWith(String... prefixes);
    }

    public KeystoreSignalProtocolStore(Context context) {
        this(context, 0);
    }

    public KeystoreSignalProtocolStore(Context context, int account) {
        this(context, account, new KeystoreEncryptedBlobStore(context));
    }

    KeystoreSignalProtocolStore(Context context, EncryptedStateStorage storage) {
        this(context, 0, storage);
    }

    KeystoreSignalProtocolStore(Context context, int account, EncryptedStateStorage storage) {
        synchronized (PROTOCOL_STATE_LOCK) {
            if (account < 0) {
                throw new IllegalArgumentException("account must not be negative");
            }
            appContext = context != null ? context.getApplicationContext() : null;
            blobs = storage;
            this.account = account;
            this.prefix = "account/" + account + "/";
            try {
                byte[] savedIdentity = blobs.get(k(IDENTITY));
                byte[] savedRegistration = blobs.get(k(REGISTRATION));
                if (account == 0 && savedIdentity == null && blobs.get(IDENTITY) != null) {
                    savedIdentity = blobs.get(IDENTITY);
                    savedRegistration = blobs.get(REGISTRATION);
                    blobs.put(k(IDENTITY), savedIdentity);
                    blobs.put(k(REGISTRATION), savedRegistration);
                    for (String sub : new String[] {
                            "counter/prekey", "counter/signed_prekey", "counter/kyber_prekey",
                            "current/signed_prekey_id", "current/kyber_prekey_id",
                            "index/prekey", "index/prekey_pool", "index/signed", "index/kyber"}) {
                        byte[] v = blobs.get(sub);
                        if (v != null) {
                            blobs.put(k(sub), v);
                        }
                    }
                }
                if ((savedIdentity == null) != (savedRegistration == null)) {
                    throw new StateFailure("incomplete local identity state", null);
                }
                if (savedIdentity == null) {
                    identity = IdentityKeyPair.generate();
                    registrationId = KeyHelper.generateRegistrationId(false);
                    blobs.put(k(IDENTITY), identity.serialize());
                    blobs.put(k(REGISTRATION), ByteBuffer.allocate(4).putInt(registrationId).array());
                } else {
                    identity = new IdentityKeyPair(savedIdentity);
                    if (savedRegistration.length != 4) throw new StateFailure("invalid registration state", null);
                    registrationId = ByteBuffer.wrap(savedRegistration).getInt();
                }
            } catch (Exception e) {
                if (e instanceof StateFailure) throw (StateFailure) e;
                throw new StateFailure("cannot load local secure identity", e);
            }
        }
    }

    @Override public IdentityKeyPair getIdentityKeyPair() { return identity; }
    @Override public int getLocalRegistrationId() { return registrationId; }

    private static final int PRE_KEY_POOL_MIN = 10;
    private static final int PRE_KEY_POOL_BATCH = 50;
    public static final long SIGNED_PREKEY_ROTATION_INTERVAL_MS = 7L * 24 * 60 * 60 * 1000L;
    public static final long KYBER_PREKEY_ROTATION_INTERVAL_MS = 7L * 24 * 60 * 60 * 1000L;
    public static final long PREKEY_SUNSET_GRACE_PERIOD_MS = 30L * 24 * 60 * 60 * 1000L;

    private int getNextPreKeyId() {
        try {
            byte[] b = blobs.get(k("counter/prekey"));
            int current = (b != null && b.length == 4) ? ByteBuffer.wrap(b).getInt() : 0;
            if (current == 0 && containsPreKey(1)) {
                current = 1;
            }
            int next = current + 1;
            if (next >= 0xFFFFFF || next <= 0) {
                next = 1;
            }
            blobs.put(k("counter/prekey"), ByteBuffer.allocate(4).putInt(next).array());
            return next;
        } catch (Exception e) {
            throw failure(e);
        }
    }

    private int getNextSignedPreKeyId() {
        try {
            byte[] b = blobs.get(k("counter/signed_prekey"));
            int current = (b != null && b.length == 4) ? ByteBuffer.wrap(b).getInt() : 1;
            int next = current + 1;
            if (next >= 0xFFFFFF || next <= 0) {
                next = 1;
            }
            blobs.put(k("counter/signed_prekey"), ByteBuffer.allocate(4).putInt(next).array());
            return next;
        } catch (Exception e) {
            throw failure(e);
        }
    }

    private int getNextKyberPreKeyId() {
        try {
            byte[] b = blobs.get(k("counter/kyber_prekey"));
            int current = (b != null && b.length == 4) ? ByteBuffer.wrap(b).getInt() : 2;
            int next = current + 1;
            if (next >= 0xFFFFFF || next <= 0) {
                next = 1;
            }
            blobs.put(k("counter/kyber_prekey"), ByteBuffer.allocate(4).putInt(next).array());
            return next;
        } catch (Exception e) {
            throw failure(e);
        }
    }

    public int getActiveSignedPreKeyId() {
        synchronized (PROTOCOL_STATE_LOCK) {
            try {
                byte[] b = blobs.get(k("current/signed_prekey_id"));
                if (b != null && b.length == 4) {
                    return ByteBuffer.wrap(b).getInt();
                }
                if (containsSignedPreKey(2)) {
                    blobs.put(k("current/signed_prekey_id"), ByteBuffer.allocate(4).putInt(2).array());
                    return 2;
                }
                List<Integer> ids = index("signed");
                if (!ids.isEmpty()) {
                    int last = ids.get(ids.size() - 1);
                    blobs.put(k("current/signed_prekey_id"), ByteBuffer.allocate(4).putInt(last).array());
                    return last;
                }
                return -1;
            } catch (Exception e) {
                throw failure(e);
            }
        }
    }

    public int getActiveKyberPreKeyId() {
        synchronized (PROTOCOL_STATE_LOCK) {
            try {
                byte[] b = blobs.get(k("current/kyber_prekey_id"));
                if (b != null && b.length == 4) {
                    return ByteBuffer.wrap(b).getInt();
                }
                if (containsKyberPreKey(3)) {
                    blobs.put(k("current/kyber_prekey_id"), ByteBuffer.allocate(4).putInt(3).array());
                    return 3;
                }
                List<Integer> ids = index("kyber");
                if (!ids.isEmpty()) {
                    int last = ids.get(ids.size() - 1);
                    blobs.put(k("current/kyber_prekey_id"), ByteBuffer.allocate(4).putInt(last).array());
                    return last;
                }
                return -1;
            } catch (Exception e) {
                throw failure(e);
            }
        }
    }

    public void replenishPreKeysIfNeeded() {
        synchronized (PROTOCOL_STATE_LOCK) {
            try {
                List<Integer> pool = index("prekey_pool");
                if (blobs.get(k("index/prekey_pool")) == null) {
                    List<Integer> existing = index("prekey");
                    for (int id : existing) {
                        if (containsPreKey(id) && !pool.contains(id)) {
                            pool.add(id);
                        }
                    }
                }
                if (pool.size() >= PRE_KEY_POOL_MIN) {
                    return;
                }
                int needed = PRE_KEY_POOL_BATCH - pool.size();
                for (int i = 0; i < needed; i++) {
                    int id = getNextPreKeyId();
                    while (containsPreKey(id)) {
                        id = getNextPreKeyId();
                    }
                    storePreKey(id, new PreKeyRecord(id, ECKeyPair.generate()));
                    pool.add(id);
                }
                saveIndex("prekey_pool", pool);
            } catch (Exception e) {
                throw failure(e);
            }
        }
    }

    public boolean rotateKeysIfNeeded() {
        return rotateKeysIfNeeded(System.currentTimeMillis());
    }

    public boolean rotateKeysIfNeeded(long now) {
        synchronized (PROTOCOL_STATE_LOCK) {
            boolean rotatedSigned = rotateSignedPreKeyIfNeeded(now);
            boolean rotatedKyber = rotateKyberPreKeyIfNeeded(now);
            pruneExpiredPreKeys(now);
            return rotatedSigned || rotatedKyber;
        }
    }

    public boolean rotateSignedPreKeyIfNeeded(long now) {
        synchronized (PROTOCOL_STATE_LOCK) {
            try {
                int activeId = getActiveSignedPreKeyId();
                SignedPreKeyRecord activeRecord = null;
                if (activeId >= 0 && containsSignedPreKey(activeId)) {
                    try {
                        activeRecord = loadSignedPreKey(activeId);
                    } catch (InvalidKeyIdException ignored) {}
                }
                if (activeRecord != null) {
                    long age = now - activeRecord.getTimestamp();
                    if (age < SIGNED_PREKEY_ROTATION_INTERVAL_MS) {
                        return false;
                    }
                }
                int newId = getNextSignedPreKeyId();
                while (containsSignedPreKey(newId)) {
                    newId = getNextSignedPreKeyId();
                }
                ECKeyPair pair = ECKeyPair.generate();
                byte[] signature = identity.getPrivateKey().calculateSignature(pair.getPublicKey().serialize());
                SignedPreKeyRecord record = new SignedPreKeyRecord(newId, now, pair, signature);
                storeSignedPreKey(newId, record);
                blobs.put(k("current/signed_prekey_id"), ByteBuffer.allocate(4).putInt(newId).array());
                return true;
            } catch (Exception e) {
                throw failure(e);
            }
        }
    }

    public boolean rotateKyberPreKeyIfNeeded(long now) {
        synchronized (PROTOCOL_STATE_LOCK) {
            try {
                int activeId = getActiveKyberPreKeyId();
                KyberPreKeyRecord activeRecord = null;
                if (activeId >= 0 && containsKyberPreKey(activeId)) {
                    try {
                        activeRecord = loadKyberPreKey(activeId);
                    } catch (InvalidKeyIdException ignored) {}
                }
                if (activeRecord != null) {
                    long age = now - activeRecord.getTimestamp();
                    if (age < KYBER_PREKEY_ROTATION_INTERVAL_MS) {
                        return false;
                    }
                }
                int newId = getNextKyberPreKeyId();
                while (containsKyberPreKey(newId)) {
                    newId = getNextKyberPreKeyId();
                }
                KEMKeyPair pair = KEMKeyPair.generate(KEMKeyType.KYBER_1024);
                byte[] signature = identity.getPrivateKey().calculateSignature(pair.getPublicKey().serialize());
                KyberPreKeyRecord record = new KyberPreKeyRecord(newId, now, pair, signature);
                storeKyberPreKey(newId, record);
                blobs.put(k("current/kyber_prekey_id"), ByteBuffer.allocate(4).putInt(newId).array());
                return true;
            } catch (Exception e) {
                throw failure(e);
            }
        }
    }

    public void pruneExpiredPreKeys(long now) {
        synchronized (PROTOCOL_STATE_LOCK) {
            try {
                int activeSignedId = getActiveSignedPreKeyId();
                for (SignedPreKeyRecord record : loadSignedPreKeys()) {
                    if (record.getId() != activeSignedId
                            && (now - record.getTimestamp()) > PREKEY_SUNSET_GRACE_PERIOD_MS) {
                        removeSignedPreKey(record.getId());
                    }
                }
                int activeKyberId = getActiveKyberPreKeyId();
                for (KyberPreKeyRecord record : loadKyberPreKeys()) {
                    if (record.getId() != activeKyberId
                            && (now - record.getTimestamp()) > PREKEY_SUNSET_GRACE_PERIOD_MS) {
                        removeKyberPreKey(record.getId());
                    }
                }
            } catch (Exception e) {
                throw failure(e);
            }
        }
    }

    /** Creates the one-time material required to publish a 1:1 pre-key bundle. */
    public LocalPreKeyMaterial ensureLocalPreKeyMaterial() {
        synchronized (PROTOCOL_STATE_LOCK) {
            try {
                replenishPreKeysIfNeeded();
                rotateKeysIfNeeded();

                List<Integer> pool = index("prekey_pool");
                int preKeyId = -1;
                while (!pool.isEmpty()) {
                    int candidate = pool.remove(0);
                    if (containsPreKey(candidate)) {
                        preKeyId = candidate;
                        break;
                    }
                }
                saveIndex("prekey_pool", pool);
                if (preKeyId < 0) {
                    preKeyId = getNextPreKeyId();
                    storePreKey(preKeyId, new PreKeyRecord(preKeyId, ECKeyPair.generate()));
                }
                if (pool.size() < PRE_KEY_POOL_MIN) {
                    replenishPreKeysIfNeeded();
                }

                int signedPreKeyId = getActiveSignedPreKeyId();
                int kyberPreKeyId = getActiveKyberPreKeyId();
                return new LocalPreKeyMaterial(preKeyId, signedPreKeyId, kyberPreKeyId,
                        loadPreKey(preKeyId), loadSignedPreKey(signedPreKeyId), loadKyberPreKey(kyberPreKeyId));
            } catch (Exception e) {
                throw failure(e);
            }
        }
    }

    public static final class LocalPreKeyMaterial {
        public final int preKeyId, signedPreKeyId, kyberPreKeyId;
        public final PreKeyRecord preKey;
        public final SignedPreKeyRecord signedPreKey;
        public final KyberPreKeyRecord kyberPreKey;
        LocalPreKeyMaterial(int p, int s, int k, PreKeyRecord pr, SignedPreKeyRecord sr, KyberPreKeyRecord kr) {
            preKeyId = p; signedPreKeyId = s; kyberPreKeyId = k; preKey = pr; signedPreKey = sr; kyberPreKey = kr;
        }
    }

    @Override public IdentityChange saveIdentity(SignalProtocolAddress address, IdentityKey key) {
        synchronized (PROTOCOL_STATE_LOCK) {
            try {
                byte[] old = blobs.get(k(key("identity", address)));
                byte[] next = key.serialize();
                blobs.put(k(key("identity", address)), next);
                return old != null && !Arrays.equals(old, next)
                        ? IdentityChange.REPLACED_EXISTING : IdentityChange.NEW_OR_UNCHANGED;
            } catch (Exception e) { throw failure(e); }
        }
    }

    @Override public boolean isTrustedIdentity(SignalProtocolAddress address, IdentityKey key, Direction direction) {
        synchronized (PROTOCOL_STATE_LOCK) {
            try {
                byte[] current = blobs.get(k(key("identity", address)));
                if (current != null) {
                    return Arrays.equals(current, key.serialize());
                }
                return direction == Direction.RECEIVING && isWaitingPeerAddress(address);
            } catch (Exception e) { throw failure(e); }
        }
    }

    private boolean isWaitingPeerAddress(SignalProtocolAddress address) {
        if (address == null || address.getName() == null || appContext == null) {
            return false;
        }
        String name = address.getName();
        if (!name.startsWith("telegram-user-")) {
            return false;
        }
        try {
            long peerUserId = Long.parseLong(name.substring("telegram-user-".length()));
            return peerUserId > 0
                    && new SecureChatState(appContext).isWaitingForAnyAccount(peerUserId);
        } catch (NumberFormatException ignored) {
            return false;
        }
    }

    @Override public IdentityKey getIdentity(SignalProtocolAddress address) {
        synchronized (PROTOCOL_STATE_LOCK) {
            try {
                byte[] saved = blobs.get(k(key("identity", address)));
                return saved == null ? null : new IdentityKey(saved);
            } catch (Exception e) { throw failure(e); }
        }
    }

    public void deleteIdentity(SignalProtocolAddress address) {
        synchronized (PROTOCOL_STATE_LOCK) {
            remove(key("identity", address));
        }
    }

    /**
     * Destroys this installation's libsignal identity, pre-keys, trust records, and sessions.
     * Device-local display copies use different roots and are deliberately preserved.
     */
    public static void resetProtocolState(Context context) {
        resetProtocolState(context, 0);
    }

    public static void resetProtocolState(Context context, int account) {
        synchronized (PROTOCOL_STATE_LOCK) {
            try {
                KeystoreEncryptedBlobStore store =
                        new KeystoreEncryptedBlobStore(context.getApplicationContext());
                store.deletePrefixes("account/" + account + "/");
                if (account == 0) {
                    store.deleteRoots(
                            IDENTITY, REGISTRATION, "counter", "current", "prekey", "signed", "kyber", "index",
                            "kyber-used", "session", "sender");
                }
            } catch (Exception e) {
                throw failure(e);
            }
        }
    }

    static boolean hasRemoteProtocolState(Context context) {
        return hasRemoteProtocolState(context, 0);
    }

    static boolean hasRemoteProtocolState(Context context, int account) {
        synchronized (PROTOCOL_STATE_LOCK) {
            String p = "account/" + account + "/";
            return new KeystoreEncryptedBlobStore(context.getApplicationContext())
                    .hasNameStartingWith(
                            p + "identity/", p + "session/", p + "sender/", p + "kyber-used/",
                            "identity/", "session/", "sender/", "kyber-used/");
        }
    }

    static void replaceIdentityForRecovery(
            Context context,
            byte[] serializedIdentity,
            int registrationId,
            Map<String, byte[]> transactionRecords) {
        replaceIdentityForRecovery(context, 0, serializedIdentity, registrationId, transactionRecords);
    }

    static void replaceIdentityForRecovery(
            Context context,
            int account,
            byte[] serializedIdentity,
            int registrationId,
            Map<String, byte[]> transactionRecords) {
        synchronized (PROTOCOL_STATE_LOCK) {
            try {
                IdentityKeyPair restored = new IdentityKeyPair(serializedIdentity);
                if (registrationId <= 0 || registrationId > 16_380) {
                    throw new IllegalArgumentException("invalid recovered registration id");
                }
                String p = "account/" + account + "/";
                Map<String, byte[]> replacements = new LinkedHashMap<>();
                replacements.put(p + IDENTITY, restored.serialize());
                replacements.put(
                        p + REGISTRATION,
                        ByteBuffer.allocate(4).putInt(registrationId).array());
                if (transactionRecords != null) {
                    if (transactionRecords.containsKey(IDENTITY)
                            || transactionRecords.containsKey(REGISTRATION)
                            || transactionRecords.containsKey(p + IDENTITY)
                            || transactionRecords.containsKey(p + REGISTRATION)) {
                        throw new IllegalArgumentException(
                                "recovery transaction cannot override local identity records");
                    }
                    for (Map.Entry<String, byte[]> entry : transactionRecords.entrySet()) {
                        String key = entry.getKey();
                        if (!key.startsWith("account/")) {
                            key = p + key;
                        }
                        replacements.put(key, entry.getValue());
                    }
                }
                KeystoreEncryptedBlobStore store =
                        new KeystoreEncryptedBlobStore(context.getApplicationContext());
                store.deletePrefixes(p);
                if (account == 0) {
                    store.deleteRoots(
                            IDENTITY, REGISTRATION, "counter", "current", "prekey", "signed", "kyber", "index",
                            "kyber-used", "session", "sender");
                }
                store.putAll(replacements);
            } catch (Exception error) {
                throw failure(error);
            }
        }
    }

    @Override public SessionRecord loadSession(SignalProtocolAddress address) {
        synchronized (PROTOCOL_STATE_LOCK) {
            requireDevice(address);
            try {
                byte[] saved = blobs.get(k(key("session", address)));
                return saved == null ? new SessionRecord() : new SessionRecord(saved);
            } catch (Exception e) { throw failure(e); }
        }
    }

    @Override public List<SessionRecord> loadExistingSessions(List<SignalProtocolAddress> addresses) throws NoSessionException {
        synchronized (PROTOCOL_STATE_LOCK) {
            List<SessionRecord> records = new ArrayList<>();
            for (SignalProtocolAddress address : addresses) {
                if (!containsSession(address)) throw new NoSessionException(address, "missing secure session");
                records.add(loadSession(address));
            }
            return records;
        }
    }

    @Override public List<Integer> getSubDeviceSessions(String name) { return Collections.emptyList(); }
    @Override public void storeSession(SignalProtocolAddress address, SessionRecord record) {
        synchronized (PROTOCOL_STATE_LOCK) {
            put(key("session", address), record.serialize());
        }
    }
    @Override public boolean containsSession(SignalProtocolAddress address) {
        synchronized (PROTOCOL_STATE_LOCK) {
            return has(key("session", address));
        }
    }
    @Override public void deleteSession(SignalProtocolAddress address) {
        synchronized (PROTOCOL_STATE_LOCK) {
            remove(key("session", address));
        }
    }
    @Override public void deleteAllSessions(String name) { /* one-device policy: callers delete the explicit address */ }

    @Override public PreKeyRecord loadPreKey(int id) throws InvalidKeyIdException {
        synchronized (PROTOCOL_STATE_LOCK) {
            try { byte[] b = get("prekey", id); if (b == null) throw new InvalidKeyIdException("missing prekey " + id); return new PreKeyRecord(b); }
            catch (InvalidKeyIdException e) { throw e; } catch (Exception e) { throw new InvalidKeyIdException(e); }
        }
    }
    @Override public void storePreKey(int id, PreKeyRecord record) {
        synchronized (PROTOCOL_STATE_LOCK) {
            putIndexed("prekey", id, record.serialize());
        }
    }
    @Override public boolean containsPreKey(int id) {
        synchronized (PROTOCOL_STATE_LOCK) {
            return get("prekey", id) != null;
        }
    }
    @Override public void removePreKey(int id) {
        synchronized (PROTOCOL_STATE_LOCK) {
            removeIndexed("prekey", id);
            List<Integer> pool = index("prekey_pool");
            if (pool.remove((Integer) id)) {
                saveIndex("prekey_pool", pool);
            }
        }
    }

    @Override public SignedPreKeyRecord loadSignedPreKey(int id) throws InvalidKeyIdException {
        synchronized (PROTOCOL_STATE_LOCK) {
            try { byte[] b = get("signed", id); if (b == null) throw new InvalidKeyIdException("missing signed prekey " + id); return new SignedPreKeyRecord(b); }
            catch (InvalidKeyIdException e) { throw e; } catch (Exception e) { throw new InvalidKeyIdException(e); }
        }
    }
    @Override public List<SignedPreKeyRecord> loadSignedPreKeys() {
        synchronized (PROTOCOL_STATE_LOCK) {
            return records("signed", SignedPreKeyRecord.class);
        }
    }
    @Override public void storeSignedPreKey(int id, SignedPreKeyRecord record) {
        synchronized (PROTOCOL_STATE_LOCK) {
            putIndexed("signed", id, record.serialize());
        }
    }
    @Override public boolean containsSignedPreKey(int id) {
        synchronized (PROTOCOL_STATE_LOCK) {
            return get("signed", id) != null;
        }
    }
    @Override public void removeSignedPreKey(int id) {
        synchronized (PROTOCOL_STATE_LOCK) {
            removeIndexed("signed", id);
        }
    }

    @Override public KyberPreKeyRecord loadKyberPreKey(int id) throws InvalidKeyIdException {
        synchronized (PROTOCOL_STATE_LOCK) {
            try { byte[] b = get("kyber", id); if (b == null) throw new InvalidKeyIdException("missing Kyber prekey " + id); return new KyberPreKeyRecord(b); }
            catch (InvalidKeyIdException e) { throw e; } catch (Exception e) { throw new InvalidKeyIdException(e); }
        }
    }
    @Override public List<KyberPreKeyRecord> loadKyberPreKeys() {
        synchronized (PROTOCOL_STATE_LOCK) {
            return records("kyber", KyberPreKeyRecord.class);
        }
    }
    @Override public void storeKyberPreKey(int id, KyberPreKeyRecord record) {
        synchronized (PROTOCOL_STATE_LOCK) {
            putIndexed("kyber", id, record.serialize());
        }
    }
    @Override public boolean containsKyberPreKey(int id) {
        synchronized (PROTOCOL_STATE_LOCK) {
            return get("kyber", id) != null;
        }
    }
    public void removeKyberPreKey(int id) {
        synchronized (PROTOCOL_STATE_LOCK) {
            removeIndexed("kyber", id);
        }
    }
    @Override public void markKyberPreKeyUsed(int id, int signedId, ECPublicKey base) throws ReusedBaseKeyException {
        synchronized (PROTOCOL_STATE_LOCK) {
            String marker = "kyber-used/" + id + "/" + signedId + "/" + hex(base.serialize());
            if (has(marker)) throw new ReusedBaseKeyException("reused Kyber prekey base key");
            put(marker, new byte[] {1});
        }
    }

    @Override public void storeSenderKey(SignalProtocolAddress sender, UUID distribution, SenderKeyRecord record) {
        synchronized (PROTOCOL_STATE_LOCK) {
            put(key("sender/" + distribution, sender), record.serialize());
        }
    }
    @Override public SenderKeyRecord loadSenderKey(SignalProtocolAddress sender, UUID distribution) {
        synchronized (PROTOCOL_STATE_LOCK) {
            try { byte[] b = blobs.get(k(key("sender/" + distribution, sender))); return b == null ? null : new SenderKeyRecord(b); }
            catch (Exception e) { throw failure(e); }
        }
    }
    public void deleteSenderKey(SignalProtocolAddress sender, UUID distribution) {
        synchronized (PROTOCOL_STATE_LOCK) {
            remove(key("sender/" + distribution, sender));
        }
    }

    private boolean has(String name) { try { return blobs.get(k(name)) != null; } catch (Exception e) { throw failure(e); } }
    private byte[] get(String kind, int id) { try { return blobs.get(k(kind + "/" + id)); } catch (Exception e) { throw failure(e); } }
    private void put(String name, byte[] data) { try { blobs.put(k(name), data); } catch (Exception e) { throw failure(e); } }
    private void remove(String name) { try { blobs.delete(k(name)); } catch (Exception e) { throw failure(e); } }
    private void putIndexed(String kind, int id, byte[] data) { put(kind + "/" + id, data); List<Integer> ids = index(kind); if (!ids.contains(id)) { ids.add(id); saveIndex(kind, ids); } }
    private void removeIndexed(String kind, int id) { remove(kind + "/" + id); List<Integer> ids = index(kind); ids.remove((Integer) id); saveIndex(kind, ids); }
    private List<Integer> index(String kind) { try { byte[] b = blobs.get(k("index/" + kind)); if (b == null) return new ArrayList<>(); String s = new String(b, StandardCharsets.US_ASCII); List<Integer> r = new ArrayList<>(); for (String p : s.split(",")) if (!p.isEmpty()) r.add(Integer.parseInt(p)); return r; } catch (Exception e) { throw failure(e); } }
    private void saveIndex(String kind, List<Integer> ids) { StringBuilder b = new StringBuilder(); for (int id : ids) { if (b.length() > 0) b.append(','); b.append(id); } put("index/" + kind, b.toString().getBytes(StandardCharsets.US_ASCII)); }
    @SuppressWarnings("unchecked") private <T> List<T> records(String kind, Class<T> type) { try { List<T> out = new ArrayList<>(); for (int id : index(kind)) { byte[] b = get(kind, id); if (b == null) continue; if (type == SignedPreKeyRecord.class) out.add((T) new SignedPreKeyRecord(b)); else out.add((T) new KyberPreKeyRecord(b)); } return out; } catch (Exception e) { throw failure(e); } }
    private static void requireDevice(SignalProtocolAddress address) { if (address.getDeviceId() != ONLY_DEVICE_ID) throw new IllegalArgumentException("only one secure device is supported"); }
    private static String key(String kind, SignalProtocolAddress address) { requireDevice(address); return kind + "/" + hex((address.getName() + ":" + address.getDeviceId()).getBytes(StandardCharsets.UTF_8)); }
    private static String hex(byte[] data) { try { return bytesToHex(MessageDigest.getInstance("SHA-256").digest(data)); } catch (Exception e) { throw new AssertionError(e); } }
    private static String bytesToHex(byte[] data) { StringBuilder b = new StringBuilder(data.length * 2); for (byte v : data) b.append(String.format("%02x", v)); return b.toString(); }
    private static StateFailure failure(Exception e) { return e instanceof StateFailure ? (StateFailure) e : new StateFailure("secure state failure", e); }
    public static final class StateFailure extends RuntimeException { StateFailure(String message, Throwable cause) { super(message, cause); } }
}
