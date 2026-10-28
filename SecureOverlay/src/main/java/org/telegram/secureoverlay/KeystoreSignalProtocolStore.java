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
    private final KeystoreEncryptedBlobStore blobs;
    private final IdentityKeyPair identity;
    private final int registrationId;

    public KeystoreSignalProtocolStore(Context context) {
        synchronized (PROTOCOL_STATE_LOCK) {
            appContext = context.getApplicationContext();
            blobs = new KeystoreEncryptedBlobStore(context);
            try {
                byte[] savedIdentity = blobs.get(IDENTITY);
                byte[] savedRegistration = blobs.get(REGISTRATION);
                if ((savedIdentity == null) != (savedRegistration == null)) {
                    throw new StateFailure("incomplete local identity state", null);
                }
                if (savedIdentity == null) {
                    identity = IdentityKeyPair.generate();
                    registrationId = KeyHelper.generateRegistrationId(false);
                    blobs.put(IDENTITY, identity.serialize());
                    blobs.put(REGISTRATION, ByteBuffer.allocate(4).putInt(registrationId).array());
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

    private int getNextPreKeyId() {
        try {
            byte[] b = blobs.get("counter/prekey");
            int current = (b != null && b.length == 4) ? ByteBuffer.wrap(b).getInt() : 0;
            if (current == 0 && containsPreKey(1)) {
                current = 1;
            }
            int next = current + 1;
            if (next >= 0xFFFFFF || next <= 0) {
                next = 1;
            }
            blobs.put("counter/prekey", ByteBuffer.allocate(4).putInt(next).array());
            return next;
        } catch (Exception e) {
            throw failure(e);
        }
    }

    public void replenishPreKeysIfNeeded() {
        synchronized (PROTOCOL_STATE_LOCK) {
            try {
                List<Integer> existing = index("prekey");
                if (existing.size() >= PRE_KEY_POOL_MIN) {
                    return;
                }
                int needed = PRE_KEY_POOL_BATCH - existing.size();
                for (int i = 0; i < needed; i++) {
                    int id = getNextPreKeyId();
                    while (containsPreKey(id)) {
                        id = getNextPreKeyId();
                    }
                    storePreKey(id, new PreKeyRecord(id, ECKeyPair.generate()));
                }
            } catch (Exception e) {
                throw failure(e);
            }
        }
    }

    /** Creates the one-time material required to publish a 1:1 pre-key bundle. */
    public LocalPreKeyMaterial ensureLocalPreKeyMaterial() {
        synchronized (PROTOCOL_STATE_LOCK) {
            final int signedPreKeyId = 2;
            final int kyberPreKeyId = 3;
            try {
                replenishPreKeysIfNeeded();
                List<Integer> existing = index("prekey");
                int preKeyId;
                if (!existing.isEmpty()) {
                    byte[] b = blobs.get("counter/prekey_offer_offset");
                    int offset = (b != null && b.length == 4) ? ByteBuffer.wrap(b).getInt() : 0;
                    if (offset < 0 || offset >= existing.size()) {
                        offset = 0;
                    }
                    preKeyId = existing.get(offset);
                    int nextOffset = (offset + 1) % existing.size();
                    blobs.put("counter/prekey_offer_offset", ByteBuffer.allocate(4).putInt(nextOffset).array());
                } else {
                    preKeyId = getNextPreKeyId();
                    storePreKey(preKeyId, new PreKeyRecord(preKeyId, ECKeyPair.generate()));
                }
                if (!containsSignedPreKey(signedPreKeyId)) {
                    ECKeyPair pair = ECKeyPair.generate();
                    storeSignedPreKey(signedPreKeyId, new SignedPreKeyRecord(signedPreKeyId,
                            System.currentTimeMillis(), pair,
                            identity.getPrivateKey().calculateSignature(pair.getPublicKey().serialize())));
                }
                if (!containsKyberPreKey(kyberPreKeyId)) {
                    KEMKeyPair pair = KEMKeyPair.generate(KEMKeyType.KYBER_1024);
                    storeKyberPreKey(kyberPreKeyId, new KyberPreKeyRecord(kyberPreKeyId,
                            System.currentTimeMillis(), pair,
                            identity.getPrivateKey().calculateSignature(pair.getPublicKey().serialize())));
                }
                return new LocalPreKeyMaterial(preKeyId, signedPreKeyId, kyberPreKeyId,
                        loadPreKey(preKeyId), loadSignedPreKey(signedPreKeyId), loadKyberPreKey(kyberPreKeyId));
            } catch (Exception e) { throw failure(e); }
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
                byte[] old = blobs.get(key("identity", address));
                byte[] next = key.serialize();
                blobs.put(key("identity", address), next);
                return old != null && !Arrays.equals(old, next)
                        ? IdentityChange.REPLACED_EXISTING : IdentityChange.NEW_OR_UNCHANGED;
            } catch (Exception e) { throw failure(e); }
        }
    }

    @Override public boolean isTrustedIdentity(SignalProtocolAddress address, IdentityKey key, Direction direction) {
        synchronized (PROTOCOL_STATE_LOCK) {
            try {
                byte[] current = blobs.get(key("identity", address));
                if (current != null) {
                    return Arrays.equals(current, key.serialize());
                }
                return direction == Direction.RECEIVING && isWaitingPeerAddress(address);
            } catch (Exception e) { throw failure(e); }
        }
    }

    private boolean isWaitingPeerAddress(SignalProtocolAddress address) {
        if (address == null || address.getName() == null) {
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
                byte[] saved = blobs.get(key("identity", address));
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
        synchronized (PROTOCOL_STATE_LOCK) {
            try {
                new KeystoreEncryptedBlobStore(context.getApplicationContext()).deleteRoots(
                        IDENTITY, REGISTRATION, "counter", "prekey", "signed", "kyber", "index",
                        "kyber-used", "session", "sender");
            } catch (Exception e) {
                throw failure(e);
            }
        }
    }

    static boolean hasRemoteProtocolState(Context context) {
        synchronized (PROTOCOL_STATE_LOCK) {
            return new KeystoreEncryptedBlobStore(context.getApplicationContext())
                    .hasNameStartingWith("identity/", "session/", "sender/", "kyber-used/");
        }
    }

    static void replaceIdentityForRecovery(
            Context context,
            byte[] serializedIdentity,
            int registrationId,
            Map<String, byte[]> transactionRecords) {
        synchronized (PROTOCOL_STATE_LOCK) {
            try {
                IdentityKeyPair restored = new IdentityKeyPair(serializedIdentity);
                if (registrationId <= 0 || registrationId > 16_380) {
                    throw new IllegalArgumentException("invalid recovered registration id");
                }
                Map<String, byte[]> replacements = new LinkedHashMap<>();
                replacements.put(IDENTITY, restored.serialize());
                replacements.put(
                        REGISTRATION,
                        ByteBuffer.allocate(4).putInt(registrationId).array());
                if (transactionRecords != null) {
                    if (transactionRecords.containsKey(IDENTITY)
                            || transactionRecords.containsKey(REGISTRATION)) {
                        throw new IllegalArgumentException(
                                "recovery transaction cannot override local identity records");
                    }
                    replacements.putAll(transactionRecords);
                }
                new KeystoreEncryptedBlobStore(context.getApplicationContext()).replaceRoots(
                        replacements,
                        IDENTITY,
                        REGISTRATION,
                        "counter",
                        "prekey",
                        "signed",
                        "kyber",
                        "index",
                        "kyber-used",
                        "session",
                        "sender");
            } catch (Exception error) {
                throw failure(error);
            }
        }
    }

    @Override public SessionRecord loadSession(SignalProtocolAddress address) {
        synchronized (PROTOCOL_STATE_LOCK) {
            requireDevice(address);
            try {
                byte[] saved = blobs.get(key("session", address));
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
            try { byte[] b = blobs.get(key("sender/" + distribution, sender)); return b == null ? null : new SenderKeyRecord(b); }
            catch (Exception e) { throw failure(e); }
        }
    }
    public void deleteSenderKey(SignalProtocolAddress sender, UUID distribution) {
        synchronized (PROTOCOL_STATE_LOCK) {
            remove(key("sender/" + distribution, sender));
        }
    }

    private boolean has(String name) { try { return blobs.get(name) != null; } catch (Exception e) { throw failure(e); } }
    private byte[] get(String kind, int id) { try { return blobs.get(kind + "/" + id); } catch (Exception e) { throw failure(e); } }
    private void put(String name, byte[] data) { try { blobs.put(name, data); } catch (Exception e) { throw failure(e); } }
    private void remove(String name) { try { blobs.delete(name); } catch (Exception e) { throw failure(e); } }
    private void putIndexed(String kind, int id, byte[] data) { put(kind + "/" + id, data); List<Integer> ids = index(kind); if (!ids.contains(id)) { ids.add(id); saveIndex(kind, ids); } }
    private void removeIndexed(String kind, int id) { remove(kind + "/" + id); List<Integer> ids = index(kind); ids.remove((Integer) id); saveIndex(kind, ids); }
    private List<Integer> index(String kind) { try { byte[] b = blobs.get("index/" + kind); if (b == null) return new ArrayList<>(); String s = new String(b, StandardCharsets.US_ASCII); List<Integer> r = new ArrayList<>(); for (String p : s.split(",")) if (!p.isEmpty()) r.add(Integer.parseInt(p)); return r; } catch (Exception e) { throw failure(e); } }
    private void saveIndex(String kind, List<Integer> ids) { StringBuilder b = new StringBuilder(); for (int id : ids) { if (b.length() > 0) b.append(','); b.append(id); } put("index/" + kind, b.toString().getBytes(StandardCharsets.US_ASCII)); }
    @SuppressWarnings("unchecked") private <T> List<T> records(String kind, Class<T> type) { try { List<T> out = new ArrayList<>(); for (int id : index(kind)) { byte[] b = get(kind, id); if (b == null) continue; if (type == SignedPreKeyRecord.class) out.add((T) new SignedPreKeyRecord(b)); else out.add((T) new KyberPreKeyRecord(b)); } return out; } catch (Exception e) { throw failure(e); } }
    private static void requireDevice(SignalProtocolAddress address) { if (address.getDeviceId() != ONLY_DEVICE_ID) throw new IllegalArgumentException("only one secure device is supported"); }
    private static String key(String kind, SignalProtocolAddress address) { requireDevice(address); return kind + "/" + hex((address.getName() + ":" + address.getDeviceId()).getBytes(StandardCharsets.UTF_8)); }
    private static String hex(byte[] data) { try { return bytesToHex(MessageDigest.getInstance("SHA-256").digest(data)); } catch (Exception e) { throw new AssertionError(e); } }
    private static String bytesToHex(byte[] data) { StringBuilder b = new StringBuilder(data.length * 2); for (byte v : data) b.append(String.format("%02x", v)); return b.toString(); }
    private static StateFailure failure(Exception e) { return e instanceof StateFailure ? (StateFailure) e : new StateFailure("secure state failure", e); }
    public static final class StateFailure extends RuntimeException { StateFailure(String message, Throwable cause) { super(message, cause); } }
}
