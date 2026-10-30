package org.telegram.secureoverlay;

import android.content.Context;
import android.content.SharedPreferences;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Per-account, per-peer secure-mode gate. No message is encrypted unless paired.
 *
 * <p>State is Keystore-encrypted and record names are derived using HMAC-SHA256
 * to protect peer IDs and pending carrier metadata at rest.</p>
 */
public final class SecureChatState {
    private static final String PREFS = "telegram_secure_chat_state_v1";
    private static final String STATE_PREFIX = "chat-state.v1.";
    private static final String EPOCH_PREFIX = "chat-epoch.v1.";
    private static final byte MAGIC = (byte) 0xC5;
    private static final byte FORMAT_VERSION = 1;

    // Legacy SharedPreferences prefixes for migration
    private static final String PAIRED_PREFIX = "paired.";
    private static final String WAITING_PREFIX = "waiting.";
    private static final String PAUSED_PREFIX = "paused.";
    private static final String IDENTITY_PENDING_PREFIX = "identity-pending.";
    private static final String PENDING_CARRIER_PREFIX = "pending-carrier.";
    private static final String PENDING_MESSAGE_PREFIX = "pending-message.";
    private static final String PENDING_KIND_PREFIX = "pending-kind.";
    private static final String LAST_PAIRING_MESSAGE_PREFIX = "last-pairing-message.";
    private static final String LAST_READY_MESSAGE_PREFIX = "last-ready-message.";
    private static final String GROUP_KEY_NEEDS_DISTRIBUTION_PREFIX = "group-key-needs-dist.";
    private static final String IDENTITY_EPOCH = "identity-epoch";

    public static final class Summary {
        public final int paired;
        public final int waiting;
        public final int paused;
        public final int identityPending;

        Summary(int paired, int waiting, int paused, int identityPending) {
            this.paired = paired;
            this.waiting = waiting;
            this.paused = paused;
            this.identityPending = identityPending;
        }

        public int total() {
            return paired + waiting + paused + identityPending;
        }
    }

    public enum PendingKind {
        NONE(0),
        IDENTITY_CHANGE(1),
        RECOVERY_ADVANCE(2),
        INITIAL_OFFER(3);

        final int value;

        PendingKind(int value) {
            this.value = value;
        }

        public static PendingKind fromValue(int val) {
            for (PendingKind k : values()) {
                if (k.value == val) return k;
            }
            return NONE;
        }
    }

    static final int STATUS_NONE = 0;
    static final int STATUS_PAIRED = 1;
    static final int STATUS_WAITING = 2;
    static final int STATUS_PAUSED = 3;
    static final int STATUS_IDENTITY_PENDING = 4;

    static final class PeerState {
        final long peerUserId;
        int status;
        String pendingCarrier;
        int pendingMessageId;
        int pendingKind;
        int lastPairingMessageId;
        int lastReadyMessageId;
        boolean groupKeyNeedsDist;

        PeerState(long peerUserId) {
            this.peerUserId = peerUserId;
        }
    }

    private final KeystoreSignalProtocolStore.EncryptedStateStorage storage;
    private final SharedPreferences legacyPreferences;
    private final byte[] nameMaskKey;
    private final Map<String, PeerState> peersCache = new ConcurrentHashMap<>();
    private final Map<Integer, Long> epochCache = new ConcurrentHashMap<>();

    public SecureChatState(Context context) {
        this(new KeystoreEncryptedBlobStore(context.getApplicationContext()),
                context.getSharedPreferences(PREFS, Context.MODE_PRIVATE));
    }

    static SecureChatState forTest(KeystoreSignalProtocolStore.EncryptedStateStorage storage) {
        return new SecureChatState(storage, null);
    }

    SecureChatState(KeystoreSignalProtocolStore.EncryptedStateStorage storage, SharedPreferences legacyPreferences) {
        this.storage = storage;
        this.legacyPreferences = legacyPreferences;
        this.nameMaskKey = SecureNameMask.getOrGenerateKey(storage);
        initAndMigrate();
    }

    private void initAndMigrate() {
        try {
            Map<String, byte[]> stateRecords = storage.snapshotPrefixes(STATE_PREFIX);
            for (Map.Entry<String, byte[]> entry : stateRecords.entrySet()) {
                PeerState p = decodePeerState(entry.getValue());
                if (p != null) {
                    int account = parseAccountFromKey(entry.getKey());
                    peersCache.put(cacheKey(account, p.peerUserId), p);
                }
            }
            Map<String, byte[]> epochRecords = storage.snapshotPrefixes(EPOCH_PREFIX);
            for (Map.Entry<String, byte[]> entry : epochRecords.entrySet()) {
                String suffix = entry.getKey().substring(EPOCH_PREFIX.length());
                try {
                    int account = Integer.parseInt(suffix);
                    long epoch = ByteBuffer.wrap(entry.getValue()).getLong();
                    epochCache.put(account, epoch);
                } catch (Exception ignore) {
                }
            }
        } catch (Exception ignore) {
        }

        if (legacyPreferences != null && !legacyPreferences.getAll().isEmpty()) {
            migrateLegacyPreferences();
        }
    }

    private void migrateLegacyPreferences() {
        Map<String, ?> all = legacyPreferences.getAll();
        Map<String, PeerState> migratedPeers = new LinkedHashMap<>();
        Map<Integer, Long> migratedEpochs = new LinkedHashMap<>();

        for (Map.Entry<String, ?> entry : all.entrySet()) {
            String key = entry.getKey();
            Object value = entry.getValue();

            if (key.startsWith(IDENTITY_EPOCH)) {
                if (key.equals(IDENTITY_EPOCH) && value instanceof Long) {
                    migratedEpochs.putIfAbsent(0, (Long) value);
                } else if (key.startsWith(IDENTITY_EPOCH + ".")) {
                    try {
                        int acc = Integer.parseInt(key.substring(IDENTITY_EPOCH.length() + 1));
                        if (value instanceof Long) {
                            migratedEpochs.put(acc, (Long) value);
                        }
                    } catch (NumberFormatException ignore) {
                    }
                }
                continue;
            }

            int firstDot = key.indexOf('.');
            if (firstDot <= 0) continue;
            int secondDot = key.indexOf('.', firstDot + 1);
            if (secondDot <= 0) continue;

            String prefix = key.substring(0, firstDot + 1);
            int account;
            long peerId;
            try {
                account = Integer.parseInt(key.substring(firstDot + 1, secondDot));
                peerId = Long.parseLong(key.substring(secondDot + 1));
            } catch (NumberFormatException ignore) {
                continue;
            }

            String ck = cacheKey(account, peerId);
            PeerState p = migratedPeers.computeIfAbsent(ck, k -> {
                PeerState existing = peersCache.get(k);
                return existing != null ? existing : new PeerState(peerId);
            });

            if (prefix.equals(PAIRED_PREFIX) && Boolean.TRUE.equals(value)) {
                p.status = STATUS_PAIRED;
            } else if (prefix.equals(WAITING_PREFIX) && Boolean.TRUE.equals(value)) {
                p.status = STATUS_WAITING;
            } else if (prefix.equals(PAUSED_PREFIX) && Boolean.TRUE.equals(value)) {
                p.status = STATUS_PAUSED;
            } else if (prefix.equals(IDENTITY_PENDING_PREFIX) && Boolean.TRUE.equals(value)) {
                p.status = STATUS_IDENTITY_PENDING;
            } else if (prefix.equals(PENDING_CARRIER_PREFIX) && value instanceof String) {
                p.pendingCarrier = (String) value;
            } else if (prefix.equals(PENDING_MESSAGE_PREFIX) && value instanceof Integer) {
                p.pendingMessageId = (Integer) value;
            } else if (prefix.equals(PENDING_KIND_PREFIX) && value instanceof Integer) {
                p.pendingKind = (Integer) value;
            } else if (prefix.equals(LAST_PAIRING_MESSAGE_PREFIX) && value instanceof Integer) {
                p.lastPairingMessageId = (Integer) value;
            } else if (prefix.equals(LAST_READY_MESSAGE_PREFIX) && value instanceof Integer) {
                p.lastReadyMessageId = (Integer) value;
            } else if (prefix.equals(GROUP_KEY_NEEDS_DISTRIBUTION_PREFIX) && Boolean.TRUE.equals(value)) {
                p.groupKeyNeedsDist = true;
            }
        }

        for (Map.Entry<String, PeerState> entry : migratedPeers.entrySet()) {
            int dot = entry.getKey().indexOf('.');
            int acc = Integer.parseInt(entry.getKey().substring(0, dot));
            persistPeer(acc, entry.getValue());
        }
        for (Map.Entry<Integer, Long> entry : migratedEpochs.entrySet()) {
            persistEpoch(entry.getKey(), entry.getValue());
        }

        legacyPreferences.edit().clear().commit();
    }

    static void clearForMissingKeystore(Context context) {
        if (!context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                .edit()
                .clear()
                .commit()) {
            throw new IllegalStateException(
                    "failed to clear orphaned secure chat state");
        }
        SecureLocalTextStore.evictDisplayPrefixes(
                SecureLocalTextStore.OUTGOING_PREFIX,
                SecureLocalTextStore.INCOMING_PREFIX);
    }

    static boolean hasStoredState(Context context) {
        return !context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                .getAll()
                .isEmpty();
    }

    public boolean isPaired(int account, long peerUserId) {
        if (peerUserId == 0) return false;
        PeerState p = peersCache.get(cacheKey(account, peerUserId));
        return p != null && p.status == STATUS_PAIRED;
    }

    public boolean isWaiting(int account, long peerUserId) {
        if (peerUserId == 0) return false;
        PeerState p = peersCache.get(cacheKey(account, peerUserId));
        return p != null && p.status == STATUS_WAITING;
    }

    public boolean isWaitingForAnyAccount(long peerUserId) {
        if (peerUserId <= 0) {
            return false;
        }
        for (PeerState p : peersCache.values()) {
            if (p.peerUserId == peerUserId && p.status == STATUS_WAITING) {
                return true;
            }
        }
        return false;
    }

    public boolean isPaused(int account, long peerUserId) {
        if (peerUserId == 0) return false;
        PeerState p = peersCache.get(cacheKey(account, peerUserId));
        return p != null && p.status == STATUS_PAUSED;
    }

    public boolean isIdentityPending(int account, long peerUserId) {
        if (peerUserId == 0) return false;
        PeerState p = peersCache.get(cacheKey(account, peerUserId));
        return p != null && p.status == STATUS_IDENTITY_PENDING;
    }

    public String getPendingCarrier(int account, long peerUserId) {
        if (peerUserId == 0) return null;
        PeerState p = peersCache.get(cacheKey(account, peerUserId));
        return p != null ? p.pendingCarrier : null;
    }

    public int getPendingMessageId(int account, long peerUserId) {
        if (peerUserId == 0) return 0;
        PeerState p = peersCache.get(cacheKey(account, peerUserId));
        return p != null ? p.pendingMessageId : 0;
    }

    public PendingKind getPendingKind(int account, long peerUserId) {
        if (peerUserId == 0) return PendingKind.NONE;
        PeerState p = peersCache.get(cacheKey(account, peerUserId));
        if (p == null || p.pendingKind == 0) {
            return PendingKind.NONE;
        }
        for (PendingKind kind : PendingKind.values()) {
            if (kind.value == p.pendingKind) {
                return kind;
            }
        }
        throw new IllegalStateException("invalid pending secure identity kind");
    }

    public int getLastPairingMessageId(int account, long peerUserId) {
        if (peerUserId == 0) return 0;
        PeerState p = peersCache.get(cacheKey(account, peerUserId));
        return p != null ? p.lastPairingMessageId : 0;
    }

    public boolean shouldAcknowledgeSessionReady(
            int account, long peerUserId, int messageId) {
        requirePeer(peerUserId);
        PeerState p = peersCache.get(cacheKey(account, peerUserId));
        int current = p != null ? p.lastReadyMessageId : 0;
        return messageId > current;
    }

    public void recordSessionReadyAcknowledgement(
            int account, long peerUserId, int messageId) {
        requirePeer(peerUserId);
        if (messageId <= 0) {
            throw new IllegalArgumentException(
                    "session-ready message id must be positive");
        }
        PeerState p = getOrCreatePeer(account, peerUserId);
        if (messageId > p.lastReadyMessageId) {
            p.lastReadyMessageId = messageId;
            persistPeer(account, p);
        }
    }

    public boolean isGroupKeyNeedsDistribution(int account, long peerGroupId) {
        if (peerGroupId >= 0) return false;
        PeerState p = peersCache.get(cacheKey(account, peerGroupId));
        return p != null && p.groupKeyNeedsDist;
    }

    public void setGroupKeyNeedsDistribution(int account, long peerGroupId, boolean needed) {
        if (peerGroupId >= 0) {
            throw new IllegalArgumentException("peer dialog id must be negative for groups");
        }
        PeerState p = getOrCreatePeer(account, peerGroupId);
        p.groupKeyNeedsDist = needed;
        persistPeer(account, p);
    }

    public long getIdentityEpoch() {
        return getIdentityEpoch(0);
    }

    public long getIdentityEpoch(int account) {
        Long val = epochCache.get(account);
        return val != null ? val : 0L;
    }

    public boolean hasAnySecureConversationState() {
        return hasAnySecureConversationState(0);
    }

    public boolean hasAnySecureConversationState(int account) {
        String prefix = account + ".";
        for (Map.Entry<String, PeerState> entry : peersCache.entrySet()) {
            if (entry.getKey().startsWith(prefix)) {
                PeerState p = entry.getValue();
                if (p.status != STATUS_NONE || p.lastPairingMessageId > 0 || p.lastReadyMessageId > 0) {
                    return true;
                }
            }
        }
        return false;
    }

    public boolean hasStateForPeer(int account, long peerUserId) {
        if (peerUserId == 0) return false;
        PeerState p = peersCache.get(cacheKey(account, peerUserId));
        return p != null && (p.status != STATUS_NONE
                || p.lastPairingMessageId > 0
                || p.lastReadyMessageId > 0);
    }

    public Summary getSummary(int account) {
        if (account < 0) {
            throw new IllegalArgumentException("account must not be negative");
        }
        String prefix = account + ".";
        int paired = 0;
        int waiting = 0;
        int paused = 0;
        int identityPending = 0;
        for (Map.Entry<String, PeerState> entry : peersCache.entrySet()) {
            if (entry.getKey().startsWith(prefix)) {
                PeerState p = entry.getValue();
                if (p.status == STATUS_PAIRED) paired++;
                else if (p.status == STATUS_WAITING) waiting++;
                else if (p.status == STATUS_PAUSED) paused++;
                else if (p.status == STATUS_IDENTITY_PENDING) identityPending++;
            }
        }
        return new Summary(paired, waiting, paused, identityPending);
    }

    List<SecureHistoryBackupCodec.PeerRecord> getRecoveryPeers(int account) {
        if (account < 0) {
            throw new IllegalArgumentException("account must not be negative");
        }
        String prefix = account + ".";
        TreeMap<Long, Integer> peers = new TreeMap<>();
        for (Map.Entry<String, PeerState> entry : peersCache.entrySet()) {
            if (entry.getKey().startsWith(prefix)) {
                PeerState p = entry.getValue();
                if (p.status != STATUS_NONE || p.lastPairingMessageId > 0) {
                    peers.put(p.peerUserId, p.lastPairingMessageId);
                }
            }
        }
        List<SecureHistoryBackupCodec.PeerRecord> records =
                new ArrayList<>(peers.size());
        for (Map.Entry<Long, Integer> peer : peers.entrySet()) {
            records.add(new SecureHistoryBackupCodec.PeerRecord(
                    peer.getKey(), peer.getValue()));
        }
        return records;
    }

    synchronized void restorePausedPeers(
            int account,
            long generation,
            List<SecureHistoryBackupCodec.PeerRecord> peers) {
        if (account < 0 || generation <= 0 || peers == null) {
            throw new IllegalArgumentException("invalid secure history chat state");
        }
        peersCache.keySet().removeIf(k -> k.startsWith(account + "."));
        try {
            storage.deleteRoots(STATE_PREFIX + account);
        } catch (Exception e) {
            throw new IllegalStateException("failed to delete secure history chat states", e);
        }
        long epoch = generation - 1;
        persistEpoch(account, epoch);

        boolean hasPrevious = false;
        long previousPeer = 0;
        Map<String, byte[]> replacements = new LinkedHashMap<>();
        for (SecureHistoryBackupCodec.PeerRecord peer : peers) {
            if (peer == null || (hasPrevious && peer.peerUserId <= previousPeer)) {
                throw new IllegalArgumentException(
                        "non-canonical secure history peer state");
            }
            PeerState state = new PeerState(peer.peerUserId);
            state.status = STATUS_PAUSED;
            state.lastPairingMessageId = peer.lastPairingMessageId;
            peersCache.put(cacheKey(account, peer.peerUserId), state);
            replacements.put(storageKey(account, peer.peerUserId), encodePeerState(state));
            previousPeer = peer.peerUserId;
            hasPrevious = true;
        }
        try {
            storage.replaceRoots(replacements, STATE_PREFIX + account);
        } catch (Exception e) {
            throw new IllegalStateException("failed to restore secure history chat state", e);
        }
    }

    public void markWaiting(int account, long peerUserId) {
        requirePeer(peerUserId);
        PeerState p = getOrCreatePeer(account, peerUserId);
        p.status = STATUS_WAITING;
        p.pendingCarrier = null;
        p.pendingMessageId = 0;
        p.pendingKind = PendingKind.NONE.value;
        persistPeer(account, p);
    }

    public void markPaired(int account, long peerUserId) {
        requirePeer(peerUserId);
        PeerState p = getOrCreatePeer(account, peerUserId);
        p.status = STATUS_PAIRED;
        p.pendingCarrier = null;
        p.pendingMessageId = 0;
        p.pendingKind = PendingKind.NONE.value;
        persistPeer(account, p);
    }

    public void pause(int account, long peerUserId) {
        requirePeer(peerUserId);
        PeerState p = getOrCreatePeer(account, peerUserId);
        p.status = STATUS_PAUSED;
        p.pendingCarrier = null;
        p.pendingMessageId = 0;
        p.pendingKind = PendingKind.NONE.value;
        persistPeer(account, p);
    }

    public void markIdentityPending(int account, long peerUserId, String carrier, int messageId) {
        markIdentityPending(
                account, peerUserId, carrier, messageId, PendingKind.IDENTITY_CHANGE);
    }

    public void markIdentityPending(
            int account,
            long peerUserId,
            String carrier,
            int messageId,
            PendingKind kind) {
        requirePeer(peerUserId);
        if (carrier == null || carrier.isEmpty() || messageId <= 0
                || kind == null || kind == PendingKind.NONE) {
            throw new IllegalArgumentException("pending identity requires a carrier and message id");
        }
        PeerState p = getOrCreatePeer(account, peerUserId);
        p.status = STATUS_IDENTITY_PENDING;
        p.pendingCarrier = carrier;
        p.pendingMessageId = messageId;
        p.pendingKind = kind.value;
        p.lastPairingMessageId = Math.max(messageId, p.lastPairingMessageId);
        persistPeer(account, p);
    }

    public void recordPairingMessage(int account, long peerUserId, int messageId) {
        requirePeer(peerUserId);
        if (messageId <= 0) {
            throw new IllegalArgumentException("pairing message id must be positive");
        }
        PeerState p = getOrCreatePeer(account, peerUserId);
        if (messageId > p.lastPairingMessageId) {
            p.lastPairingMessageId = messageId;
            persistPeer(account, p);
        }
    }

    public void approvePendingIdentity(int account, long peerUserId) {
        PeerState p = peersCache.get(cacheKey(account, peerUserId));
        if (p == null || p.status != STATUS_IDENTITY_PENDING || p.pendingMessageId <= 0) {
            throw new IllegalStateException("no pending secure identity");
        }
        int pendingMessageId = p.pendingMessageId;
        p.status = STATUS_PAIRED;
        p.pendingCarrier = null;
        p.pendingMessageId = 0;
        p.pendingKind = PendingKind.NONE.value;
        p.lastPairingMessageId = Math.max(pendingMessageId, p.lastPairingMessageId);
        persistPeer(account, p);
    }

    public void rejectPendingIdentity(int account, long peerUserId) {
        if (!isIdentityPending(account, peerUserId)) {
            return;
        }
        pause(account, peerUserId);
    }

    public void resetForNewIdentity() {
        resetForNewIdentity(0);
    }

    public synchronized void resetForNewIdentity(int account) {
        long nextEpoch = getIdentityEpoch(account) + 1;
        peersCache.keySet().removeIf(k -> k.startsWith(account + "."));
        try {
            storage.deleteRoots(STATE_PREFIX + account);
        } catch (Exception e) {
            throw new IllegalStateException("failed to reset secure chat states", e);
        }
        persistEpoch(account, nextEpoch);
    }

    void resetForRecoveredIdentity(long generation) {
        resetForRecoveredIdentity(0, generation);
    }

    synchronized void resetForRecoveredIdentity(int account, long generation) {
        if (generation <= 0) {
            throw new IllegalArgumentException("recovered generation must be positive");
        }
        long epoch = generation - 1;
        peersCache.keySet().removeIf(k -> k.startsWith(account + "."));
        try {
            storage.deleteRoots(STATE_PREFIX + account);
        } catch (Exception e) {
            throw new IllegalStateException("failed to reset recovered secure chat states", e);
        }
        persistEpoch(account, epoch);
    }

    private static void requirePeer(long peerUserId) {
        if (peerUserId == 0) {
            throw new IllegalArgumentException("secure chats require a valid peer");
        }
    }

    private PeerState getOrCreatePeer(int account, long peerUserId) {
        String ck = cacheKey(account, peerUserId);
        PeerState existing = peersCache.get(ck);
        if (existing != null) {
            return existing;
        }
        PeerState created = new PeerState(peerUserId);
        peersCache.put(ck, created);
        return created;
    }

    private String cacheKey(int account, long peerUserId) {
        return account + "." + peerUserId;
    }

    private String storageKey(int account, long peerUserId) {
        String peerMask = SecureNameMask.maskPeer(nameMaskKey, account, peerUserId);
        return STATE_PREFIX + account + "." + peerMask;
    }

    private static int parseAccountFromKey(String key) {
        String sub = key.substring(STATE_PREFIX.length());
        int dot = sub.indexOf('.');
        return Integer.parseInt(sub.substring(0, dot));
    }

    private synchronized void persistPeer(int account, PeerState state) {
        peersCache.put(cacheKey(account, state.peerUserId), state);
        String key = storageKey(account, state.peerUserId);
        try {
            if (state.status == STATUS_NONE && state.lastPairingMessageId == 0
                    && state.lastReadyMessageId == 0 && !state.groupKeyNeedsDist) {
                storage.delete(key);
                peersCache.remove(cacheKey(account, state.peerUserId));
            } else {
                storage.put(key, encodePeerState(state));
            }
        } catch (Exception e) {
            throw new IllegalStateException("failed to persist secure chat state", e);
        }
    }

    private synchronized void persistEpoch(int account, long epoch) {
        epochCache.put(account, epoch);
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            new DataOutputStream(bytes).writeLong(epoch);
            storage.put(EPOCH_PREFIX + account, bytes.toByteArray());
        } catch (Exception e) {
            throw new IllegalStateException("failed to persist identity epoch", e);
        }
    }

    private static byte[] encodePeerState(PeerState state) {
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            DataOutputStream out = new DataOutputStream(bytes);
            out.writeByte(MAGIC);
            out.writeByte(FORMAT_VERSION);
            out.writeLong(state.peerUserId);
            out.writeByte(state.status);
            out.writeInt(state.lastPairingMessageId);
            out.writeInt(state.lastReadyMessageId);
            out.writeBoolean(state.groupKeyNeedsDist);
            out.writeByte(state.pendingKind);
            out.writeInt(state.pendingMessageId);
            out.writeUTF(state.pendingCarrier != null ? state.pendingCarrier : "");
            out.flush();
            return bytes.toByteArray();
        } catch (IOException e) {
            throw new IllegalStateException("cannot encode peer state", e);
        }
    }

    private static PeerState decodePeerState(byte[] data) {
        if (data == null || data.length < 18) {
            return null;
        }
        try {
            DataInputStream in = new DataInputStream(new ByteArrayInputStream(data));
            byte m = in.readByte();
            byte v = in.readByte();
            if (m != MAGIC || v != FORMAT_VERSION) {
                return null;
            }
            long peerUserId = in.readLong();
            PeerState p = new PeerState(peerUserId);
            p.status = in.readByte();
            p.lastPairingMessageId = in.readInt();
            p.lastReadyMessageId = in.readInt();
            p.groupKeyNeedsDist = in.readBoolean();
            p.pendingKind = in.readByte();
            p.pendingMessageId = in.readInt();
            String carrier = in.readUTF();
            p.pendingCarrier = carrier.isEmpty() ? null : carrier;
            return p;
        } catch (IOException e) {
            return null;
        }
    }
}
