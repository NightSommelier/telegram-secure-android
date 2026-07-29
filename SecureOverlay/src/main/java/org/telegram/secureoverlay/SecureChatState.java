package org.telegram.secureoverlay;

import android.content.Context;
import android.content.SharedPreferences;
import java.util.Map;

/** Per-account, per-peer secure-mode gate. No message is encrypted unless paired. */
public final class SecureChatState {
    private static final String PREFS = "telegram_secure_chat_state_v1";
    private static final String PAIRED_PREFIX = "paired.";
    private static final String WAITING_PREFIX = "waiting.";
    private static final String PAUSED_PREFIX = "paused.";
    private static final String IDENTITY_PENDING_PREFIX = "identity-pending.";
    private static final String PENDING_CARRIER_PREFIX = "pending-carrier.";
    private static final String PENDING_MESSAGE_PREFIX = "pending-message.";
    private static final String PENDING_KIND_PREFIX = "pending-kind.";
    private static final String LAST_PAIRING_MESSAGE_PREFIX = "last-pairing-message.";
    private static final String IDENTITY_EPOCH = "identity-epoch";
    private final SharedPreferences preferences;

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
        RECOVERY_ADVANCE(2);

        final int value;

        PendingKind(int value) {
            this.value = value;
        }
    }

    public SecureChatState(Context context) {
        preferences = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    public boolean isPaired(int account, long peerUserId) {
        return peerUserId > 0 && preferences.getBoolean(key(PAIRED_PREFIX, account, peerUserId), false);
    }

    public boolean isWaiting(int account, long peerUserId) {
        return peerUserId > 0 && preferences.getBoolean(key(WAITING_PREFIX, account, peerUserId), false);
    }

    public boolean isPaused(int account, long peerUserId) {
        return peerUserId > 0 && preferences.getBoolean(key(PAUSED_PREFIX, account, peerUserId), false);
    }

    public boolean isIdentityPending(int account, long peerUserId) {
        return peerUserId > 0
                && preferences.getBoolean(key(IDENTITY_PENDING_PREFIX, account, peerUserId), false);
    }

    public String getPendingCarrier(int account, long peerUserId) {
        return preferences.getString(key(PENDING_CARRIER_PREFIX, account, peerUserId), null);
    }

    public int getPendingMessageId(int account, long peerUserId) {
        return preferences.getInt(key(PENDING_MESSAGE_PREFIX, account, peerUserId), 0);
    }

    public PendingKind getPendingKind(int account, long peerUserId) {
        int value = preferences.getInt(key(PENDING_KIND_PREFIX, account, peerUserId), 0);
        for (PendingKind kind : PendingKind.values()) {
            if (kind.value == value) {
                return kind;
            }
        }
        throw new IllegalStateException("invalid pending secure identity kind");
    }

    public int getLastPairingMessageId(int account, long peerUserId) {
        return preferences.getInt(key(LAST_PAIRING_MESSAGE_PREFIX, account, peerUserId), 0);
    }

    public long getIdentityEpoch() {
        return preferences.getLong(IDENTITY_EPOCH, 0);
    }

    public boolean hasAnySecureConversationState() {
        for (String name : preferences.getAll().keySet()) {
            if (!IDENTITY_EPOCH.equals(name)) {
                return true;
            }
        }
        return false;
    }

    public Summary getSummary(int account) {
        if (account < 0) {
            throw new IllegalArgumentException("account must not be negative");
        }
        String accountSuffix = account + ".";
        int paired = countBooleanKeys(PAIRED_PREFIX + accountSuffix);
        int waiting = countBooleanKeys(WAITING_PREFIX + accountSuffix);
        int paused = countBooleanKeys(PAUSED_PREFIX + accountSuffix);
        int identityPending = countBooleanKeys(IDENTITY_PENDING_PREFIX + accountSuffix);
        return new Summary(paired, waiting, paused, identityPending);
    }

    public void markWaiting(int account, long peerUserId) {
        requirePeer(peerUserId);
        if (!preferences.edit()
                .remove(key(PAIRED_PREFIX, account, peerUserId))
                .remove(key(PAUSED_PREFIX, account, peerUserId))
                .remove(key(IDENTITY_PENDING_PREFIX, account, peerUserId))
                .remove(key(PENDING_CARRIER_PREFIX, account, peerUserId))
                .remove(key(PENDING_MESSAGE_PREFIX, account, peerUserId))
                .remove(key(PENDING_KIND_PREFIX, account, peerUserId))
                .putBoolean(key(WAITING_PREFIX, account, peerUserId), true)
                .commit()) {
            throw new IllegalStateException("failed to persist secure pairing state");
        }
    }

    public void markPaired(int account, long peerUserId) {
        requirePeer(peerUserId);
        if (!preferences.edit()
                .remove(key(WAITING_PREFIX, account, peerUserId))
                .remove(key(PAUSED_PREFIX, account, peerUserId))
                .remove(key(IDENTITY_PENDING_PREFIX, account, peerUserId))
                .remove(key(PENDING_CARRIER_PREFIX, account, peerUserId))
                .remove(key(PENDING_MESSAGE_PREFIX, account, peerUserId))
                .remove(key(PENDING_KIND_PREFIX, account, peerUserId))
                .putBoolean(key(PAIRED_PREFIX, account, peerUserId), true)
                .commit()) {
            throw new IllegalStateException("failed to persist secure chat state");
        }
    }

    public void pause(int account, long peerUserId) {
        requirePeer(peerUserId);
        if (!preferences.edit()
                .remove(key(PAIRED_PREFIX, account, peerUserId))
                .remove(key(WAITING_PREFIX, account, peerUserId))
                .remove(key(IDENTITY_PENDING_PREFIX, account, peerUserId))
                .remove(key(PENDING_CARRIER_PREFIX, account, peerUserId))
                .remove(key(PENDING_MESSAGE_PREFIX, account, peerUserId))
                .remove(key(PENDING_KIND_PREFIX, account, peerUserId))
                .putBoolean(key(PAUSED_PREFIX, account, peerUserId), true)
                .commit()) {
            throw new IllegalStateException("failed to disable secure chat state");
        }
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
        int lastMessageId = Math.max(messageId, getLastPairingMessageId(account, peerUserId));
        if (!preferences.edit()
                .remove(key(PAIRED_PREFIX, account, peerUserId))
                .remove(key(WAITING_PREFIX, account, peerUserId))
                .remove(key(PAUSED_PREFIX, account, peerUserId))
                .putBoolean(key(IDENTITY_PENDING_PREFIX, account, peerUserId), true)
                .putString(key(PENDING_CARRIER_PREFIX, account, peerUserId), carrier)
                .putInt(key(PENDING_MESSAGE_PREFIX, account, peerUserId), messageId)
                .putInt(key(PENDING_KIND_PREFIX, account, peerUserId), kind.value)
                .putInt(key(LAST_PAIRING_MESSAGE_PREFIX, account, peerUserId), lastMessageId)
                .commit()) {
            throw new IllegalStateException("failed to persist pending secure identity");
        }
    }

    public void recordPairingMessage(int account, long peerUserId, int messageId) {
        requirePeer(peerUserId);
        if (messageId <= 0) {
            throw new IllegalArgumentException("pairing message id must be positive");
        }
        int current = getLastPairingMessageId(account, peerUserId);
        if (messageId > current && !preferences.edit()
                .putInt(key(LAST_PAIRING_MESSAGE_PREFIX, account, peerUserId), messageId)
                .commit()) {
            throw new IllegalStateException("failed to persist pairing replay boundary");
        }
    }

    public void approvePendingIdentity(int account, long peerUserId) {
        int pendingMessageId = getPendingMessageId(account, peerUserId);
        if (!isIdentityPending(account, peerUserId) || pendingMessageId <= 0) {
            throw new IllegalStateException("no pending secure identity");
        }
        if (!preferences.edit()
                .remove(key(WAITING_PREFIX, account, peerUserId))
                .remove(key(PAUSED_PREFIX, account, peerUserId))
                .remove(key(IDENTITY_PENDING_PREFIX, account, peerUserId))
                .remove(key(PENDING_CARRIER_PREFIX, account, peerUserId))
                .remove(key(PENDING_MESSAGE_PREFIX, account, peerUserId))
                .remove(key(PENDING_KIND_PREFIX, account, peerUserId))
                .putBoolean(key(PAIRED_PREFIX, account, peerUserId), true)
                .putInt(key(LAST_PAIRING_MESSAGE_PREFIX, account, peerUserId),
                        Math.max(pendingMessageId, getLastPairingMessageId(account, peerUserId)))
                .commit()) {
            throw new IllegalStateException("failed to approve secure identity");
        }
    }

    public void rejectPendingIdentity(int account, long peerUserId) {
        if (!isIdentityPending(account, peerUserId)) {
            return;
        }
        pause(account, peerUserId);
    }

    public void resetForNewIdentity() {
        long nextEpoch = getIdentityEpoch() + 1;
        if (!preferences.edit().clear().putLong(IDENTITY_EPOCH, nextEpoch).commit()) {
            throw new IllegalStateException("failed to reset secure chat states");
        }
    }

    void resetForRecoveredIdentity(long generation) {
        if (generation <= 0) {
            throw new IllegalArgumentException("recovered generation must be positive");
        }
        long epoch = generation - 1;
        if (!preferences.edit().clear().putLong(IDENTITY_EPOCH, epoch).commit()) {
            throw new IllegalStateException("failed to reset recovered secure chat states");
        }
    }

    private static void requirePeer(long peerUserId) {
        if (peerUserId <= 0) {
            throw new IllegalArgumentException("secure chats require a user peer");
        }
    }

    private int countBooleanKeys(String prefix) {
        int count = 0;
        for (Map.Entry<String, ?> entry : preferences.getAll().entrySet()) {
            if (entry.getKey().startsWith(prefix) && Boolean.TRUE.equals(entry.getValue())) {
                count++;
            }
        }
        return count;
    }

    private static String key(String prefix, int account, long peerUserId) {
        return prefix + account + '.' + peerUserId;
    }
}
