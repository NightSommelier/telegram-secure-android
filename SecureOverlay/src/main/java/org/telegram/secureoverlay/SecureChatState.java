package org.telegram.secureoverlay;

import android.content.Context;
import android.content.SharedPreferences;

/** Per-account, per-peer secure-mode gate. No message is encrypted unless paired. */
public final class SecureChatState {
    private static final String PREFS = "telegram_secure_chat_state_v1";
    private static final String PAIRED_PREFIX = "paired.";
    private static final String WAITING_PREFIX = "waiting.";
    private static final String PAUSED_PREFIX = "paused.";
    private static final String IDENTITY_PENDING_PREFIX = "identity-pending.";
    private static final String PENDING_CARRIER_PREFIX = "pending-carrier.";
    private static final String PENDING_MESSAGE_PREFIX = "pending-message.";
    private static final String LAST_PAIRING_MESSAGE_PREFIX = "last-pairing-message.";
    private static final String IDENTITY_EPOCH = "identity-epoch";
    private final SharedPreferences preferences;

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

    public int getLastPairingMessageId(int account, long peerUserId) {
        return preferences.getInt(key(LAST_PAIRING_MESSAGE_PREFIX, account, peerUserId), 0);
    }

    public long getIdentityEpoch() {
        return preferences.getLong(IDENTITY_EPOCH, 0);
    }

    public void markWaiting(int account, long peerUserId) {
        requirePeer(peerUserId);
        if (!preferences.edit()
                .remove(key(PAIRED_PREFIX, account, peerUserId))
                .remove(key(PAUSED_PREFIX, account, peerUserId))
                .remove(key(IDENTITY_PENDING_PREFIX, account, peerUserId))
                .remove(key(PENDING_CARRIER_PREFIX, account, peerUserId))
                .remove(key(PENDING_MESSAGE_PREFIX, account, peerUserId))
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
                .putBoolean(key(PAUSED_PREFIX, account, peerUserId), true)
                .commit()) {
            throw new IllegalStateException("failed to disable secure chat state");
        }
    }

    public void markIdentityPending(int account, long peerUserId, String carrier, int messageId) {
        requirePeer(peerUserId);
        if (carrier == null || carrier.isEmpty() || messageId <= 0) {
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

    private static void requirePeer(long peerUserId) {
        if (peerUserId <= 0) {
            throw new IllegalArgumentException("secure chats require a user peer");
        }
    }

    private static String key(String prefix, int account, long peerUserId) {
        return prefix + account + '.' + peerUserId;
    }
}
