package org.telegram.secureoverlay;

import android.content.Context;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Singleton lifecycle and session manager for {@link SecureChatEngine} instances per Telegram account.
 *
 * <p>Centralizes engine lifecycle management, thread-safe session caching, one-time recovery and
 * identity initialization, and feature flag enforcement (disabling unverified group encryption by default per SA-19).</p>
 */
public final class SecureSessionManager {

    /** Group encryption feature flag (disabled by default per SA-19). */
    public static volatile boolean GROUPS_ENABLED = false;

    private static final Map<Integer, SecureSessionManager> managers = new ConcurrentHashMap<>();

    private final Context appContext;
    private final int account;
    private final ConcurrentHashMap<Long, SecureChatEngine> engineCache = new ConcurrentHashMap<>();
    private final AtomicBoolean initialized = new AtomicBoolean(false);

    private SecureSessionManager(Context context, int account) {
        if (account < 0) {
            throw new IllegalArgumentException("invalid account: " + account);
        }
        Context app = context != null ? context.getApplicationContext() : null;
        this.appContext = app != null ? app : context;
        this.account = account;
    }

    public static SecureSessionManager getInstance(Context context, int account) {
        return managers.computeIfAbsent(account, a -> new SecureSessionManager(context, a));
    }

    public static SecureChatEngine getEngine(Context context, int account, long peerUserId) {
        return getInstance(context, account).getEngineForPeer(peerUserId);
    }

    /**
     * Initializes durable identity and checks for interrupted recovery procedures once per account.
     */
    public void ensureInitialized() {
        if (initialized.get()) {
            return;
        }
        synchronized (this) {
            if (initialized.get()) {
                return;
            }
            if (appContext != null) {
                SecureHistoryBackupManager.resumeInterruptedRestore(appContext);
                SecureIdentityBackupManager.resumeInterruptedImport(appContext);
                SecureChatState state = new SecureChatState(appContext);
                SecureRecoveryGenerationStore recoveryStore =
                        new SecureRecoveryGenerationStore(appContext, account);
                recoveryStore.ensureLocalIdentity(
                        SecureChatEngine.generationForEpoch(state.getIdentityEpoch(account)));
            }
            initialized.set(true);
        }
    }

    public SecureChatEngine getEngineForPeer(long peerUserId) {
        if (peerUserId == 0) {
            throw new IllegalArgumentException("valid peerUserId is required");
        }
        if (peerUserId < 0 && !GROUPS_ENABLED) {
            throw new SecureChatEngine.SecureChatException("secure groups are disabled", null);
        }
        ensureInitialized();
        return engineCache.computeIfAbsent(peerUserId,
                id -> new SecureChatEngine(appContext, account, id));
    }

    public void clear() {
        engineCache.clear();
    }

    public static void resetAll() {
        for (SecureSessionManager manager : managers.values()) {
            manager.clear();
        }
        managers.clear();
    }
}
