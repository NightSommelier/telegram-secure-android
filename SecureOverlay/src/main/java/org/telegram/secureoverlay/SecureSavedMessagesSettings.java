package org.telegram.secureoverlay;

import android.content.Context;
import android.content.SharedPreferences;

/** Account-scoped default for the optional protected Saved Messages mode. */
public final class SecureSavedMessagesSettings {
    private static final String PREFERENCES = "fork_secure_saved_messages";
    private static final String SECURE_DEFAULT_PREFIX = "secure_default.";

    private SecureSavedMessagesSettings() {
    }

    public static boolean isSecureByDefault(Context context, int account) {
        requireAccount(account);
        return preferences(context).getBoolean(SECURE_DEFAULT_PREFIX + account, false);
    }

    public static void setSecureByDefault(Context context, int account, boolean enabled) {
        requireAccount(account);
        if (!preferences(context).edit()
                .putBoolean(SECURE_DEFAULT_PREFIX + account, enabled)
                .commit()) {
            throw new IllegalStateException("cannot persist Saved Messages security setting");
        }
    }

    static void clearForTests(Context context) {
        if (!preferences(context).edit().clear().commit()) {
            throw new IllegalStateException("cannot clear Saved Messages security settings");
        }
    }

    private static SharedPreferences preferences(Context context) {
        if (context == null) {
            throw new IllegalArgumentException("context is required");
        }
        return context.getApplicationContext().getSharedPreferences(
                PREFERENCES, Context.MODE_PRIVATE);
    }

    private static void requireAccount(int account) {
        if (account < 0) {
            throw new IllegalArgumentException("account must be non-negative");
        }
    }
}
