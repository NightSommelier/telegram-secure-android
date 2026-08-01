package org.telegram.secureoverlay;

import android.content.Context;
import android.content.SharedPreferences;

/** Local content-display policy for Fork-Secure. */
public final class SecureContentSettings {
    private static final String PREFERENCES = "fork_secure_content_settings";
    private static final String SCREEN_PROTECTION = "screen_protection";

    private SecureContentSettings() {
    }

    public static boolean isScreenProtectionEnabled(Context context) {
        return preferences(context).getBoolean(SCREEN_PROTECTION, true);
    }

    public static void setScreenProtectionEnabled(Context context, boolean enabled) {
        if (!preferences(context).edit().putBoolean(SCREEN_PROTECTION, enabled).commit()) {
            throw new IllegalStateException("cannot persist secure screen protection setting");
        }
    }

    static void clearForTests(Context context) {
        if (!preferences(context).edit().clear().commit()) {
            throw new IllegalStateException("cannot clear secure content settings");
        }
    }

    private static SharedPreferences preferences(Context context) {
        if (context == null) {
            throw new IllegalArgumentException("context is required");
        }
        return context.getApplicationContext().getSharedPreferences(
                PREFERENCES, Context.MODE_PRIVATE);
    }
}
