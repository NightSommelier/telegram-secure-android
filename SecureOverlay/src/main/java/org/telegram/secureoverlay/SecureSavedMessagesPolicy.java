package org.telegram.secureoverlay;

/** Pure policy boundary for protected Saved Messages; no Telegram or storage access. */
public final class SecureSavedMessagesPolicy {
    public enum Mode {
        PLAIN,
        PROTECTED
    }

    public enum ContentKind {
        TEXT,
        PHOTO,
        VIDEO,
        DOCUMENT,
        AUDIO,
        VOICE,
        ROUND_VIDEO,
        ANIMATION
    }

    private SecureSavedMessagesPolicy() {
    }

    public static Mode defaultMode(boolean secureByDefault) {
        return secureByDefault ? Mode.PROTECTED : Mode.PLAIN;
    }

    public static boolean canForward(Mode source, Mode target) {
        return source == Mode.PLAIN || target == Mode.PROTECTED;
    }

    public static boolean supports(ContentKind kind) {
        return kind != null;
    }
}
