package org.telegram.secureoverlay;

import java.net.IDN;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Direct, non-reflective link security analyzer for Fork-Secure chats.
 *
 * <p>Protects against:
 * <ul>
 *   <li>IDN homoglyph spoofing and mixed-script labels</li>
 *   <li>Punycode obfuscation targeting high-value domains</li>
 *   <li>Invisible, zero-width, and bidirectional override characters</li>
 *   <li>User-info authority spoofing (embedded credentials before @)</li>
 *   <li>Obfuscated hex/octal/dword IP address representations</li>
 * </ul>
 */
public final class SecureLinkGuard {

    private static final Pattern USER_INFO_PATTERN = Pattern.compile(
            "^[a-zA-Z][a-zA-Z0-9+.-]*://[^/@?#]+@[^/?#]+.*");

    private static final Pattern IP_V4_PATTERN = Pattern.compile(
            "^(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})$");

    private static final Pattern OBFUSCATED_IP_PATTERN = Pattern.compile(
            "^(?:0x[0-9a-fA-F]+|0[0-7]+|\\d+)(?:\\.(?:0x[0-9a-fA-F]+|0[0-7]+|\\d+)){0,3}$");

    private static final Set<String> HIGH_VALUE_DOMAINS = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
            "telegram.org",
            "telegram.me",
            "t.me",
            "google.com",
            "apple.com",
            "paypal.com",
            "github.com",
            "microsoft.com",
            "amazon.com",
            "twitter.com",
            "x.com",
            "facebook.com",
            "instagram.com",
            "signal.org",
            "whatsapp.com",
            "binance.com",
            "coinbase.com"
    )));

    public static final class Analysis {
        public final String originalUrl;
        public final String host;
        public final String unicodeHost;
        public final String punycodeHost;
        public final String canonicalDisplayUrl;
        public final boolean isSuspicious;
        public final boolean hasPunycode;
        public final boolean hasMixedScripts;
        public final boolean hasInvisibleChars;
        public final boolean hasUserInfoSpoofing;
        public final boolean hasConfusableTarget;
        public final boolean isObfuscatedIp;
        public final String targetSpoofedDomain;
        public final String warningReason;

        public Analysis(
                String originalUrl,
                String host,
                String unicodeHost,
                String punycodeHost,
                String canonicalDisplayUrl,
                boolean isSuspicious,
                boolean hasPunycode,
                boolean hasMixedScripts,
                boolean hasInvisibleChars,
                boolean hasUserInfoSpoofing,
                boolean hasConfusableTarget,
                boolean isObfuscatedIp,
                String targetSpoofedDomain,
                String warningReason) {
            this.originalUrl = originalUrl;
            this.host = host;
            this.unicodeHost = unicodeHost;
            this.punycodeHost = punycodeHost;
            this.canonicalDisplayUrl = canonicalDisplayUrl;
            this.isSuspicious = isSuspicious;
            this.hasPunycode = hasPunycode;
            this.hasMixedScripts = hasMixedScripts;
            this.hasInvisibleChars = hasInvisibleChars;
            this.hasUserInfoSpoofing = hasUserInfoSpoofing;
            this.hasConfusableTarget = hasConfusableTarget;
            this.isObfuscatedIp = isObfuscatedIp;
            this.targetSpoofedDomain = targetSpoofedDomain;
            this.warningReason = warningReason;
        }

        @Override
        public String toString() {
            return "Analysis{" +
                    "host='" + host + '\'' +
                    ", isSuspicious=" + isSuspicious +
                    ", hasPunycode=" + hasPunycode +
                    ", hasMixedScripts=" + hasMixedScripts +
                    ", hasInvisibleChars=" + hasInvisibleChars +
                    ", hasUserInfoSpoofing=" + hasUserInfoSpoofing +
                    ", hasConfusableTarget=" + hasConfusableTarget +
                    ", targetSpoofedDomain='" + targetSpoofedDomain + '\'' +
                    '}';
        }
    }

    private SecureLinkGuard() {
    }

    /**
     * Fast non-reflective boolean check whether a URL has suspicious spoofing characteristics.
     */
    public static boolean isSuspicious(String url) {
        return analyze(url).isSuspicious;
    }

    /**
     * Fully analyzes the given URL for spoofing, homoglyphs, and obfuscation.
     */
    public static Analysis analyze(String url) {
        if (url == null || url.trim().isEmpty()) {
            return new Analysis("", "", "", "", "", false, false, false, false, false, false, false, null, null);
        }

        final String cleanUrl = url.trim();
        final boolean hasInvisibleChars = containsInvisibleOrControlChars(cleanUrl);
        final boolean hasUserInfoSpoofing = USER_INFO_PATTERN.matcher(cleanUrl).matches();

        String rawHost = "";
        String temp = cleanUrl;
        int schemeIdx = temp.indexOf("://");
        if (schemeIdx != -1) {
            temp = temp.substring(schemeIdx + 3);
        }
        int atIdx = temp.indexOf('@');
        if (atIdx != -1) {
            temp = temp.substring(atIdx + 1);
        }
        int slashIdx = temp.indexOf('/');
        if (slashIdx != -1) {
            temp = temp.substring(0, slashIdx);
        }
        int questionIdx = temp.indexOf('?');
        if (questionIdx != -1) {
            temp = temp.substring(0, questionIdx);
        }
        int hashIdx = temp.indexOf('#');
        if (hashIdx != -1) {
            temp = temp.substring(0, hashIdx);
        }
        int colonIdx = temp.indexOf(':');
        if (colonIdx != -1) {
            temp = temp.substring(0, colonIdx);
        }
        rawHost = temp;

        if (rawHost != null) {
            rawHost = rawHost.toLowerCase(Locale.US).trim();
            while (rawHost.endsWith(".")) {
                rawHost = rawHost.substring(0, rawHost.length() - 1);
            }
        } else {
            rawHost = "";
        }

        String unicodeHost = "";
        String punycodeHost = "";
        try {
            unicodeHost = IDN.toUnicode(rawHost);
        } catch (Exception e) {
            unicodeHost = rawHost;
        }

        try {
            punycodeHost = IDN.toASCII(unicodeHost);
        } catch (Exception e) {
            punycodeHost = rawHost;
        }

        final boolean hasPunycode = punycodeHost.contains("xn--") || rawHost.contains("xn--");
        final boolean hasMixedScripts = hasMixedScriptLabel(unicodeHost);

        String targetSpoofedDomain = null;
        boolean hasConfusableTarget = false;
        String skeleton = toConfusableSkeleton(unicodeHost);
        for (String target : HIGH_VALUE_DOMAINS) {
            if (skeleton.equals(target) && !unicodeHost.equals(target) && !punycodeHost.equals(target)) {
                hasConfusableTarget = true;
                targetSpoofedDomain = target;
                break;
            }
        }

        boolean isObfuscatedIp = false;
        if (!rawHost.isEmpty()) {
            Matcher ipv4Matcher = IP_V4_PATTERN.matcher(rawHost);
            if (ipv4Matcher.matches()) {
                isObfuscatedIp = false;
            } else if (OBFUSCATED_IP_PATTERN.matcher(rawHost).matches()) {
                isObfuscatedIp = true;
            }
        }

        boolean isSuspicious = hasUserInfoSpoofing
                || hasInvisibleChars
                || hasMixedScripts
                || hasConfusableTarget
                || isObfuscatedIp
                || hasPunycode;

        StringBuilder warningBuilder = new StringBuilder();
        if (hasUserInfoSpoofing) {
            warningBuilder.append("User info credential spoofing (@ in authority). ");
        }
        if (hasInvisibleChars) {
            warningBuilder.append("Invisible or formatting control characters detected. ");
        }
        if (hasConfusableTarget) {
            warningBuilder.append("Visual homoglyph spoofing targeting '")
                    .append(targetSpoofedDomain)
                    .append("'. ");
        } else if (hasMixedScripts) {
            warningBuilder.append("Mixed Latin and non-Latin character sets in domain. ");
        }
        if (isObfuscatedIp) {
            warningBuilder.append("Obfuscated or numerical IP address. ");
        }
        if (hasPunycode && !hasConfusableTarget && !hasMixedScripts) {
            warningBuilder.append("Internationalized Punycode domain (")
                    .append(punycodeHost)
                    .append("). ");
        }

        String warningReason = warningBuilder.length() > 0 ? warningBuilder.toString().trim() : null;

        String canonicalDisplayUrl;
        if (hasPunycode && !unicodeHost.equalsIgnoreCase(punycodeHost)) {
            canonicalDisplayUrl = cleanUrl.replace(rawHost, unicodeHost + " [" + punycodeHost + "]");
        } else {
            canonicalDisplayUrl = cleanUrl;
        }

        return new Analysis(
                cleanUrl,
                rawHost,
                unicodeHost,
                punycodeHost,
                canonicalDisplayUrl,
                isSuspicious,
                hasPunycode,
                hasMixedScripts,
                hasInvisibleChars,
                hasUserInfoSpoofing,
                hasConfusableTarget,
                isObfuscatedIp,
                targetSpoofedDomain,
                warningReason
        );
    }

    /**
     * Checks if a string contains invisible, zero-width, bidirectional override, or control chars.
     */
    public static boolean containsInvisibleOrControlChars(String str) {
        if (str == null) return false;
        for (int i = 0; i < str.length(); i++) {
            char c = str.charAt(i);
            // Zero-width & joiners & soft hyphen
            if (c == '\u200B' || c == '\u200C' || c == '\u200D' || c == '\u2060' || c == '\uFEFF' || c == '\u00AD') {
                return true;
            }
            // BiDi direction & overrides
            if (c == '\u200E' || c == '\u200F' || (c >= '\u202A' && c <= '\u202E') || (c >= '\u2066' && c <= '\u2069')) {
                return true;
            }
            // C0 and C1 control characters (excluding newline/tab/carriage return if present in body)
            if ((c < 0x20 && c != '\t' && c != '\r' && c != '\n') || (c >= 0x7F && c <= 0x9F)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Checks if any label of the host mixes Latin letters with non-Latin letters.
     */
    public static boolean hasMixedScriptLabel(String host) {
        if (host == null || host.isEmpty()) return false;
        String[] labels = host.split("\\.");
        for (String label : labels) {
            boolean hasLatin = false;
            boolean hasNonLatinLetter = false;
            for (int i = 0; i < label.length(); i++) {
                char c = label.charAt(i);
                if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
                    hasLatin = true;
                } else if (Character.isLetter(c)) {
                    hasNonLatinLetter = true;
                }
            }
            if (hasLatin && hasNonLatinLetter) {
                return true;
            }
        }
        return false;
    }

    /**
     * Maps visually confusable Cyrillic, Greek, and fullwidth glyphs to Latin equivalents.
     */
    public static String toConfusableSkeleton(String str) {
        if (str == null) return "";
        StringBuilder sb = new StringBuilder(str.length());
        for (int i = 0; i < str.length(); i++) {
            char c = str.charAt(i);
            sb.append(mapConfusableChar(c));
        }
        return sb.toString().toLowerCase(Locale.US);
    }

    private static char mapConfusableChar(char c) {
        // Cyrillic lookalikes
        switch (c) {
            case '\u0430': case '\u0410': return 'a'; // Cyrillic a
            case '\u0441': case '\u0421': return 'c'; // Cyrillic es
            case '\u0435': case '\u0415': case '\u0451': case '\u0401': return 'e'; // Cyrillic ie / io
            case '\u0456': case '\u0406': case '\u0457': case '\u0407': return 'i'; // Cyrillic i / yi
            case '\u0458': case '\u0408': return 'j'; // Cyrillic je
            case '\u043E': case '\u041E': return 'o'; // Cyrillic o
            case '\u0440': case '\u0420': return 'p'; // Cyrillic er
            case '\u0455': case '\u0405': return 's'; // Cyrillic dze
            case '\u0443': case '\u0423': return 'y'; // Cyrillic u
            case '\u0445': case '\u0425': return 'x'; // Cyrillic ha
            case '\u0501': case '\u0500': return 'd'; // Cyrillic komi de
            case '\u051B': case '\u051A': return 'q'; // Cyrillic qa
            case '\u051D': case '\u051C': return 'w'; // Cyrillic we
            case '\u04BB': case '\u04BA': return 'h'; // Cyrillic shha

            // Greek lookalikes
            case '\u03B1': case '\u0391': return 'a'; // Alpha
            case '\u03B2': case '\u0392': return 'b'; // Beta
            case '\u03B5': case '\u0395': return 'e'; // Epsilon
            case '\u03B9': case '\u0399': return 'i'; // Iota
            case '\u03BA': case '\u039A': return 'k'; // Kappa
            case '\u03BF': case '\u039F': return 'o'; // Omicron
            case '\u03C1': case '\u03A1': return 'p'; // Rho
            case '\u03C4': case '\u03A4': return 't'; // Tau
            case '\u03C5': case '\u03A5': return 'u'; // Upsilon
            case '\u03BD': case '\u039D': return 'v'; // Nu
            case '\u03C7': case '\u03A7': return 'x'; // Chi

            default:
                // Fullwidth Latin characters \uFF21-\uFF3A (A-Z) and \uFF41-\uFF5A (a-z)
                if (c >= '\uFF21' && c <= '\uFF3A') {
                    return (char) ('a' + (c - '\uFF21'));
                }
                if (c >= '\uFF41' && c <= '\uFF5A') {
                    return (char) ('a' + (c - '\uFF41'));
                }
                return Character.toLowerCase(c);
        }
    }
}
