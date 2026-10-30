package org.telegram.secureoverlay;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public final class SecureLinkGuardJvmTest {

    @Test
    public void pathEmbeddedAtSymbolDoesNotSpoofDestinationHost() {
        SecureLinkGuard.Analysis analysis =
                SecureLinkGuard.analyze("https://evil.example/login@paypal.com");

        assertEquals("evil.example", analysis.host);
        assertEquals("evil.example", analysis.unicodeHost);
        assertTrue(analysis.hasUserInfoSpoofing);
        assertTrue(analysis.isSuspicious);
    }

    @Test
    public void backslashInAuthorityIsFlaggedAndDoesNotSpoofHost() {
        SecureLinkGuard.Analysis backslashPath =
                SecureLinkGuard.analyze("https://evil.example\\.paypal.com/login");
        assertEquals("evil.example", backslashPath.host);
        assertTrue(backslashPath.hasUserInfoSpoofing);
        assertTrue(backslashPath.isSuspicious);

        SecureLinkGuard.Analysis backslashAt =
                SecureLinkGuard.analyze("https://paypal.com\\@evil.example/login");
        assertTrue(backslashAt.hasUserInfoSpoofing);
        assertTrue(backslashAt.isSuspicious);
    }

    @Test
    public void percentEncodedUserInfoInAuthorityIsFlagged() {
        SecureLinkGuard.Analysis analysis =
                SecureLinkGuard.analyze("https://paypal.com%40evil.example/login");

        assertTrue(analysis.hasUserInfoSpoofing);
        assertTrue(analysis.isSuspicious);
    }

    @Test
    public void legitimateHandlePathKeepsTrueAuthorityHost() {
        SecureLinkGuard.Analysis analysis =
                SecureLinkGuard.analyze("https://t.me/@durov");

        assertEquals("t.me", analysis.host);
        assertFalse(analysis.hasUserInfoSpoofing);
        assertFalse(analysis.isSuspicious);
    }

    @Test
    public void ipv6LiteralHostWithPortIsPreserved() {
        SecureLinkGuard.Analysis analysis =
                SecureLinkGuard.analyze("http://[2001:db8::1]:8080/health");

        assertEquals("[2001:db8::1]", analysis.host);
        assertFalse(analysis.hasUserInfoSpoofing);
    }

    @Test
    public void mixedCaseHomoglyphHostRebuildsCanonicalAndSafeCopyUrls() {
        // Cyrillic capital Er (\u0420) followed by Latin "aypal.com"
        String url = "https://\u0420aypal.com:8443/Login";
        SecureLinkGuard.Analysis analysis = SecureLinkGuard.analyze(url);

        assertTrue(analysis.isSuspicious);
        assertTrue(analysis.hasConfusableTarget);
        assertEquals("paypal.com", analysis.targetSpoofedDomain);
        assertTrue(analysis.canonicalDisplayUrl.contains("[" + analysis.punycodeHost + "]"));
        assertEquals(
                "https://" + analysis.punycodeHost + ":8443/Login",
                SecureLinkGuard.toSafeCopyUrl(analysis));
    }
}
