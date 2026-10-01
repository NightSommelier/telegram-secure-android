package org.telegram.secureoverlay;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
public final class SecureLinkGuardTest {

    @Test
    public void allowsLegitimateUrl() {
        SecureLinkGuard.Analysis analysis = SecureLinkGuard.analyze("https://telegram.org/blog");
        assertFalse(analysis.isSuspicious);
        assertFalse(analysis.hasPunycode);
        assertFalse(analysis.hasMixedScripts);
        assertFalse(analysis.hasInvisibleChars);
        assertFalse(analysis.hasUserInfoSpoofing);
        assertFalse(analysis.hasConfusableTarget);
        assertEquals("telegram.org", analysis.host);
        assertEquals("telegram.org", analysis.unicodeHost);
    }

    @Test
    public void detectsMixedScriptHomoglyphTargetingTelegram() {
        // 'е' (\u0435) and 'а' (\u0430) are Cyrillic lookalikes
        String spoofedUrl = "https://t\u0435l\u0435gr\u0430m.org/security";
        SecureLinkGuard.Analysis analysis = SecureLinkGuard.analyze(spoofedUrl);

        assertTrue(analysis.isSuspicious);
        assertTrue(analysis.hasMixedScripts);
        assertTrue(analysis.hasConfusableTarget);
        assertEquals("telegram.org", analysis.targetSpoofedDomain);
        assertNotNull(analysis.warningReason);
    }

    @Test
    public void detectsUserInfoSpoofingInUrlAuthority() {
        String spoofedUrl = "https://telegram.org:admin@phishing.site/account";
        SecureLinkGuard.Analysis analysis = SecureLinkGuard.analyze(spoofedUrl);

        assertTrue(analysis.isSuspicious);
        assertTrue(analysis.hasUserInfoSpoofing);
        assertNotNull(analysis.warningReason);
    }

    @Test
    public void detectsInvisibleAndBidiOverrideCharacters() {
        String invisibleZeroWidth = "https://safe-site.org/index\u200B.html";
        SecureLinkGuard.Analysis analysis1 = SecureLinkGuard.analyze(invisibleZeroWidth);
        assertTrue(analysis1.isSuspicious);
        assertTrue(analysis1.hasInvisibleChars);

        String bidiOverride = "https://site.com/docs/\u202Ereversed";
        SecureLinkGuard.Analysis analysis2 = SecureLinkGuard.analyze(bidiOverride);
        assertTrue(analysis2.isSuspicious);
        assertTrue(analysis2.hasInvisibleChars);
    }

    @Test
    public void detectsPunycodeDomains() {
        String unicodeTarget = "t\u0435l\u0435gr\u0430m.org";
        String punycode = java.net.IDN.toASCII(unicodeTarget);
        String punycodeUrl = "https://" + punycode + "/update";
        SecureLinkGuard.Analysis analysis = SecureLinkGuard.analyze(punycodeUrl);

        assertTrue(analysis.isSuspicious);
        assertTrue(analysis.hasPunycode);
        // It resolves to tеlеgrаm.org which targets telegram.org
        assertTrue(analysis.hasConfusableTarget);
        assertEquals("telegram.org", analysis.targetSpoofedDomain);
    }

    @Test
    public void detectsObfuscatedHexOrDecimalIp() {
        String dwordIp = "http://2130706433/";
        SecureLinkGuard.Analysis analysis = SecureLinkGuard.analyze(dwordIp);
        assertTrue(analysis.isSuspicious);
        assertTrue(analysis.isObfuscatedIp);

        String legitimateIp = "http://192.168.1.1/setup";
        SecureLinkGuard.Analysis analysisLegit = SecureLinkGuard.analyze(legitimateIp);
        assertFalse(analysisLegit.isObfuscatedIp);
    }

    @Test
    public void handlesNullOrMalformedGracefully() {
        SecureLinkGuard.Analysis nullAnalysis = SecureLinkGuard.analyze(null);
        assertFalse(nullAnalysis.isSuspicious);

        SecureLinkGuard.Analysis emptyAnalysis = SecureLinkGuard.analyze("   ");
        assertFalse(emptyAnalysis.isSuspicious);

        assertFalse(SecureLinkGuard.isSuspicious(null));
        assertFalse(SecureLinkGuard.isSuspicious(""));
    }
}
