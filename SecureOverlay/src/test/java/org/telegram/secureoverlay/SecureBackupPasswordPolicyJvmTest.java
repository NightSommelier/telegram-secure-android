package org.telegram.secureoverlay;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.Collections;
import java.util.UUID;
import org.junit.Test;
import org.signal.libsignal.protocol.IdentityKeyPair;

public final class SecureBackupPasswordPolicyJvmTest {

    @Test
    public void rejectsShortAndTrivialPasswords() {
        assertFalse(SecureIdentityBackupCodec.isStrongPassword(null));
        assertFalse(SecureIdentityBackupCodec.isStrongPassword(new char[0]));
        assertFalse(SecureIdentityBackupCodec.isStrongPassword("short".toCharArray()));
        assertFalse(SecureIdentityBackupCodec.isStrongPassword("11-char-pwd".toCharArray()));
        assertFalse(SecureIdentityBackupCodec.isStrongPassword("aaaaaaaaaaaa".toCharArray()));
        assertFalse(SecureIdentityBackupCodec.isStrongPassword("            ".toCharArray()));

        assertTrue(SecureIdentityBackupCodec.isStrongPassword("StrongPass#1".toCharArray()));
        assertTrue(SecureIdentityBackupCodec.isStrongPassword(
                "correct horse battery staple".toCharArray()));
    }

    @Test
    public void codecsEnforceMinimumTwelveCharStrongPasswordFailClosed() {
        IdentityKeyPair identity = IdentityKeyPair.generate();
        SecureIdentityBackupCodec.Payload identityPayload =
                new SecureIdentityBackupCodec.Payload(
                        UUID.randomUUID(),
                        10001L,
                        1L,
                        1_700_000_000L,
                        1234,
                        identity.serialize());
        SecureHistoryBackupCodec.Payload historyPayload =
                new SecureHistoryBackupCodec.Payload(
                        UUID.randomUUID(),
                        10001L,
                        1L,
                        1_700_000_000L,
                        1234,
                        identity.serialize(),
                        Collections.emptyList(),
                        Collections.emptyList());

        try {
            SecureIdentityBackupCodec.encrypt(identityPayload, "five5".toCharArray());
            fail("Expected 5-character password to be rejected by identity backup codec");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("12"));
        }

        try {
            SecureHistoryBackupCodec.encrypt(historyPayload, "eleven-char".toCharArray());
            fail("Expected 11-character password to be rejected by history backup codec");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("12"));
        }

        assertEquals(12, SecureIdentityBackupCodec.MIN_PASSWORD_CHARS);
        assertEquals(12, SecureHistoryBackupCodec.MIN_PASSWORD_CHARS);
    }
}
