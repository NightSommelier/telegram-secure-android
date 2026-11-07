package org.telegram.secureoverlay;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.Collections;
import java.util.UUID;
import org.junit.Test;
import org.signal.libsignal.protocol.IdentityKeyPair;

public final class SecureBackupSecretJvmTest {
    @Test
    public void identityBackupRejectsEmptyPasswordAndNoPasswordHeaderFlag() {
        IdentityKeyPair identity = IdentityKeyPair.generate();
        SecureIdentityBackupCodec.Payload payload = new SecureIdentityBackupCodec.Payload(
                UUID.fromString("00112233-4455-6677-8899-aabbccddeeff"),
                123456789L,
                3L,
                1_700_000_000L,
                4096,
                identity.serialize());

        try {
            SecureIdentityBackupCodec.encrypt(payload, new char[0]);
            fail("Identity backup encrypt must reject empty password");
        } catch (IllegalArgumentException expected) {
            assertEquals("identity backup password is required", expected.getMessage());
        }

        try {
            SecureIdentityBackupCodec.encrypt(payload, null);
            fail("Identity backup encrypt must reject null password");
        } catch (IllegalArgumentException expected) {
            assertEquals("identity backup password is required", expected.getMessage());
        }

        char[] password = "strong-backup-secret".toCharArray();
        byte[] archive = SecureIdentityBackupCodec.encrypt(payload, password);
        assertTrue(SecureIdentityBackupCodec.requiresPassword(archive));
        SecureIdentityBackupCodec.Payload decoded =
                SecureIdentityBackupCodec.decrypt(archive, password);
        assertArrayEquals(payload.serializedIdentity, decoded.serializedIdentity);

        byte[] flaggedNoPassword = archive.clone();
        flaggedNoPassword[9] = 1;
        try {
            SecureIdentityBackupCodec.decrypt(flaggedNoPassword, password);
            fail("Identity backup must reject non-empty password with FLAG_NO_PASSWORD header");
        } catch (SecurityException expected) {
            assertTrue(expected.getMessage().contains("empty password"));
        }
        try {
            SecureIdentityBackupCodec.decrypt(flaggedNoPassword, new char[0]);
            fail("Identity backup must reject tampered FLAG_NO_PASSWORD header via AEAD AAD");
        } catch (SecurityException expected) {
            assertTrue(expected.getMessage().contains("modified"));
        }
    }

    @Test
    public void historyBackupRejectsEmptyPasswordAndNoPasswordHeaderFlag() {
        IdentityKeyPair identity = IdentityKeyPair.generate();
        SecureHistoryBackupCodec.Payload payload = new SecureHistoryBackupCodec.Payload(
                UUID.fromString("11223344-5566-7788-99aa-bbccddeeff00"),
                987654321L,
                5L,
                1_700_000_100L,
                8192,
                identity.serialize(),
                Collections.emptyList(),
                Collections.emptyList());

        try {
            SecureHistoryBackupCodec.encrypt(payload, new char[0]);
            fail("History backup encrypt must reject empty password");
        } catch (IllegalArgumentException expected) {
            assertEquals("secure history password is required", expected.getMessage());
        }

        try {
            SecureHistoryBackupCodec.encrypt(payload, null);
            fail("History backup encrypt must reject null password");
        } catch (IllegalArgumentException expected) {
            assertEquals("secure history password is required", expected.getMessage());
        }

        char[] password = "strong-history-secret".toCharArray();
        byte[] archive = SecureHistoryBackupCodec.encrypt(payload, password);
        assertTrue(SecureHistoryBackupCodec.requiresPassword(archive));
        SecureHistoryBackupCodec.Payload decoded =
                SecureHistoryBackupCodec.decrypt(archive, password);
        assertArrayEquals(payload.serializedIdentity, decoded.serializedIdentity);

        byte[] flaggedNoPassword = archive.clone();
        flaggedNoPassword[9] = 1;
        try {
            SecureHistoryBackupCodec.decrypt(flaggedNoPassword, password);
            fail("History backup must reject non-empty password with FLAG_NO_PASSWORD header");
        } catch (SecurityException expected) {
            assertTrue(expected.getMessage().contains("empty password"));
        }
        try {
            SecureHistoryBackupCodec.decrypt(flaggedNoPassword, new char[0]);
            fail("History backup must reject tampered FLAG_NO_PASSWORD header via AEAD AAD");
        } catch (SecurityException expected) {
            assertTrue(expected.getMessage().contains("modified"));
        }
    }
}
