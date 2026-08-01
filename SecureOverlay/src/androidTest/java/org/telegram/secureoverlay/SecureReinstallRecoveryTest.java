package org.telegram.secureoverlay;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;

import android.content.Context;

import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;

import java.security.KeyStore;
import java.util.Arrays;
import java.util.UUID;

import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
public final class SecureReinstallRecoveryTest {
    private static final String KEYSTORE = "AndroidKeyStore";
    private static final String KEY_ALIAS = "telegram_secure_overlay_state_key_v1";

    @Test
    public void restoredPreferencesWithoutKeystoreKeyBecomeFreshInstall() throws Exception {
        Context context = ApplicationProvider.getApplicationContext();
        long peer = positiveRandomLong();
        char[] password = "reinstall-test-password".toCharArray();
        byte[] archive = null;
        try {
            SecureChatEngine.resetOwnIdentity(context);
            SecureIdentityBackupManager.IdentityInfo before =
                    SecureIdentityBackupManager.getIdentityInfo(context);
            archive = SecureIdentityBackupManager.exportArchive(
                    context, 930000001L, password);
            new SecureChatState(context).markPaired(0, peer);

            KeyStore keyStore = KeyStore.getInstance(KEYSTORE);
            keyStore.load(null);
            keyStore.deleteEntry(KEY_ALIAS);
            KeystoreEncryptedBlobStore.resetInstallationCheckForTests();

            SecureIdentityBackupManager.IdentityInfo fresh =
                    SecureIdentityBackupManager.getIdentityInfo(context);

            assertNotEquals(before.fingerprint, fresh.fingerprint);
            assertFalse(new SecureChatState(context).hasAnySecureConversationState());
            assertFalse(KeystoreSignalProtocolStore.hasRemoteProtocolState(context));

            SecureIdentityBackupManager.prepareImport(
                    context, 930000001L, archive, password);
            SecureIdentityBackupManager.commitPreparedImport(context);
            assertFalse(new SecureChatState(context).hasAnySecureConversationState());
            assertFalse(KeystoreSignalProtocolStore.hasRemoteProtocolState(context));
            SecureIdentityBackupManager.IdentityInfo restored =
                    SecureIdentityBackupManager.getIdentityInfo(context);
            org.junit.Assert.assertEquals(before.fingerprint, restored.fingerprint);

            SecureChatEngine pairing =
                    new SecureChatEngine(context, 0, peer);
            pairing.createPairingOffer();
            org.junit.Assert.assertEquals(
                    SecureChatEngine.Mode.WAITING, pairing.getMode());
        } finally {
            Arrays.fill(password, '\0');
            if (archive != null) {
                Arrays.fill(archive, (byte) 0);
            }
            try {
                SecureIdentityBackupManager.cancelPreparedImport(context);
            } catch (RuntimeException ignored) {
                // No staged import remains after successful commit.
            }
            SecureChatEngine.resetOwnIdentity(context);
        }
    }

    private static long positiveRandomLong() {
        long value = UUID.randomUUID().getMostSignificantBits() & Long.MAX_VALUE;
        return value == 0 ? 1 : value;
    }
}
