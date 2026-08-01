package org.telegram.secureoverlay;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import android.content.Context;
import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
public final class SecureSavedMessageCryptoTest {
    private SecureSavedMessagesKeyStore.KeyMaterial key;

    @Before
    public void setUp() throws Exception {
        Context context = ApplicationProvider.getApplicationContext();
        SecureSavedMessagesKeyStore store = new SecureSavedMessagesKeyStore(context);
        store.clearForTests(0);
        key = store.getOrCreate(0);
    }

    @Test
    public void textRoundTripsAndCarrierDoesNotContainPlaintext() {
        byte[] record = SecureSavedMessageCrypto.encryptText("private saved note", key);
        assertEquals("private saved note", SecureSavedMessageCrypto.decryptText(record, key));
        assertEquals(-1, new String(record, java.nio.charset.StandardCharsets.UTF_8)
                .indexOf("private saved note"));
    }

    @Test
    public void tamperAndWrongGenerationFailClosed() throws Exception {
        byte[] record = SecureSavedMessageCrypto.encryptText("note", key);
        record[record.length - 1] ^= 1;
        try {
            SecureSavedMessageCrypto.decryptText(record, key);
            fail("tampered record must be rejected");
        } catch (IllegalArgumentException expected) {
            // Expected authentication failure.
        }
        Context context = ApplicationProvider.getApplicationContext();
        SecureSavedMessagesKeyStore.KeyMaterial rotated =
                new SecureSavedMessagesKeyStore(context).rotate(0);
        try {
            SecureSavedMessageCrypto.decryptText(
                    SecureSavedMessageCrypto.encryptText("note", key), rotated);
            fail("old generation must not decrypt with new key");
        } catch (IllegalArgumentException expected) {
            // Expected generation rejection.
        }
    }
}
