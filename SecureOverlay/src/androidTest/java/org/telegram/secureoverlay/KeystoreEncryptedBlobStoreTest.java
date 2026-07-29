package org.telegram.secureoverlay;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNull;

import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import java.nio.charset.StandardCharsets;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
public final class KeystoreEncryptedBlobStoreTest {
    @Test
    public void roundTripsAndDeletesEncryptedState() throws Exception {
        KeystoreEncryptedBlobStore store = new KeystoreEncryptedBlobStore(ApplicationProvider.getApplicationContext());
        String name = "instrumentation-roundtrip";
        byte[] plaintext = "not stored as plaintext".getBytes(StandardCharsets.UTF_8);
        store.put(name, plaintext);
        assertArrayEquals(plaintext, store.get(name));
        store.delete(name);
        assertNull(store.get(name));
    }
}
