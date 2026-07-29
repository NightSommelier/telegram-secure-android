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

    @Test
    public void deletesMultipleRecordsTogether() throws Exception {
        KeystoreEncryptedBlobStore store =
                new KeystoreEncryptedBlobStore(
                        ApplicationProvider.getApplicationContext());
        String first = "instrumentation-delete-all-first";
        String second = "instrumentation-delete-all-second";
        store.put(first, new byte[] {1});
        store.put(second, new byte[] {2});

        store.deleteAll(first, second);

        assertNull(store.get(first));
        assertNull(store.get(second));
    }

    @Test
    public void deletesOnlyMatchingPrefixes() throws Exception {
        KeystoreEncryptedBlobStore store =
                new KeystoreEncryptedBlobStore(
                        ApplicationProvider.getApplicationContext());
        String first = "instrumentation-prefix.one";
        String second = "instrumentation-prefix.two";
        String retained = "instrumentation-retained";
        store.put(first, new byte[] {1});
        store.put(second, new byte[] {2});
        store.put(retained, new byte[] {3});

        store.deletePrefixes("instrumentation-prefix.");

        assertNull(store.get(first));
        assertNull(store.get(second));
        assertArrayEquals(new byte[] {3}, store.get(retained));
        store.delete(retained);
    }
}
