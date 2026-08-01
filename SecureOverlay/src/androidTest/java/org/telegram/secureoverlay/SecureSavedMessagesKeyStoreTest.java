package org.telegram.secureoverlay;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

import android.content.Context;

import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
public final class SecureSavedMessagesKeyStoreTest {
    private Context context;
    private SecureSavedMessagesKeyStore store;

    @Before
    public void setUp() throws Exception {
        context = ApplicationProvider.getApplicationContext();
        store = new SecureSavedMessagesKeyStore(context);
        store.clearForTests(0);
        store.clearForTests(1);
    }

    @After
    public void tearDown() throws Exception {
        store.clearForTests(0);
        store.clearForTests(1);
    }

    @Test
    public void keyPersistsPerAccountAndRotationCreatesNewGeneration() throws Exception {
        SecureSavedMessagesKeyStore.KeyMaterial first = store.getOrCreate(0);
        SecureSavedMessagesKeyStore.KeyMaterial persisted =
                new SecureSavedMessagesKeyStore(context).getOrCreate(0);
        assertEquals(1, first.generation);
        assertArrayEquals(first.key, persisted.key);

        SecureSavedMessagesKeyStore.KeyMaterial rotated = store.rotate(0);
        assertEquals(2, rotated.generation);
        assertNotEquals(java.util.Arrays.toString(first.key),
                java.util.Arrays.toString(rotated.key));

        SecureSavedMessagesKeyStore.KeyMaterial otherAccount = store.getOrCreate(1);
        assertEquals(1, otherAccount.generation);
        assertNotEquals(java.util.Arrays.toString(rotated.key),
                java.util.Arrays.toString(otherAccount.key));
    }
}
