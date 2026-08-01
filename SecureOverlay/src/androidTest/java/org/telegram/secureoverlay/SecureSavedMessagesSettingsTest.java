package org.telegram.secureoverlay;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import android.content.Context;

import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
public final class SecureSavedMessagesSettingsTest {
    private Context context;

    @Before
    public void setUp() {
        context = ApplicationProvider.getApplicationContext();
        SecureSavedMessagesSettings.clearForTests(context);
    }

    @After
    public void tearDown() {
        SecureSavedMessagesSettings.clearForTests(context);
    }

    @Test
    public void secureSavedMessagesIsOffByDefaultAndScopedPerAccount() {
        assertFalse(SecureSavedMessagesSettings.isSecureByDefault(context, 0));
        assertFalse(SecureSavedMessagesSettings.isSecureByDefault(context, 1));

        SecureSavedMessagesSettings.setSecureByDefault(context, 0, true);

        assertTrue(SecureSavedMessagesSettings.isSecureByDefault(context, 0));
        assertFalse(SecureSavedMessagesSettings.isSecureByDefault(context, 1));
    }
}
