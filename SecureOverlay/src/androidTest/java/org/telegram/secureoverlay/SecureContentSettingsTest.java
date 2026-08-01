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
public final class SecureContentSettingsTest {
    private Context context;

    @Before
    public void setUp() {
        context = ApplicationProvider.getApplicationContext();
        SecureContentSettings.clearForTests(context);
    }

    @After
    public void tearDown() {
        SecureContentSettings.clearForTests(context);
    }

    @Test
    public void screenProtectionDefaultsToEnabledAndPersistsChoice() {
        assertTrue(SecureContentSettings.isScreenProtectionEnabled(context));

        SecureContentSettings.setScreenProtectionEnabled(context, false);
        assertFalse(SecureContentSettings.isScreenProtectionEnabled(context));

        SecureContentSettings.setScreenProtectionEnabled(context, true);
        assertTrue(SecureContentSettings.isScreenProtectionEnabled(context));
    }
}
