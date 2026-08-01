package org.telegram.secureoverlay;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertEquals;

import org.junit.Test;

public final class SecureSavedMessagesPolicyTest {
    @Test
    public void defaultModeFollowsAccountSetting() {
        assertEquals(SecureSavedMessagesPolicy.Mode.PLAIN,
                SecureSavedMessagesPolicy.defaultMode(false));
        assertEquals(SecureSavedMessagesPolicy.Mode.PROTECTED,
                SecureSavedMessagesPolicy.defaultMode(true));
    }

    @Test
    public void protectedContentCannotBeForwardedToPlainChat() {
        assertFalse(SecureSavedMessagesPolicy.canForward(
                SecureSavedMessagesPolicy.Mode.PROTECTED,
                SecureSavedMessagesPolicy.Mode.PLAIN));
        assertTrue(SecureSavedMessagesPolicy.canForward(
                SecureSavedMessagesPolicy.Mode.PROTECTED,
                SecureSavedMessagesPolicy.Mode.PROTECTED));
        assertTrue(SecureSavedMessagesPolicy.canForward(
                SecureSavedMessagesPolicy.Mode.PLAIN,
                SecureSavedMessagesPolicy.Mode.PLAIN));
    }

    @Test
    public void supportedKindsAreExplicitAndNullIsRejected() {
        for (SecureSavedMessagesPolicy.ContentKind kind
                : SecureSavedMessagesPolicy.ContentKind.values()) {
            assertTrue(SecureSavedMessagesPolicy.supports(kind));
        }
        assertFalse(SecureSavedMessagesPolicy.supports(null));
    }
}
