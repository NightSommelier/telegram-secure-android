package org.telegram.secureoverlay;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import org.junit.Test;

public final class SecurePeerBindingJvmTest {
    @Test
    public void acceptsMatchingOneToOneSenderAndRejectsUnspecified() {
        SecureChatEngine.requireValidInboundSender(1001L, 1001L);

        try {
            SecureChatEngine.requireValidInboundSender(1001L, 0L);
            fail("1:1 chat must reject zero/unspecified senderUserId (SA-37)");
        } catch (SecureChatEngine.SecureChatException expected) {
            assertEquals("1:1 message requires positive sender user ID", expected.getMessage());
        }
    }

    @Test
    public void rejectsMismatchedOrNegativeSenderInOneToOneChat() {
        try {
            SecureChatEngine.requireValidInboundSender(1001L, 2002L);
            fail("1:1 chat must reject mismatched positive senderUserId");
        } catch (SecureChatEngine.SecureChatException expected) {
            assertEquals("1:1 message sender does not match peer dialog", expected.getMessage());
        }

        try {
            SecureChatEngine.requireValidInboundSender(1001L, -100555L);
            fail("1:1 chat must reject negative senderUserId");
        } catch (SecureChatEngine.SecureChatException expected) {
            assertEquals("1:1 message requires positive sender user ID", expected.getMessage());
        }
    }

    @Test
    public void enforcesPositiveSenderInGroupChat() {
        SecureChatEngine.requireValidInboundSender(-100999888L, 2002L);

        try {
            SecureChatEngine.requireValidInboundSender(-100999888L, 0L);
            fail("Group chat must reject zero senderUserId");
        } catch (SecureChatEngine.SecureChatException expected) {
            assertEquals("group message requires positive sender user ID", expected.getMessage());
        }

        try {
            SecureChatEngine.requireValidInboundSender(-100999888L, -5L);
            fail("Group chat must reject negative senderUserId");
        } catch (SecureChatEngine.SecureChatException expected) {
            assertEquals("group message requires positive sender user ID", expected.getMessage());
        }
    }
}
