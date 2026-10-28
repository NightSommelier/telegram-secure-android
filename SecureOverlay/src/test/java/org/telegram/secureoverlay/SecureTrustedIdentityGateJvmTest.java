package org.telegram.secureoverlay;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import org.junit.Test;

public final class SecureTrustedIdentityGateJvmTest {
    @Test
    public void rejectsUnsolicitedInboundMessageWhenChatIsOffWithoutTrustedIdentity() {
        try {
            SecureChatEngine.requireInboundSessionAllowed(
                    1001L,
                    false,
                    false,
                    false,
                    false,
                    false);
            fail("Expected unsolicited message in OFF state without session/identity to be rejected");
        } catch (SecureChatEngine.SecureChatException expected) {
            assertEquals("unsolicited secure message before pairing", expected.getMessage());
        }
    }

    @Test
    public void rejectsInboundMessageWhenIdentityChangeIsPendingVerification() {
        try {
            SecureChatEngine.requireInboundSessionAllowed(
                    1001L,
                    false,
                    false,
                    true,
                    true,
                    true);
            fail("Expected inbound message to be blocked while identity change is pending");
        } catch (SecureChatEngine.SecureChatException expected) {
            assertEquals("new contact identity requires verification", expected.getMessage());
        }
    }

    @Test
    public void allowsInboundMessageWhenWaitingOrPairedOrTrustedSessionExists() {
        // Waiting for pairing acknowledgement after createPairingOffer()
        SecureChatEngine.requireInboundSessionAllowed(
                1001L, false, true, false, false, false);
        // Active paired session
        SecureChatEngine.requireInboundSessionAllowed(
                1001L, true, false, false, true, true);
        // Paused chat with existing trusted session
        SecureChatEngine.requireInboundSessionAllowed(
                1001L, false, false, false, true, true);
        // Group chat uses SenderKey path
        SecureChatEngine.requireInboundSessionAllowed(
                -100999888L, false, false, false, false, false);
    }
}
