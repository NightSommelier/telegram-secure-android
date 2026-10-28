package org.telegram.secureoverlay;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.fail;

import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import org.junit.Test;

public final class SecureOverlayJvmTest {
    @Test
    public void unifiedSessionLockMatchesProtocolStoreLock() throws Exception {
        Field engineLock = SecureChatEngine.class.getDeclaredField("SESSION_LOCK");
        engineLock.setAccessible(true);
        Field storeLock = KeystoreSignalProtocolStore.class.getDeclaredField("PROTOCOL_STATE_LOCK");
        storeLock.setAccessible(true);
        assertNotNull(engineLock.get(null));
        assertSame(storeLock.get(null), engineLock.get(null));
    }

    @Test
    public void encodesAndDecodesTextContent() {
        byte[] encoded = SecureContentCodec.encodeText("Fork-Secure Phase 0 test");
        SecureContentCodec.Decoded decoded = SecureContentCodec.decode(encoded);
        assertEquals(SecureContentCodec.TYPE_TEXT, decoded.type);
        assertEquals("Fork-Secure Phase 0 test", decoded.text);
        assertArrayEquals(
                "Fork-Secure Phase 0 test".getBytes(StandardCharsets.UTF_8),
                decoded.text.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    public void encodesAndDecodesPairwiseSenderKeyDistribution() {
        long groupChatId = -100123456789L;
        byte[] distributionBytes = "pairwise-sender-key-dist".getBytes(StandardCharsets.UTF_8);
        byte[] encoded =
                SecureContentCodec.encodeSenderKeyDistribution(groupChatId, distributionBytes);
        SecureContentCodec.Decoded decoded = SecureContentCodec.decode(encoded);
        assertEquals(SecureContentCodec.TYPE_SENDER_KEY_DISTRIBUTION, decoded.type);
        assertNotNull(decoded.senderKeyDistribution);
        assertEquals(groupChatId, decoded.senderKeyDistribution.groupChatId);
        assertArrayEquals(distributionBytes, decoded.senderKeyDistribution.distributionBytes);
    }

    @Test
    public void rejectsPositiveGroupChatIdInSenderKeyDistribution() {
        byte[] distributionBytes = "pairwise-sender-key-dist".getBytes(StandardCharsets.UTF_8);
        try {
            SecureContentCodec.encodeSenderKeyDistribution(12345L, distributionBytes);
            fail("Expected positive groupChatId to be rejected");
        } catch (IllegalArgumentException expected) {
            assertNotNull(expected);
        }
    }
}
