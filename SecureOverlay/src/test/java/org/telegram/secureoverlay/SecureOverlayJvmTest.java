package org.telegram.secureoverlay;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.nio.charset.StandardCharsets;
import org.junit.Test;

public final class SecureOverlayJvmTest {
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
