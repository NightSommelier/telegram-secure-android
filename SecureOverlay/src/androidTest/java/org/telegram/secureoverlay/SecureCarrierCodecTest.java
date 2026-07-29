package org.telegram.secureoverlay;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import android.util.Base64;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
public final class SecureCarrierCodecTest {
    @Test
    public void roundTripsKnownCarrierExactly() {
        byte[] payload = "verified payload".getBytes(StandardCharsets.UTF_8);
        String carrier = SecureCarrierCodec.encode(SecureCarrierCodec.TYPE_WHISPER, payload);

        assertTrue(SecureCarrierCodec.isMarked(carrier));
        assertFalse(SecureCarrierCodec.isMarked("ordinary message"));
        SecureCarrierCodec.Decoded decoded = SecureCarrierCodec.decode(carrier);

        assertEquals(SecureCarrierCodec.TYPE_WHISPER, decoded.type);
        assertArrayEquals(payload, decoded.payload);
    }

    @Test
    public void ignoresOrdinaryTelegramText() {
        assertNull(SecureCarrierCodec.decode("ordinary message"));
        assertNull(SecureCarrierCodec.decode(null));
    }

    @Test
    public void rejectsMalformedMarkedCarriers() {
        assertMalformed(SecureCarrierCodec.PREFIX);
        assertMalformed(SecureCarrierCodec.PREFIX + "not base64");
        assertMalformed(SecureCarrierCodec.encode(
                SecureCarrierCodec.TYPE_PREKEY, new byte[] {1}) + "\n");

        ByteBuffer wrongLength = ByteBuffer.allocate(7).order(ByteOrder.BIG_ENDIAN);
        wrongLength.put((byte) 1);
        wrongLength.put((byte) SecureCarrierCodec.TYPE_WHISPER);
        wrongLength.putInt(2);
        wrongLength.put((byte) 1);
        assertMalformed(SecureCarrierCodec.PREFIX + Base64.encodeToString(
                wrongLength.array(), Base64.NO_WRAP | Base64.URL_SAFE));

        ByteBuffer unknownType = ByteBuffer.allocate(7).order(ByteOrder.BIG_ENDIAN);
        unknownType.put((byte) 1);
        unknownType.put((byte) 99);
        unknownType.putInt(1);
        unknownType.put((byte) 1);
        assertMalformed(SecureCarrierCodec.PREFIX + Base64.encodeToString(
                unknownType.array(), Base64.NO_WRAP | Base64.URL_SAFE));
    }

    private static void assertMalformed(String carrier) {
        try {
            SecureCarrierCodec.decode(carrier);
            fail("expected malformed secure carrier");
        } catch (IllegalArgumentException expected) {
            // Expected: recognized carriers must fail closed.
        }
    }
}
