package org.telegram.secureoverlay;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
public final class SecureLocalTextStoreTest {
    @Test
    public void keepsIncomingAndOutgoingCopiesSeparate() throws Exception {
        SecureLocalTextStore store = new SecureLocalTextStore(
                ApplicationProvider.getApplicationContext(), 0, 424242);
        String carrier = SecureCarrierCodec.encode(
                SecureCarrierCodec.TYPE_WHISPER,
                UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8));

        assertNull(store.loadOutgoing(carrier));
        assertNull(store.loadIncoming(carrier));

        store.rememberOutgoing(carrier, "outgoing text");
        assertEquals("outgoing text", store.loadOutgoing(carrier));
        assertNull(store.loadIncoming(carrier));

        store.rememberIncoming(carrier, "incoming text");
        assertEquals("outgoing text", store.loadOutgoing(carrier));
        assertEquals("incoming text", store.loadIncoming(carrier));
    }

    @Test
    public void reloadsAuthenticatedIncomingCopyForMetadataOnlyMessageReplacement()
            throws Exception {
        long peerId = UUID.randomUUID().getMostSignificantBits() & Long.MAX_VALUE;
        if (peerId == 0) {
            peerId = 1;
        }
        String carrier = SecureCarrierCodec.encode(
                SecureCarrierCodec.TYPE_WHISPER,
                UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8));

        SecureLocalTextStore firstView = new SecureLocalTextStore(
                ApplicationProvider.getApplicationContext(), 0, peerId);
        firstView.rememberIncoming(carrier, "reaction-safe text");

        // A reaction update constructs a new MessageObject and therefore a new view-side reader.
        // Restoring its preview must use the authenticated cache, not replay the ratchet.
        SecureLocalTextStore replacementView = new SecureLocalTextStore(
                ApplicationProvider.getApplicationContext(), 0, peerId);
        assertEquals("reaction-safe text", replacementView.loadIncoming(carrier));
        assertNull(replacementView.loadOutgoing(carrier));
    }
}
