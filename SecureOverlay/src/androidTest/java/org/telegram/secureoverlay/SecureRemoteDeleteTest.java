package org.telegram.secureoverlay;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import android.content.Context;
import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Collections;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
public final class SecureRemoteDeleteTest {
    private static final int ACCOUNT = 0;
    private static final long PEER_ID = 998877L;

    private Context context;
    private SecureLocalMessageCache cache;

    @Before
    public void setUp() throws Exception {
        context = ApplicationProvider.getApplicationContext();
        cache = new SecureLocalMessageCache(context, ACCOUNT, PEER_ID);
        cache.forgetPeer();
    }

    @Test
    public void forgetByDigestPurgesBlobsAndPlaintextFileOnDisk() throws Exception {
        String carrier = "TGS1:1:AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=";
        byte[] carrierDigest = MessageDigest.getInstance("SHA-256")
                .digest(carrier.getBytes(StandardCharsets.UTF_8));

        // Create temporary plaintext file
        File tempFile = File.createTempFile("secure-media-test", ".bin", context.getCacheDir());
        try (FileOutputStream out = new FileOutputStream(tempFile)) {
            out.write("secret decrypted file data".getBytes(StandardCharsets.UTF_8));
        }
        assertTrue(tempFile.exists());

        // Put into MediaIndex
        SecureMediaIndex mediaIndex = new SecureMediaIndex(context, ACCOUNT, PEER_ID);
        mediaIndex.put(new SecureMediaIndex.Entry(
                101,
                1000,
                carrier,
                SecureMediaIndex.KIND_PHOTO,
                tempFile.getAbsolutePath(),
                "photo.jpg",
                "image/jpeg",
                "caption",
                100,
                100));

        // Put into text store and content store
        SecureLocalTextStore textStore = new SecureLocalTextStore(context, ACCOUNT, PEER_ID);
        textStore.rememberIncoming(carrier, "Decrypted message text");

        SecureLocalContentStore contentStore = new SecureLocalContentStore(context, ACCOUNT, PEER_ID);
        contentStore.rememberIncoming(carrier, SecureContentCodec.encodeText("Decrypted message text"));

        // Verify stores have it
        assertNotNull(mediaIndex.find(101, carrier));
        assertEquals("Decrypted message text", textStore.loadIncoming(carrier));
        assertNotNull(contentStore.loadIncoming(carrier));

        // Execute forgetByDigest
        boolean purged = cache.forgetByDigest(carrierDigest);
        assertTrue(purged);

        // Verify everything was wiped:
        assertNull(mediaIndex.find(101, carrier));
        assertNull(textStore.loadIncoming(carrier));
        assertNull(contentStore.loadIncoming(carrier));
        assertFalse(tempFile.exists()); // Plaintext file on disk deleted!
    }
}
