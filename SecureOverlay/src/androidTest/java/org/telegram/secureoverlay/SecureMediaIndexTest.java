package org.telegram.secureoverlay;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import android.content.Context;

import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;

import java.util.List;
import java.util.concurrent.ThreadLocalRandom;

import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
public final class SecureMediaIndexTest {
    @Test
    public void indexesFiltersUpdatesAndForgetsAuthenticatedMedia() {
        Context context = ApplicationProvider.getApplicationContext();
        long peer = ThreadLocalRandom.current().nextLong(1, Long.MAX_VALUE);
        SecureMediaIndex index = new SecureMediaIndex(context, 0, peer);
        try {
            index.put(entry(
                    10, 100, "TGS1:photo-old",
                    SecureMediaIndex.KIND_PHOTO, "/cache/old.jpg"));
            index.put(entry(
                    20, 300, "TGS1:file",
                    SecureMediaIndex.KIND_FILE, "/cache/report.pdf"));
            index.put(entry(
                    30, 200, "TGS1:photo-new",
                    SecureMediaIndex.KIND_PHOTO, "/cache/new.jpg"));

            List<SecureMediaIndex.Entry> photos =
                    index.list(SecureMediaIndex.KIND_PHOTO);
            assertEquals(2, photos.size());
            assertEquals(30, photos.get(0).messageId);
            assertEquals(10, photos.get(1).messageId);
            assertEquals(2, index.count(SecureMediaIndex.KIND_PHOTO));
            assertEquals(1, index.count(SecureMediaIndex.KIND_FILE));

            assertEquals(
                    "/cache/new.jpg",
                    index.find(30, "TGS1:photo-new").plaintextPath);
            assertNull(index.find(30, "TGS1:wrong-carrier"));

            index.put(entry(
                    30, 400, "TGS1:photo-new",
                    SecureMediaIndex.KIND_PHOTO, "/cache/rebuilt.jpg"));
            photos = index.list(SecureMediaIndex.KIND_PHOTO);
            assertEquals(2, photos.size());
            assertEquals(30, photos.get(0).messageId);
            assertEquals("/cache/rebuilt.jpg", photos.get(0).plaintextPath);

            assertTrue(index.forget("TGS1:photo-new"));
            assertNull(index.find(30, "TGS1:photo-new"));
            assertEquals(1, index.count(SecureMediaIndex.KIND_PHOTO));
        } finally {
            index.forgetPeer();
        }
    }

    @Test
    public void missingPlaintextCacheDoesNotRemoveRecoverableIndexEntry() {
        Context context = ApplicationProvider.getApplicationContext();
        long peer = ThreadLocalRandom.current().nextLong(1, Long.MAX_VALUE);
        SecureMediaIndex index = new SecureMediaIndex(context, 1, peer);
        try {
            SecureMediaIndex.Entry expected = entry(
                    44, 500, "TGS1:evicted-photo",
                    SecureMediaIndex.KIND_PHOTO,
                    "/cache/does-not-exist.jpg");
            index.put(expected);

            SecureMediaIndex.Entry restored =
                    index.find(44, "TGS1:evicted-photo");
            assertEquals(expected.messageId, restored.messageId);
            assertEquals(expected.plaintextPath, restored.plaintextPath);
            assertEquals(1, index.list(SecureMediaIndex.KIND_PHOTO).size());
        } finally {
            index.forgetPeer();
        }
    }

    private static SecureMediaIndex.Entry entry(
            int messageId,
            int date,
            String carrier,
            int kind,
            String path) {
        return new SecureMediaIndex.Entry(
                messageId,
                date,
                carrier,
                kind,
                path,
                kind == SecureMediaIndex.KIND_PHOTO ? "photo.jpg" : "report.pdf",
                kind == SecureMediaIndex.KIND_PHOTO
                        ? "image/jpeg" : "application/pdf",
                "caption",
                kind == SecureMediaIndex.KIND_PHOTO ? 640 : 0,
                kind == SecureMediaIndex.KIND_PHOTO ? 480 : 0);
    }
}
